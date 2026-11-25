using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;

sealed class RpcError(int code, string message) : Exception(message)
{
    internal int Code => code;
}

sealed class Lru<T> where T : notnull
{
    private readonly LinkedList<(ulong Key, T Value)> order = new();
    private readonly Dictionary<ulong, LinkedListNode<(ulong Key, T Value)>> index = new();
    private const int Capacity = 100_000;

    internal bool TryGet(ulong key, out T value)
    {
        lock (index)
        {
            if (index.TryGetValue(key, out var node))
            {
                order.Remove(node);
                order.AddFirst(node);
                value = node.Value.Value;
                return true;
            }
        }
        value = default!;
        return false;
    }

    internal void Set(ulong key, T value)
    {
        lock (index)
        {
            if (index.Remove(key, out var old)) order.Remove(old);
            index[key] = order.AddFirst((key, value));
            if (index.Count > Capacity)
            {
                index.Remove(order.Last!.Value.Key);
                order.RemoveLast();
            }
        }
    }
}

sealed record Options(string Encoding, string Details, bool Rewards, bool HasVersion);

sealed class Archive(string origin, CancellationToken shutdown)
{
    private const int SliceLimit = 128 * 1024 * 1024;
    private readonly Lru<(ulong Offset, uint Length)> ranges = new();
    private readonly Lru<string> hashes = new();
    private readonly SemaphoreSlim upstream = new(32);
    private readonly HttpClient client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, UseProxy = false, UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(10), MaxConnectionsPerServer = 32
    }) { Timeout = Timeout.InfiniteTimeSpan };

    private async Task<byte[]> Range(string path, ulong slot, ulong start, int length, int cap)
    {
        Wire.Check(start <= ulong.MaxValue - (ulong)(length - 1), "Range end overflow");
        var end = start + (ulong)(length - 1);
        for (int attempt = 0; attempt < 5; attempt++)
        {
            TimeSpan? retry = null;
            await upstream.WaitAsync(shutdown);
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(shutdown);
                timeout.CancelAfter(TimeSpan.FromSeconds(60));
                using var request = new HttpRequestMessage(HttpMethod.Get, origin + path);
                request.Headers.TryAddWithoutValidation("Range", FormattableString.Invariant($"bytes={start}-{end}"));
                request.Headers.UserAgent.ParseAdd("onlyblocks/csharp");
                request.Headers.ConnectionClose = true;
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                int status = (int)response.StatusCode;
                if (status == 404) throw new RpcError(-32004, $"Block not available for slot {slot}");
                if (status == 206)
                {
                    long? declared = response.Content.Headers.ContentLength;
                    Wire.Check(declared == null || declared <= cap, "Range body exceeds limit");
                    using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
                    // Read a mismatched framed body fully (up to the cap) so a short delivery is retried.
                    byte[] body = new byte[length];
                    int filled = 0;
                    while (filled < length)
                    {
                        int n = await stream.ReadAsync(body.AsMemory(filled), timeout.Token);
                        if (n == 0) break;
                        filled += n;
                    }
                    if (filled == length)
                    {
                        byte[] extra = new byte[8192];
                        int total = filled;
                        while (true)
                        {
                            int n = await stream.ReadAsync(extra.AsMemory(0, Math.Min(extra.Length, cap - total + 1)), timeout.Token);
                            if (n == 0) break;
                            total += n;
                            Wire.Check(total <= cap, "Range body exceeds limit");
                        }
                        filled = total;
                    }
                    Wire.Check(filled == length, "Range response length mismatch");
                    return body;
                }
                Wire.Check(status == 429 || status is >= 500 and <= 599, $"Unexpected upstream HTTP {status}");
                var header = response.Headers.RetryAfter;
                retry = header?.Delta ?? (header?.Date - DateTimeOffset.UtcNow);
            }
            catch (Exception ex) when (!shutdown.IsCancellationRequested &&
                ex is HttpRequestException or OperationCanceledException or IOException && ex is not InvalidDataException)
            {
                // The origin failed to deliver a complete response. Retry with backoff.
            }
            finally { upstream.Release(); }

            if (attempt < 4)
            {
                double delay = retry is TimeSpan t ? Math.Clamp(t.TotalMilliseconds, 0, 10_000)
                    : 200 * (1 << attempt) * (0.5 + Random.Shared.NextDouble() * 0.5);
                await Task.Delay(TimeSpan.FromMilliseconds(delay), shutdown);
            }
        }
        throw new InvalidDataException("Old Faithful retries exhausted");
    }

    private async Task<Car> Load(ulong slot)
    {
        ulong epoch = slot / 432_000;
        string prefix = FormattableString.Invariant($"/{epoch}/epoch-{epoch}");
        if (!ranges.TryGet(slot, out var entry))
        {
            byte[] index = await Range(prefix + "-slot-ranges.raw", slot, slot % 432_000 * 12, 12, 12);
            var r = new Reader(index);
            entry = (r.U64(), r.U32());
            ranges.Set(slot, entry);
        }
        if (entry.Length == 0) throw new RpcError(-32007, $"Slot {slot} was skipped");
        Wire.Check(entry.Length <= SliceLimit, "CAR slice exceeds limit");
        return new Car(await Range(prefix + ".car", slot, entry.Offset, (int)entry.Length, SliceLimit));
    }

    internal async Task<object> Block(ulong slot, Options options)
    {
        var car = await Load(slot);
        Wire.Check(car.Slot == slot, "CAR slot mismatch");
        string hash = car.Hash();
        hashes.Set(slot, hash);
        string previous;
        if (slot == 0) previous = Car.ZeroHash;
        else if (!hashes.TryGet(car.Parent, out previous))
        {
            previous = (await Load(car.Parent)).Hash();
            hashes.Set(car.Parent, previous);
        }

        var block = new Dictionary<string, object?>
        {
            ["previousBlockhash"] = previous, ["blockhash"] = hash, ["parentSlot"] = car.Parent,
            ["blockTime"] = car.Time, ["blockHeight"] = car.Height
        };
        if (options.Details != "none")
        {
            var transactions = new List<object>();
            bool signatures = options.Details == "signatures";
            foreach (string key in car.Transactions())
            {
                var node = car.Node(key, 0);
                var tx = new Transaction(car.Frame(Car.Field(node, 1)));
                if (signatures)
                {
                    Wire.Check(tx.Signatures.Length != 0, "Transaction has no signatures");
                    transactions.Add(Wire.Base58(tx.Signatures[0].Span));
                    continue;
                }
                var meta = Car.Field(node, 2) is object?[] frame ? Metadata.ReadMeta(slot, car.Frame(frame)) : null;
                if (tx.V0)
                {
                    if (!options.HasVersion) throw new RpcError(-32015, "Transaction version 0 requires maxSupportedTransactionVersion");
                    meta ??= new Meta();
                }
                transactions.Add(tx.Json(meta, options));
            }
            block[signatures ? "signatures" : "transactions"] = transactions;
        }
        if (options.Rewards)
        {
            RewardSet rewards = new([]);
            if (car.Rewards is string key && car.Contains(key))
            {
                var node = car.Node(key, 5);
                if (node.Length > 2) rewards = Metadata.ReadRewards(slot, car.Frame(node[2]));
            }
            block["rewards"] = rewards.Rewards;
            if (rewards.Partitions != null) block["numRewardPartitions"] = rewards.Partitions;
        }
        return block;
    }
}

sealed class Rpc(Archive archive)
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private static object Error(int code, string message, JsonElement? id = null) =>
        new { jsonrpc = "2.0", error = new { code, message }, id };

    private static JsonElement Field(JsonElement value, string key) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var found) ? found : default;

    private static bool Missing(JsonElement v) => v.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null;
    private static string? Text(JsonElement v) => v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static RpcError InvalidParams() => new(-32602, "Invalid params");

    private static ulong UInt(JsonElement v, ulong limit)
    {
        if (v.ValueKind != JsonValueKind.Number) throw InvalidParams();
        string raw = v.GetRawText();
        if (raw.Length > 20 || raw.Any(c => c is < '0' or > '9') ||
            !ulong.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out ulong n) || n > limit) throw InvalidParams();
        return n;
    }

    private static (ulong Slot, Options Options) BlockParams(JsonElement p)
    {
        if (p.ValueKind != JsonValueKind.Array || p.GetArrayLength() is < 1 or > 2) throw InvalidParams();
        ulong slot = UInt(p[0], ulong.MaxValue);
        var cfg = p.GetArrayLength() == 2 ? p[1] : default;
        string V(string key, string fallback)
        {
            var value = Field(cfg, key);
            return Missing(value) ? fallback : Text(value) ?? throw InvalidParams();
        }
        if (!Missing(cfg) && cfg.ValueKind is not (JsonValueKind.String or JsonValueKind.Object)) throw InvalidParams();
        string encoding = Text(cfg) ?? V("encoding", "json"), details = V("transactionDetails", "full");
        if (encoding is not ("json" or "jsonParsed" or "base64" or "base58") ||
            details is not ("full" or "accounts" or "signatures" or "none") ||
            details == "accounts" && encoding != "json" ||
            V("commitment", "finalized") is not ("finalized" or "confirmed")) throw InvalidParams();
        var rewards = Field(cfg, "rewards");
        if (!Missing(rewards) && rewards.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw InvalidParams();
        var version = Field(cfg, "maxSupportedTransactionVersion");
        if (!Missing(version)) UInt(version, 255);
        return (slot, new Options(encoding, details, rewards.ValueKind != JsonValueKind.False, !Missing(version)));
    }

    // JsonDocument defers decoding strings until accessed. Check Unicode throughout the envelope.
    private static void ValidateStrings(JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.String: value.GetString(); break;
            case JsonValueKind.Array:
                foreach (var element in value.EnumerateArray()) ValidateStrings(element);
                break;
            case JsonValueKind.Object:
                foreach (var property in value.EnumerateObject())
                {
                    _ = property.Name;
                    ValidateStrings(property.Value);
                }
                break;
        }
    }

    private async Task<object> Dispatch(JsonElement request)
    {
        if (request.ValueKind != JsonValueKind.Object) return Error(-32600, "Invalid Request");
        var version = Field(request, "jsonrpc");
        var method = Field(request, "method");
        var idField = Field(request, "id");
        var name = Text(method);
        if ((!Missing(version) && Text(version) == null) || (!Missing(method) && name == null) ||
            (!Missing(idField) && idField.ValueKind is not (JsonValueKind.String or JsonValueKind.Number)))
            return Error(-32600, "Invalid Request");
        JsonElement? id = Missing(idField) ? null : idField;
        if (Text(version) != "2.0" || name == null) return Error(-32600, "Invalid Request", id);

        try
        {
            object result;
            switch (name)
            {
                case "getHealth":
                    var p = Field(request, "params");
                    if (!Missing(p) && !(p.ValueKind == JsonValueKind.Array && p.GetArrayLength() == 0)) throw InvalidParams();
                    result = "ok";
                    break;
                case "getBlock":
                    var (slot, options) = BlockParams(Field(request, "params"));
                    result = await archive.Block(slot, options);
                    break;
                default: return Error(-32601, "Method not found: " + name, id);
            }
            return new { jsonrpc = "2.0", result, id };
        }
        catch (RpcError ex) { return Error(ex.Code, ex.Message, id); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Error(-32603, string.IsNullOrEmpty(ex.Message) ? "Internal error" : ex.Message, id);
        }
    }

    internal async Task<byte[]> Handle(ReadOnlyMemory<byte> body)
    {
        JsonDocument request;
        try
        {
            Wire.Utf8.GetCharCount(body.Span);
            request = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 128 });
        }
        catch (Exception ex) when (ex is JsonException or System.Text.DecoderFallbackException)
        {
            return JsonSerializer.SerializeToUtf8Bytes(Error(-32700, "Parse error"), JsonOptions);
        }

        using (request)
        {
            try { ValidateStrings(request.RootElement); }
            catch (InvalidOperationException)
            {
                return JsonSerializer.SerializeToUtf8Bytes(Error(-32700, "Parse error"), JsonOptions);
            }

            object answer;
            if (request.RootElement.ValueKind != JsonValueKind.Array) answer = await Dispatch(request.RootElement);
            else if (request.RootElement.GetArrayLength() is < 1 or > 100) answer = Error(-32600, "Invalid batch size");
            else
            {
                var batch = new List<object>();
                foreach (var item in request.RootElement.EnumerateArray()) batch.Add(await Dispatch(item));
                answer = batch;
            }
            return JsonSerializer.SerializeToUtf8Bytes(answer, JsonOptions);
        }
    }
}

static class Program
{
    private const int MaxBody = 1024 * 1024;

    private static (string Bind, string Origin) Parse(string[] args)
    {
        string bind = Environment.GetEnvironmentVariable("ONLYBLOCKS_BIND") ?? "127.0.0.1:8899";
        string origin = Environment.GetEnvironmentVariable("OLD_FAITHFUL_BASE_URL") ?? "https://files.old-faithful.net";
        for (int i = 0; i < args.Length; i++)
        {
            var parts = args[i].Split('=', 2);
            string value = parts.Length == 2 ? parts[1] : ++i < args.Length ? args[i] : throw new ArgumentException("Missing flag value");
            switch (parts[0])
            {
                case "--bind": bind = value; break;
                case "--base-url": origin = value; break;
                default: throw new ArgumentException("Unknown flag " + parts[0]);
            }
        }
        origin = origin.Trim().TrimEnd('/');
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var url) || url.Scheme is not ("http" or "https") ||
            url.Query.Length > 0 || url.Fragment.Length > 0 || url.UserInfo.Length > 0)
            throw new ArgumentException("--base-url requires an HTTP or HTTPS origin");
        return (bind, origin);
    }

    private static async Task Serve(HttpListenerContext context, Rpc rpc, CancellationToken shutdown, SemaphoreSlim handlers)
    {
        try
        {
            using var response = context.Response;
            response.KeepAlive = false;
            response.ContentLength64 = 0;
            var request = context.Request;
            if (request.HttpMethod != "POST" || request.RawUrl != "/")
            {
                response.StatusCode = 404;
                return;
            }
            if (request.ContentLength64 > MaxBody)
            {
                response.StatusCode = 413;
                return;
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(shutdown);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            using var body = new MemoryStream();
            byte[] buffer = new byte[8192];
            while (true)
            {
                int count = await request.InputStream.ReadAsync(buffer.AsMemory(0,
                    Math.Min(buffer.Length, MaxBody - (int)body.Length + 1)), timeout.Token);
                if (count == 0) break;
                if (body.Length + count > MaxBody)
                {
                    response.StatusCode = 413;
                    return;
                }
                body.Write(buffer.AsSpan(0, count));
            }
            byte[] output = await rpc.Handle(body.GetBuffer().AsMemory(0, (int)body.Length));
            response.ContentType = "application/json";
            response.ContentLength64 = output.Length;
            using var writeTimeout = CancellationTokenSource.CreateLinkedTokenSource(shutdown);
            writeTimeout.CancelAfter(TimeSpan.FromSeconds(10));
            await response.OutputStream.WriteAsync(output, writeTimeout.Token);
        }
        catch (Exception ex) when (ex is IOException or HttpListenerException or OperationCanceledException or ObjectDisposedException)
        {
            context.Response.Abort();
        }
        finally { handlers.Release(); }
    }

    internal static async Task<int> Main(string[] args)
    {
        try
        {
            var (address, origin) = Parse(args);
            var bind = address.Split(':', 2);
            if (bind.Length != 2 || !ushort.TryParse(bind[1], NumberStyles.None, CultureInfo.InvariantCulture, out ushort port) ||
                port == 0 || Uri.CheckHostName(bind[0]) is not (UriHostNameType.Dns or UriHostNameType.IPv4))
                throw new ArgumentException("--bind requires an IPv4 HOST:PORT");

            using var stop = new CancellationTokenSource();
            using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; stop.Cancel(); });
            using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; stop.Cancel(); });
            using var listener = new HttpListener();
            listener.Prefixes.Add($"http://{(bind[0] == "0.0.0.0" ? "+" : bind[0])}:{port}/");
            var handlers = new SemaphoreSlim(64);
            var rpc = new Rpc(new Archive(origin, stop.Token));
            listener.Start();
            while (!stop.IsCancellationRequested)
            {
                await handlers.WaitAsync(stop.Token);
                var context = await listener.GetContextAsync().WaitAsync(stop.Token);
                _ = Serve(context, rpc, stop.Token, handlers);
            }
            return 0;
        }
        catch (OperationCanceledException) { return 0; }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }
}
