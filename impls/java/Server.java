package onlyblocks;

import com.sun.net.httpserver.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import static onlyblocks.Wire.*;

public final class Server {
    private static final int MAX_BODY = 1 << 20, MAX_SLICE = 128 << 20;
    private static final String ZERO_HASH = "1".repeat(32);
    static final class RpcError extends RuntimeException {
        final int code;
        RpcError(int code, String message) { super(message); this.code = code; }
    }
    private static final class Lru<K, V> {
        private final LinkedHashMap<K, V> map = new LinkedHashMap<>(16, .75f, true);
        synchronized V get(K key) { return map.get(key); }
        synchronized void put(K key, V value) {
            map.put(key, value);
            if (map.size() > 100_000) map.remove(map.keySet().iterator().next());
        }
    }
    private static final class RangeStatus extends RuntimeException {
        final int code;
        final String retryAfter;
        RangeStatus(HttpResponse.ResponseInfo info) {
            code = info.statusCode();
            retryAfter = info.headers().firstValue("Retry-After").orElse(null);
        }
    }
    private static final class RangeBody implements HttpResponse.BodySubscriber<byte[]> {
        private final int cap;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private Flow.Subscription subscription;
        RangeBody(int cap) { this.cap = cap; }
        public CompletionStage<byte[]> getBody() { return result; }
        public void onSubscribe(Flow.Subscription sub) { subscription = sub; sub.request(1); }
        public void onNext(List<ByteBuffer> buffers) {
            for (var buf : buffers) {
                if (buf.remaining() > cap - out.size()) {
                    result.completeExceptionally(new BadData("Oversized range"));
                    subscription.cancel();
                    return;
                }
                byte[] bytes = new byte[buf.remaining()];
                buf.get(bytes);
                out.writeBytes(bytes);
            }
            subscription.request(1);
        }
        public void onError(Throwable e) { result.completeExceptionally(e); }
        public void onComplete() { result.complete(out.toByteArray()); }
    }
    private static long retryDelay(String header, int failures) {
        if (header != null) {
            try {
                long seconds = Long.parseUnsignedLong(header.trim());
                return Long.compareUnsigned(seconds, 10) > 0 ? 10_000 : seconds * 1000;
            } catch (NumberFormatException ignored) { }
            try {
                long ms = Duration.between(ZonedDateTime.now(),
                    ZonedDateTime.parse(header, DateTimeFormatter.RFC_1123_DATE_TIME)).toMillis();
                return Math.max(0, Math.min(ms, 10_000));
            } catch (RuntimeException ignored) { }
        }
        long base = 200L << failures;
        return ThreadLocalRandom.current().nextLong(base / 2, base + 1);
    }
    private static final class Archive {
        private record Range(long offset, long length) {}
        private final String base;
        private final Lru<Long, Range> ranges = new Lru<>();
        private final Lru<Long, String> hashes = new Lru<>();
        private final Semaphore permits = new Semaphore(32);
        private final HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10)).build();
        Archive(String base) { this.base = base; }

        private byte[] read(long slot, String suffix, long start, int length, int cap) throws InterruptedException {
            long end = start + length - 1;
            check(Long.compareUnsigned(end, start) >= 0);
            long epoch = Long.divideUnsigned(slot, 432000);
            var request = HttpRequest.newBuilder(URI.create(base + "/" + epoch + "/epoch-" + epoch + suffix))
                .timeout(Duration.ofSeconds(60)).header("User-Agent", "onlyblocks/java")
                .header("Range", "bytes=" + Long.toUnsignedString(start) + "-" + Long.toUnsignedString(end))
                .GET().build();
            for (int failures = 0; failures < 5; failures++) {
                String retryAfter = null;
                permits.acquire();
                try {
                    var future = client.sendAsync(request, info -> {
                        if (info.statusCode() != 206) throw new RangeStatus(info);
                        check(info.headers().firstValueAsLong("Content-Length").orElse(0) <= cap);
                        return new RangeBody(cap);
                    });
                    HttpResponse<byte[]> response = null;
                    try { response = future.get(60, TimeUnit.SECONDS); }
                    catch (TimeoutException e) { future.cancel(true); }
                    catch (InterruptedException e) { future.cancel(true); throw e; }
                    catch (ExecutionException e) {
                        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
                            if (cause instanceof BadData bad) throw bad;
                            if (cause instanceof RangeStatus status) {
                                if (status.code == 404)
                                    throw new RpcError(-32004, "Block not available for slot " + Long.toUnsignedString(slot));
                                check(status.code == 429 || status.code >= 500 && status.code < 600);
                                retryAfter = status.retryAfter;
                                break;
                            }
                        }
                    }
                    if (response != null) {
                        check(response.body().length == length);
                        return response.body();
                    }
                } finally { permits.release(); }
                if (failures < 4) Thread.sleep(retryDelay(retryAfter, failures));
            }
            throw new BadData("Archive range retries exhausted");
        }

        private Car load(long slot) throws InterruptedException {
            var range = ranges.get(slot);
            if (range == null) {
                long at = Long.remainderUnsigned(slot, 432000) * 12;
                var r = new Reader(read(slot, "-slot-ranges.raw", at, 12, 12));
                range = new Range(r.u64(), r.le(4));
                ranges.put(slot, range);
            }
            if (range.length == 0) throw new RpcError(-32007, "Slot " + Long.toUnsignedString(slot) + " was skipped");
            check(range.length <= MAX_SLICE);
            return new Car(read(slot, ".car", range.offset, (int) range.length, MAX_SLICE));
        }
        private String hash(long slot, Car car, List<Cid> entries) {
            String hash = ZERO_HASH;
            if (!entries.isEmpty()) hash = pubkey((byte[]) at(car.get(entries.get(entries.size() - 1), 1), 2));
            hashes.put(slot, hash);
            return hash;
        }
        Object block(long slot, Solana.Options options) throws InterruptedException {
            var car = load(slot);
            var block = car.block;
            check(u64(at(block, 1), 0) == slot);
            var entries = links(at(block, 3));
            var info = list(at(block, 4));
            long parent = u64(at(info, 0), 0);
            String hash = hash(slot, car, entries), previous = ZERO_HASH;
            if (slot != 0) {
                previous = hashes.get(parent);
                if (previous == null) {
                    var p = load(parent);
                    previous = hash(parent, p, links(at(p.block, 3)));
                }
            }
            Object time = at(info, 1);
            Long timestamp = time instanceof Long t ? t :
                time instanceof Unsigned t && t.bits() >= 0 ? Long.valueOf(t.bits()) : null;
            var out = obj("previousBlockhash", previous, "blockhash", hash, "parentSlot", uint(parent),
                "blockTime", timestamp != null && timestamp != 0 ? timestamp : null,
                "blockHeight", at(info, 2) instanceof Unsigned h ? uint(h.bits()) : null);
            if (!options.details().equals("none")) {
                boolean onlySignatures = options.details().equals("signatures");
                var txs = new ArrayList<>();
                for (var entryKey : entries) {
                    var entry = car.get(entryKey, 1);
                    check(at(entry, 2) instanceof byte[] b && b.length == 32);
                    for (var txKey : links(at(entry, 3))) {
                        var node = car.get(txKey, 0);
                        var tx = new Solana.Transaction(car.payload(at(node, 1)));
                        if (onlySignatures) txs.add(b58(tx.signatures.get(0)));
                        else {
                            var meta = at(node, 2) instanceof List<?> data ? Solana.metadata(slot, car.payload(data)) : null;
                            txs.add(tx.json(meta, options));
                        }
                    }
                }
                out.put(onlySignatures ? "signatures" : "transactions", txs);
            }
            if (options.rewards()) {
                List<?> node = null;
                if (at(block, 5) instanceof byte[] bytes) {
                    var cid = link(bytes);
                    if (!cid.absent()) node = car.find(cid, 5);
                }
                out.putAll(Solana.rewards(slot, node != null && node.size() > 2 ? car.payload(node.get(2)) : EMPTY));
            }
            return out;
        }
    }

    private static RpcError invalidParams() { return new RpcError(-32602, "Invalid params"); }
    private static Long unsigned(Object value) { return value instanceof Json.Num n ? n.unsigned() : null; }
    private static String enumParam(Map<?, ?> config, String key, String fallback, String... options) {
        Object v = config.get(key);
        if (v == null) return fallback;
        if (!(v instanceof String s) || !Arrays.asList(options).contains(s)) throw invalidParams();
        return s;
    }
    private static Object block(Archive archive, Object params) throws InterruptedException {
        if (!(params instanceof List<?> list) || list.size() < 1 || list.size() > 2) throw invalidParams();
        Long slot = unsigned(list.get(0));
        if (slot == null) throw invalidParams();
        Object option = at(list, 1);
        Map<?, ?> cfg;
        if (option == null) cfg = Map.of();
        else if (option instanceof String s) cfg = Map.of("encoding", s);
        else if (option instanceof Map<?, ?> m) cfg = m;
        else throw invalidParams();
        String encoding = enumParam(cfg, "encoding", "json", "json", "jsonParsed", "base64", "base58");
        String details = enumParam(cfg, "transactionDetails", "full", "full", "accounts", "signatures", "none");
        enumParam(cfg, "commitment", "finalized", "finalized", "confirmed");
        Object rewards = cfg.get("rewards");
        if (rewards != null && !(rewards instanceof Boolean)) throw invalidParams();
        Integer maxVersion = null;
        Object max = cfg.get("maxSupportedTransactionVersion");
        if (max != null) {
            Long version = unsigned(max);
            if (version == null || Long.compareUnsigned(version, 255) > 0) throw invalidParams();
            maxVersion = version.intValue();
            if (encoding.equals("base58") && maxVersion >= 1) {
                throw new RpcError(-32602, "base58 encoding is not supported with maxSupportedTransactionVersion >= 1");
            }
        }
        if (details.equals("accounts") && !encoding.equals("json")) throw invalidParams();
        return archive.block(slot, new Solana.Options(encoding, details, !Boolean.FALSE.equals(rewards), maxVersion));
    }
    private static Object error(Object id, int code, String message) {
        return obj("jsonrpc", "2.0", "id", id, "error", obj("code", code, "message", message));
    }
    private static Object dispatch(Archive archive, Object input) {
        if (!(input instanceof Map<?, ?> request)) return error(null, -32600, "Invalid Request");
        Object protocol = request.get("jsonrpc"), method = request.get("method"), id = request.get("id");
        if ((protocol != null && !(protocol instanceof String)) || (method != null && !(method instanceof String)) ||
            (id != null && !(id instanceof String) && !(id instanceof Json.Num))) return error(null, -32600, "Invalid Request");
        if (!"2.0".equals(protocol) || method == null) return error(id, -32600, "Invalid Request");
        try {
            Object params = request.get("params");
            Object result = switch ((String) method) {
                case "getHealth" -> {
                    if (params != null && (!(params instanceof List<?> a) || !a.isEmpty())) throw invalidParams();
                    yield "ok";
                }
                case "getBlock" -> block(archive, params);
                default -> throw new RpcError(-32601, "Method not found: " + method);
            };
            return obj("jsonrpc", "2.0", "id", id, "result", result);
        } catch (RpcError e) { return error(id, e.code, e.getMessage()); }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return error(id, -32603, "Request interrupted");
        } catch (RuntimeException e) { return error(id, -32603, "Internal error"); }
    }
    private static Object rpc(Archive archive, byte[] body) {
        Object parsed;
        try { parsed = new Json(body).parse(); }
        catch (BadData e) { return error(null, -32700, "Parse error"); }
        if (parsed instanceof List<?> batch) {
            if (batch.isEmpty() || batch.size() > 100) return error(null, -32600, "Invalid Request");
            return batch.stream().map(item -> dispatch(archive, item)).toList();
        }
        return dispatch(archive, parsed);
    }
    private static void serve(HttpExchange e, Archive archive) throws IOException {
        try (e) {
            e.getResponseHeaders().set("Connection", "close");
            if (!e.getRequestURI().getRawPath().equals("/")) { e.sendResponseHeaders(404, -1); return; }
            if (!e.getRequestMethod().equals("POST")) { e.sendResponseHeaders(405, -1); return; }
            String length = e.getRequestHeaders().getFirst("Content-Length");
            if (length != null && Long.parseLong(length) > MAX_BODY) { e.sendResponseHeaders(413, -1); return; }
            byte[] body = e.getRequestBody().readNBytes(MAX_BODY + 1);
            if (body.length > MAX_BODY) { e.sendResponseHeaders(413, -1); return; }
            byte[] output = Json.encode(rpc(archive, body));
            e.getResponseHeaders().set("Content-Type", "application/json");
            e.sendResponseHeaders(200, output.length);
            e.getResponseBody().write(output);
        }
    }

    public static void main(String[] args) throws IOException {
        String bind = System.getenv().getOrDefault("ONLYBLOCKS_BIND", "127.0.0.1:8899");
        String base = System.getenv().getOrDefault("OLD_FAITHFUL_BASE_URL", "https://files.old-faithful.net");
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            int split = arg.indexOf('=');
            String flag = split < 0 ? arg : arg.substring(0, split);
            if (!flag.equals("--bind") && !flag.equals("--base-url")) throw new IllegalArgumentException("Unknown flag " + flag);
            if (split < 0 && i + 1 == args.length) throw new IllegalArgumentException("Missing value for " + flag);
            String val = split < 0 ? args[++i] : arg.substring(split + 1);
            if (flag.equals("--bind")) bind = val;
            else base = val;
        }
        base = base.strip().replaceFirst("/+$", "");
        var uri = URI.create(base);
        if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme())) || uri.getHost() == null)
            throw new IllegalArgumentException("Invalid archive base URL");
        int colon = bind.lastIndexOf(':');
        String host = bind.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        int port = Integer.parseInt(bind.substring(colon + 1));
        var archive = new Archive(base);
        var executor = Executors.newFixedThreadPool(40);
        var server = HttpServer.create(new InetSocketAddress(host, port), 128);
        server.setExecutor(executor);
        server.createContext("/", exchange -> serve(exchange, archive));
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop(0);
            executor.shutdownNow();
        }));
        server.start();
    }
}
