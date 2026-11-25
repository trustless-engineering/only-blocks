using System.Buffers.Binary;
using System.Text;

static class Wire
{
    internal static void Check(bool valid, string message = "Invalid archive data")
    {
        if (!valid) throw new InvalidDataException(message);
    }

    internal static readonly UTF8Encoding Utf8 = new(false, true);
    internal static string Text(ReadOnlySpan<byte> bytes)
    {
        try { return Utf8.GetString(bytes); }
        catch (DecoderFallbackException ex) { throw new InvalidDataException("Invalid UTF-8", ex); }
    }

    internal static string Base58(ReadOnlySpan<byte> data)
    {
        const string alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        int zero = 0;
        while (zero < data.Length && data[zero] == 0) zero++;
        // Convert in base 58^5 to reduce the number of divisions for large transactions.
        var digits = new List<uint>();
        foreach (byte b in data[zero..])
        {
            ulong carry = b;
            for (int i = 0; i < digits.Count; i++)
            {
                carry += (ulong)digits[i] << 8;
                digits[i] = (uint)(carry % 656356768);
                carry /= 656356768;
            }
            if (carry != 0) digits.Add((uint)carry);
        }
        var result = new StringBuilder().Append('1', zero);
        Span<char> group = stackalloc char[5];
        for (int i = digits.Count - 1; i >= 0; i--)
        {
            uint digit = digits[i];
            for (int j = 4; j >= 0; j--)
            {
                group[j] = alphabet[(int)(digit % 58)];
                digit /= 58;
            }
            int start = 0;
            if (i == digits.Count - 1)
                while (group[start] == '1') start++;
            result.Append(group[start..]);
        }
        return result.ToString();
    }

    private static ulong[] CrcTable()
    {
        var result = new ulong[256];
        for (ulong i = 0; i < 256; i++)
        {
            ulong x = i;
            for (int j = 0; j < 8; j++) x = (x >> 1) ^ ((x & 1) == 0 ? 0 : 0xd800000000000000);
            result[i] = x;
        }
        return result;
    }

    private static readonly ulong[] Crc = CrcTable();

    internal static bool HashMatches(ReadOnlySpan<byte> bytes, ulong expected)
    {
        ulong crc = ulong.MaxValue;
        foreach (byte b in bytes) crc = (crc >> 8) ^ Crc[(byte)(crc ^ b)];
        if (~crc == expected) return true;
        ulong fnv = 0xcbf29ce484222325;
        foreach (byte b in bytes) fnv = unchecked((fnv ^ b) * 0x100000001b3);
        return fnv == expected;
    }
}

sealed class Reader(ReadOnlyMemory<byte> data)
{
    internal int Position { get; private set; }
    internal int Left => data.Length - Position;
    internal byte Peek => Left > 0 ? data.Span[Position] : throw new InvalidDataException("Truncated input");

    internal ReadOnlyMemory<byte> Take(int count)
    {
        Wire.Check(count >= 0 && count <= Left, "Truncated input");
        var value = data.Slice(Position, count);
        Position += count;
        return value;
    }
    internal byte U8() => Take(1).Span[0];
    internal ulong Le(int count)
    {
        ulong value = 0;
        var bytes = Take(count).Span;
        for (int i = 0; i < bytes.Length; i++) value |= (ulong)bytes[i] << (8 * i);
        return value;
    }
    internal uint U32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4).Span);
    internal ulong U64() => BinaryPrimitives.ReadUInt64LittleEndian(Take(8).Span);
    internal double F64() => BitConverter.UInt64BitsToDouble(U64());
    internal ulong Varint()
    {
        ulong value = 0;
        for (int i = 0; i < 10; i++)
        {
            byte b = U8();
            Wire.Check(i != 9 || b <= 1, "Varint overflow");
            value |= (ulong)(b & 127) << (i * 7);
            if (b < 128) return value;
        }
        throw new InvalidDataException("Varint overflow");
    }
    internal int Compact()
    {
        int value = 0;
        for (int i = 0; i < 3; i++)
        {
            byte b = U8();
            Wire.Check((i == 0 || b != 0) && (i != 2 || b <= 3), "Invalid compact-u16");
            value |= (b & 127) << (i * 7);
            if (b < 128) return value;
        }
        throw new InvalidDataException("Invalid compact-u16");
    }
    internal int Count(ulong count, int minimum = 1)
    {
        Wire.Check(count <= (ulong)(Left / minimum), "Length exceeds enclosing value");
        return (int)count;
    }
    internal T[] Items<T>(ulong count, int minimum, Func<T> next)
    {
        var result = new List<T>();
        int size = Count(count, minimum);
        for (int i = 0; i < size; i++) result.Add(next());
        return result.ToArray();
    }
}

static class Cbor
{
    internal static object? Read(Reader reader, int depth = 0)
    {
        Wire.Check(depth < 128, "CBOR nesting too deep");
        int initial = reader.U8(), major = initial >> 5, info = initial & 31;
        bool indefinite = info == 31;
        Wire.Check(info < 28 || indefinite && major is >= 2 and <= 5);
        ulong arg = 0;
        if (info < 24) arg = (ulong)info;
        else if (!indefinite)
            foreach (byte b in reader.Take(1 << (info - 24)).Span) arg = (arg << 8) | b;

        switch (major)
        {
            case 0: return arg;
            case 1: return arg <= long.MaxValue ? -1L - (long)arg : null;
            case 2:
            case 3:
                if (!indefinite)
                {
                    var bytes = reader.Take(reader.Count(arg));
                    return major == 2 ? bytes : Wire.Text(bytes.Span);
                }
                using (var parts = new MemoryStream())
                {
                    while (reader.Peek != 255)
                    {
                        Wire.Check(reader.Peek >> 5 == major && (reader.Peek & 31) != 31);
                        object? part = Read(reader, depth + 1);
                        if (part is ReadOnlyMemory<byte> binary) parts.Write(binary.Span);
                        else parts.Write(Wire.Utf8.GetBytes((string)part!));
                    }
                    reader.U8();
                    var all = parts.ToArray();
                    return major == 2 ? new ReadOnlyMemory<byte>(all) : Wire.Text(all);
                }
            case 4:
                if (!indefinite) return reader.Items(arg, 1, () => Read(reader, depth + 1));
                var list = new List<object?>();
                while (reader.Peek != 255) list.Add(Read(reader, depth + 1));
                reader.U8();
                return list.ToArray();
            case 5:
                bool version = false;
                int count = indefinite ? 0 : reader.Count(arg, 2);
                while (indefinite ? reader.Peek != 255 : count-- > 0)
                {
                    version |= Read(reader, depth + 1) is string key && key == "version";
                    Read(reader, depth + 1);
                }
                if (indefinite) reader.U8();
                return new CborMap(version);
            case 6: return Read(reader, depth + 1);
            default:
                return info switch
                {
                    20 => false, 21 => true, 22 or 23 => null,
                    25 => (double)BitConverter.UInt16BitsToHalf((ushort)arg),
                    26 => (double)BitConverter.UInt32BitsToSingle((uint)arg),
                    27 => BitConverter.UInt64BitsToDouble(arg),
                    _ => throw new InvalidDataException("Unknown CBOR simple value")
                };
        }
    }

    internal static object? Exact(ReadOnlyMemory<byte> data)
    {
        var reader = new Reader(data);
        var value = Read(reader);
        Wire.Check(reader.Left == 0, "Trailing CBOR data");
        return value;
    }

    internal sealed record CborMap(bool HasVersion);
}

sealed class Car
{
    private readonly Dictionary<string, ReadOnlyMemory<byte>> nodes = new(StringComparer.Ordinal);
    internal const string ZeroHash = "11111111111111111111111111111111";
    internal ulong Slot { get; }
    internal ulong Parent { get; }
    internal long? Time { get; }
    internal ulong? Height { get; }
    internal string[] Entries { get; }
    internal string? Rewards { get; }

    private static (string Key, bool Absent) Cid(ReadOnlyMemory<byte> bytes, Reader reader)
    {
        ulong a = reader.Varint(), b = reader.Varint();
        bool absent = false;
        if (a == 18 && b == 32) reader.Take(32);
        else
        {
            Wire.Check(a == 1, "Unsupported CID version");
            ulong hash = reader.Varint(), length = reader.Varint();
            Wire.Check(length <= 64, "CID digest too large");
            reader.Take((int)length);
            absent = hash == 0 && length == 0;
        }
        return (Encoding.Latin1.GetString(bytes.Span[..reader.Position]), absent);
    }

    private static (string Key, bool Absent) Link(object? value)
    {
        if (value is not ReadOnlyMemory<byte> bytes || bytes.Length == 0 || bytes.Span[0] != 0)
            throw new InvalidDataException("Invalid CAR link");
        return Cid(bytes[1..], new Reader(bytes[1..]));
    }

    private static string[] Links(object? value) =>
        value is object?[] entries ? entries.Select(x => Link(x).Key).ToArray() : [];

    internal static object? Field(object?[]? node, int index) =>
        node != null && index < node.Length ? node[index] : null;

    private static object?[] Kind(object? value, ulong kind)
    {
        if (value is object?[] node && Field(node, 0) is ulong code && code == kind) return node;
        throw new InvalidDataException("Unexpected CAR node kind");
    }

    internal Car(ReadOnlyMemory<byte> data)
    {
        var reader = new Reader(data);
        ReadOnlyMemory<byte> block = default;
        bool first = true;
        while (reader.Left > 0)
        {
            ulong size = reader.Varint();
            if (size == 0) continue;
            Wire.Check(size <= 32 * 1024 * 1024, "CAR section too large");
            var section = reader.Take((int)size);
            bool header = false;
            if (first && (section.Span[0] >> 5) == 5)
            {
                try { header = Cbor.Exact(section) is Cbor.CborMap { HasVersion: true }; }
                catch (InvalidDataException) { }
            }
            first = false;
            if (header) continue;
            var cidReader = new Reader(section);
            string key = Cid(section, cidReader).Key;
            var node = section[cidReader.Position..];
            nodes[key] = node;
            if (node.Length < 2 || node.Span[0] >> 5 != 4) continue;
            int info = node.Span[0] & 31;
            if (info is >= 28 and <= 30) continue;
            int prefix = info < 24 || info == 31 ? 1 : 1 + (1 << (info - 24));
            if (node.Length > prefix && node.Span[prefix] == 2) block = node;
        }
        var fields = Kind(Cbor.Exact(block), 2);
        Slot = Field(fields, 1) is ulong slot ? slot : throw new InvalidDataException("Missing block slot");
        Entries = Links(Field(fields, 3));
        var meta = Field(fields, 4) as object?[];
        Parent = Field(meta, 0) is ulong parent ? parent : 0;
        Time = Field(meta, 1) switch
        {
            long negative => negative,
            ulong positive when positive is > 0 and <= long.MaxValue => (long)positive,
            _ => null
        };
        Height = Field(meta, 2) as ulong?;
        if (Field(fields, 5) is ReadOnlyMemory<byte> link)
        {
            var cid = Link(link);
            if (!cid.Absent) Rewards = cid.Key;
        }
    }

    internal object?[] Node(string key, ulong kind) =>
        nodes.TryGetValue(key, out var data)
            ? Kind(Cbor.Exact(data), kind) : throw new InvalidDataException("Missing CAR link");

    internal bool Contains(string key) => nodes.ContainsKey(key);

    private static ReadOnlyMemory<byte> EntryHash(object?[] node)
    {
        if (Field(node, 2) is ReadOnlyMemory<byte> hash && hash.Length == 32) return hash;
        throw new InvalidDataException("Invalid entry hash");
    }

    internal string Hash()
    {
        if (Entries.Length == 0) return ZeroHash;
        var entry = Node(Entries[^1], 1);
        Links(Field(entry, 3));
        return Wire.Base58(EntryHash(entry).Span);
    }

    internal IEnumerable<string> Transactions()
    {
        foreach (string key in Entries)
        {
            var entry = Node(key, 1);
            EntryHash(entry);
            foreach (string tx in Links(Field(entry, 3))) yield return tx;
        }
    }

    internal ReadOnlyMemory<byte> Frame(object? value)
    {
        var frame = Kind(value, 6);
        var first = Field(frame, 4) is ReadOnlyMemory<byte> data ? data : default;
        var next = Links(Field(frame, 5));
        var expected = Field(frame, 1) as ulong?;
        if (next.Length == 0)
        {
            Wire.Check(expected == null || Wire.HashMatches(first.Span, expected.Value), "DataFrame hash mismatch");
            return first;
        }

        using var output = new MemoryStream();
        output.Write(first.Span);
        var visited = new HashSet<string>();
        var stack = new Stack<string>(next.Reverse());
        while (stack.TryPop(out string? key))
        {
            Wire.Check(visited.Add(key), "Repeated DataFrame CID");
            frame = Node(key, 6);
            if (Field(frame, 4) is ReadOnlyMemory<byte> part)
            {
                Wire.Check(output.Length + part.Length <= 512 * 1024 * 1024, "DataFrame too large");
                output.Write(part.Span);
            }
            next = Links(Field(frame, 5));
            for (int i = next.Length - 1; i >= 0; i--) stack.Push(next[i]);
        }
        var bytes = output.GetBuffer().AsMemory(0, (int)output.Length);
        Wire.Check(expected == null || Wire.HashMatches(bytes.Span, expected.Value), "DataFrame hash mismatch");
        return bytes;
    }
}
