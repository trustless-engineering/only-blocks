using System.Buffers.Binary;
using System.Numerics;
using static Wire;

// RFC 8878 decoder for dictionary-free frames. Tables and algorithms follow ZSTD_MINI_SPEC.md.
static class Zstd
{
    private const int Limit = 512 * 1024 * 1024, BlockMax = 128 * 1024;

    private static readonly int[] LL_BASE = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
    ];
    private static readonly int[] LL_BITS = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    ];
    private static readonly int[] ML_BASE = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539
    ];
    private static readonly int[] ML_BITS = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    ];
    private static readonly int[] LL_DEFAULT = [
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1
    ];
    private static readonly int[] ML_DEFAULT = [
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1
    ];
    private static readonly int[] OF_DEFAULT = [
        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1
    ];

    private readonly record struct Cell(int Symbol, int Bits, int Base = 0);
    private sealed record Table(Cell[] Cells, int Log);
    private static readonly Table[] Defaults =
        [BuildFse(LL_DEFAULT, 6), BuildFse(OF_DEFAULT, 5), BuildFse(ML_DEFAULT, 6)];
    private static readonly int[] MaxSymbol = [35, 31, 52];
    private static readonly int[] MaxLog = [9, 8, 9];

    private sealed class Frame
    {
        internal Table? Huffman;
        internal readonly Table?[] Sequence = new Table?[3];
        internal readonly int[] Repeat = [1, 4, 8];
    }

    private static int High(int value) => BitOperations.Log2((uint)value);

    private sealed class Backward
    {
        private readonly ReadOnlyMemory<byte> data;
        internal int Bits;
        internal Backward(ReadOnlyMemory<byte> bytes)
        {
            Check(!bytes.IsEmpty && bytes.Span[^1] != 0, "Missing Zstd bitstream marker");
            data = bytes;
            Bits = (bytes.Length - 1) * 8 + High(bytes.Span[^1]);
        }

        internal int Peek(int n)
        {
            if (Bits <= 0 || n == 0) return 0;
            int lo = Math.Max(0, Bits - n);
            int first = lo >> 3, last = (Bits - 1) >> 3;
            ulong word = 0;
            var bytes = data.Span;
            for (int i = first; i <= last; i++) word |= (ulong)bytes[i] << ((i - first) * 8);
            ulong value = (word >> (lo & 7)) & ((1UL << (Bits - lo)) - 1);
            return (int)(value << Math.Max(0, n - Bits));
        }

        internal int Read(int n)
        {
            int value = Peek(n);
            Bits -= n;
            return value;
        }
    }

    private static Table ReadFse(ReadOnlyMemory<byte> data, Reader r, int maxSymbol, int maxLog)
    {
        int bit = 0;
        int Peek(int width)
        {
            int value = 0;
            for (int i = 0; i < width && bit + i < data.Length * 8; i++)
            {
                int p = bit + i;
                value |= ((data.Span[p >> 3] >> (p & 7)) & 1) << i;
            }
            return value;
        }
        int Read(int width)
        {
            int value = Peek(width);
            bit += width;
            Check(bit <= data.Length * 8, "Truncated Zstd FSE description");
            return value;
        }

        int log = Read(4) + 5;
        Check(log <= maxLog, "Zstd FSE accuracy log too large");
        int threshold = 1 << log, remaining = threshold + 1, width = log + 1;
        var probabilities = new List<int>();
        while (remaining > 1)
        {
            Check(probabilities.Count <= maxSymbol, "Too many Zstd FSE symbols");
            int maximum = 2 * threshold - 1 - remaining;
            int low = Peek(width - 1);
            int value = low < maximum ? Read(width - 1) : Read(width);
            if (value >= threshold) value -= maximum;
            int probability = value - 1;
            probabilities.Add(probability);
            remaining -= Math.Abs(probability);
            Check(remaining >= 1, "Invalid Zstd FSE probability");
            if (probability == 0)
            {
                int repeat;
                do
                {
                    repeat = Read(2);
                    for (int i = 0; i < repeat; i++) probabilities.Add(0);
                    Check(probabilities.Count <= maxSymbol + 1, "Too many Zstd FSE symbols");
                } while (repeat == 3);
            }
            while (remaining < threshold)
            {
                width--;
                threshold >>= 1;
            }
        }
        r.Take((bit + 7) >> 3);
        return BuildFse(probabilities.ToArray(), log);
    }

    private static Table BuildFse(int[] probabilities, int log)
    {
        int size = 1 << log, high = size - 1, position = 0;
        int[] symbols = new int[size], next = new int[probabilities.Length];
        for (int i = 0; i < probabilities.Length; i++)
        {
            int p = probabilities[i];
            if (p == -1) symbols[high--] = i;
            next[i] = Math.Abs(p);
        }
        int step = (size >> 1) + (size >> 3) + 3;
        for (int i = 0; i < probabilities.Length; i++)
            for (int n = 0; n < probabilities[i]; n++)
            {
                symbols[position] = i;
                do { position = (position + step) & (size - 1); } while (position > high);
            }
        Check(position == 0, "Invalid Zstd FSE distribution");
        var cells = new Cell[size];
        for (int i = 0; i < size; i++)
        {
            int symbol = symbols[i], count = next[symbol]++;
            int bits = log - High(count);
            cells[i] = new Cell(symbol, bits, (count << bits) - size);
        }
        return new(cells, log);
    }

    private static Table Huffman(Reader r)
    {
        int header = r.U8();
        var weights = new List<int>();
        if (header >= 128)
        {
            int count = header - 127;
            var packed = r.Take((count + 1) / 2).Span;
            for (int i = 0; i < count; i++)
                weights.Add(i % 2 == 0 ? packed[i / 2] >> 4 : packed[i / 2] & 15);
        }
        else
        {
            var section = r.Take(header);
            var fr = new Reader(section);
            var table = ReadFse(section, fr, 255, 6);
            var bits = new Backward(section[fr.Position..]);
            int a = bits.Read(table.Log), b = bits.Read(table.Log);
            Check(bits.Bits >= 0, "Truncated Zstd Huffman initial states");
            while (true)
            {
                Check(weights.Count < 255, "Too many Zstd Huffman weights");
                var cell = table.Cells[a];
                weights.Add(cell.Symbol);
                a = cell.Base + bits.Read(cell.Bits);
                if (bits.Bits < 0)
                {
                    weights.Add(table.Cells[b].Symbol);
                    break;
                }
                (a, b) = (b, a);
            }
        }
        Check(weights.Count <= 255, "Too many Zstd Huffman weights");
        int total = 0;
        foreach (int weight in weights)
        {
            Check(weight <= 11, "Invalid Zstd Huffman weight");
            if (weight != 0) total += 1 << (weight - 1);
        }
        int log = High(total) + 1;
        Check(total != 0 && log <= 11, "Invalid Zstd Huffman length");
        int rest = (1 << log) - total;
        Check(BitOperations.IsPow2(rest), "Invalid Zstd Huffman distribution");
        weights.Add(High(rest) + 1);
        var cells = new Cell[1 << log];
        int pos = 0;
        for (int w = 1; w <= log; w++)
            for (int symbol = 0; symbol < weights.Count; symbol++)
                if (weights[symbol] == w)
                {
                    int n = 1 << (w - 1);
                    cells.AsSpan(pos, n).Fill(new Cell(symbol, log + 1 - w));
                    pos += n;
                }
        return new(cells, log);
    }

    private static void HuffStream(ReadOnlyMemory<byte> data, Table table, Span<byte> output)
    {
        var bits = new Backward(data);
        for (int i = 0; i < output.Length; i++)
        {
            var cell = table.Cells[bits.Peek(table.Log)];
            output[i] = (byte)cell.Symbol;
            bits.Bits -= cell.Bits;
            Check(bits.Bits >= 0, "Truncated Zstd Huffman stream");
        }
        Check(bits.Bits == 0, "Trailing Zstd Huffman bits");
    }

    private static ReadOnlyMemory<byte> Literals(Reader r, Frame frame, int maxBlock)
    {
        int first = r.U8(), type = first & 3, format = (first >> 2) & 3;
        if (type <= 1)
        {
            int size = format is 0 or 2 ? first >> 3 : (first >> 4) + ((int)r.Le(format == 1 ? 1 : 2) << 4);
            Check(size <= maxBlock, "Zstd literals exceed block size");
            if (type == 0) return r.Take(size);
            var raw = new byte[size];
            raw.AsSpan().Fill(r.U8());
            return raw;
        }

        int width = format is 0 or 1 ? 10 : format == 2 ? 14 : 18;
        ulong h = (uint)first | (r.Le(format <= 1 ? 2 : format + 1) << 8);
        int mask = (1 << width) - 1;
        int regenerated = (int)((h >> 4) & (uint)mask);
        Check(regenerated <= maxBlock, "Zstd literals exceed block size");
        var literals = new Reader(r.Take((int)((h >> (4 + width)) & (uint)mask)));
        var huf = type == 2 ? frame.Huffman = Huffman(literals) : frame.Huffman;
        if (huf == null) throw new InvalidDataException("Missing previous Zstd Huffman table");

        var output = new byte[regenerated];
        if (format == 0) HuffStream(literals.Take(literals.Left), huf, output);
        else
        {
            int a = (int)literals.Le(2), b = (int)literals.Le(2), c = (int)literals.Le(2);
            int part = (regenerated + 3) / 4;
            Check(part * 3 <= regenerated, "Invalid Zstd Huffman stream sizes");
            HuffStream(literals.Take(a), huf, output.AsSpan(0, part));
            HuffStream(literals.Take(b), huf, output.AsSpan(part, part));
            HuffStream(literals.Take(c), huf, output.AsSpan(part * 2, part));
            HuffStream(literals.Take(literals.Left), huf, output.AsSpan(part * 3));
        }
        return output;
    }

    private static Table SequenceTable(ReadOnlyMemory<byte> data, Reader r, Frame frame, int mode, int kind)
    {
        Table Rle()
        {
            byte symbol = r.U8();
            Check(symbol <= MaxSymbol[kind], "Invalid Zstd RLE symbol");
            return new([new Cell(symbol, 0)], 0);
        }

        var table = mode switch
        {
            0 => Defaults[kind],
            1 => Rle(),
            2 => ReadFse(data[r.Position..], r, MaxSymbol[kind], MaxLog[kind]),
            _ => frame.Sequence[kind] ?? throw new InvalidDataException("Missing previous Zstd sequence table")
        };
        frame.Sequence[kind] = table;
        return table;
    }

    private sealed class Output
    {
        private byte[] buffer = [];
        internal int Length { get; private set; }
        internal ReadOnlyMemory<byte> Bytes => buffer.AsMemory(0, Length);
        private Span<byte> Space(int n)
        {
            Check(n <= Limit - Length, "Zstd output exceeds 512 MiB");
            int start = Length;
            Length += n;
            if (Length > buffer.Length)
                Array.Resize(ref buffer, Math.Min(Limit, Math.Max(Length, Math.Max(4096, buffer.Length * 2))));
            return buffer.AsSpan(start, n);
        }
        internal void Add(ReadOnlySpan<byte> data) => data.CopyTo(Space(data.Length));
        internal void Repeat(byte value, int count) => Space(count).Fill(value);
        internal void Match(int offset, int count)
        {
            int source = Length - offset;
            var destination = Space(count);
            int done = Math.Min(offset, count);
            buffer.AsSpan(source, done).CopyTo(destination);
            // Each copy doubles the initialized range, including overlapping matches.
            while (done < count)
            {
                int next = Math.Min(done, count - done);
                destination[..next].CopyTo(destination[done..]);
                done += next;
            }
        }
    }

    private static void Compressed(ReadOnlyMemory<byte> data, Frame frame, Output output, int frameStart, int maxBlock, ulong window)
    {
        int blockStart = output.Length;
        var r = new Reader(data);
        var literals = Literals(r, frame, maxBlock);
        int count = r.U8();
        if (count == 0)
        {
            Check(r.Left == 0, "Trailing data after empty Zstd sequence section");
            output.Add(literals.Span);
            return;
        }
        if (count == 255) count = (int)r.Le(2) + 0x7f00;
        else if (count >= 128) count = ((count - 128) << 8) + r.U8();
        int modes = r.U8();
        Check((modes & 3) == 0, "Reserved Zstd sequence bits");
        var ll = SequenceTable(data, r, frame, modes >> 6, 0);
        var of = SequenceTable(data, r, frame, (modes >> 4) & 3, 1);
        var ml = SequenceTable(data, r, frame, (modes >> 2) & 3, 2);
        var bits = new Backward(data[r.Position..]);
        int ls = bits.Read(ll.Log), os = bits.Read(of.Log), ms = bits.Read(ml.Log);
        int lit = 0;
        for (int i = 0; i < count; i++)
        {
            var l = ll.Cells[ls];
            var o = of.Cells[os];
            var m = ml.Cells[ms];
            ulong code = (1UL << o.Symbol) + (uint)bits.Read(o.Symbol);
            int match = ML_BASE[m.Symbol] + bits.Read(ML_BITS[m.Symbol]);
            int literal = LL_BASE[l.Symbol] + bits.Read(LL_BITS[l.Symbol]);
            Check(bits.Bits >= 0 && literal <= literals.Length - lit && literal + match <= maxBlock - (output.Length - blockStart),
                "Invalid Zstd sequence lengths");
            output.Add(literals.Span.Slice(lit, literal));
            lit += literal;
            int offset;
            var rep = frame.Repeat;
            if (code > 3)
            {
                Check(code - 3 <= int.MaxValue, "Zstd offset too large");
                offset = (int)(code - 3);
                rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = offset;
            }
            else
            {
                int index = (int)code - 1 + (literal == 0 ? 1 : 0);
                offset = index == 3 ? rep[0] - 1 : rep[index];
                if (index >= 2) rep[2] = rep[1];
                if (index >= 1) { rep[1] = rep[0]; rep[0] = offset; }
            }
            Check(offset > 0 && offset <= output.Length - frameStart && (ulong)offset <= window, "Zstd offset outside frame window");
            output.Match(offset, match);
            if (i + 1 != count)
            {
                ls = l.Base + bits.Read(l.Bits);
                ms = m.Base + bits.Read(m.Bits);
                os = o.Base + bits.Read(o.Bits);
                Check(bits.Bits >= 0, "Truncated Zstd sequence states");
            }
        }
        Check(bits.Bits == 0 && literals.Length - lit <= maxBlock - (output.Length - blockStart),
            "Invalid Zstd block ending");
        output.Add(literals.Span[lit..]);
    }

    internal static ReadOnlyMemory<byte> Decode(ReadOnlyMemory<byte> input)
    {
        var r = new Reader(input);
        var output = new Output();
        while (r.Left > 0)
        {
            uint magic = r.U32();
            if ((magic & 0xfffffff0) == 0x184d2a50)
            {
                r.Take(r.Count(r.U32()));
                continue;
            }
            Check(magic == 0xfd2fb528, "Unknown Zstd frame magic");
            int descriptor = r.U8(), flag = descriptor >> 6;
            Check((descriptor & 8) == 0, "Reserved Zstd frame bit");
            bool single = (descriptor & 32) != 0, checksum = (descriptor & 4) != 0;
            ulong window = 0;
            if (!single)
            {
                int wd = r.U8();
                ulong basis = 1UL << (10 + (wd >> 3));
                window = basis + (basis >> 3) * (uint)(wd & 7);
            }
            int dict = descriptor & 3;
            Check(r.Le(dict == 0 ? 0 : 1 << (dict - 1)) == 0, "Zstd dictionaries are unsupported");
            int sizeBytes = flag == 0 ? (single ? 1 : 0) : 1 << flag;
            ulong size = r.Le(sizeBytes) + (sizeBytes == 2 ? 256UL : 0);
            if (single) window = size;
            Check(size <= (ulong)(Limit - output.Length), "Zstd frame too large");
            int maxBlock = (int)Math.Min(window, BlockMax);
            int frameStart = output.Length;
            var frame = new Frame();
            int header;
            do
            {
                header = (int)r.Le(3);
                int blockSize = header >> 3;
                Check(blockSize <= maxBlock, "Zstd block too large");
                switch ((header >> 1) & 3)
                {
                    case 0: output.Add(r.Take(blockSize).Span); break;
                    case 1: output.Repeat(r.U8(), blockSize); break;
                    case 2: Compressed(r.Take(blockSize), frame, output, frameStart, maxBlock, window); break;
                    default: throw new InvalidDataException("Reserved Zstd block type");
                }
            } while ((header & 1) == 0);
            Check(sizeBytes == 0 || output.Length - frameStart == (long)size, "Zstd content size mismatch");
            if (checksum)
                Check(r.U32() == (uint)Xxh64(output.Bytes.Span[frameStart..]), "Zstd checksum mismatch");
        }
        return output.Bytes;
    }

    private const ulong P1 = 0x9e3779b185ebca87, P2 = 0xc2b2ae3d27d4eb4f, P3 = 0x165667b19e3779f9,
        P4 = 0x85ebca77c2b2ae63, P5 = 0x27d4eb2f165667c5;

    private static ulong Round(ulong acc, ulong lane) => BitOperations.RotateLeft(acc + lane * P2, 31) * P1;
    private static ulong Xxh64(ReadOnlySpan<byte> data)
    {
        int i = 0;
        ulong hash = P5;
        if (data.Length >= 32)
        {
            Span<ulong> lanes = [unchecked(P1 + P2), P2, 0, unchecked(0UL - P1)];
            while (i <= data.Length - 32)
                for (int lane = 0; lane < 4; lane++, i += 8)
                    lanes[lane] = Round(lanes[lane], BinaryPrimitives.ReadUInt64LittleEndian(data[i..]));
            hash = BitOperations.RotateLeft(lanes[0], 1) + BitOperations.RotateLeft(lanes[1], 7) +
                BitOperations.RotateLeft(lanes[2], 12) + BitOperations.RotateLeft(lanes[3], 18);
            foreach (ulong lane in lanes) hash = (hash ^ Round(0, lane)) * P1 + P4;
        }
        hash += (ulong)data.Length;
        while (i <= data.Length - 8)
        {
            hash = BitOperations.RotateLeft(hash ^ Round(0, BinaryPrimitives.ReadUInt64LittleEndian(data[i..])), 27) * P1 + P4;
            i += 8;
        }
        if (i <= data.Length - 4)
        {
            hash = BitOperations.RotateLeft(hash ^ BinaryPrimitives.ReadUInt32LittleEndian(data[i..]) * P1, 23) * P2 + P3;
            i += 4;
        }
        while (i < data.Length) hash = BitOperations.RotateLeft(hash ^ data[i++] * P5, 11) * P1;
        hash = (hash ^ (hash >> 33)) * P2;
        hash = (hash ^ (hash >> 29)) * P3;
        return hash ^ (hash >> 32);
    }
}
