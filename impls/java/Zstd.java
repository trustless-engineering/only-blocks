package onlyblocks;

import java.util.*;
import static onlyblocks.Wire.*;

/** A whole-buffer, dictionary-free RFC 8878 decoder. */
final class Zstd {
    private static final int MAX_OUTPUT = 512 << 20;
    private static final int MAX_BLOCK = 128 << 10;
    private static final int[] LL_BASE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
           16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
           8192, 16384, 32768, 65536};
    private static final int[] LL_BITS = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
           13, 14, 15, 16};
    private static final int[] ML_BASE = {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
           19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
           35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
           4099, 8195, 16387, 32771, 65539};
    private static final int[] ML_BITS = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
           12, 13, 14, 15, 16};
    private static final int[] LL_DEFAULT = {4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
              2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
              -1, -1, -1, -1};
    private static final int[] ML_DEFAULT = {1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
              -1, -1, -1, -1, -1};
    private static final int[] OF_DEFAULT = {1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1};

    private static int high(int value) { return 31 - Integer.numberOfLeadingZeros(value); }
    private static final class Backward {
        final Reader r;
        int bits;
        Backward(Reader r) {
            this.r = r;
            check(r.left() > 0 && r.data[r.end - 1] != 0);
            bits = 8 * (r.left() - 1) + high(r.data[r.end - 1] & 255);
        }
        int peek(int n) {
            int low = bits - n;
            if (n == 0 || bits <= 0) return 0;
            int from = Math.max(0, low), first = from >>> 3, last = (bits - 1) >>> 3;
            long word = 0;
            for (int i = first; i <= last; i++) word |= (long) (r.data[r.pos + i] & 255) << (8 * (i - first));
            long mask = (1L << (bits - from)) - 1;
            return (int) (((word >>> (from & 7)) & mask) << (from - low));
        }
        int read(int n) { int v = peek(n); bits -= n; return v; }
    }
    private static final class Forward {
        final Reader r;
        int bit;
        Forward(Reader r) { this.r = r; bit = 8 * r.pos; }
        int peek(int n) {
            int v = 0;
            for (int i = 0; i < n; i++) {
                int p = bit + i;
                if ((p >>> 3) < r.end) v |= ((r.data[p >>> 3] >>> (p & 7)) & 1) << i;
            }
            return v;
        }
        int read(int n) {
            int value = peek(n);
            bit += n;
            check(bit <= r.end * 8);
            return value;
        }
    }
    private record Cell(int symbol, int bits, int base) {}
    private record Table(Cell[] cells, int log) {
        Cell at(int i) { return cells[i]; }
    }

    private static Table fse(int[] prob, int log) {
        int size = 1 << log;
        check(Arrays.stream(prob).map(Math::abs).sum() == size);
        int[] symbols = new int[size], counters = prob.clone();
        int high = size - 1;
        for (int s = 0; s < prob.length; s++) if (prob[s] == -1) {
            symbols[high--] = s;
            counters[s] = 1;
        }
        int step = (size >>> 1) + (size >>> 3) + 3, pos = 0;
        for (int s = 0; s < prob.length; s++) {
            for (int p = 0; p < prob[s]; p++) {
                symbols[pos] = s;
                do { pos = (pos + step) & (size - 1); } while (pos > high);
            }
        }
        check(pos == 0);
        Cell[] cells = new Cell[size];
        for (int i = 0; i < size; i++) {
            int s = symbols[i], n = counters[s]++;
            int bits = log - high(n);
            cells[i] = new Cell(s, bits, (n << bits) - size);
        }
        return new Table(cells, log);
    }
    private static Table readFse(Reader r, int maxSymbol, int maxLog) {
        var in = new Forward(r);
        int log = in.read(4) + 5;
        check(log <= maxLog);
        int threshold = 1 << log, remaining = threshold + 1, width = log + 1;
        int[] prob = new int[maxSymbol + 1];
        int symbol = 0;
        while (remaining > 1) {
            check(symbol < prob.length);
            int max = 2 * threshold - 1 - remaining;
            int low = in.peek(width - 1), value;
            if (low < max) value = in.read(width - 1);
            else {
                value = in.read(width);
                if (value >= threshold) value -= max;
            }
            int p = value - 1;
            prob[symbol++] = p;
            remaining -= Math.abs(p);
            check(remaining >= 1);
            if (p == 0) {
                int repeat;
                do {
                    repeat = in.read(2);
                    symbol += repeat;
                    check(symbol <= prob.length);
                } while (repeat == 3);
            }
            while (remaining < threshold) { width--; threshold >>>= 1; }
        }
        r.pos = (in.bit + 7) >>> 3;
        return fse(prob, log);
    }
    private static Table huffman(Reader r) {
        int header = r.u8();
        var weights = new ArrayList<Integer>();
        if (header >= 128) {
            int n = header - 127;
            byte[] packed = r.bytes((n + 1) / 2);
            for (int i = 0; i < n; i++) weights.add((packed[i / 2] >>> (i % 2 == 0 ? 4 : 0)) & 15);
        } else {
            var part = r.part(header);
            var fse = readFse(part, 255, 6);
            var br = new Backward(part);
            int[] states = {br.read(fse.log), br.read(fse.log)};
            check(br.bits >= 0);
            int i = 0;
            while (true) {
                check(weights.size() < 255);
                var cell = fse.at(states[i]);
                weights.add(cell.symbol);
                states[i] = cell.base + br.read(cell.bits);
                i ^= 1;
                if (br.bits < 0) {
                    weights.add(fse.at(states[i]).symbol);
                    break;
                }
            }
        }
        check(weights.size() <= 255);
        int total = 0;
        for (int weight : weights) {
            check(weight <= 11);
            if (weight != 0) total += 1 << (weight - 1);
        }
        check(total > 0);
        int log = high(total) + 1, rest = (1 << log) - total;
        check(log <= 11 && Integer.bitCount(rest) == 1);
        weights.add(high(rest) + 1);
        Cell[] cells = new Cell[1 << log];
        int start = 0;
        for (int w = 1; w <= log; w++) for (int s = 0; s < weights.size(); s++) if (weights.get(s) == w) {
            int count = 1 << (w - 1);
            Arrays.fill(cells, start, start + count, new Cell(s, log + 1 - w, 0));
            start += count;
        }
        return new Table(cells, log);
    }

    private static final class Frame {
        final int start;
        final long window;
        final long[] rep = {1, 4, 8};
        final Table[] tables = new Table[3];
        Table huffman;
        Frame(int start, long window) { this.start = start; this.window = window; }
        long offset(long value, int literals) {
            int index = value > 3 ? 3 : (int) value - 1 + (literals == 0 ? 1 : 0);
            long offset = value > 3 ? value - 3 : index == 3 ? rep[0] - 1 : rep[index];
            if (index != 0) {
                if (index >= 2) rep[2] = rep[1];
                rep[1] = rep[0];
                rep[0] = offset;
            }
            return offset;
        }
    }
    private static void stream(Reader input, Table table, byte[] out, int start, int count) {
        var br = new Backward(input);
        for (int i = start; i < start + count; i++) {
            var cell = table.at(br.peek(table.log));
            br.bits -= cell.bits;
            check(br.bits >= 0);
            out[i] = (byte) cell.symbol;
        }
        check(br.bits == 0);
    }
    private static byte[] literals(Reader r, Frame frame) {
        int first = r.u8(), type = first & 3, format = (first >>> 2) & 3;
        if (type < 2) {
            int size = switch (format) {
                case 0, 2 -> first >>> 3;
                case 1 -> (first >>> 4) + (r.u8() << 4);
                default -> (first >>> 4) + ((int) r.le(2) << 4);
            };
            check(size <= MAX_BLOCK);
            if (type == 0) return r.bytes(size);
            var out = new byte[size];
            Arrays.fill(out, (byte) r.u8());
            return out;
        }
        int width = format < 2 ? 10 : format == 2 ? 14 : 18;
        long header = first | (r.le((width - 10) / 4 + 2) << 8);
        int size = (int) (header >>> 4) & ((1 << width) - 1);
        check(size <= MAX_BLOCK);
        var part = r.part((int) (header >>> (4 + width)));
        if (type == 2) frame.huffman = huffman(part);
        var table = frame.huffman;
        check(table != null);
        var out = new byte[size];
        if (format == 0) stream(part, table, out, 0, size);
        else {
            int[] sizes = {(int) part.le(2), (int) part.le(2), (int) part.le(2)};
            int quarter = (size + 3) / 4;
            check(size >= 3 * quarter);
            for (int i = 0; i < 3; i++) stream(part.part(sizes[i]), table, out, i * quarter, quarter);
            stream(part, table, out, 3 * quarter, size - 3 * quarter);
        }
        return out;
    }

    private static final Table[] PREDEFINED = {fse(LL_DEFAULT, 6), fse(OF_DEFAULT, 5), fse(ML_DEFAULT, 6)};
    private static final int[] MAX_SYMBOL = {35, 31, 52}, MAX_LOG = {9, 8, 9};

    private static final class Output {
        byte[] bytes = new byte[256];
        int size;
        void reserve(int n) {
            check(n >= 0 && n <= MAX_OUTPUT - size);
            if (size + n > bytes.length) bytes = Arrays.copyOf(bytes, Math.max(size + n, bytes.length * 2));
        }
        void append(byte[] input, int pos, int n) {
            reserve(n);
            System.arraycopy(input, pos, bytes, size, n);
            size += n;
        }
        void repeat(byte value, int n) {
            reserve(n);
            Arrays.fill(bytes, size, size + n, value);
            size += n;
        }
        void match(int offset, int n) {
            reserve(n);
            for (int i = 0; i < n; i++, size++) bytes[size] = bytes[size - offset];
        }
    }

    private static void compressed(Reader r, Output out, Frame frame, int limit) {
        byte[] literals = literals(r, frame);
        int start = out.size, first = r.u8(), lit = 0;
        if (first == 0) {
            check(r.left() == 0 && literals.length <= limit);
            out.append(literals, 0, literals.length);
            return;
        }
        int count = first < 128 ? first : first < 255 ? ((first - 128) << 8) + r.u8() : (int) r.le(2) + 0x7f00;
        int modes = r.u8();
        check((modes & 3) == 0);
        Table[] tables = frame.tables;
        for (int i = 0; i < 3; i++) {
            tables[i] = switch ((modes >>> (6 - 2 * i)) & 3) {
                case 0 -> PREDEFINED[i];
                case 1 -> {
                    int code = r.u8();
                    check(code <= MAX_SYMBOL[i]);
                    yield new Table(new Cell[] { new Cell(code, 0, 0) }, 0);
                }
                case 2 -> readFse(r, MAX_SYMBOL[i], MAX_LOG[i]);
                default -> tables[i];
            };
            check(tables[i] != null);
        }
        var br = new Backward(r);
        int ll = br.read(tables[0].log), of = br.read(tables[1].log), ml = br.read(tables[2].log);
        for (int i = 0; i < count; i++) {
            var lc = tables[0].at(ll);
            var oc = tables[1].at(of);
            var mc = tables[2].at(ml);
            long value = (1L << oc.symbol) + br.read(oc.symbol);
            int matches = ML_BASE[mc.symbol] + br.read(ML_BITS[mc.symbol]);
            int length = LL_BASE[lc.symbol] + br.read(LL_BITS[lc.symbol]);
            check(br.bits >= 0 && lit + length <= literals.length && out.size - start + length + matches <= limit);
            out.append(literals, lit, length);
            lit += length;
            long offset = frame.offset(value, length);
            check(offset > 0 && offset <= frame.window && offset <= out.size - frame.start);
            out.match((int) offset, matches);
            if (i + 1 < count) {
                ll = lc.base + br.read(lc.bits);
                ml = mc.base + br.read(mc.bits);
                of = oc.base + br.read(oc.bits);
                check(br.bits >= 0);
            }
        }
        check(br.bits == 0 && out.size - start + literals.length - lit <= limit);
        out.append(literals, lit, literals.length - lit);
    }

    static byte[] decode(byte[] bytes) {
        var r = new Reader(bytes);
        var out = new Output();
        while (r.left() > 0) {
            int magic = r.u32();
            if ((magic & 0xfffffff0) == 0x184d2a50) {
                r.skip(r.count(r.le(4)));
                continue;
            }
            check(magic == 0xfd2fb528);
            int descriptor = r.u8();
            check((descriptor & 8) == 0);
            boolean single = (descriptor & 32) != 0;
            long window = 0;
            if (!single) {
                int wd = r.u8();
                long base = 1L << (10 + (wd >>> 3));
                window = base + (base >>> 3) * (wd & 7);
            }
            int did = new int[] {0, 1, 2, 4}[descriptor & 3];
            check(r.le(did) == 0);
            int width = new int[] {single ? 1 : 0, 2, 4, 8}[descriptor >>> 6];
            long contentSize = r.le(width) + (width == 2 ? 256 : 0);
            check(contentSize >= 0 && contentSize <= MAX_OUTPUT - out.size);
            var frame = new Frame(out.size, single ? contentSize : window);
            int limit = (int) Math.min(MAX_BLOCK, frame.window), header;
            do {
                header = (int) r.le(3);
                int n = header >>> 3;
                check(n <= limit);
                switch ((header >>> 1) & 3) {
                    case 0 -> {
                        var part = r.part(n);
                        out.append(part.data, part.pos, n);
                    }
                    case 1 -> out.repeat((byte) r.u8(), n);
                    case 2 -> compressed(r.part(n), out, frame, limit);
                    default -> throw new BadData("Reserved Zstd block");
                }
            } while ((header & 1) == 0);
            check(width == 0 || contentSize == out.size - frame.start);
            if ((descriptor & 4) != 0) check(r.u32() == (int) xxh64(out.bytes, frame.start, out.size));
        }
        return Arrays.copyOf(out.bytes, out.size);
    }

    private static final long P1 = 0x9e3779b185ebca87L, P2 = 0xc2b2ae3d27d4eb4fL,
        P3 = 0x165667b19e3779f9L, P4 = 0x85ebca77c2b2ae63L, P5 = 0x27d4eb2f165667c5L;
    private static long round(long acc, long lane) { return Long.rotateLeft(acc + lane * P2, 31) * P1; }
    private static long xxh64(byte[] bytes, int start, int end) {
        var r = new Reader(bytes, start, end);
        long h = P5;
        if (r.left() >= 32) {
            long[] lanes = {P1 + P2, P2, 0, -P1};
            while (r.left() >= 32) for (int i = 0; i < 4; i++) lanes[i] = round(lanes[i], r.u64());
            h = Long.rotateLeft(lanes[0], 1) + Long.rotateLeft(lanes[1], 7) +
                Long.rotateLeft(lanes[2], 12) + Long.rotateLeft(lanes[3], 18);
            for (long lane : lanes) h = (h ^ round(0, lane)) * P1 + P4;
        }
        h += end - start;
        while (r.left() >= 8) h = Long.rotateLeft(h ^ round(0, r.u64()), 27) * P1 + P4;
        if (r.left() >= 4) h = Long.rotateLeft(h ^ (r.le(4) * P1), 23) * P2 + P3;
        while (r.left() > 0) h = Long.rotateLeft(h ^ (r.u8() * P5), 11) * P1;
        h = (h ^ (h >>> 33)) * P2;
        h = (h ^ (h >>> 29)) * P3;
        return h ^ (h >>> 32);
    }
}
