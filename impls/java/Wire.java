package onlyblocks;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;
import java.util.function.Supplier;

final class Wire {
    static final byte[] EMPTY = new byte[0];
    static final class BadData extends RuntimeException {
        BadData(String message) { super(message); }
        BadData(String message, Throwable cause) { super(message, cause); }
    }
    static void check(boolean ok) {
        if (!ok) throw new BadData("Invalid archive data");
    }
    static Map<String, Object> obj(Object... pairs) {
        var result = new LinkedHashMap<String, Object>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }
    static Json.Num uint(long value) { return new Json.Num(Long.toUnsignedString(value)); }
    static Object at(List<?> list, int index) { return index < list.size() ? list.get(index) : null; }
    static List<?> list(Object value) { return value instanceof List<?> l ? l : List.of(); }
    static String utf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new BadData("Invalid UTF-8", e);
        }
    }
    static final class Reader {
        final byte[] data;
        int pos;
        final int end;
        Reader(byte[] data) { this(data, 0, data.length); }
        Reader(byte[] data, int pos, int end) { this.data = data; this.pos = pos; this.end = end; }
        int left() { return end - pos; }
        void skip(int n) { check(n >= 0 && n <= left()); pos += n; }
        int u8() { skip(1); return data[pos - 1] & 255; }
        long le(int n) {
            long v = 0;
            for (int i = 0; i < n; i++) v |= (long) u8() << (8 * i);
            return v;
        }
        int u32() { return (int) le(4); }
        long u64() { return le(8); }
        long varint() {
            long v = 0;
            for (int i = 0; i < 10; i++) {
                int b = u8();
                check(i < 9 || b <= 1);
                v |= (long) (b & 127) << (7 * i);
                if (b < 128) return v;
            }
            throw new BadData("Invalid varint");
        }
        int shortLength() {
            int v = 0;
            for (int i = 0; i < 3; i++) {
                int b = u8();
                check((i == 0 || b != 0) && (i < 2 || b < 4));
                v |= (b & 127) << (7 * i);
                if (b < 128) return v;
            }
            throw new BadData("Invalid compact-u16");
        }
        int count(long value, int limit) {
            check(value >= 0 && value <= limit);
            return (int) value;
        }
        int count(long value) { return count(value, left()); }
        Reader part(int n) { int start = pos; skip(n); return new Reader(data, start, pos); }
        byte[] bytes(int n) { int start = pos; skip(n); return Arrays.copyOfRange(data, start, pos); }
        byte[] vector() { return bytes(count(u64())); }
        String text() { return utf8(vector()); }
        <T> List<T> list(Supplier<T> read) { return items(count(u64()), read); }
        <T> T option(Supplier<T> read) {
            return switch (left() == 0 ? 0 : u8()) {
                case 0 -> null;
                case 1 -> read.get();
                default -> throw new BadData("Invalid option");
            };
        }
    }
    static <T> List<T> items(int n, Supplier<T> read) {
        var out = new ArrayList<T>(Math.min(n, 1024));
        for (int i = 0; i < n; i++) out.add(read.get());
        return out;
    }
    static String b64(byte[] bytes) { return Base64.getEncoder().encodeToString(bytes); }
    static List<Integer> indices(byte[] bytes) {
        var out = new ArrayList<Integer>(bytes.length);
        for (byte b : bytes) out.add(b & 255);
        return out;
    }
    static String b58(byte[] bytes) {
        var out = new StringBuilder();
        var n = new BigInteger(1, bytes);
        var radix = BigInteger.valueOf(58);
        while (n.signum() != 0) {
            var qr = n.divideAndRemainder(radix);
            out.append("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".charAt(qr[1].intValue()));
            n = qr[0];
        }
        for (byte b : bytes) {
            if (b != 0) break;
            out.append('1');
        }
        return out.reverse().toString();
    }
    static String pubkey(byte[] bytes) { check(bytes.length == 32); return b58(bytes); }

    record Unsigned(long bits) {}
    static long u64(Object value, long fallback) { return value instanceof Unsigned n ? n.bits : fallback; }
    private static Object cbor(Reader r, int depth) {
        check(depth <= 128);
        int tag = r.u8(), major = tag >>> 5, info = tag & 31;
        if (major == 7) return switch (info) {
            case 20 -> false;
            case 21 -> true;
            case 22, 23 -> null;
            case 25, 26, 27 -> {
                r.skip(1 << (info - 24));
                yield Double.NaN; // Archive schemas never use a floating-point field.
            }
            default -> throw new BadData("Invalid CBOR simple value");
        };
        long arg = info;
        if (info >= 24 && info <= 27) {
            arg = 0;
            for (int i = 0; i < (1 << (info - 24)); i++) arg = (arg << 8) | r.u8();
        }
        boolean indefinite = info == 31;
        check(info < 28 || indefinite && major >= 2 && major <= 5);
        return switch (major) {
            case 0 -> new Unsigned(arg);
            case 1 -> arg >= 0 ? (Object) (-1 - arg) : Double.NaN;
            case 2, 3 -> {
                byte[] bytes;
                if (!indefinite) bytes = r.bytes(r.count(arg));
                else {
                    var out = new ByteArrayOutputStream();
                    cborItems(r, arg, true, () -> {
                        check((r.data[r.pos] & 255) >>> 5 == major && (r.data[r.pos] & 31) != 31);
                        var part = cbor(r, depth + 1);
                        out.writeBytes(part instanceof String s ? s.getBytes(StandardCharsets.UTF_8) : (byte[]) part);
                    });
                    bytes = out.toByteArray();
                }
                yield major == 2 ? bytes : utf8(bytes);
            }
            case 4 -> {
                var out = new ArrayList<>();
                cborItems(r, arg, indefinite, () -> out.add(cbor(r, depth + 1)));
                yield out;
            }
            case 5 -> {
                var out = new HashMap<>();
                cborItems(r, arg, indefinite, () -> out.put(cbor(r, depth + 1), cbor(r, depth + 1)));
                yield out;
            }
            case 6 -> cbor(r, depth + 1);
            default -> throw new BadData("Invalid CBOR major type");
        };
    }
    private static void cborItems(Reader r, long arg, boolean indefinite, Runnable item) {
        if (indefinite) {
            while (r.left() > 0 && (r.data[r.pos] & 255) != 255) item.run();
            r.skip(1);
        } else {
            int n = r.count(arg);
            for (int i = 0; i < n; i++) item.run();
        }
    }
    record Cid(String key, boolean absent) {}
    static Cid cid(Reader r) {
        int start = r.pos;
        long a = r.varint(), b = r.varint();
        boolean absent = false;
        if (a == 18 && b == 32) r.skip(32);
        else {
            check(a == 1);
            long code = r.varint();
            int n = r.count(r.varint(), 64);
            r.skip(n);
            absent = code == 0 && n == 0;
        }
        return new Cid(new String(r.data, start, r.pos - start, StandardCharsets.ISO_8859_1), absent);
    }
    static Cid link(Object value) {
        if (!(value instanceof byte[] bytes)) throw new BadData("Invalid CID link");
        var r = new Reader(bytes);
        check(r.u8() == 0);
        return cid(r);
    }
    static List<Cid> links(Object value) { return list(value).stream().map(Wire::link).toList(); }
    static List<?> node(Object value, int kind) {
        var fields = list(value);
        check(at(fields, 0) instanceof Unsigned n && n.bits == kind);
        return fields;
    }
    record Section(byte[] bytes, int start, int end) {
        Object decode() {
            var r = new Reader(bytes, start, end);
            Object value = cbor(r, 0);
            check(r.left() == 0);
            return value;
        }
    }
    static final class Car {
        private final Map<String, Section> index = new HashMap<>();
        final List<?> block;
        Car(byte[] bytes) {
            var r = new Reader(bytes);
            boolean first = true;
            Section blockSection = null;
            while (r.left() > 0) {
                int size = r.count(r.varint(), 32 << 20);
                if (size == 0) continue;
                var section = r.part(size);
                boolean header = first && header(new Section(bytes, section.pos, section.end));
                first = false;
                if (header) continue;
                Cid key = cid(section);
                Section node = new Section(bytes, section.pos, section.end);
                index.put(key.key, node);
                if (section.left() <= 1) continue;
                int tag = bytes[section.pos] & 255, info = tag & 31;
                int extra = info < 24 || info == 31 ? 0 : info <= 27 ? 1 << (info - 24) : -1;
                if (tag >>> 5 == 4 && extra >= 0 && section.left() > 1 + extra &&
                    bytes[section.pos + 1 + extra] == 2) blockSection = node;
            }
            check(blockSection != null);
            block = node(blockSection.decode(), 2);
            check(at(block, 1) instanceof Unsigned);
        }
        private boolean header(Section section) {
            if ((section.bytes[section.start] & 0xe0) != 0xa0) return false;
            try { return section.decode() instanceof Map<?, ?> map && map.containsKey("version"); }
            catch (BadData e) { return false; }
        }
        List<?> find(Cid cid, int kind) {
            var section = index.get(cid.key);
            return section == null ? null : node(section.decode(), kind);
        }
        List<?> get(Cid cid, int kind) {
            var value = find(cid, kind);
            check(value != null);
            return value;
        }
        byte[] payload(Object value) {
            var root = node(value, 6);
            var next = links(at(root, 5));
            byte[] result = at(root, 4) instanceof byte[] b ? b : EMPTY;
            if (!next.isEmpty()) {
                var out = new ByteArrayOutputStream();
                out.writeBytes(result);
                var stack = new ArrayDeque<Cid>();
                var seen = new HashSet<String>();
                push(stack, next);
                while (!stack.isEmpty()) {
                    var link = stack.pop();
                    check(seen.add(link.key));
                    var frame = get(link, 6);
                    if (at(frame, 4) instanceof byte[] data) out.writeBytes(data);
                    push(stack, links(at(frame, 5)));
                }
                result = out.toByteArray();
            }
            if (at(root, 1) instanceof Unsigned hash) check(crc64(result) == hash.bits || fnv(result) == hash.bits);
            return result;
        }
        private void push(ArrayDeque<Cid> stack, List<Cid> links) {
            for (int i = links.size() - 1; i >= 0; i--) stack.push(links.get(i));
        }
    }

    private static final long[] CRC = new long[256];
    static {
        for (int i = 0; i < CRC.length; i++) {
            long v = i;
            for (int j = 0; j < 8; j++) v = (v >>> 1) ^ ((v & 1) == 0 ? 0 : 0xd800000000000000L);
            CRC[i] = v;
        }
    }
    private static long crc64(byte[] data) {
        long v = -1;
        for (byte b : data) v = (v >>> 8) ^ CRC[((int) v ^ b) & 255];
        return ~v;
    }
    private static long fnv(byte[] data) {
        long v = 0xcbf29ce484222325L;
        for (byte b : data) v = (v ^ (b & 255)) * 0x100000001b3L;
        return v;
    }
}
