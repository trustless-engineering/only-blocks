const std = @import("std");
pub const A = std.mem.Allocator;
pub const Invalid = error{ Invalid, OutOfMemory };
pub const mib = 1024 * 1024;
pub const max_slice = 128 * mib;
pub const epoch_slots = 432000;
pub const Eql = struct {
    pub fn bytes(a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
};
pub const Reader = struct {
    left: []const u8,
    pub fn take(r: *Reader, n: u64) error{Invalid}![]const u8 {
        if (n > r.left.len) return error.Invalid;
        const out = r.left[0..@intCast(n)];
        r.left = r.left[@intCast(n)..];
        return out;
    }
    pub fn peek(r: Reader) error{Invalid}!u8 {
        if (r.left.len == 0) return error.Invalid;
        return r.left[0];
    }
    pub fn byte(r: *Reader) error{Invalid}!u8 {
        return (try r.take(1))[0];
    }
    pub fn int(r: *Reader, comptime T: type) error{Invalid}!T {
        return std.mem.readInt(T, (try r.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
    pub fn le(r: *Reader, n: u4) error{Invalid}!u64 {
        var out: u64 = 0;
        for (try r.take(n), 0..) |b, i| out |= @as(u64, b) << @as(u6, @intCast(8 * i));
        return out;
    }
    pub fn leb(r: *Reader) error{Invalid}!u64 {
        var n: u64 = 0;
        for (0..10) |i| {
            const b = try r.byte();
            if (i == 9 and b > 1) return error.Invalid;
            n |= @as(u64, b & 127) << @as(u6, @intCast(i * 7));
            if (b < 128) return n;
        }
        return error.Invalid;
    }
    pub fn compact(r: *Reader) error{Invalid}!usize {
        var n: usize = 0;
        for (0..3) |i| {
            const b = try r.byte();
            if ((i > 0 and b == 0) or (i == 2 and b > 3)) return error.Invalid;
            n |= @as(usize, b & 127) << @as(std.math.Log2Int(usize), @intCast(i * 7));
            if (b < 128) return n;
        }
        return error.Invalid;
    }
    pub fn count(r: *Reader, min: usize) error{Invalid}!usize {
        const n = try r.int(u64);
        if (n > r.left.len / min) return error.Invalid;
        return @intCast(n);
    }
    pub fn option(r: *Reader) error{Invalid}!bool {
        return switch (try r.byte()) {
            0 => false,
            1 => true,
            else => error.Invalid,
        };
    }
    pub fn optional(r: *Reader) error{Invalid}!bool {
        return r.left.len > 0 and try r.option();
    }
    pub fn text(r: *Reader) error{Invalid}![]const u8 {
        return validText(try r.take(try r.int(u64)));
    }
};

pub fn validText(p: []const u8) error{Invalid}![]const u8 {
    if (!std.unicode.utf8ValidateSlice(p)) return error.Invalid;
    return p;
}

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
pub fn base58(a: A, data: []const u8) Invalid![]const u8 {
    const zeros = std.mem.findNone(u8, data, &.{0}) orelse data.len;
    const digits = try a.alloc(u8, (data.len - zeros) * 138 / 100 + 1);
    var count: usize = 0;
    for (data[zeros..]) |b| {
        var carry: u16 = b;
        for (digits[0..count]) |*d| {
            carry += @as(u16, d.*) * 256;
            d.* = @intCast(carry % 58);
            carry /= 58;
        }
        while (carry > 0) : (carry /= 58) {
            digits[count] = @intCast(carry % 58);
            count += 1;
        }
    }
    std.mem.reverse(u8, digits[0..count]);
    const out = try a.alloc(u8, zeros + count);
    @memset(out[0..zeros], '1');
    for (out[zeros..], digits[0..count]) |*d, n| d.* = alphabet[n];
    a.free(digits);
    return out;
}
pub fn pubkey(a: A, p: []const u8) Invalid![]const u8 {
    if (p.len != 32) return error.Invalid;
    return base58(a, p);
}
pub fn base64(a: A, p: []const u8) Invalid![]const u8 {
    const coder = std.base64.standard.Encoder;
    return coder.encode(try a.alloc(u8, coder.calcSize(p.len)), p);
}

pub const Cbor = union(enum) {
    other,
    uint: u64,
    negative: i64,
    bytes: []const u8,
    text: []const u8,
    array: []const Cbor,
    map_has_version: bool,

    pub fn asArray(v: Cbor) []const Cbor {
        return if (v == .array) v.array else &.{};
    }
    pub fn asBytes(v: Cbor) []const u8 {
        return if (v == .bytes) v.bytes else &.{};
    }
    pub fn asUint(v: Cbor) ?u64 {
        return if (v == .uint) v.uint else null;
    }
    pub fn at(values: []const Cbor, i: usize) Cbor {
        return if (i < values.len) values[i] else .other;
    }
};
fn cborArg(r: *Reader, info: u8) Invalid!u64 {
    if (info < 24) return info;
    if (info > 27) return error.Invalid;
    const size: u4 = @as(u4, 1) << @as(u2, @intCast(info - 24));
    var value: u64 = 0;
    for (try r.take(size)) |b| value = (value << 8) | b;
    return value;
}
fn cborItem(a: A, r: *Reader, depth: u8) Invalid!Cbor {
    if (depth > 128) return error.Invalid;
    const head = try r.byte();
    const major = head >> 5;
    const info = head & 31;
    if (major == 7) return switch (info) {
        20...23 => .other,
        25...27 => blk: {
            _ = try cborArg(r, info);
            break :blk .other;
        },
        else => error.Invalid,
    };
    const indefinite = info == 31;
    if (indefinite and (major < 2 or major > 5)) return error.Invalid;
    const size = if (indefinite) 0 else try cborArg(r, info);
    switch (major) {
        0 => return .{ .uint = size },
        1 => return if (size <= std.math.maxInt(i64)) .{ .negative = -1 - @as(i64, @intCast(size)) } else .other,
        6 => return cborItem(a, r, depth + 1),
        2, 3 => {
            var p: []const u8 = undefined;
            if (!indefinite) {
                p = try r.take(size);
            } else {
                var chunks: std.ArrayList(u8) = .empty;
                while (try r.peek() != 255) {
                    const h = try r.byte();
                    if (h >> 5 != major) return error.Invalid;
                    const chunk = try r.take(try cborArg(r, h & 31));
                    if (major == 3) _ = try validText(chunk);
                    try chunks.appendSlice(a, chunk);
                }
                _ = try r.byte();
                p = chunks.items;
            }
            return if (major == 2) .{ .bytes = p } else .{ .text = try validText(p) };
        },
        4, 5 => {
            if (!indefinite and size > r.left.len / (1 + @as(usize, major - 4))) return error.Invalid;
            var list: std.ArrayList(Cbor) = .empty;
            var version = false;
            var i: u64 = 0;
            while (if (indefinite) try r.peek() != 255 else i < size) : (i += 1) {
                const x = try cborItem(a, r, depth + 1);
                if (major == 4) {
                    try list.append(a, x);
                } else {
                    if (x == .text and Eql.bytes(x.text, "version")) version = true;
                    _ = try cborItem(a, r, depth + 1);
                }
            }
            if (indefinite) _ = try r.byte();
            return if (major == 4) .{ .array = list.items } else .{ .map_has_version = version };
        },
        else => unreachable,
    }
}
fn cbor(a: A, p: []const u8) Invalid!Cbor {
    var r = Reader{ .left = p };
    const value = try cborItem(a, &r, 0);
    if (r.left.len != 0) return error.Invalid;
    return value;
}
pub const Cid = struct {
    key: []const u8,
    absent: bool = false,
};
fn cid(r: *Reader) Invalid!Cid {
    const start = r.left;
    const version = try r.leb();
    const codec = try r.leb();
    var absent = false;
    if (version == 0x12 and codec == 0x20) {
        _ = try r.take(32);
    } else {
        if (version != 1) return error.Invalid;
        const hash = try r.leb();
        const size = try r.leb();
        if (size > 64) return error.Invalid;
        _ = try r.take(size);
        absent = hash == 0 and size == 0;
    }
    return .{ .key = start[0 .. start.len - r.left.len], .absent = absent };
}
pub fn link(v: Cbor) Invalid!Cid {
    const p = v.asBytes();
    if (p.len == 0 or p[0] != 0) return error.Invalid;
    var r = Reader{ .left = p[1..] };
    return cid(&r);
}
pub fn links(a: A, v: Cbor) Invalid![][]const u8 {
    const input = v.asArray();
    const keys = try a.alloc([]const u8, input.len);
    for (keys, input) |*key, x| key.* = (try link(x)).key;
    return keys;
}
fn node(value: Cbor, kind: u64) Invalid![]const Cbor {
    const arr = value.asArray();
    if ((Cbor.at(arr, 0).asUint() orelse return error.Invalid) != kind) return error.Invalid;
    return arr;
}
pub const Car = struct {
    index: std.StringHashMapUnmanaged([]const u8),
    block: []const Cbor,

    pub fn parse(a: A, data: []const u8) Invalid!Car {
        var r = Reader{ .left = data };
        var index: std.StringHashMapUnmanaged([]const u8) = .empty;
        var block: ?[]const u8 = null;
        var first = true;
        while (r.left.len != 0) {
            const n = try r.leb();
            if (n == 0) continue;
            if (n > 32 * mib) return error.Invalid;
            var section = Reader{ .left = try r.take(n) };
            const header = first and (try section.peek()) >> 5 == 5;
            first = false;
            if (header) {
                if (cbor(a, section.left)) |v| {
                    if (v == .map_has_version and v.map_has_version) continue;
                } else |err| if (err == error.OutOfMemory) return err;
            }
            const id = try cid(&section);
            const p = section.left;
            try index.put(a, id.key, p);
            if (p.len == 0 or p[0] >> 5 != 4) continue;
            const info = p[0] & 31;
            const width: usize = switch (info) {
                0...23, 31 => 1,
                24 => 2,
                25 => 3,
                26 => 5,
                27 => 9,
                else => continue,
            };
            if (p.len > width and p[width] == 2) block = p;
        }
        return .{ .index = index, .block = try node(try cbor(a, block orelse return error.Invalid), 2) };
    }
    pub fn load(c: Car, a: A, key: []const u8, kind: u64) Invalid![]const Cbor {
        return node(try cbor(a, c.index.get(key) orelse return error.Invalid), kind);
    }
    pub fn frame(c: Car, a: A, v: Cbor) Invalid![]const u8 {
        const root = try node(v, 6);
        var data = Cbor.at(root, 4).asBytes();
        const next = try links(a, Cbor.at(root, 5));
        if (next.len > 0) {
            var out: std.ArrayList(u8) = .empty;
            try out.appendSlice(a, data);
            var stack: std.ArrayList([][]const u8) = .empty;
            try stack.append(a, next);
            var seen: std.StringHashMapUnmanaged(void) = .empty;
            while (stack.items.len > 0) {
                const top = &stack.items[stack.items.len - 1];
                if (top.len == 0) {
                    _ = stack.pop();
                    continue;
                }
                const key = top.*[0];
                top.* = top.*[1..];
                const entry = try seen.getOrPut(a, key);
                if (entry.found_existing) return error.Invalid;
                const f = try c.load(a, key, 6);
                const p = Cbor.at(f, 4).asBytes();
                if (p.len > max_slice - out.items.len) return error.Invalid;
                try out.appendSlice(a, p);
                const children = try links(a, Cbor.at(f, 5));
                if (children.len > 0) try stack.append(a, children);
            }
            data = out.items;
        }
        if (Cbor.at(root, 1).asUint()) |expected| {
            if (std.hash.crc.@"CRC-64/GO-ISO".hash(data) != expected and std.hash.Fnv1a_64.hash(data) != expected)
                return error.Invalid;
        }
        return data;
    }
};
