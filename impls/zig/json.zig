const std = @import("std");
const w = @import("wire.zig");
pub const V = std.json.Value;
pub const A = w.A;
pub const J = struct {
    a: A,

    pub fn val(j: J, x: anytype) w.Invalid!V {
        const T = @TypeOf(x);
        if (T == V) return x;
        return switch (@typeInfo(T)) {
            .null => .null,
            .bool => .{ .bool = x },
            .int, .comptime_int => if (std.math.cast(i64, x)) |n| .{ .integer = n } else .{ .number_string = try std.fmt.allocPrint(j.a, "{d}", .{x}) },
            .float => if (std.math.isFinite(x)) .{ .float = x } else .null,
            .optional => if (x) |v| j.val(v) else .null,
            .pointer => .{ .string = x },
            .@"struct" => j.obj(x),
            else => @compileError("unsupported JSON value " ++ @typeName(T)),
        };
    }
    pub fn obj(j: J, x: anytype) w.Invalid!V {
        var v: V = .{ .object = .empty };
        inline for (comptime std.meta.fieldNames(@TypeOf(x))) |name| {
            try v.object.put(j.a, name, try j.val(@field(x, name)));
        }
        return v;
    }
    pub fn arr(j: J) V {
        return .{ .array = std.array_list.Managed(V).init(j.a) };
    }
    pub fn tuple(j: J, x: anytype) w.Invalid!V {
        var v = j.arr();
        inline for (x) |n| try v.array.append(try j.val(n));
        return v;
    }
    pub fn put(j: J, v: *V, key: []const u8, x: anytype) w.Invalid!void {
        try v.object.put(j.a, key, try j.val(x));
    }
    pub fn append(j: J, v: *V, x: anytype) w.Invalid!void {
        try v.array.append(try j.val(x));
    }
    pub fn list(j: J, values: anytype) w.Invalid!V {
        var out = j.arr();
        try out.array.ensureTotalCapacity(values.len);
        for (values) |v| out.array.appendAssumeCapacity(try j.val(v));
        return out;
    }
};
pub fn get(v: V, key: []const u8) V {
    return if (v == .object) v.object.get(key) orelse .null else .null;
}
pub fn items(v: V) []const V {
    return if (v == .array) v.array.items else &.{};
}
pub fn text(v: V) []const u8 {
    return if (v == .string) v.string else "";
}
pub fn is(v: V, s: []const u8) bool {
    return v == .string and w.Eql.bytes(v.string, s);
}

pub fn parseUnsigned(comptime T: type, p: []const u8) ?T {
    if (p.len == 0) return null;
    for (p) |c| if (c < '0' or c > '9') return null;
    return std.fmt.parseInt(T, p, 10) catch null;
}
pub fn num(comptime T: type, v: V) ?T {
    return switch (v) {
        .number_string => parseUnsigned(T, v.number_string),
        .integer => std.math.cast(T, v.integer),
        else => null,
    };
}
