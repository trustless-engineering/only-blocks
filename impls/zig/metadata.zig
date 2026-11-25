const std = @import("std");
const w = @import("wire.zig");
const js = @import("json.zig");
const tx = @import("transaction.zig");
const J = js.J;
const V = js.V;
const Reader = w.Reader;
const Invalid = w.Invalid;
const at = js.get;
const text = js.text;
const values = js.items;
const reward_types = [_][]const u8{ "Fee", "Rent", "Staking", "Voting" };

fn reward(j: J, key: []const u8, lamports: i64, balance: u64, kind: ?[]const u8, commission: ?u8) Invalid!V {
    return j.obj(.{ .pubkey = key, .lamports = lamports, .postBalance = balance, .rewardType = kind, .commission = commission });
}
fn numberText(comptime T: type, p: []const u8) ?T {
    return js.parseUnsigned(T, if (p.len > 0 and p[0] == '+') p[1..] else p);
}
fn displayAmount(j: J, amount: []const u8, decimals: u8) Invalid![]const u8 {
    const n = numberText(u64, amount) orelse 0;
    var buffer: [20]u8 = undefined;
    const digits = std.fmt.bufPrint(&buffer, "{d}", .{n}) catch unreachable;
    if (decimals == 0 or n == 0) return j.a.dupe(u8, digits);
    const d: usize = decimals;
    const point = @max(digits.len, d + 1) - d;
    const out = try j.a.alloc(u8, point + 1 + d);
    const zeros = out.len - 1 - digits.len;
    for (0..out.len) |i| {
        if (i == point) {
            out[i] = '.';
            continue;
        }
        const unpunctuated = i - @intFromBool(i > point);
        out[i] = if (unpunctuated < zeros) '0' else digits[unpunctuated - zeros];
    }
    const trimmed = std.mem.trimEnd(u8, out, "0");
    return if (trimmed[trimmed.len - 1] == '.') trimmed[0 .. trimmed.len - 1] else trimmed;
}
fn token(j: J, index: u8, mint: []const u8, ui: ?f64, decimals: u8, amount: []const u8, display: []const u8, owner: []const u8, program: []const u8) Invalid!V {
    var v = try j.obj(.{
        .accountIndex = index,
        .mint = mint,
        .uiTokenAmount = try j.obj(.{ .uiAmount = ui, .decimals = decimals, .amount = amount, .uiAmountString = if (display.len == 0) try displayAmount(j, amount, decimals) else display }),
    });
    if (owner.len > 0) try j.put(&v, "owner", owner);
    if (program.len > 0) try j.put(&v, "programId", program);
    return v;
}
fn retData(j: J, program: []const u8, data: []const u8) Invalid!V {
    return j.obj(.{ .programId = try w.pubkey(j.a, program), .data = try j.tuple(.{ try w.base64(j.a, data), "base64" }) });
}

const Field = struct {
    name: []const u8,
    kind: enum { number, double, bytes, string, message, many_number, many_bytes, many_string, many_message },
    nested: []const Field = &.{},
};
const ins_fields = [_]Field{
    .{ .name = "program", .kind = .number }, .{ .name = "accounts", .kind = .bytes }, .{ .name = "data", .kind = .bytes }, .{ .name = "stack", .kind = .number },
};
const group_fields = [_]Field{ .{ .name = "index", .kind = .number }, .{ .name = "instructions", .kind = .many_message, .nested = &ins_fields } };
const ui_fields = [_]Field{
    .{ .name = "ui", .kind = .double }, .{ .name = "decimals", .kind = .number }, .{ .name = "amount", .kind = .string }, .{ .name = "display", .kind = .string },
};
const balance_fields = [_]Field{
    .{ .name = "index", .kind = .number }, .{ .name = "mint", .kind = .string },    .{ .name = "amount", .kind = .message, .nested = &ui_fields },
    .{ .name = "owner", .kind = .string }, .{ .name = "program", .kind = .string },
};
const reward_fields = [_]Field{
    .{ .name = "pubkey", .kind = .string }, .{ .name = "lamports", .kind = .number },   .{ .name = "postBalance", .kind = .number },
    .{ .name = "type", .kind = .number },   .{ .name = "commission", .kind = .string }, .{ .name = "bps", .kind = .string },
};
const rewards_fields = [_]Field{
    .{ .name = "items", .kind = .many_message, .nested = &reward_fields },
    .{ .name = "partitions", .kind = .message, .nested = &.{.{ .name = "count", .kind = .number }} },
};
const meta_fields = [_]Field{
    .{ .name = "error", .kind = .message, .nested = &.{.{ .name = "bytes", .kind = .bytes }} },
    .{ .name = "fee", .kind = .number },
    .{ .name = "pre", .kind = .many_number },
    .{ .name = "post", .kind = .many_number },
    .{ .name = "inner", .kind = .many_message, .nested = &group_fields },
    .{ .name = "logs", .kind = .many_string },
    .{ .name = "pre_tokens", .kind = .many_message, .nested = &balance_fields },
    .{ .name = "post_tokens", .kind = .many_message, .nested = &balance_fields },
    .{ .name = "rewards", .kind = .many_message, .nested = &reward_fields },
    .{ .name = "inner_none", .kind = .number },
    .{ .name = "logs_none", .kind = .number },
    .{ .name = "writable", .kind = .many_bytes },
    .{ .name = "readonly", .kind = .many_bytes },
    .{ .name = "return_data", .kind = .message, .nested = &.{ .{ .name = "program", .kind = .bytes }, .{ .name = "data", .kind = .bytes } } },
    .{ .name = "return_none", .kind = .number },
    .{ .name = "compute", .kind = .number },
    .{ .name = "cost", .kind = .number },
};
fn protoKey(r: *Reader) Invalid!u32 {
    const key = try r.leb();
    if (key < 8 or key > std.math.maxInt(u32)) return error.Invalid;
    return @intCast(key);
}
fn skipProto(r: *Reader, key: u32, depth: u8) Invalid!void {
    switch (key & 7) {
        0 => _ = try r.leb(),
        1 => _ = try r.take(8),
        2 => _ = try r.take(try r.leb()),
        3 => {
            if (depth >= 100) return error.Invalid;
            while (true) {
                const child = try protoKey(r);
                if (child & 7 == 4) {
                    if (child >> 3 != key >> 3) return error.Invalid;
                    return;
                }
                try skipProto(r, child, depth + 1);
            }
        },
        5 => _ = try r.take(4),
        else => return error.Invalid,
    }
}
fn proto(j: J, p: []const u8, fields: []const Field, existing: V) Invalid!V {
    var r = Reader{ .left = p };
    var result = if (existing == .object) existing else try j.obj(.{});
    while (r.left.len > 0) {
        const key = try protoKey(&r);
        const field = key >> 3;
        const wire = key & 7;
        if (field > fields.len) {
            try skipProto(&r, key, 0);
            continue;
        }
        const f = fields[field - 1];
        const many = switch (f.kind) {
            .many_number, .many_bytes, .many_string, .many_message => true,
            else => false,
        };
        var list = if (many) at(result, f.name) else V.null;
        if (many and list == .null) list = j.arr();
        if (f.kind == .many_number and wire == 2) {
            var packed_values = Reader{ .left = try r.take(try r.leb()) };
            while (packed_values.left.len > 0) try j.append(&list, try packed_values.leb());
            try j.put(&result, f.name, list);
            continue;
        }
        const v = switch (f.kind) {
            .number, .many_number => blk: {
                if (wire != 0) return error.Invalid;
                break :blk try j.val(try r.leb());
            },
            .double => blk: {
                if (wire != 1) return error.Invalid;
                break :blk try j.val(@as(f64, @bitCast(try r.int(u64))));
            },
            else => blk: {
                if (wire != 2) return error.Invalid;
                const part = try r.take(try r.leb());
                break :blk switch (f.kind) {
                    .string, .many_string => try j.val(try w.validText(part)),
                    .bytes, .many_bytes => try j.val(part),
                    .message, .many_message => try proto(j, part, f.nested, if (many) .null else at(result, f.name)),
                    else => unreachable,
                };
            },
        };
        if (many) {
            try j.append(&list, v);
            try j.put(&result, f.name, list);
        } else try j.put(&result, f.name, v);
    }
    return result;
}
fn number(v: V) u64 {
    return js.num(u64, v) orelse 0;
}
fn protoReward(j: J, m: V) Invalid!V {
    const typ: u32 = @truncate(number(at(m, "type")));
    const kind = if (typ > 0 and typ <= reward_types.len) reward_types[typ - 1] else null;
    const commission = numberText(u8, text(at(m, "commission"))) orelse blk: {
        const bps = numberText(u16, text(at(m, "bps"))) orelse break :blk null;
        break :blk std.math.cast(u8, bps / 100);
    };
    return reward(j, text(at(m, "pubkey")), @bitCast(number(at(m, "lamports"))), number(at(m, "postBalance")), kind, commission);
}
fn protoToken(j: J, m: V) Invalid!V {
    const a = at(m, "amount");
    const f = at(a, "ui");
    const ui = if (f == .float and @abs(f.float) > 0x1p-52) f.float else null;
    return token(j, @truncate(number(at(m, "index"))), text(at(m, "mint")), ui, @truncate(number(at(a, "decimals"))), text(at(a, "amount")), text(at(a, "display")), text(at(m, "owner")), text(at(m, "program")));
}
fn defaultList(j: J, v: V) V {
    return if (v == .null) j.arr() else v;
}
fn transformList(j: J, v: V, convert: fn (J, V) Invalid!V) Invalid!V {
    var out = j.arr();
    for (values(v)) |entry| try j.append(&out, try convert(j, entry));
    return out;
}
fn addresses(j: J, v: V) Invalid![][]const u8 {
    const a = values(v);
    const out = try j.a.alloc([]const u8, a.len);
    for (out, a) |*key, x| key.* = try w.pubkey(j.a, text(x));
    return out;
}
fn protoMeta(j: J, m: V) Invalid!tx.Meta {
    var out = tx.Meta{
        .fee = number(at(m, "fee")),
        .pre = defaultList(j, at(m, "pre")),
        .post = defaultList(j, at(m, "post")),
        .pre_tokens = try transformList(j, at(m, "pre_tokens"), protoToken),
        .post_tokens = try transformList(j, at(m, "post_tokens"), protoToken),
        .rewards = try transformList(j, at(m, "rewards"), protoReward),
        .writable = try addresses(j, at(m, "writable")),
        .readonly = try addresses(j, at(m, "readonly")),
        .compute = at(m, "compute"),
        .cost = at(m, "cost"),
    };
    const failure = at(m, "error");
    if (failure != .null) {
        var r = Reader{ .left = text(at(failure, "bytes")) };
        out.err = try tx.transactionError(j, &r);
    }
    if (number(at(m, "inner_none")) == 0) {
        const from = values(at(m, "inner"));
        const groups = try j.a.alloc(tx.Group, from.len);
        for (groups, from) |*group, g| {
            const input = values(at(g, "instructions"));
            const instructions = try j.a.alloc(tx.Instruction, input.len);
            for (instructions, input) |*ix, v| {
                const stack = at(v, "stack");
                ix.* = .{ .program = @truncate(number(at(v, "program"))), .accounts = text(at(v, "accounts")), .data = text(at(v, "data")), .stack = if (stack == .null) null else @as(u32, @truncate(number(stack))) };
            }
            group.* = .{ .index = @truncate(number(at(g, "index"))), .instructions = instructions };
        }
        out.inner = groups;
    }
    if (number(at(m, "logs_none")) == 0) out.logs = defaultList(j, at(m, "logs"));
    const ret = at(m, "return_data");
    if (ret != .null and number(at(m, "return_none")) == 0) out.return_data = try retData(j, text(at(ret, "program")), text(at(ret, "data")));
    return out;
}

fn bincodeReward(j: J, r: *Reader, extended: bool) Invalid!V {
    const key = try r.text();
    const lamports = try r.int(i64);
    const balance = if (!extended or r.left.len > 0) try r.int(u64) else 0;
    var kind: ?[]const u8 = null;
    if ((!extended or r.left.len > 0) and try r.option()) {
        const typ = try r.int(u32);
        if (typ >= reward_types.len) return error.Invalid;
        kind = reward_types[typ];
    }
    const commission = if (extended and try r.optional()) try r.byte() else null;
    return reward(j, key, lamports, balance, kind, commission);
}
fn bincodeToken(j: J, r: *Reader, layout: u8) Invalid!V {
    const index = try r.byte();
    const mint = try r.text();
    const ui: f64 = @bitCast(try r.int(u64));
    const decimals = try r.byte();
    const amount = try r.text();
    const owner = if (layout >= 2 and r.left.len > 0) try r.text() else "";
    const program = if (layout >= 3 and r.left.len > 0) try r.text() else "";
    return token(j, index, mint, ui, decimals, amount, "", owner, program);
}
fn bincodeTokens(j: J, r: *Reader, layout: u8) Invalid!V {
    if (!try r.optional()) return .null;
    var out = j.arr();
    for (0..try r.count(26)) |_| try j.append(&out, try bincodeToken(j, r, layout));
    return out;
}
fn bincodeRewards(j: J, r: *Reader, extended: bool) Invalid!V {
    var out = j.arr();
    for (0..try r.count(if (extended) 16 else 25)) |_| try j.append(&out, try bincodeReward(j, r, extended));
    return out;
}
fn bincodeMeta(j: J, r: *Reader, legacy: bool, layout: u8) Invalid!tx.Meta {
    var out = tx.Meta{};
    const status = try r.int(u32);
    if (status > 1) return error.Invalid;
    if (status == 1) out.err = try tx.transactionError(j, r);
    out.fee = try r.int(u64);
    out.pre = j.arr();
    for (0..try r.count(8)) |_| try j.append(&out.pre, try r.int(u64));
    out.post = j.arr();
    for (0..try r.count(8)) |_| try j.append(&out.post, try r.int(u64));
    if (try r.optional()) {
        const groups = try j.a.alloc(tx.Group, try r.count(9));
        for (groups) |*group| {
            const i = try r.byte();
            const instructions = try j.a.alloc(tx.Instruction, try r.count(if (legacy) 3 else 4));
            for (instructions) |*ix| {
                ix.* = try tx.Instruction.read(r, null);
                if (!legacy and try r.option()) ix.stack = try r.int(u32);
            }
            group.* = .{ .index = i, .instructions = instructions };
        }
        out.inner = groups;
    }
    if (try r.optional()) {
        out.logs = j.arr();
        for (0..try r.count(8)) |_| try j.append(&out.logs, try r.text());
    }
    out.pre_tokens = try bincodeTokens(j, r, layout);
    out.post_tokens = try bincodeTokens(j, r, layout);
    if (try r.optional()) out.rewards = try bincodeRewards(j, r, true);
    if (try r.optional()) out.return_data = try retData(j, try r.take(32), try r.take(try r.int(u64)));
    if (try r.optional()) out.compute = try j.val(try r.int(u64));
    if (try r.optional()) out.cost = try j.val(try r.int(u64));
    return out;
}
const Rewards = struct { list: V, partitions: ?u64 = null };
fn Payload(comptime rewards_mode: bool) type {
    return if (rewards_mode) Rewards else tx.Meta;
}
fn bincodePayload(comptime rewards_mode: bool, j: J, p: []const u8) Invalid!Payload(rewards_mode) {
    if (rewards_mode) {
        for ([_]bool{ true, false }) |extended| {
            var r = Reader{ .left = p };
            if (bincodeRewards(j, &r, extended)) |list| {
                if (r.left.len == 0) return .{ .list = list };
            } else |e| if (e != error.Invalid) return e;
        }
        var r = Reader{ .left = p };
        return .{ .list = try bincodeRewards(j, &r, true) };
    }
    for (0..4) |i| {
        var r = Reader{ .left = p };
        if (bincodeMeta(j, &r, i != 0, if (i == 0) 3 else @intCast(i))) |m| {
            if (r.left.len == 0) return m;
        } else |e| if (e != error.Invalid) return e;
    }
    var r = Reader{ .left = p };
    return bincodeMeta(j, &r, false, 3);
}
fn payload(comptime rewards_mode: bool, j: J, slot: u64, p: []const u8) Invalid!Payload(rewards_mode) {
    const early = slot < 157 * w.epoch_slots;
    if (early) {
        if (bincodePayload(rewards_mode, j, p)) |v| {
            return v;
        } else |e| if (e != error.Invalid) return e;
    }
    const m = proto(j, p, if (rewards_mode) &rewards_fields else &meta_fields, .null) catch |e| {
        if (early or e != error.Invalid) return e;
        return bincodePayload(rewards_mode, j, p);
    };
    if (!rewards_mode) return protoMeta(j, m);
    const partitions = at(m, "partitions");
    return .{ .list = try transformList(j, at(m, "items"), protoReward), .partitions = if (partitions != .null) number(at(partitions, "count")) else null };
}

const max_plain = 512 * w.mib;
// Walk whole frames first to reject truncation independently of the streaming
// reader's EOF, and allocate the actual advertised window for each frame.
fn decompress(j: J, p: []const u8) Invalid![]const u8 {
    var r = Reader{ .left = p };
    var out: std.ArrayList(u8) = .empty;
    while (r.left.len > 0) {
        const start = r.left;
        const magic = try r.int(u32);
        if (magic & 0xfffffff0 == 0x184d2a50) {
            _ = try r.take(try r.int(u32));
            continue;
        }
        if (magic != 0xfd2fb528) return error.Invalid;
        const flag = try r.byte();
        if (flag & 8 != 0) return error.Invalid;
        const single = flag & 32 != 0;
        var window: u64 = 0;
        if (!single) {
            const descriptor = try r.byte();
            const base = @as(u64, 1) << @as(u6, @intCast(10 + (descriptor >> 3)));
            window = base + (base >> 3) * (descriptor & 7);
        }
        const dictionary_width = ([4]u4{ 0, 1, 2, 4 })[flag & 3];
        if (try r.le(dictionary_width) != 0) return error.Invalid;
        var size_width = ([4]u4{ 0, 2, 4, 8 })[flag >> 6];
        if (single and size_width == 0) size_width = 1;
        const size = (try r.le(size_width)) + @as(u64, if (size_width == 2) 256 else 0);
        if (single) window = size;
        if (window > 128 * w.mib or size > max_plain - out.items.len) return error.Invalid;
        while (true) {
            const header = try r.le(3);
            const n = header >> 3;
            if (n > @min(window, 128 * 1024)) return error.Invalid;
            _ = switch ((header >> 1) & 3) {
                0, 2 => try r.take(n),
                1 => try r.take(1),
                3 => return error.Invalid,
                else => unreachable,
            };
            if (header & 1 != 0) break;
        }
        const checksum = if (flag & 4 != 0) try r.int(u32) else null;
        const frame = start[0 .. start.len - r.left.len];
        // std rejects any dictionary-ID flag, including an explicitly zero
        // ID. Remove that field before passing a dictionary-free frame to it.
        const decoder_input = if (dictionary_width > 0) blk: {
            const fixed = try j.a.alloc(u8, frame.len - dictionary_width);
            const prefix: usize = if (single) 5 else 6;
            @memcpy(fixed[0..prefix], frame[0..prefix]);
            fixed[4] &= 0xfc;
            @memcpy(fixed[prefix..], frame[prefix + dictionary_width ..]);
            break :blk fixed;
        } else frame;
        var input = std.Io.Reader.fixed(decoder_input);
        const scratch = try std.heap.page_allocator.alloc(u8, @as(usize, @intCast(window)) + 128 * 1024);
        defer std.heap.page_allocator.free(scratch);
        var decoder = std.compress.zstd.Decompress.init(&input, scratch, .{ .window_len = @intCast(window) });
        const remaining = max_plain - out.items.len;
        const plain = decoder.reader.allocRemaining(j.a, .limited(remaining + 1)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Invalid,
        };
        // An internal end-of-bitstream must not look like a successful EOF.
        if (decoder.state != .new_frame or input.bufferedLen() != 0) return error.Invalid;
        if (plain.len > remaining or (size_width != 0 and plain.len != size)) return error.Invalid;
        if (checksum) |check| if (@as(u32, @truncate(std.hash.XxHash64.hash(0, plain))) != check) return error.Invalid;
        if (out.items.len == 0 and r.left.len == 0) return plain;
        try out.appendSlice(j.a, plain);
    }
    return out.items;
}
fn decodeFrame(comptime rewards_mode: bool, j: J, slot: u64, p: []const u8) Invalid!Payload(rewards_mode) {
    if (std.mem.startsWith(u8, p, "\x28\xb5\x2f\xfd")) {
        const plain = decompress(j, p) catch |e| {
            if (e != error.Invalid) return e;
            return payload(rewards_mode, j, slot, p);
        };
        return payload(rewards_mode, j, slot, plain);
    }
    if (payload(rewards_mode, j, slot, p)) |v| {
        return v;
    } else |e| {
        if (e != error.Invalid) return e;
        const plain = try decompress(j, p);
        return payload(rewards_mode, j, slot, plain);
    }
}
pub fn metadata(j: J, slot: u64, p: []const u8) Invalid!?tx.Meta {
    if (p.len == 0) return null;
    return try decodeFrame(false, j, slot, p);
}
pub fn rewards(j: J, slot: u64, p: []const u8) Invalid!Rewards {
    if (p.len == 0) return .{ .list = j.arr() };
    return decodeFrame(true, j, slot, p);
}

test "bounded Zstd frames, skippable frames and checksum validation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const j = J{ .a = arena.allocator() };
    const empty = "\x28\xb5\x2f\xfd\x20\x00\x01\x00\x00";
    const skip = "\x50\x2a\x4d\x18\x03\x00\x00\x00\x01\x02\x03";
    const raw = "\x28\xb5\x2f\xfd\x20\x0a\x51\x00\x00onlyblocks";
    const checked = "\x28\xb5\x2f\xfd\x04\x58\x4d\x00\x00\x18abc\x01\x00\x7e\x6e\x08\x48\xc3\xd3\x0e";
    const combined = skip ++ empty ++ raw ++ checked;
    try std.testing.expectEqualStrings("onlyblocksabcabcabcabcabcabcabcabc", try decompress(j, combined));
    try std.testing.expectError(error.Invalid, decompress(j, combined[0 .. combined.len - 1]));
    try std.testing.expectError(error.Invalid, decompress(j, combined ++ "\x00"));
    var altered = checked.*;
    altered[checked.len - 1] ^= 1;
    try std.testing.expectError(error.Invalid, decompress(j, altered[0..checked.len]));
}
