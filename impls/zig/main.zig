const std = @import("std");
const w = @import("wire.zig");
const js = @import("json.zig");
const tx = @import("transaction.zig");
const codecs = @import("metadata.zig");
const Io = std.Io;
const J = js.J;
const V = js.V;
const A = w.A;
const Cbor = w.Cbor;
const at = js.get;
const eq = w.Eql.bytes;
const zero_hash = "11111111111111111111111111111111";
const Range = struct { offset: u64, length: u32 };
const Hash = struct {
    bytes: [44]u8 = undefined,
    len: usize,
    fn init(p: []const u8) Hash {
        var hash = Hash{ .len = p.len };
        @memcpy(hash.bytes[0..p.len], p);
        return hash;
    }
};
const ArchiveError = w.Invalid || error{ Unarchived, Skipped, UnsupportedVersion };
fn Cache(comptime T: type) type {
    return struct {
        const Self = @This();
        const Entry = struct { key: u64, value: T, node: std.DoublyLinkedList.Node = .{} };
        lock: Io.Mutex = .init,
        items: std.AutoHashMapUnmanaged(u64, *Entry) = .empty,
        order: std.DoublyLinkedList = .{},

        fn touch(c: *Self, p: *Entry) void {
            c.order.remove(&p.node);
            c.order.prepend(&p.node);
        }
        fn get(c: *Self, io: Io, key: u64) ?T {
            c.lock.lockUncancelable(io);
            defer c.lock.unlock(io);
            const p = c.items.get(key) orelse return null;
            c.touch(p);
            return p.value;
        }
        fn set(c: *Self, io: Io, a: A, key: u64, value: T) !void {
            c.lock.lockUncancelable(io);
            defer c.lock.unlock(io);
            if (c.items.get(key)) |p| {
                p.value = value;
                c.touch(p);
                return;
            }
            const p = if (c.items.count() == 100_000) blk: {
                const node = c.order.popLast() orelse unreachable;
                const oldest: *Entry = @fieldParentPtr("node", node);
                _ = c.items.remove(oldest.key);
                break :blk oldest;
            } else try a.create(Entry);
            errdefer a.destroy(p);
            p.* = .{ .key = key, .value = value };
            try c.items.put(a, key, p);
            c.order.prepend(&p.node);
        }
    };
}
const Archive = struct {
    a: A,
    io: Io,
    base: std.Uri,
    client: std.http.Client,
    attempts: Io.Semaphore = .{ .permits = 32 },
    ranges: Cache(Range) = .{},
    hashes: Cache(Hash) = .{},

    const Attempt = union(enum) { data: []const u8, retry: ?i64, missing, invalid };

    fn attempt(s: *Archive, a: A, uri: std.Uri, interval: []const u8, length: usize, cap: usize, connected: *Io.Event) Attempt {
        var request = s.client.request(.GET, uri, .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{ .user_agent = .{ .override = "onlyblocks/zig" }, .accept_encoding = .{ .override = "identity" } },
            .extra_headers = &.{.{ .name = "range", .value = interval }},
        }) catch return .{ .retry = null };
        defer request.deinit();
        connected.set(s.io);
        request.sendBodiless() catch return .{ .retry = null };
        var response = request.receiveHead(&.{}) catch return .{ .retry = null };
        // Range bodies have no reuse value. Closing also prevents deinit from
        // draining a large body after a status or length rejection.
        if (request.connection) |c| c.closing = true;
        const status = @backingInt(response.head.status);
        if (status == 404) return .missing;
        if (status == 429 or (status >= 500 and status <= 599)) {
            var headers = response.head.iterateHeaders();
            while (headers.next()) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "retry-after")) return .{ .retry = retryAfter(s.io, h.value) };
            }
            return .{ .retry = null };
        }
        if (status != 206) return .invalid;
        const declared = response.head.content_length;
        if (declared) |n| if (n > cap) return .invalid;
        var transfer: [4096]u8 = undefined;
        const body = response.reader(&transfer);
        const data = body.allocRemaining(a, .limited(length + 1)) catch |e| switch (e) {
            error.StreamTooLong => {
                if (cap == length) return .invalid;
                // allocRemaining consumed the limited prefix. Continue until
                // framing completes or the actual range cap is hit.
                _ = body.discardShort(cap - length) catch return .{ .retry = null };
                return .invalid;
            },
            error.OutOfMemory => return .invalid,
            else => return .{ .retry = null },
        };
        if (declared) |n| if (n != data.len) return .{ .retry = null };
        if (data.len != length) return .invalid;
        return .{ .data = data };
    }
    fn watchdog(io: Io, connected: *Io.Event) void {
        const start = Io.Clock.awake.now(io);
        connected.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } }) catch return;
        const deadline = start.addDuration(.fromSeconds(60));
        const left = Io.Clock.awake.now(io).durationTo(deadline);
        if (left.nanoseconds > 0) Io.sleep(io, left, .awake) catch {};
    }
    fn rangeAttempt(s: *Archive, a: A, uri: std.Uri, interval: []const u8, length: usize, cap: usize) !Attempt {
        try s.attempts.wait(s.io);
        defer s.attempts.post(s.io);
        const Completion = union(enum) { result: Attempt, timeout: void };
        var messages: [2]Completion = undefined;
        var select = Io.Select(Completion).init(s.io, &messages);
        defer select.cancelDiscard();
        var connected: Io.Event = .unset;
        try select.concurrent(.result, attempt, .{ s, a, uri, interval, length, cap, &connected });
        try select.concurrent(.timeout, watchdog, .{ s.io, &connected });
        return switch (try select.await()) {
            .result => |r| r,
            .timeout => .{ .retry = null },
        };
    }
    fn readRange(s: *Archive, a: A, slot: u64, suffix: []const u8, start: u64, length: usize, cap: usize) ArchiveError![]const u8 {
        if (length == 0 or length > cap or start > std.math.maxInt(u64) - (length - 1)) return error.Invalid;
        const epoch = slot / w.epoch_slots;
        var target = s.base;
        const prefix = std.mem.trimEnd(u8, target.path.percent_encoded, "/");
        target.path = .{ .percent_encoded = try std.fmt.allocPrint(a, "{s}/{d}/epoch-{d}{s}", .{ prefix, epoch, epoch, suffix }) };
        var b: [64]u8 = undefined;
        const interval = std.fmt.bufPrint(&b, "bytes={d}-{d}", .{ start, start + (length - 1) }) catch unreachable;
        for (0..5) |failure| {
            const result = s.rangeAttempt(a, target, interval, length, cap) catch return error.Invalid;
            switch (result) {
                .data => |data| return data,
                .missing => return error.Unarchived,
                .invalid => return error.Invalid,
                .retry => |after| {
                    if (failure == 4) break;
                    const base = @as(u32, 200) << @as(u5, @intCast(failure));
                    var sample: u32 = undefined;
                    s.io.random(std.mem.asBytes(&sample));
                    const delay = after orelse base / 2 + sample % (base / 2 + 1);
                    if (delay > 0) Io.sleep(s.io, .fromMilliseconds(delay), .awake) catch return error.Invalid;
                },
            }
        }
        return error.Invalid;
    }
    fn load(s: *Archive, a: A, slot: u64) ArchiveError!w.Car {
        const range = s.ranges.get(s.io, slot) orelse blk: {
            var r = w.Reader{ .left = try s.readRange(a, slot, "-slot-ranges.raw", slot % w.epoch_slots * 12, 12, 12) };
            const span = Range{ .offset = try r.int(u64), .length = try r.int(u32) };
            try s.ranges.set(s.io, s.a, slot, span);
            break :blk span;
        };
        if (range.length == 0) return error.Skipped;
        return w.Car.parse(a, try s.readRange(a, slot, ".car", range.offset, range.length, w.max_slice));
    }
    fn blockHash(s: *Archive, a: A, slot: u64, car: w.Car, entries: [][]const u8) ArchiveError![]const u8 {
        const hash = if (entries.len != 0) try w.pubkey(a, Cbor.at(try car.load(a, entries[entries.len - 1], 1), 2).asBytes()) else zero_hash;
        try s.hashes.set(s.io, s.a, slot, Hash.init(hash));
        return hash;
    }
    fn previousHash(s: *Archive, a: A, slot: u64, parent: u64) ArchiveError![]const u8 {
        if (slot == 0) return zero_hash;
        if (s.hashes.get(s.io, parent)) |hash| return a.dupe(u8, hash.bytes[0..hash.len]);
        var scratch = std.heap.ArenaAllocator.init(s.a);
        defer scratch.deinit();
        const b = scratch.allocator();
        const car = try s.load(b, parent);
        _ = Cbor.at(car.block, 1).asUint() orelse return error.Invalid;
        const entries = try w.links(b, Cbor.at(car.block, 3));
        return a.dupe(u8, try s.blockHash(b, parent, car, entries));
    }

    fn block(s: *Archive, j: J, o: tx.Options) ArchiveError!V {
        const a = j.a;
        const car = try s.load(a, o.slot);
        if ((Cbor.at(car.block, 1).asUint() orelse return error.Invalid) != o.slot) return error.Invalid;
        const entries = try w.links(a, Cbor.at(car.block, 3));
        const hash = try s.blockHash(a, o.slot, car, entries);
        const header = Cbor.at(car.block, 4).asArray();
        const parent = Cbor.at(header, 0).asUint() orelse 0;
        const previous = try s.previousHash(a, o.slot, parent);
        const stamp = Cbor.at(header, 1);
        const time: ?i64 = switch (stamp) {
            .uint => if (stamp.uint != 0) std.math.cast(i64, stamp.uint) else null,
            .negative => stamp.negative,
            else => null,
        };
        var value = try j.obj(.{ .previousBlockhash = previous, .blockhash = hash, .parentSlot = parent, .blockTime = time, .blockHeight = Cbor.at(header, 2).asUint() });
        if (o.details != .none) {
            var items = j.arr();
            for (entries) |id| {
                const entry = try car.load(a, id, 1);
                if (Cbor.at(entry, 2).asBytes().len != 32) return error.Invalid;
                for (try w.links(a, Cbor.at(entry, 3))) |tx_id| {
                    const node = try car.load(a, tx_id, 0);
                    const transaction = try tx.Tx.read(j, try car.frame(a, Cbor.at(node, 1)));
                    if (o.details == .signatures) {
                        if (transaction.signatures.len < 64) return error.Invalid;
                        try j.append(&items, try w.base58(a, transaction.signatures[0..64]));
                    } else {
                        const data = Cbor.at(node, 2);
                        const meta = if (data == .array) try codecs.metadata(j, o.slot, try car.frame(a, data)) else null;
                        try j.append(&items, try transaction.json(j, meta, o));
                    }
                }
            }
            try j.put(&value, if (o.details == .signatures) "signatures" else "transactions", items);
        }
        if (o.rewards) {
            var data: []const u8 = &.{};
            const v = Cbor.at(car.block, 5);
            if (v == .bytes) {
                const id = try w.link(v);
                if (!id.absent and car.index.contains(id.key)) {
                    const node = try car.load(a, id.key, 5);
                    if (node.len > 2) data = try car.frame(a, node[2]);
                }
            }
            const decoded = try codecs.rewards(j, o.slot, data);
            try j.put(&value, "rewards", decoded.list);
            if (decoded.partitions) |n| try j.put(&value, "numRewardPartitions", n);
        }
        return value;
    }
};

fn nextToken(it: anytype) []const u8 {
    return it.next() orelse "";
}
fn retryAfter(io: Io, p: []const u8) ?i64 {
    if (js.parseUnsigned(u64, p)) |seconds| return @as(i64, @intCast(@min(seconds, 10))) * 1000;
    // Accept IMF-fixdate, obsolete RFC 850, and ANSI C asctime.
    var it = std.mem.tokenizeAny(u8, p, " ,:-");
    const weekday = nextToken(&it);
    const weekdays = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" };
    var valid = false;
    for (weekdays) |name| if (eq(weekday, name)) {
        valid = true;
        break;
    };
    if (!valid) return null;
    const first = nextToken(&it);
    const day_first = js.parseUnsigned(u8, first);
    const month = if (day_first != null) nextToken(&it) else first;
    const day = day_first orelse js.parseUnsigned(u8, nextToken(&it)) orelse return null;
    var year_bytes = if (day_first != null) nextToken(&it) else "";
    const hour = js.parseUnsigned(u8, nextToken(&it)) orelse return null;
    const minute = js.parseUnsigned(u8, nextToken(&it)) orelse return null;
    const second = js.parseUnsigned(u8, nextToken(&it)) orelse return null;
    if (day_first == null) year_bytes = nextToken(&it) else if (!eq(nextToken(&it), "GMT")) return null;
    if (it.next() != null) return null;
    var year: i64 = js.parseUnsigned(u16, year_bytes) orelse return null;
    if (year_bytes.len == 2) year += if (year >= 69) @as(i64, 1900) else 2000 else if (year_bytes.len != 4) return null;
    if (hour > 23 or minute > 59 or second > 60) return null;
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const leap = @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
    const days_in_month = [_]u8{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var days: i64 = 0;
    for (months, days_in_month) |name, n| {
        if (eq(name, month)) {
            if (day == 0 or day > n) return null;
            const y = year - 1;
            const before = 365 * y + @divFloor(y, 4) - @divFloor(y, 100) + @divFloor(y, 400);
            const date = (before - 719162 + days + day - 1) * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
            return @as(i64, @min(@max(date - Io.Clock.real.now(io).toSeconds(), 0), 10)) * 1000;
        }
        days += n;
    }
    return null;
}

fn blockParams(p: V) ?tx.Options {
    const args = js.items(p);
    if (args.len < 1 or args.len > 2) return null;
    var o = tx.Options{ .slot = js.num(u64, args[0]) orelse return null };
    if (args.len == 1 or args[1] == .null) return o;
    const config = args[1];
    if (config != .string and config != .object) return null;
    const encoding = if (config == .string) config else at(config, "encoding");
    if (encoding != .null) o.encoding = std.meta.stringToEnum(@TypeOf(o.encoding), js.text(encoding)) orelse return null;
    const details = at(config, "transactionDetails");
    if (details != .null) o.details = std.meta.stringToEnum(@TypeOf(o.details), js.text(details)) orelse return null;
    if (o.details == .accounts and o.encoding != .json) return null;
    const commitment = at(config, "commitment");
    if (commitment != .null and !js.is(commitment, "finalized") and !js.is(commitment, "confirmed")) return null;
    const rewards = at(config, "rewards");
    if (rewards != .null) o.rewards = if (rewards == .bool) rewards.bool else return null;
    const version = at(config, "maxSupportedTransactionVersion");
    if (version != .null) {
        _ = js.num(u8, version) orelse return null;
        o.version = true;
    }
    return o;
}
fn rpcError(j: J, id: V, code: i32, message: []const u8) w.Invalid!V {
    return j.obj(.{ .jsonrpc = "2.0", .id = id, .@"error" = try j.obj(.{ .code = code, .message = message }) });
}
fn dispatch(s: *Archive, j: J, p: V) w.Invalid!V {
    const version = at(p, "jsonrpc");
    const method = at(p, "method");
    const id = at(p, "id");
    if (p != .object or (version != .null and version != .string) or (method != .null and method != .string) or
        (id != .null and id != .string and id != .number_string)) return rpcError(j, .null, -32600, "Invalid Request");
    if (!js.is(version, "2.0") or method != .string) return rpcError(j, id, -32600, "Invalid Request");
    const params = at(p, "params");
    const result = blk: {
        if (js.is(method, "getHealth")) {
            if (params != .null and (params != .array or params.array.items.len != 0)) return rpcError(j, id, -32602, "Invalid getHealth params");
            break :blk try j.val("ok");
        }
        if (js.is(method, "getBlock")) {
            const o = blockParams(params) orelse return rpcError(j, id, -32602, "Invalid getBlock params");
            break :blk s.block(j, o) catch |err| return switch (err) {
                error.Unarchived => rpcError(j, id, -32004, "Block not available"),
                error.Skipped => rpcError(j, id, -32007, "Slot was skipped"),
                error.UnsupportedVersion => rpcError(j, id, -32015, "Transaction version (0) requires maxSupportedTransactionVersion: 0"),
                else => rpcError(j, id, -32603, "Archive read or decode failed"),
            };
        }
        return rpcError(j, id, -32601, "Method not found");
    };
    return j.obj(.{ .jsonrpc = "2.0", .id = id, .result = result });
}
fn depthAllowed(body: []const u8) bool {
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (body) |c| {
        if (in_string) {
            if (escaped) escaped = false else if (c == '\\') escaped = true else if (c == '"') in_string = false;
        } else switch (c) {
            '"' => in_string = true,
            '[', '{' => {
                depth += 1;
                if (depth > 128) return false;
            },
            ']', '}' => depth -|= 1,
            else => {},
        }
    }
    return true;
}
fn rpc(s: *Archive, j: J, body: []const u8) w.Invalid!V {
    if (!depthAllowed(body)) return rpcError(j, .null, -32700, "Parse error");
    const p = std.json.parseFromSliceLeaky(V, j.a, body, .{ .parse_numbers = false, .duplicate_field_behavior = .use_last }) catch
        return rpcError(j, .null, -32700, "Parse error");
    if (p != .array) return dispatch(s, j, p);
    const items = p.array.items;
    if (items.len == 0 or items.len > 100) return rpcError(j, .null, -32600, "Invalid Request");
    var out = j.arr();
    for (items) |item| try j.append(&out, try dispatch(s, j, item));
    return out;
}

fn serve(s: *Archive, stream: Io.net.Stream) !void {
    var rbuf: [8192]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = stream.reader(s.io, &rbuf);
    var writer = stream.writer(s.io, &wbuf);
    var http = std.http.Server.init(&reader.interface, &writer.interface);
    var req = try http.receiveHead();
    if (!eq(req.head.target, "/")) return req.respond("", .{ .status = .not_found, .keep_alive = false });
    if (req.head.method != .POST) return req.respond("", .{ .status = .method_not_allowed, .keep_alive = false });
    const declared = req.head.content_length;
    const chunked = req.head.transfer_encoding == .chunked;
    if ((declared orelse 0) > w.mib) return req.respond("", .{ .status = .payload_too_large, .keep_alive = false });
    var arena = std.heap.ArenaAllocator.init(s.a);
    defer arena.deinit();
    const j = J{ .a = arena.allocator() };
    var transfer: [4096]u8 = undefined;
    const body = if (declared != null or chunked)
        (try req.readerExpectContinue(&transfer)).allocRemaining(j.a, .limited(w.mib + 1)) catch |err| switch (err) {
            error.StreamTooLong => return req.respond("", .{ .status = .payload_too_large, .keep_alive = false }),
            else => return err,
        }
    else
        "";
    if (body.len > w.mib) return req.respond("", .{ .status = .payload_too_large, .keep_alive = false });
    if (!chunked and (declared orelse 0) != body.len) return req.respond("", .{ .status = .bad_request, .keep_alive = false });
    const payload = try std.json.Stringify.valueAlloc(j.a, try rpc(s, j, body), .{});
    try req.respond(payload, .{ .keep_alive = false, .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }} });
}
fn connection(s: *Archive, semaphore: *Io.Semaphore, stream: Io.net.Stream) void {
    defer semaphore.post(s.io);
    defer stream.close(s.io);
    serve(s, stream) catch {};
}

fn bindAddress(io: Io, p: []const u8) !Io.net.IpAddress {
    const colon = std.mem.findScalarLast(u8, p, ':') orelse return error.InvalidArgument;
    const port = js.parseUnsigned(u16, p[colon + 1 ..]) orelse return error.InvalidArgument;
    const host = p[0..colon];
    if (host.len > 1 and host[0] == '[' and host[host.len - 1] == ']') return Io.net.IpAddress.parseIp6(host[1 .. host.len - 1], port);
    if (Io.net.IpAddress.parseIp4(host, port)) |value| return value else |_| {}
    const name = try Io.net.HostName.init(host);
    var buffer: [16]Io.net.HostName.LookupResult = undefined;
    var queue = Io.Queue(Io.net.HostName.LookupResult).init(&buffer);
    try name.lookup(io, &queue, .{ .port = port, .family = .ip4 });
    while (queue.getOneUncancelable(io)) |result| {
        if (result == .address) return result.address;
    } else |_| {}
    return error.InvalidArgument;
}
fn stop(_: std.posix.SIG) callconv(.c) void {
    // All application state is process-local. The OS closes sockets on exit,
    // aborting active requests even if an upstream peer is stalled.
    std.c._exit(0);
}
pub fn main(init: std.process.Init) !void {
    const permanent = init.arena.allocator();
    const args = try init.minimal.args.toSlice(permanent);
    var bind = init.environ_map.get("ONLYBLOCKS_BIND") orelse "127.0.0.1:8899";
    var base = init.environ_map.get("OLD_FAITHFUL_BASE_URL") orelse "https://files.old-faithful.net";
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const position = std.mem.findScalar(u8, arg, '=');
        const name = if (position) |p| arg[0..p] else arg;
        const value = if (position) |p| arg[p + 1 ..] else blk: {
            i += 1;
            if (i >= args.len) return error.InvalidArgument;
            break :blk args[i];
        };
        if (eq(name, "--bind")) bind = value else if (eq(name, "--base-url")) base = value else return error.InvalidArgument;
    }
    base = std.mem.trimEnd(u8, std.mem.trim(u8, base, " \r\n\t"), "/");
    const target = try std.Uri.parse(base);
    if ((!eq(target.scheme, "http") and !eq(target.scheme, "https")) or target.host == null) return error.InvalidArchiveUrl;
    const io = init.io;
    var archive = Archive{ .a = init.gpa, .io = io, .base = target, .client = .{ .allocator = init.gpa, .io = io } };
    defer archive.client.deinit();
    const address = try bindAddress(io, bind);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const action = std.posix.Sigaction{ .handler = .{ .handler = stop }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);
    var active: Io.Semaphore = .{ .permits = 64 };
    var group: Io.Group = .init;
    defer group.cancel(io);
    while (true) {
        try active.wait(io);
        const stream = server.accept(io) catch |err| {
            active.post(io);
            if (err == error.ConnectionAborted) continue;
            return err;
        };
        group.concurrent(io, connection, .{ &archive, &active, stream }) catch {
            stream.close(io);
            active.post(io);
        };
    }
}
