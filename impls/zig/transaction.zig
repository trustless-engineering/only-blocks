const std = @import("std");
const w = @import("wire.zig");
const js = @import("json.zig");
const J = js.J;
const V = js.V;
const Reader = w.Reader;
const Invalid = w.Invalid;
const eq = w.Eql.bytes;

pub const Instruction = struct {
    program: u8,
    accounts: []const u8,
    data: []const u8,
    stack: ?u32,
    pub fn read(r: *Reader, stack: ?u32) Invalid!Instruction {
        return .{
            .program = try r.byte(),
            .accounts = try r.take(try r.compact()),
            .data = try r.take(try r.compact()),
            .stack = stack,
        };
    }
    pub fn json(ix: Instruction, j: J, keys: ?[]const []const u8) Invalid!V {
        const data = try w.base58(j.a, ix.data);
        if (keys) |all| {
            if (ix.program >= all.len) return error.Invalid;
            var accounts = j.arr();
            for (ix.accounts) |i| {
                if (i >= all.len) return error.Invalid;
                try j.append(&accounts, all[i]);
            }
            return j.obj(.{ .programId = all[ix.program], .accounts = accounts, .data = data, .stackHeight = ix.stack });
        }
        return j.obj(.{ .programIdIndex = ix.program, .accounts = try j.list(ix.accounts), .data = data, .stackHeight = ix.stack });
    }
};
pub const Group = struct {
    index: u8,
    instructions: []const Instruction,
};
pub const Meta = struct {
    err: V = .null,
    fee: u64 = 0,
    pre: V = .null,
    post: V = .null,
    inner: ?[]const Group = null,
    logs: V = .null,
    pre_tokens: V = .null,
    post_tokens: V = .null,
    rewards: V = .null,
    writable: []const []const u8 = &.{},
    readonly: []const []const u8 = &.{},
    return_data: V = .null,
    compute: V = .null,
    cost: V = .null,

    pub fn json(m: Meta, j: J, options: Options, keys: ?[]const []const u8) Invalid!V {
        const status = if (m.err == .null) try j.obj(.{ .Ok = null }) else try j.obj(.{ .Err = m.err });
        var value = try j.obj(.{
            .err = m.err,
            .status = status,
            .fee = m.fee,
            .preBalances = if (m.pre == .null) j.arr() else m.pre,
            .postBalances = if (m.post == .null) j.arr() else m.post,
            .preTokenBalances = m.pre_tokens,
            .postTokenBalances = m.post_tokens,
        });
        if (options.rewards) {
            try j.put(&value, "rewards", m.rewards);
        } else if (options.details != .accounts) {
            try j.put(&value, "rewards", null);
        }
        if (options.details == .accounts) return value;
        var inner: V = .null;
        if (m.inner) |groups| {
            inner = j.arr();
            for (groups) |g| {
                var instructions = j.arr();
                for (g.instructions) |ix| try j.append(&instructions, try ix.json(j, keys));
                try j.append(&inner, .{ .index = g.index, .instructions = instructions });
            }
        }
        try j.put(&value, "innerInstructions", inner);
        try j.put(&value, "logMessages", m.logs);
        if (options.encoding != .jsonParsed) {
            try j.put(&value, "loadedAddresses", .{ .writable = try j.list(m.writable), .readonly = try j.list(m.readonly) });
        }
        if (m.return_data != .null) try j.put(&value, "returnData", m.return_data);
        if (m.compute != .null) try j.put(&value, "computeUnitsConsumed", m.compute);
        if (m.cost != .null) try j.put(&value, "costUnits", m.cost);
        return value;
    }
};

pub const Options = struct {
    slot: u64,
    encoding: enum { json, jsonParsed, base58, base64 } = .json,
    details: enum { full, accounts, signatures, none } = .full,
    rewards: bool = true,
    version: bool = false,
};
const loader = "BPFLoaderUpgradeab1e11111111111111111111111";
const reserved = std.StaticStringMap(void).initComptime(.{
    .{ "AddressLookupTab1e1111111111111111111111111", {} },
    .{ "BPFLoader2111111111111111111111111111111111", {} },
    .{ "BPFLoader1111111111111111111111111111111111", {} },
    .{ "BPFLoaderUpgradeab1e11111111111111111111111", {} },
    .{ "ComputeBudget111111111111111111111111111111", {} },
    .{ "Config1111111111111111111111111111111111111", {} },
    .{ "Ed25519SigVerify111111111111111111111111111", {} },
    .{ "Feature111111111111111111111111111111111111", {} },
    .{ "LoaderV411111111111111111111111111111111111", {} },
    .{ "KeccakSecp256k11111111111111111111111111111", {} },
    .{ "Secp256r1SigVerify1111111111111111111111111", {} },
    .{ "StakeConfig11111111111111111111111111111111", {} },
    .{ "Stake11111111111111111111111111111111111111", {} },
    .{ "11111111111111111111111111111111", {} },
    .{ "Vote111111111111111111111111111111111111111", {} },
    .{ "ZkE1Gama1Proof11111111111111111111111111111", {} },
    .{ "ZkTokenProof1111111111111111111111111111111", {} },
    .{ "SysvarC1ock11111111111111111111111111111111", {} },
    .{ "SysvarEpochRewards1111111111111111111111111", {} },
    .{ "SysvarEpochSchedu1e111111111111111111111111", {} },
    .{ "SysvarFees111111111111111111111111111111111", {} },
    .{ "Sysvar1nstructions1111111111111111111111111", {} },
    .{ "SysvarLastRestartS1ot1111111111111111111111", {} },
    .{ "SysvarRecentB1ockHashes11111111111111111111", {} },
    .{ "SysvarRent111111111111111111111111111111111", {} },
    .{ "SysvarRewards111111111111111111111111111111", {} },
    .{ "SysvarS1otHashes111111111111111111111111111", {} },
    .{ "SysvarS1otHistory11111111111111111111111111", {} },
    .{ "SysvarStakeHistory1111111111111111111111111", {} },
    .{ "NativeLoader1111111111111111111111111111111", {} },
    .{ "Sysvar1111111111111111111111111111111111111", {} },
});
pub const Tx = struct {
    v0: bool,
    header: [3]u8,
    signatures: []const u8,
    keys: []const []const u8,
    blockhash: []const u8,
    instructions: []const Instruction,
    lookups: V,
    raw: []const u8,

    pub fn read(j: J, p: []const u8) Invalid!Tx {
        var r = Reader{ .left = p };
        const signatures = try r.take((try r.compact()) * 64);
        const prefix = try r.byte();
        if (prefix > 128) return error.Invalid;
        const v0 = prefix == 128;
        const header = [3]u8{ if (v0) try r.byte() else prefix, try r.byte(), try r.byte() };
        const key_count = try r.compact();
        if (key_count > r.left.len / 32) return error.Invalid;
        const keys = try j.a.alloc([]const u8, key_count);
        for (keys) |*key| key.* = try w.pubkey(j.a, try r.take(32));
        const hash = try w.pubkey(j.a, try r.take(32));
        const instruction_count = try r.compact();
        if (instruction_count > r.left.len / 3) return error.Invalid;
        const instructions = try j.a.alloc(Instruction, instruction_count);
        for (instructions) |*ix| ix.* = try Instruction.read(&r, 1);
        var lookups = j.arr();
        if (v0) {
            const n = try r.compact();
            if (n > r.left.len / 34) return error.Invalid;
            for (0..n) |_| {
                const key = try w.pubkey(j.a, try r.take(32));
                const writable = try j.list(try r.take(try r.compact()));
                const readonly = try j.list(try r.take(try r.compact()));
                try j.append(&lookups, .{ .accountKey = key, .writableIndexes = writable, .readonlyIndexes = readonly });
            }
        }
        return .{
            .v0 = v0,
            .header = header,
            .signatures = signatures,
            .keys = keys,
            .blockhash = hash,
            .instructions = instructions,
            .lookups = lookups,
            .raw = p[0 .. p.len - r.left.len],
        };
    }
    fn accountList(tx: Tx, j: J, keys: []const []const u8, loaded_writable: usize) Invalid!V {
        var out = j.arr();
        var invoked = @as([256]bool, @splat(false));
        for (tx.instructions) |ix| invoked[ix.program] = true;
        var upgradeable = false;
        for (keys) |key| if (eq(key, loader)) {
            upgradeable = true;
            break;
        };
        for (keys, 0..) |key, i| {
            const from_lookup = i >= tx.keys.len;
            const signer = i < tx.header[0];
            const candidate = if (from_lookup) i - tx.keys.len < loaded_writable else if (signer)
                i < tx.header[0] -| tx.header[1]
            else
                i < tx.keys.len -| tx.header[2];
            const writable = candidate and !reserved.has(key) and (upgradeable or i >= 256 or !invoked[i]);
            try j.append(&out, .{ .pubkey = key, .signer = signer, .writable = writable, .source = if (from_lookup) @as([]const u8, "lookupTable") else "transaction" });
        }
        return out;
    }
    pub fn json(tx: Tx, j: J, metadata: ?Meta, options: Options) (Invalid || error{UnsupportedVersion})!V {
        const meta = metadata orelse if (tx.v0) Meta{} else null;
        if (tx.v0 and !options.version) return error.UnsupportedVersion;
        var resolved: ?[]const []const u8 = null;
        const value = blk: {
            switch (options.encoding) {
                .base64 => break :blk try j.tuple(.{ try w.base64(j.a, tx.raw), "base64" }),
                .base58 => break :blk try j.tuple(.{ try w.base58(j.a, tx.raw), "base58" }),
                else => {},
            }
            var signatures = j.arr();
            var p = tx.signatures;
            while (p.len > 0) : (p = p[64..]) try j.append(&signatures, try w.base58(j.a, p[0..64]));
            const parsed = options.encoding == .jsonParsed;
            const account_keys = if (parsed or options.details == .accounts) keys: {
                const loaded = if (tx.v0) meta.? else Meta{};
                const keys = try std.mem.concat(j.a, []const u8, &.{ tx.keys, loaded.writable, loaded.readonly });
                if (parsed) resolved = keys;
                break :keys try tx.accountList(j, keys, loaded.writable.len);
            } else try j.list(tx.keys);
            if (options.details == .accounts) break :blk try j.obj(.{ .signatures = signatures, .accountKeys = account_keys });
            var instructions = j.arr();
            for (tx.instructions) |ix| try j.append(&instructions, try ix.json(j, resolved));
            var message = try j.obj(.{ .accountKeys = account_keys, .recentBlockhash = tx.blockhash, .instructions = instructions });
            if (!parsed) {
                try j.put(&message, "header", .{ .numRequiredSignatures = tx.header[0], .numReadonlySignedAccounts = tx.header[1], .numReadonlyUnsignedAccounts = tx.header[2] });
            }
            if (tx.v0) try j.put(&message, "addressTableLookups", tx.lookups);
            break :blk try j.obj(.{ .signatures = signatures, .message = message });
        };
        var out = try j.obj(.{ .transaction = value, .meta = if (meta) |m| try m.json(j, options, resolved) else .null });
        if (meta != null and options.version) {
            if (tx.v0) try j.put(&out, "version", 0) else try j.put(&out, "version", "legacy");
        }
        return out;
    }
};

const instruction_errors = [_][]const u8{
    "GenericError",
    "InvalidArgument",
    "InvalidInstructionData",
    "InvalidAccountData",
    "AccountDataTooSmall",
    "InsufficientFunds",
    "IncorrectProgramId",
    "MissingRequiredSignature",
    "AccountAlreadyInitialized",
    "UninitializedAccount",
    "UnbalancedInstruction",
    "ModifiedProgramId",
    "ExternalAccountLamportSpend",
    "ExternalAccountDataModified",
    "ReadonlyLamportChange",
    "ReadonlyDataModified",
    "DuplicateAccountIndex",
    "ExecutableModified",
    "RentEpochModified",
    "NotEnoughAccountKeys",
    "AccountDataSizeChanged",
    "AccountNotExecutable",
    "AccountBorrowFailed",
    "AccountBorrowOutstanding",
    "DuplicateAccountOutOfSync",
    "Custom",
    "InvalidError",
    "ExecutableDataModified",
    "ExecutableLamportChange",
    "ExecutableAccountNotRentExempt",
    "UnsupportedProgramId",
    "CallDepth",
    "MissingAccount",
    "ReentrancyNotAllowed",
    "MaxSeedLengthExceeded",
    "InvalidSeeds",
    "InvalidRealloc",
    "ComputationalBudgetExceeded",
    "PrivilegeEscalation",
    "ProgramEnvironmentSetupFailure",
    "ProgramFailedToComplete",
    "ProgramFailedToCompile",
    "Immutable",
    "IncorrectAuthority",
    "BorshIoError",
    "AccountNotRentExempt",
    "InvalidAccountOwner",
    "ArithmeticOverflow",
    "UnsupportedSysvar",
    "IllegalOwner",
    "MaxAccountsDataAllocationsExceeded",
    "MaxAccountsExceeded",
    "MaxInstructionTraceLengthExceeded",
    "BuiltinProgramsMustConsumeComputeUnits",
};
const transaction_errors = [_][]const u8{
    "AccountInUse",
    "AccountLoadedTwice",
    "AccountNotFound",
    "ProgramAccountNotFound",
    "InsufficientFundsForFee",
    "InvalidAccountForFee",
    "AlreadyProcessed",
    "BlockhashNotFound",
    "InstructionError",
    "CallChainTooDeep",
    "MissingSignatureForFee",
    "InvalidAccountIndex",
    "SignatureFailure",
    "InvalidProgramForExecution",
    "SanitizeFailure",
    "ClusterMaintenance",
    "AccountBorrowOutstanding",
    "WouldExceedMaxBlockCostLimit",
    "UnsupportedVersion",
    "InvalidWritableAccount",
    "WouldExceedMaxAccountCostLimit",
    "WouldExceedAccountDataBlockLimit",
    "TooManyAccountLocks",
    "AddressLookupTableNotFound",
    "InvalidAddressLookupTableOwner",
    "InvalidAddressLookupTableData",
    "InvalidAddressLookupTableIndex",
    "InvalidRentPayingAccount",
    "WouldExceedMaxVoteCostLimit",
    "WouldExceedAccountDataTotalLimit",
    "DuplicateInstruction",
    "InsufficientFundsForRent",
    "MaxLoadedAccountsDataSizeExceeded",
    "InvalidLoadedAccountsDataSizeLimit",
    "ResanitizationNeeded",
    "ProgramExecutionTemporarilyRestricted",
    "UnbalancedTransaction",
    "ProgramCacheHitMaxLimit",
    "CommitCancelled",
};
pub fn transactionError(j: J, r: *Reader) Invalid!V {
    const n = try r.int(u32);
    if (n >= transaction_errors.len) return error.Invalid;
    const name = transaction_errors[n];
    if (n == 8) {
        const index = try r.byte();
        const code = try r.int(u32);
        if (code >= instruction_errors.len) return error.Invalid;
        const reason = if (code == 25) try j.obj(.{ .Custom = try r.int(u32) }) else try j.val(instruction_errors[code]);
        return j.obj(.{ .InstructionError = try j.tuple(.{ index, reason }) });
    }
    if (n == 30 or n == 31 or n == 35) {
        var value = try j.obj(.{});
        const index = try r.byte();
        if (n == 30) try j.put(&value, name, index) else try j.put(&value, name, .{ .account_index = index });
        return value;
    }
    return j.val(name);
}
