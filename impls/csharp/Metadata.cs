using System.Globalization;
using static Wire;

sealed record Instruction(byte Program, ReadOnlyMemory<byte> Accounts, ReadOnlyMemory<byte> Data, uint? Height)
{
    internal static Instruction Read(Reader r, uint? height = null) =>
        new(r.U8(), r.Take(r.Compact()), r.Take(r.Compact()), height);

    internal object Json(string[]? keys)
    {
        if (keys == null)
            return new { programIdIndex = Program, accounts = Indexes(Accounts), data = Base58(Data.Span), stackHeight = Height };
        string Key(int index) => index < keys.Length ? keys[index] : throw new InvalidDataException("Invalid account index");
        return new { programId = Key(Program), accounts = Indexes(Accounts).Select(Key).ToArray(), data = Base58(Data.Span), stackHeight = Height };
    }

    internal static int[] Indexes(ReadOnlyMemory<byte> bytes)
    {
        var result = new int[bytes.Length];
        for (int i = 0; i < result.Length; i++) result[i] = bytes.Span[i];
        return result;
    }
}

sealed record Inner(byte Index, Instruction[] Instructions);
sealed record Reward(string Pubkey, long Lamports, ulong PostBalance, string? RewardType, int? Commission);
sealed record RewardSet(Reward[] Rewards, ulong? Partitions = null);
sealed record ReturnValue(string ProgramId, string[] Data);

sealed class Meta
{
    internal object? Error;
    internal ulong Fee;
    internal ulong[] Pre = [], Post = [];
    internal Inner[]? Inner;
    internal string[]? Logs;
    internal object[]? PreTokens, PostTokens;
    internal Reward[]? Rewards;
    internal string[] Writable = [], Readonly = [];
    internal ReturnValue? Return;
    internal ulong? Compute, Cost;

    internal Dictionary<string, object?> Json(bool accounts, string[]? parsedKeys, bool rewards)
    {
        var value = new Dictionary<string, object?>
        {
            ["err"] = Error,
            ["status"] = new Dictionary<string, object?> { [Error == null ? "Ok" : "Err"] = Error },
            ["fee"] = Fee, ["preBalances"] = Pre, ["postBalances"] = Post,
            ["preTokenBalances"] = PreTokens, ["postTokenBalances"] = PostTokens
        };
        if (rewards || !accounts) value["rewards"] = rewards ? Rewards : null;
        if (accounts) return value;
        value["innerInstructions"] = Inner?.Select(x => new
        {
            index = x.Index, instructions = x.Instructions.Select(i => i.Json(parsedKeys)).ToArray()
        }).ToArray();
        value["logMessages"] = Logs;
        if (parsedKeys == null) value["loadedAddresses"] = new { writable = Writable, @readonly = Readonly };
        if (Return != null) value["returnData"] = Return;
        if (Compute != null) value["computeUnitsConsumed"] = Compute;
        if (Cost != null) value["costUnits"] = Cost;
        return value;
    }
}

sealed class Proto
{
    private static readonly Dictionary<char, string[]> Schemas = new()
    {
        ['M'] = "E v p p I* s* T* T* R* v v b* b* D v v v".Split(' '),
        ['E'] = ["b"], ['I'] = ["v", "J*"], ['J'] = ["v", "b", "b", "v"],
        ['T'] = ["v", "s", "A", "s", "s"], ['A'] = ["d", "v", "s", "s"],
        ['D'] = ["b", "b"], ['S'] = ["R*", "N"], ['N'] = ["v"],
        ['R'] = ["s", "v", "v", "v", "s", "s"]
    };

    private readonly Dictionary<int, object> values = new();
    internal T Get<T>(int field, T fallback) => values.TryGetValue(field, out var value) ? (T)value : fallback;
    internal ulong U(int field) => Get(field, 0UL);
    internal ulong? Optional(int field) => values.ContainsKey(field) ? U(field) : null;
    internal string S(int field) => Get(field, "");
    internal ReadOnlyMemory<byte> B(int field) => Get<ReadOnlyMemory<byte>>(field, default);
    internal Proto? Child(int field) => Get<Proto?>(field, null);
    internal IEnumerable<T> All<T>(int field) => Get<List<object>?>(field, null)?.Cast<T>() ?? [];

    private void Add(int field, object value)
    {
        if (!values.TryGetValue(field, out object? list)) values[field] = list = new List<object>();
        ((List<object>)list).Add(value);
    }

    private static (int Field, int Wire) Key(Reader r)
    {
        ulong key = r.Varint();
        Check(key is >= 8 and <= uint.MaxValue, "Invalid protobuf key");
        return ((int)(key >> 3), (int)(key & 7));
    }

    private static void Skip(Reader r, int field, int wire, int depth)
    {
        Check(depth < 100, "Protobuf group nesting too deep");
        switch (wire)
        {
            case 0: r.Varint(); return;
            case 1: r.Take(8); return;
            case 2: r.Take(r.Count(r.Varint())); return;
            case 5: r.Take(4); return;
            case 3:
                while (true)
                {
                    var (number, type) = Key(r);
                    if (type == 4)
                    {
                        Check(number == field, "Mismatched protobuf group");
                        return;
                    }
                    Skip(r, number, type, depth + 1);
                }
            default: throw new InvalidDataException("Invalid protobuf wire type");
        }
    }

    internal static Proto Read(ReadOnlyMemory<byte> data, char schema, Proto? into = null)
    {
        var message = into ?? new Proto();
        var fields = Schemas[schema];
        var r = new Reader(data);
        while (r.Left > 0)
        {
            var (field, wire) = Key(r);
            if (field > fields.Length)
            {
                Skip(r, field, wire, 0);
                continue;
            }
            var spec = fields[field - 1];
            char type = spec[0];
            if (type == 'p')
            {
                Check(wire is 0 or 2, "Invalid packed protobuf field");
                if (wire == 0) message.Add(field, r.Varint());
                else
                {
                    var packed = new Reader(r.Take(r.Count(r.Varint())));
                    while (packed.Left > 0) message.Add(field, packed.Varint());
                }
                continue;
            }

            Check(wire == (type == 'v' ? 0 : type == 'd' ? 1 : 2), "Wrong protobuf wire type");
            bool repeated = spec.Length > 1;
            object value;
            if (type == 'v') value = r.Varint();
            else if (type == 'd') value = r.F64();
            else
            {
                var bytes = r.Take(r.Count(r.Varint()));
                value = type switch
                {
                    's' => Text(bytes.Span), 'b' => bytes,
                    _ => Read(bytes, type, repeated ? null : message.Child(field))
                };
            }
            if (repeated) message.Add(field, value);
            else message.values[field] = value;
        }
        return message;
    }
}

static class Metadata
{
    private static readonly string[] RewardTypes = ["Fee", "Rent", "Staking", "Voting"];
    private static readonly string[] TxErrors = """
        AccountInUse AccountLoadedTwice AccountNotFound ProgramAccountNotFound InsufficientFundsForFee
        InvalidAccountForFee AlreadyProcessed BlockhashNotFound InstructionError CallChainTooDeep
        MissingSignatureForFee InvalidAccountIndex SignatureFailure InvalidProgramForExecution SanitizeFailure
        ClusterMaintenance AccountBorrowOutstanding WouldExceedMaxBlockCostLimit UnsupportedVersion InvalidWritableAccount
        WouldExceedMaxAccountCostLimit WouldExceedAccountDataBlockLimit TooManyAccountLocks AddressLookupTableNotFound
        InvalidAddressLookupTableOwner InvalidAddressLookupTableData InvalidAddressLookupTableIndex InvalidRentPayingAccount
        WouldExceedMaxVoteCostLimit WouldExceedAccountDataTotalLimit DuplicateInstruction InsufficientFundsForRent
        MaxLoadedAccountsDataSizeExceeded InvalidLoadedAccountsDataSizeLimit ResanitizationNeeded
        ProgramExecutionTemporarilyRestricted UnbalancedTransaction ProgramCacheHitMaxLimit CommitCancelled
        """.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

    private static readonly string[] InstructionErrors = """
        GenericError InvalidArgument InvalidInstructionData InvalidAccountData AccountDataTooSmall InsufficientFunds
        IncorrectProgramId MissingRequiredSignature AccountAlreadyInitialized UninitializedAccount UnbalancedInstruction
        ModifiedProgramId ExternalAccountLamportSpend ExternalAccountDataModified ReadonlyLamportChange ReadonlyDataModified
        DuplicateAccountIndex ExecutableModified RentEpochModified NotEnoughAccountKeys AccountDataSizeChanged
        AccountNotExecutable AccountBorrowFailed AccountBorrowOutstanding DuplicateAccountOutOfSync Custom InvalidError
        ExecutableDataModified ExecutableLamportChange ExecutableAccountNotRentExempt UnsupportedProgramId CallDepth
        MissingAccount ReentrancyNotAllowed MaxSeedLengthExceeded InvalidSeeds InvalidRealloc ComputationalBudgetExceeded
        PrivilegeEscalation ProgramEnvironmentSetupFailure ProgramFailedToComplete ProgramFailedToCompile Immutable
        IncorrectAuthority BorshIoError AccountNotRentExempt InvalidAccountOwner ArithmeticOverflow UnsupportedSysvar
        IllegalOwner MaxAccountsDataAllocationsExceeded MaxAccountsExceeded MaxInstructionTraceLengthExceeded
        BuiltinProgramsMustConsumeComputeUnits
        """.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

    private static object Error(Reader r)
    {
        uint variant = r.U32();
        Check(variant < TxErrors.Length, "Unknown transaction error");
        if (variant == 8)
        {
            byte index = r.U8();
            uint instruction = r.U32();
            Check(instruction < InstructionErrors.Length, "Unknown instruction error");
            object detail = instruction == 25 ? Variant("Custom", r.U32()) : InstructionErrors[instruction];
            return Variant("InstructionError", new object[] { index, detail });
        }
        return variant switch
        {
            30 => Variant("DuplicateInstruction", r.U8()),
            31 => Variant("InsufficientFundsForRent", new { account_index = r.U8() }),
            35 => Variant("ProgramExecutionTemporarilyRestricted", new { account_index = r.U8() }),
            _ => TxErrors[variant]
        };
    }

    private static Dictionary<string, object> Variant(string name, object payload) => new() { [name] = payload };

    private static string Pubkey(ReadOnlyMemory<byte> bytes)
    {
        Check(bytes.Length == 32, "Invalid pubkey length");
        return Base58(bytes.Span);
    }

    private static string TokenText(string amount, byte decimals)
    {
        string text = ulong.TryParse(amount, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out ulong n)
            && !amount.StartsWith('-') ? n.ToString(CultureInfo.InvariantCulture) : "0";
        if (decimals == 0) return text;
        text = text.PadLeft(decimals + 1, '0');
        return text.Insert(text.Length - decimals, ".").TrimEnd('0').TrimEnd('.');
    }

    private static object Token(byte index, string mint, string owner, string program, double? ui, byte decimals,
        string amount, string uiString = "")
    {
        var result = new Dictionary<string, object?>
        {
            ["accountIndex"] = index, ["mint"] = mint,
            ["uiTokenAmount"] = new
            {
                uiAmount = ui is double d && double.IsFinite(d) ? ui : null,
                decimals, amount, uiAmountString = uiString.Length > 0 ? uiString : TokenText(amount, decimals)
            }
        };
        if (owner.Length > 0) result["owner"] = owner;
        if (program.Length > 0) result["programId"] = program;
        return result;
    }

    private static Reward ProtoReward(Proto p)
    {
        int? commission = null;
        if (ushort.TryParse(p.S(5), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out ushort percent)
            && percent <= 255 && !p.S(5).StartsWith('-')) commission = percent;
        else if (ushort.TryParse(p.S(6), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out ushort bps)
            && bps / 100 <= 255 && !p.S(6).StartsWith('-')) commission = bps / 100;
        int type = (int)p.U(4);
        return new(p.S(1), (long)p.U(2), p.U(3), type is >= 1 and <= 4 ? RewardTypes[type - 1] : null, commission);
    }

    private static object ProtoToken(Proto p)
    {
        var a = p.Child(3) ?? new Proto();
        double ui = a.Get(1, 0.0);
        return Token((byte)p.U(1), p.S(2), p.S(4), p.S(5), Math.Abs(ui) > 2.220446049250313e-16 ? ui : null,
            (byte)a.U(2), a.S(3), a.S(4));
    }

    private static ReturnValue Return(ReadOnlyMemory<byte> program, ReadOnlyMemory<byte> data) =>
        new(Pubkey(program), [Convert.ToBase64String(data.Span), "base64"]);

    private static Meta ConvertMeta(Proto p) => new()
    {
        Error = p.Child(1) is Proto err ? Error(new Reader(err.B(1))) : null,
        Fee = p.U(2), Pre = p.All<ulong>(3).ToArray(), Post = p.All<ulong>(4).ToArray(),
        Inner = p.U(10) != 0 ? null : p.All<Proto>(5).Select(x => new Inner((byte)x.U(1),
            x.All<Proto>(2).Select(i => new Instruction((byte)i.U(1), i.B(2), i.B(3),
                i.Optional(4) is ulong h ? (uint)h : null)).ToArray())).ToArray(),
        Logs = p.U(11) != 0 ? null : p.All<string>(6).ToArray(),
        PreTokens = p.All<Proto>(7).Select(ProtoToken).ToArray(),
        PostTokens = p.All<Proto>(8).Select(ProtoToken).ToArray(),
        Rewards = p.All<Proto>(9).Select(ProtoReward).ToArray(),
        Writable = p.All<ReadOnlyMemory<byte>>(12).Select(Pubkey).ToArray(),
        Readonly = p.All<ReadOnlyMemory<byte>>(13).Select(Pubkey).ToArray(),
        Return = p.U(15) == 0 && p.Child(14) is Proto ret ? Return(ret.B(1), ret.B(2)) : null,
        Compute = p.Optional(16), Cost = p.Optional(17)
    };

    private static string String(Reader r) => Text(r.Take(r.Count(r.U64())).Span);
    private static T[] Vec<T>(Reader r, int minimum, Func<T> next) => r.Items(r.U64(), minimum, next);
    private static T Option<T>(Reader r, Func<T> next, T fallback, bool eof = false) =>
        eof && r.Left == 0 ? fallback : r.U8() switch
        {
            0 => fallback, 1 => next(), _ => throw new InvalidDataException("Invalid bincode option")
        };

    private static Reward StoredReward(Reader r, bool legacy = false)
    {
        string key = String(r);
        long lamports = (long)r.U64();
        ulong balance = !legacy && r.Left == 0 ? 0 : r.U64();
        string? type = Option<string?>(r, () =>
        {
            uint code = r.U32();
            Check(code < RewardTypes.Length, "Unknown reward type");
            return RewardTypes[code];
        }, null, !legacy);
        int? commission = legacy ? null : Option<int?>(r, () => r.U8(), null, true);
        return new(key, lamports, balance, type, commission);
    }

    private static object StoredToken(Reader r, int layout)
    {
        byte index = r.U8();
        string mint = String(r);
        double ui = r.F64();
        byte decimals = r.U8();
        string amount = String(r);
        string owner = layout == 1 || layout != 2 && r.Left == 0 ? "" : String(r);
        string program = layout is 1 or 2 || r.Left == 0 ? "" : String(r);
        return Token(index, mint, owner, program, ui, decimals, amount);
    }

    private static Meta StoredMeta(ReadOnlyMemory<byte> data, int layout, bool strict)
    {
        var r = new Reader(data);
        object? error = r.U32() switch
        {
            0 => null, 1 => Error(r), _ => throw new InvalidDataException("Invalid bincode status")
        };
        var m = new Meta
        {
            Error = error, Fee = r.U64(), Pre = Vec(r, 8, r.U64), Post = Vec(r, 8, r.U64)
        };
        m.Inner = Option(r, () => Vec(r, 9, () => new Inner(r.U8(), Vec(r, 3, () =>
        {
            var instruction = Instruction.Read(r);
            return layout == 0 ? instruction with { Height = Option<uint?>(r, () => r.U32(), null) } : instruction;
        }))), null, true);
        m.Logs = Option(r, () => Vec(r, 8, () => String(r)), null, true);
        m.PreTokens = Option(r, () => Vec(r, 26, () => StoredToken(r, layout)), null, true);
        m.PostTokens = Option(r, () => Vec(r, 26, () => StoredToken(r, layout)), null, true);
        m.Rewards = Option(r, () => Vec(r, 16, () => StoredReward(r)), null, true);
        m.Return = Option(r, () => Return(r.Take(32), r.Take(r.Count(r.U64()))), null, true);
        m.Compute = Option<ulong?>(r, () => r.U64(), null, true);
        m.Cost = Option<ulong?>(r, () => r.U64(), null, true);
        Check(!strict || r.Left == 0, "Trailing bincode metadata");
        return m;
    }

    private static Meta BinMeta(ReadOnlyMemory<byte> data)
    {
        for (int layout = 0; layout < 4; layout++)
        {
            try { return StoredMeta(data, layout, true); }
            catch (InvalidDataException) { }
        }
        return StoredMeta(data, 0, false);
    }

    private static RewardSet BinRewards(ReadOnlyMemory<byte> data)
    {
        for (int layout = 0; ; layout++)
        {
            var r = new Reader(data);
            try
            {
                var rewards = Vec(r, 16, () => StoredReward(r, layout == 1));
                Check(layout == 2 || r.Left == 0, "Trailing bincode rewards");
                return new(rewards);
            }
            catch (InvalidDataException) when (layout < 2) { }
        }
    }

    private static RewardSet ProtoRewards(ReadOnlyMemory<byte> data)
    {
        var p = Proto.Read(data, 'S');
        return new(p.All<Proto>(1).Select(ProtoReward).ToArray(), p.Child(2)?.U(1));
    }

    private static T Unwrap<T>(ReadOnlyMemory<byte> data, Func<ReadOnlyMemory<byte>, T> decode)
    {
        if (data.Span.StartsWith(new byte[] { 0x28, 0xb5, 0x2f, 0xfd }))
        {
            ReadOnlyMemory<byte> plain;
            try { plain = Zstd.Decode(data); }
            catch (InvalidDataException) { plain = data; }
            return decode(plain);
        }
        try { return decode(data); }
        catch (InvalidDataException first)
        {
            ReadOnlyMemory<byte> plain;
            try { plain = Zstd.Decode(data); }
            catch (InvalidDataException) { throw new InvalidDataException(first.Message, first); }
            return decode(plain);
        }
    }

    internal static Meta? ReadMeta(ulong slot, ReadOnlyMemory<byte> data) => data.IsEmpty ? null : Unwrap(data, b =>
    {
        if (slot < 67_824_000)
        {
            try { return BinMeta(b); }
            catch (InvalidDataException) { return ConvertMeta(Proto.Read(b, 'M')); }
        }
        Proto p;
        try { p = Proto.Read(b, 'M'); }
        catch (InvalidDataException) { return BinMeta(b); }
        return ConvertMeta(p);
    });

    internal static RewardSet ReadRewards(ulong slot, ReadOnlyMemory<byte> data) => data.IsEmpty ? new([]) : Unwrap(data, b =>
    {
        if (slot < 67_824_000)
        {
            try { return BinRewards(b); }
            catch (InvalidDataException) { return ProtoRewards(b); }
        }
        try { return ProtoRewards(b); }
        catch (InvalidDataException) { return BinRewards(b); }
    });
}
