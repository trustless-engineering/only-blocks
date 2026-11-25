using static Wire;

sealed class Transaction
{
    private const string UpgradeableLoader = "BPFLoaderUpgradeab1e11111111111111111111111";
    private static readonly HashSet<string> Reserved = new("""
        AddressLookupTab1e1111111111111111111111111   BPFLoader2111111111111111111111111111111111
        BPFLoader1111111111111111111111111111111111   BPFLoaderUpgradeab1e11111111111111111111111
        ComputeBudget111111111111111111111111111111   Config1111111111111111111111111111111111111
        Ed25519SigVerify111111111111111111111111111   Feature111111111111111111111111111111111111
        LoaderV411111111111111111111111111111111111   KeccakSecp256k11111111111111111111111111111
        Secp256r1SigVerify1111111111111111111111111   StakeConfig11111111111111111111111111111111
        Stake11111111111111111111111111111111111111   11111111111111111111111111111111
        Vote111111111111111111111111111111111111111   ZkE1Gama1Proof11111111111111111111111111111
        ZkTokenProof1111111111111111111111111111111   SysvarC1ock11111111111111111111111111111111
        SysvarEpochRewards1111111111111111111111111   SysvarEpochSchedu1e111111111111111111111111
        SysvarFees111111111111111111111111111111111   Sysvar1nstructions1111111111111111111111111
        SysvarLastRestartS1ot1111111111111111111111   SysvarRecentB1ockHashes11111111111111111111
        SysvarRent111111111111111111111111111111111   SysvarRewards111111111111111111111111111111
        SysvarS1otHashes111111111111111111111111111   SysvarS1otHistory11111111111111111111111111
        SysvarStakeHistory1111111111111111111111111   NativeLoader1111111111111111111111111111111
        Sysvar1111111111111111111111111111111111111
        """.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private sealed record Lookup(ReadOnlyMemory<byte> Key, ReadOnlyMemory<byte> Writable, ReadOnlyMemory<byte> Readonly)
    {
        internal object Json() => new
        {
            accountKey = Base58(Key.Span), writableIndexes = Instruction.Indexes(Writable),
            readonlyIndexes = Instruction.Indexes(Readonly)
        };
    }

    private sealed record InstructionHeader(byte Program, byte Accounts, int DataLength);
    private sealed record TransactionConfig(ulong? PriorityFee, uint? ComputeUnitLimit,
        uint? LoadedAccountsDataSizeLimit, uint? HeapSize);

    internal ReadOnlyMemory<byte>[] Signatures { get; }
    internal int? Version { get; }
    private readonly byte required, readonlySigned, readonlyUnsigned;
    private readonly ReadOnlyMemory<byte>[] keys;
    private readonly ReadOnlyMemory<byte> recent, raw;
    private readonly Instruction[] instructions;
    private readonly Lookup[] lookups;
    private readonly TransactionConfig? config;

    internal Transaction(ReadOnlyMemory<byte> bytes)
    {
        var r = new Reader(bytes);
        byte first = r.U8();
        if (first == 0x81)
        {
            Version = 1;
            required = r.U8();
            readonlySigned = r.U8();
            readonlyUnsigned = r.U8();
            uint mask = r.U32(), priorityBits = mask & 3;
            Check((mask & ~0x1fu) == 0 && priorityBits is 0 or 3, "Invalid transaction config mask");
            recent = r.Take(32);
            int numInstructions = r.U8();
            keys = r.Items(r.U8(), 32, () => r.Take(32));
            config = new TransactionConfig(
                priorityBits == 3 ? r.U64() : null,
                (mask & 4) != 0 ? r.U32() : null,
                (mask & 8) != 0 ? r.U32() : null,
                (mask & 16) != 0 ? r.U32() : null);
            var headers = r.Items((ulong)numInstructions, 4, () => new InstructionHeader(r.U8(), r.U8(), (int)r.Le(2)));
            instructions = headers.Select(h => new Instruction(h.Program, r.Take(h.Accounts), r.Take(h.DataLength), 1)).ToArray();
            Signatures = r.Items(required, 64, () => r.Take(64));
            lookups = [];
        }
        else
        {
            Check(first < 0x80, "Invalid transaction discriminator");
            Signatures = r.Items(first, 64, () => r.Take(64));
            byte prefix = r.U8();
            Check(prefix <= 0x80, "Unsupported transaction message version");
            bool v0 = prefix == 0x80;
            Version = v0 ? 0 : null;
            required = v0 ? r.U8() : prefix;
            readonlySigned = r.U8();
            readonlyUnsigned = r.U8();
            keys = r.Items((ulong)r.Compact(), 32, () => r.Take(32));
            recent = r.Take(32);
            instructions = r.Items((ulong)r.Compact(), 3, () => Instruction.Read(r, 1));
            lookups = v0 ? r.Items((ulong)r.Compact(), 34, () =>
                new Lookup(r.Take(32), r.Take(r.Compact()), r.Take(r.Compact()))) : [];
        }
        raw = bytes[..r.Position];
    }

    private object[] Accounts(string[] combined, int writableLoaded)
    {
        bool loader = combined.Contains(UpgradeableLoader);
        var invoked = instructions.Select(i => (int)i.Program).ToHashSet();
        return combined.Select((key, i) =>
        {
            bool isStatic = i < keys.Length;
            bool writable = !isStatic ? i - keys.Length < writableLoaded :
                i >= required ? i < keys.Length - readonlyUnsigned : i < required - readonlySigned;
            writable = writable && !Reserved.Contains(key) && (loader || !invoked.Contains(i));
            return (object)new { pubkey = key, writable, signer = i < required, source = isStatic ? "transaction" : "lookupTable" };
        }).ToArray();
    }

    internal object Json(Meta? meta, Options opts)
    {
        bool accounts = opts.Details == "accounts", parsed = opts.Encoding == "jsonParsed";
        string[]? parsedKeys = null;
        object transaction;
        if (opts.Encoding is "base64" or "base58")
        {
            string bytes = opts.Encoding == "base64" ? Convert.ToBase64String(raw.Span) : Base58(raw.Span);
            transaction = new[] { bytes, opts.Encoding };
        }
        else
        {
            string[] s = Signatures.Select(b => Base58(b.Span)).ToArray();
            string[] statics = keys.Select(b => Base58(b.Span)).ToArray();
            string[] combined = Version == 0 && meta != null && (accounts || parsed)
                ? [.. statics, .. meta.Writable, .. meta.Readonly] : statics;
            if (parsed) parsedKeys = combined;
            object accountKeys = accounts || parsed ? Accounts(combined, Version == 0 ? meta?.Writable.Length ?? 0 : 0) : statics;
            if (accounts) transaction = new { signatures = s, accountKeys };
            else
            {
                var message = new Dictionary<string, object>
                {
                    ["accountKeys"] = accountKeys, ["recentBlockhash"] = Base58(recent.Span),
                    ["instructions"] = instructions.Select(i => i.Json(parsedKeys)).ToArray()
                };
                if (!parsed) message["header"] = new
                {
                    numRequiredSignatures = required, numReadonlySignedAccounts = readonlySigned,
                    numReadonlyUnsignedAccounts = readonlyUnsigned
                };
                if (Version == 0) message["addressTableLookups"] = lookups.Select(x => x.Json()).ToArray();
                if (config != null) message["transactionConfig"] = config;
                transaction = new { signatures = s, message };
            }
        }
        var result = new Dictionary<string, object?>
        {
            ["transaction"] = transaction, ["meta"] = meta?.Json(accounts, parsedKeys, opts.Rewards)
        };
        if (meta != null && opts.MaxVersion != null) result["version"] = (object?)Version ?? "legacy";
        return result;
    }
}
