package onlyblocks;

import java.util.*;
import java.util.function.*;
import static onlyblocks.Wire.*;

final class Solana {
    record Instruction(int program, byte[] accounts, byte[] data, Long height) {
        Object json(List<String> keys) {
            var indexes = indices(accounts);
            if (keys == null) return obj("programIdIndex", program, "accounts", indexes, "data", b58(data), "stackHeight", height);
            return obj("programId", keys.get(program), "accounts", indexes.stream().map(keys::get).toList(),
                "data", b58(data), "stackHeight", height);
        }
    }
    private static Instruction instruction(Reader r, Long height) {
        return new Instruction(r.u8(), r.bytes(r.shortLength()), r.bytes(r.shortLength()), height);
    }
    private record Inner(int index, List<Instruction> instructions) {
        Object json(List<String> keys) {
            return obj("index", index, "instructions", instructions.stream().map(ix -> ix.json(keys)).toList());
        }
    }
    record Options(String encoding, String details, boolean rewards, boolean maxVersion) {}
    static final class Transaction {
        final List<byte[]> signatures;
        final boolean versioned;
        final int signers, readonlySigned, readonlyUnsigned;
        final List<String> keys;
        final String hash;
        final List<Instruction> instructions;
        final List<?> lookups;
        final byte[] raw;
        Transaction(byte[] bytes) {
            var r = new Reader(bytes);
            signatures = items(r.shortLength(), () -> r.bytes(64));
            int prefix = r.u8();
            check(prefix <= 128);
            versioned = prefix == 128;
            signers = versioned ? r.u8() : prefix;
            readonlySigned = r.u8();
            readonlyUnsigned = r.u8();
            keys = items(r.shortLength(), () -> b58(r.bytes(32)));
            hash = b58(r.bytes(32));
            instructions = items(r.shortLength(), () -> instruction(r, 1L));
            lookups = versioned ? items(r.shortLength(), () -> obj(
                "accountKey", b58(r.bytes(32)), "writableIndexes", indices(r.bytes(r.shortLength())),
                "readonlyIndexes", indices(r.bytes(r.shortLength())))) : null;
            raw = Arrays.copyOf(bytes, r.pos);
        }
        private List<?> accounts(List<String> combined, int writableCount) {
            var programs = new HashSet<Integer>();
            instructions.forEach(ix -> programs.add(ix.program));
            boolean upgradeable = combined.contains(UPGRADEABLE);
            var out = new ArrayList<>();
            for (int i = 0; i < combined.size(); i++) {
                String key = combined.get(i);
                boolean lookup = i >= keys.size();
                boolean signer = i < signers;
                boolean writable = lookup ? i - keys.size() < writableCount :
                    signer ? i < signers - readonlySigned : i < keys.size() - readonlyUnsigned;
                out.add(obj("pubkey", key, "signer", signer,"writable",
                    writable && !RESERVED.contains(key) && (upgradeable || !programs.contains(i)),
                    "source", lookup ? "lookupTable" : "transaction"));
            }
            return out;
        }
        Object json(Meta input, Options options) {
            var meta = input == null && versioned ? new Meta() : input;
            if (versioned && !options.maxVersion) throw new Server.RpcError(-32015, "Version 0 requires maxSupportedTransactionVersion");
            boolean parsed = options.encoding.equals("jsonParsed");
            boolean accountsOnly = options.details.equals("accounts");
            List<String> combined = new ArrayList<>(keys);
            int writableCount = 0;
            if (versioned) {
                combined.addAll(meta.writable);
                combined.addAll(meta.readonly);
                writableCount = meta.writable.size();
            }
            List<String> parsedKeys = parsed ? combined : null;
            Object tx;
            if (options.encoding.equals("base58")) tx = List.of(b58(raw), "base58");
            else if (options.encoding.equals("base64")) tx = List.of(b64(raw), "base64");
            else {
                var result = obj("signatures", signatures.stream().map(Wire::b58).toList());
                var accounts = parsed || accountsOnly ? accounts(combined, writableCount) : keys;
                if (accountsOnly) result.put("accountKeys", accounts);
                else {
                    var message = obj("accountKeys", accounts, "recentBlockhash", hash,
                        "instructions", instructions.stream().map(ix -> ix.json(parsedKeys)).toList());
                    if (!parsed) message.put("header", obj("numRequiredSignatures", signers,
                        "numReadonlySignedAccounts", readonlySigned, "numReadonlyUnsignedAccounts", readonlyUnsigned));
                    if (versioned) message.put("addressTableLookups", lookups);
                    result.put("message", message);
                }
                tx = result;
            }
            var result = obj("transaction", tx, "meta", meta == null ? null : meta.json(options, parsedKeys));
            if (meta != null && options.maxVersion) result.put("version", versioned ? 0 : "legacy");
            return result;
        }
    }

    private static final String UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";
    private static final Set<String> RESERVED = Set.of("""
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
        """.strip().split("\\s+"));

    static final class Meta {
        Object err, preTokens, postTokens, rewards, logs, returned;
        List<Inner> inner;
        List<Long> pre = List.of(), post = List.of();
        List<String> writable = List.of(), readonly = List.of();
        long fee;
        Long compute, cost;
        Object json(Options options, List<String> keys) {
            boolean accounts = options.details.equals("accounts");
            var result = obj("err", err, "status", err == null ? obj("Ok", null) : obj("Err", err),
                "fee", uint(fee), "preBalances", pre.stream().map(Wire::uint).toList(),
                "postBalances", post.stream().map(Wire::uint).toList(),
                "preTokenBalances", preTokens, "postTokenBalances", postTokens);
            if (options.rewards || !accounts) result.put("rewards", options.rewards ? rewards : null);
            if (!accounts) {
                result.put("innerInstructions", inner == null ? null : inner.stream().map(i -> i.json(keys)).toList());
                result.put("logMessages", logs);
                if (keys == null) result.put("loadedAddresses", obj("writable", writable, "readonly", readonly));
                if (returned != null) result.put("returnData", returned);
                if (compute != null) result.put("computeUnitsConsumed", uint(compute));
                if (cost != null) result.put("costUnits", uint(cost));
            }
            return result;
        }
    }

    private static final String[] INSTRUCTION_ERRORS = """
GenericError InvalidArgument InvalidInstructionData InvalidAccountData AccountDataTooSmall
InsufficientFunds IncorrectProgramId MissingRequiredSignature AccountAlreadyInitialized
UninitializedAccount UnbalancedInstruction ModifiedProgramId ExternalAccountLamportSpend
ExternalAccountDataModified ReadonlyLamportChange ReadonlyDataModified DuplicateAccountIndex
ExecutableModified RentEpochModified NotEnoughAccountKeys AccountDataSizeChanged
AccountNotExecutable AccountBorrowFailed AccountBorrowOutstanding DuplicateAccountOutOfSync
Custom InvalidError ExecutableDataModified ExecutableLamportChange ExecutableAccountNotRentExempt
UnsupportedProgramId CallDepth MissingAccount ReentrancyNotAllowed MaxSeedLengthExceeded
InvalidSeeds InvalidRealloc ComputationalBudgetExceeded PrivilegeEscalation
ProgramEnvironmentSetupFailure ProgramFailedToComplete ProgramFailedToCompile Immutable
IncorrectAuthority BorshIoError AccountNotRentExempt InvalidAccountOwner ArithmeticOverflow
UnsupportedSysvar IllegalOwner MaxAccountsDataAllocationsExceeded MaxAccountsExceeded
MaxInstructionTraceLengthExceeded BuiltinProgramsMustConsumeComputeUnits
        """.strip().split("\\s+");
    private static final String[] TX_ERRORS = """
AccountInUse AccountLoadedTwice AccountNotFound ProgramAccountNotFound InsufficientFundsForFee
InvalidAccountForFee AlreadyProcessed BlockhashNotFound InstructionError CallChainTooDeep
MissingSignatureForFee InvalidAccountIndex SignatureFailure InvalidProgramForExecution
SanitizeFailure ClusterMaintenance AccountBorrowOutstanding WouldExceedMaxBlockCostLimit
UnsupportedVersion InvalidWritableAccount WouldExceedMaxAccountCostLimit
WouldExceedAccountDataBlockLimit TooManyAccountLocks AddressLookupTableNotFound
InvalidAddressLookupTableOwner InvalidAddressLookupTableData InvalidAddressLookupTableIndex
InvalidRentPayingAccount WouldExceedMaxVoteCostLimit WouldExceedAccountDataTotalLimit
DuplicateInstruction InsufficientFundsForRent MaxLoadedAccountsDataSizeExceeded
InvalidLoadedAccountsDataSizeLimit ResanitizationNeeded ProgramExecutionTemporarilyRestricted
UnbalancedTransaction ProgramCacheHitMaxLimit CommitCancelled
        """.strip().split("\\s+");
    private static final String[] REWARD_TYPES = {"Fee", "Rent", "Staking", "Voting"};

    private static Object txError(Reader r) {
        int kind = r.u32();
        check(kind >= 0 && kind < TX_ERRORS.length);
        String name = TX_ERRORS[kind];
        return switch (kind) {
            case 8 -> {
                int index = r.u8(), sub = r.u32();
                check(sub >= 0 && sub < INSTRUCTION_ERRORS.length);
                Object instruction = sub == 25 ? obj("Custom", r.le(4)) : INSTRUCTION_ERRORS[sub];
                yield obj(name, List.of(index, instruction));
            }
            case 30 -> obj(name, r.u8());
            case 31, 35 -> obj(name, obj("account_index", r.u8()));
            default -> name;
        };
    }
    private static Long unsignedText(String text) {
        int start = text.startsWith("+") ? 1 : 0;
        for (int i = start; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') return null;
        }
        try { return Long.parseUnsignedLong(text); }
        catch (NumberFormatException e) { return null; }
    }
    private static Object token(int index, String mint, Double ui, int decimals, String amount, String owner,
                                String program, String display) {
        if (display.isEmpty()) {
            Long value = unsignedText(amount);
            String digits = value == null ? "0" : Long.toUnsignedString(value);
            if (decimals > 0) {
                digits = "0".repeat(Math.max(0, decimals + 1 - digits.length())) + digits;
                int split = digits.length() - decimals;
                display = digits.substring(0, split) + "." + digits.substring(split);
                int end = display.length();
                while (display.charAt(end - 1) == '0') end--;
                if (display.charAt(end - 1) == '.') end--;
                display = display.substring(0, end);
            } else display = digits;
        }
        var out = obj("accountIndex", index, "mint", mint, "uiTokenAmount", obj(
            "uiAmount", ui != null && Double.isFinite(ui) ? ui : null, "decimals", decimals, "amount", amount,
            "uiAmountString", display));
        if (!owner.isEmpty()) out.put("owner", owner);
        if (!program.isEmpty()) out.put("programId", program);
        return out;
    }
    private static Object reward(String key, long lamports, long post, String type, Integer commission) {
        return obj("pubkey", key, "lamports", lamports, "postBalance", uint(post), "rewardType", type, "commission", commission);
    }
    private static Object returnData(byte[] program, byte[] data) {
        return obj("programId", pubkey(program), "data", List.of(b64(data), "base64"));
    }
    private static Object storedReward(Reader r, boolean extended) {
        String key = r.text();
        long lamports = r.u64();
        long balance = extended && r.left() == 0 ? 0 : r.u64();
        check(extended || r.left() > 0);
        String type = r.option(() -> { int i = r.u32(); check(i >= 0 && i < 4); return REWARD_TYPES[i]; });
        return reward(key, lamports, balance, type, extended ? r.option(r::u8) : null);
    }
    private static Object storedToken(Reader r, int layout) {
        int index = r.u8();
        String mint = r.text();
        double ui = Double.longBitsToDouble(r.u64());
        int decimals = r.u8();
        String amount = r.text();
        String owner = layout >= 2 && r.left() > 0 ? r.text() : "";
        String program = layout >= 3 && r.left() > 0 ? r.text() : "";
        return token(index, mint, ui, decimals, amount, owner, program, "");
    }
    private static Meta storedMeta(Reader r, boolean legacy, int layout) {
        int status = r.u32();
        check(status == 0 || status == 1);
        var m = new Meta();
        m.err = status == 0 ? null : txError(r);
        m.fee = r.u64();
        m.pre = r.list(r::u64);
        m.post = r.list(r::u64);
        m.inner = r.option(() -> r.list(() -> new Inner(r.u8(), r.list(() -> {
            var ix = instruction(r, null);
            return legacy ? ix : new Instruction(ix.program, ix.accounts, ix.data, r.option(() -> r.le(4)));
        }))));
        m.logs = r.option(() -> r.list(r::text));
        m.preTokens = r.option(() -> r.list(() -> storedToken(r, layout)));
        m.postTokens = r.option(() -> r.list(() -> storedToken(r, layout)));
        m.rewards = r.option(() -> r.list(() -> storedReward(r, true)));
        m.returned = r.option(() -> returnData(r.bytes(32), r.vector()));
        m.compute = r.option(r::u64);
        m.cost = r.option(r::u64);
        return m;
    }
    private static <T> T bincode(byte[] bytes, List<Function<Reader, T>> layouts) {
        for (var layout : layouts) {
            var r = new Reader(bytes);
            try {
                T value = layout.apply(r);
                if (r.left() == 0) return value;
            } catch (BadData e) { /* Try an older record layout. */ }
        }
        return layouts.get(0).apply(new Reader(bytes));
    }
    private static Meta legacyMeta(byte[] bytes) {
        return bincode(bytes, List.of(r -> storedMeta(r, false, 3), r -> storedMeta(r, true, 1),
            r -> storedMeta(r, true, 2), r -> storedMeta(r, true, 3)));
    }
    private static Map<String, Object> legacyRewards(byte[] bytes) {
        return obj("rewards", bincode(bytes, List.of(r -> r.list(() -> storedReward(r, true)),
            r -> r.list(() -> storedReward(r, false)))));
    }

    private sealed interface Field permits Scalar, Schema, Repeated {}
    private enum Scalar implements Field { VARINT, DOUBLE, BYTES, TEXT, PACKED }
    private record Schema(Field... fields) implements Field {}
    private record Repeated(Field field) implements Field {}
    private static final Field V = Scalar.VARINT, B = Scalar.BYTES, T = Scalar.TEXT, P = Scalar.PACKED;
    private static final Schema IX = new Schema(V, B, B, V);
    private static final Schema TOKEN = new Schema(V, T, new Schema(Scalar.DOUBLE, V, T, T), T, T);
    private static final Schema REWARD = new Schema(T, V, V, V, T, T);
    private static final Schema REWARDS = new Schema(new Repeated(REWARD), new Schema(V));
    private static final Schema META = new Schema(new Schema(B), V, P, P, new Repeated(new Schema(V, new Repeated(IX))),
        new Repeated(T), new Repeated(TOKEN), new Repeated(TOKEN), new Repeated(REWARD), V, V,
        new Repeated(B), new Repeated(B), new Schema(B, B), V, V, V);

    private static final class Proto {
        final Map<Integer, Object> values = new HashMap<>();
        @SuppressWarnings("unchecked")
        <T> List<T> list(int n) { return (List<T>) values.computeIfAbsent(n, key -> new ArrayList<>()); }
        Long scalar(int n) { return (Long) values.get(n); }
        long num(int n) { return (Long) values.getOrDefault(n, 0L); }
        int u8(int n) { return (int) num(n) & 255; }
        String text(int n) { return (String) values.getOrDefault(n, ""); }
        byte[] bytes(int n) { return (byte[]) values.getOrDefault(n, EMPTY); }
        Proto sub(int n) { return (Proto) values.get(n); }
    }
    private static long key(Reader r) {
        long key = r.varint(), n = key >>> 3;
        check(n > 0 && n <= 0x1fffffff);
        return key;
    }
    private static void skip(Reader r, int n, int wire, int depth) {
        check(depth <= 128);
        switch (wire) {
            case 0 -> r.varint();
            case 1 -> r.skip(8);
            case 2 -> r.skip(r.count(r.varint()));
            case 3 -> {
                while (true) {
                    long k = key(r);
                    int field = (int) (k >>> 3), w = (int) k & 7;
                    if (w == 4) { check(n == field); break; }
                    skip(r, field, w, depth + 1);
                }
            }
            case 5 -> r.skip(4);
            default -> throw new BadData("Invalid protobuf wire type");
        }
    }
    private static Proto protobuf(Reader r, Schema schema, Proto out) {
        while (r.left() > 0) {
            long k = key(r);
            int n = (int) (k >>> 3), wire = (int) k & 7;
            if (n > schema.fields.length) { skip(r, n, wire, 0); continue; }
            Field spec = schema.fields[n - 1];
            if (spec == P) {
                var values = out.<Long>list(n);
                if (wire == 0) values.add(r.varint());
                else {
                    check(wire == 2);
                    var part = r.part(r.count(r.varint()));
                    while (part.left() > 0) values.add(part.varint());
                }
                continue;
            }
            boolean repeated = spec instanceof Repeated;
            Field field = repeated ? ((Repeated) spec).field : spec;
            check(wire == (field == V ? 0 : field == Scalar.DOUBLE ? 1 : 2));
            Object value;
            if (field instanceof Schema child) {
                var target = repeated ? null : out.sub(n);
                value = protobuf(r.part(r.count(r.varint())), child, target == null ? new Proto() : target);
            } else value = switch ((Scalar) field) {
                case VARINT -> r.varint();
                case DOUBLE -> Double.longBitsToDouble(r.u64());
                case BYTES -> r.bytes(r.count(r.varint()));
                case TEXT -> utf8(r.bytes(r.count(r.varint())));
                default -> throw new AssertionError("Unexpected schema");
            };
            if (repeated) out.list(n).add(value);
            else out.values.put(n, value);
        }
        return out;
    }
    private static Object protoReward(Proto p) {
        Long value = unsignedText(p.text(5));
        Integer commission = value != null && Long.compareUnsigned(value, 255) <= 0 ? value.intValue() : null;
        if (commission == null) {
            Long bps = unsignedText(p.text(6));
            if (bps != null && Long.compareUnsigned(bps, 25599) <= 0) commission = bps.intValue() / 100;
        }
        int type = (int) p.num(4);
        return reward(p.text(1), p.num(2), p.num(3), type > 0 && type < 5 ? REWARD_TYPES[type - 1] : null, commission);
    }
    private static Object protoToken(Proto p) {
        var a = p.sub(3);
        if (a == null) a = new Proto();
        Double ui = (Double) a.values.get(1);
        if (ui != null && !(Math.abs(ui) > Math.ulp(1.0))) ui = null;
        return token(p.u8(1), p.text(2), ui, a.u8(2), a.text(3), p.text(4), p.text(5), a.text(4));
    }
    private static Meta protoMeta(Proto p) {
        var m = new Meta();
        if (p.sub(1) != null) m.err = txError(new Reader(p.sub(1).bytes(1)));
        m.fee = p.num(2);
        m.pre = p.list(3);
        m.post = p.list(4);
        if (p.num(10) == 0) m.inner = p.<Proto>list(5).stream().map(group ->
            new Inner(group.u8(1), group.<Proto>list(2).stream().map(ix -> new Instruction(ix.u8(1), ix.bytes(2),
                ix.bytes(3), ix.scalar(4) == null ? null : ix.num(4) & 0xffffffffL)).toList())).toList();
        if (p.num(11) == 0) m.logs = p.list(6);
        m.preTokens = p.<Proto>list(7).stream().map(Solana::protoToken).toList();
        m.postTokens = p.<Proto>list(8).stream().map(Solana::protoToken).toList();
        m.rewards = p.<Proto>list(9).stream().map(Solana::protoReward).toList();
        m.writable = p.<byte[]>list(12).stream().map(Wire::pubkey).toList();
        m.readonly = p.<byte[]>list(13).stream().map(Wire::pubkey).toList();
        if (p.num(15) == 0 && p.sub(14) != null) m.returned = returnData(p.sub(14).bytes(1), p.sub(14).bytes(2));
        m.compute = p.scalar(16);
        m.cost = p.scalar(17);
        return m;
    }
    private static Map<String, Object> protoRewards(Proto p) {
        var out = obj("rewards", p.<Proto>list(1).stream().map(Solana::protoReward).toList());
        if (p.sub(2) != null) out.put("numRewardPartitions", uint(p.sub(2).num(1)));
        return out;
    }
    private static <T> T payload(long slot, byte[] bytes, Schema schema, Function<byte[], T> legacy, Function<Proto, T> convert) {
        Function<byte[], T> decode = data -> {
            if (Long.compareUnsigned(slot, 67_824_000) < 0) {
                try { return legacy.apply(data); } catch (BadData e) { /* Try protobuf. */ }
                return convert.apply(protobuf(new Reader(data), schema, new Proto()));
            }
            Proto parsed;
            try { parsed = protobuf(new Reader(data), schema, new Proto()); }
            catch (BadData e) { return legacy.apply(data); }
            return convert.apply(parsed);
        };
        if (bytes.length >= 4 && new Reader(bytes).u32() == 0xfd2fb528) {
            byte[] data;
            try { data = Zstd.decode(bytes); } catch (BadData e) { data = bytes; }
            return decode.apply(data);
        }
        try { return decode.apply(bytes); }
        catch (BadData first) {
            byte[] data;
            try { data = Zstd.decode(bytes); } catch (BadData e) { throw first; }
            return decode.apply(data);
        }
    }
    static Meta metadata(long slot, byte[] bytes) {
        return bytes.length == 0 ? null : payload(slot, bytes, META, Solana::legacyMeta, Solana::protoMeta);
    }
    static Map<String, Object> rewards(long slot, byte[] bytes) {
        return bytes.length == 0 ? obj("rewards", List.of()) : payload(slot, bytes, REWARDS, Solana::legacyRewards, Solana::protoRewards);
    }
}
