internal data class Instruction(val program: Int, val accounts: ByteArray, val data: ByteArray, val height: Long?) {
    fun json(keys: List<String>?): Obj {
        val indices = accounts.indicesList()
        return if (keys == null) obj("programIdIndex" to program, "accounts" to indices,
            "data" to data.b58(), "stackHeight" to height)
        else obj("programId" to keys[program], "accounts" to indices.map(keys::get),
            "data" to data.b58(), "stackHeight" to height)
    }
}
internal fun Bytes.instruction(height: Long?) = Instruction(u8(), bytes(short()), bytes(short()), height)
internal data class Inner(val index: Int, val instructions: List<Instruction>)

internal class Transaction(bytes: ByteArray) {
    val signatures: List<ByteArray>
    private val versioned: Boolean
    private val signers: Int
    private val readonlySigned: Int
    private val readonlyUnsigned: Int
    private val keys: List<String>
    private val hash: String
    private val instructions: List<Instruction>
    private val lookups: List<Obj>?
    private val raw: ByteArray
    init {
        val r = Bytes(bytes)
        signatures = List(r.short()) { r.bytes(64) }
        val prefix = r.u8()
        versioned = prefix >= 128
        requireWire(prefix <= 128, "Unknown transaction version")
        signers = if (versioned) r.u8() else prefix
        readonlySigned = r.u8()
        readonlyUnsigned = r.u8()
        keys = List(r.short()) { r.bytes(32).b58() }
        hash = r.bytes(32).b58()
        instructions = List(r.short()) { r.instruction(1) }
        lookups = if (versioned) List(r.short()) { obj("accountKey" to r.bytes(32).b58(),
            "writableIndexes" to r.bytes(r.short()).indicesList(),
            "readonlyIndexes" to r.bytes(r.short()).indicesList()) } else null
        raw = bytes.copyOf(r.pos)
    }

    fun json(input: Meta?, options: BlockOptions): Obj {
        val meta = input ?: if (versioned) Meta() else null
        if (versioned && options.maxVersion == null) throw RpcFailure(-32015, "Transaction version 0 requires maxSupportedTransactionVersion")
        val parsed = options.encoding == "jsonParsed"
        val accountsOnly = options.details == "accounts"
        val loadedWritable = if (versioned) meta?.writable.orEmpty() else emptyList()
        val combined = keys + loadedWritable + if (versioned) meta?.readonly.orEmpty() else emptyList()
        val parsedKeys = if (parsed) combined else null
        val accounts = if (parsed || accountsOnly) {
            val programs = instructions.map { it.program }.toSet()
            val upgradeable = UPGRADEABLE in combined
            combined.mapIndexed { i, key ->
                val lookup = i >= keys.size
                val writable = when {
                    lookup -> i - keys.size < loadedWritable.size
                    i < signers -> i < signers - readonlySigned
                    else -> i < keys.size - readonlyUnsigned
                }
                obj("pubkey" to key, "signer" to (i < signers),
                    "writable" to (writable && key !in RESERVED && (upgradeable || i !in programs)),
                    "source" to if (lookup) "lookupTable" else "transaction")
            }
        } else keys
        val transaction = when (options.encoding) {
            "base58" -> listOf(raw.b58(), "base58")
            "base64" -> listOf(raw.b64(), "base64")
            else -> {
                val result = obj("signatures" to signatures.map(ByteArray::b58))
                if (accountsOnly) result["accountKeys"] = accounts
                else {
                    val message = obj("accountKeys" to accounts, "recentBlockhash" to hash,
                        "instructions" to instructions.map { it.json(parsedKeys) })
                    if (!parsed) message["header"] = obj("numRequiredSignatures" to signers,
                        "numReadonlySignedAccounts" to readonlySigned, "numReadonlyUnsignedAccounts" to readonlyUnsigned)
                    if (lookups != null) message["addressTableLookups"] = lookups
                    result["message"] = message
                }
                result
            }
        }
        val out = obj("transaction" to transaction, "meta" to meta?.json(options, parsedKeys))
        if (meta != null && options.maxVersion != null) out["version"] = if (versioned) 0 else "legacy"
        return out
    }
}
private const val UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111"
private val RESERVED = """
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
""".trim().split(Regex("\\s+")).toSet()

internal data class Meta(
    var error: Any? = null, var fee: ULong = 0uL,
    var pre: List<ULong> = emptyList(), var post: List<ULong> = emptyList(),
    var inner: List<Inner>? = null, var logs: List<String>? = null,
    var preTokens: List<Obj>? = null, var postTokens: List<Obj>? = null,
    var rewards: List<Obj>? = null, var writable: List<String> = emptyList(),
    var readonly: List<String> = emptyList(), var returned: Obj? = null,
    var compute: ULong? = null, var cost: ULong? = null,
) {
    fun json(options: BlockOptions, keys: List<String>?): Obj {
        val accountsOnly = options.details == "accounts"
        val result = obj("err" to error, "status" to if (error == null) obj("Ok" to null) else obj("Err" to error),
            "fee" to unsigned(fee), "preBalances" to pre.map(::unsigned), "postBalances" to post.map(::unsigned),
            "preTokenBalances" to preTokens, "postTokenBalances" to postTokens)
        if (options.rewards || !accountsOnly) result["rewards"] = if (options.rewards) rewards else null
        if (!accountsOnly) {
            result["innerInstructions"] = inner?.map { obj("index" to it.index,
                "instructions" to it.instructions.map { ix -> ix.json(keys) }) }
            result["logMessages"] = logs
            if (keys == null) result["loadedAddresses"] = obj("writable" to writable, "readonly" to readonly)
            returned?.let { result["returnData"] = it }
            compute?.let { result["computeUnitsConsumed"] = unsigned(it) }
            cost?.let { result["costUnits"] = unsigned(it) }
        }
        return result
    }
}

private val instructionErrors = """
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
""".trim().split(Regex("\\s+"))
private val transactionErrors = """
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
""".trim().split(Regex("\\s+"))
private val rewardTypes = listOf("Fee", "Rent", "Staking", "Voting")

private fun Bytes.txError(): Any {
    val i = u32()
    val name = transactionErrors.getOrNull(i.toInt()) ?: throw DecodeFailure("Invalid transaction error")
    return when (i) {
        8L -> {
            val index = u8()
            val kind = u32()
            val err = if (kind == 25L) obj("Custom" to u32()) else instructionErrors.getOrNull(kind.toInt())
                ?: throw DecodeFailure("Invalid instruction error")
            obj(name to listOf(index, err))
        }
        30L -> obj(name to u8())
        31L, 35L -> obj(name to obj("account_index" to u8()))
        else -> name
    }
}

private fun unsignedText(text: String): ULong? {
    val digits = text.removePrefix("+")
    return if (digits.all { it in '0'..'9' }) digits.toULongOrNull() else null
}
private fun token(index: Int, mint: String, ui: Double?, decimals: Int, amount: String,
                  owner: String, program: String, display: String = ""): Obj {
    val digits = (unsignedText(amount) ?: 0uL).toString().padStart(decimals + 1, '0')
    val computed = if (decimals == 0) digits else
        (digits.dropLast(decimals) + "." + digits.takeLast(decimals)).trimEnd('0').trimEnd('.')
    val result = obj("accountIndex" to index, "mint" to mint, "uiTokenAmount" to obj(
        "uiAmount" to ui?.takeIf(Double::isFinite), "decimals" to decimals,
        "amount" to amount, "uiAmountString" to display.ifEmpty { computed }))
    if (owner.isNotEmpty()) result["owner"] = owner
    if (program.isNotEmpty()) result["programId"] = program
    return result
}
private fun reward(pubkey: String, lamports: Long, balance: ULong, type: String?, commission: Int?) =
    obj("pubkey" to pubkey, "lamports" to lamports, "postBalance" to unsigned(balance),
        "rewardType" to type, "commission" to commission)

private fun Bytes.storedReward(extended: Boolean): Obj {
    val pubkey = text()
    val lamports = u64().toLong()
    val balance = if (extended && remaining == 0) 0uL else u64()
    val type = if (extended || remaining > 0) optional {
        rewardTypes.getOrNull(u32().toInt()) ?: throw DecodeFailure("Invalid reward type")
    } else throw DecodeFailure("Missing reward type")
    val commission = if (extended) optional(::u8) else null
    return reward(pubkey, lamports, balance, type, commission)
}
private fun Bytes.storedToken(layout: Int): Obj {
    val index = u8()
    val mint = text()
    val ui = Double.fromBits(u64().toLong())
    val decimals = u8()
    val amount = text()
    val owner = if (layout >= 2 && remaining > 0) text() else ""
    val program = if (layout >= 3 && remaining > 0) text() else ""
    return token(index, mint, ui, decimals, amount, owner, program)
}
private fun Bytes.storedMeta(legacy: Boolean, layout: Int): Meta {
    val status = u32()
    requireWire(status <= 1)
    return Meta(
        error = if (status == 1L) txError() else null,
        fee = u64(), pre = list(::u64), post = list(::u64),
        inner = optional { list {
            Inner(u8(), list {
                val ix = instruction(null)
                if (legacy) ix else ix.copy(height = optional(::u32))
            })
        } },
        logs = optional { list(::text) },
        preTokens = optional { list { storedToken(layout) } },
        postTokens = optional { list { storedToken(layout) } },
        rewards = optional { list { storedReward(true) } },
        returned = optional { obj("programId" to bytes(32).pubkey(), "data" to listOf(vector().b64(), "base64")) },
        compute = optional(::u64), cost = optional(::u64),
    )
}
private fun <T> bincode(bytes: ByteArray, readers: List<Bytes.() -> T>): T {
    for (read in readers) {
        val r = Bytes(bytes)
        try {
            val value = r.read()
            if (r.remaining == 0) return value
        } catch (_: Exception) {
            // Retry historical layouts with a fresh cursor.
        }
    }
    return Bytes(bytes).run(readers.first())
}
private fun legacyMeta(bytes: ByteArray) = bincode(bytes, listOf({ storedMeta(false, 3) },
    { storedMeta(true, 1) }, { storedMeta(true, 2) }, { storedMeta(true, 3) }))
private fun legacyRewards(bytes: ByteArray) = obj("rewards" to bincode(bytes,
    listOf({ list { storedReward(true) } }, { list { storedReward(false) } })))

private sealed interface Field {
    data object Varint : Field
    data object Fixed64 : Field
    data object Bytes : Field
    data object Text : Field
    data object Packed : Field
    data class Message(val fields: List<Field>) : Field
    data class Repeated(val field: Field) : Field
}
private fun message(vararg fields: Field) = Field.Message(fields.toList())
private fun repeated(field: Field) = Field.Repeated(field)
private val v = Field.Varint
private val b = Field.Bytes
private val t = Field.Text
private val ixSchema = message(v, b, b, v)
private val tokenSchema = message(v, t, message(Field.Fixed64, v, t, t), t, t)
private val rewardSchema = message(t, v, v, v, t, t)
private val rewardsSchema = message(repeated(rewardSchema), message(v))
private val metaSchema = message(message(b), v, Field.Packed, Field.Packed,
    repeated(message(v, repeated(ixSchema))), repeated(t), repeated(tokenSchema), repeated(tokenSchema),
    repeated(rewardSchema), v, v, repeated(b), repeated(b), message(b, b), v, v, v)

private class Proto {
    private val fields = HashMap<Int, Any>()
    fun get(n: Int) = fields[n]
    fun set(n: Int, value: Any) { fields[n] = value }
    @Suppress("UNCHECKED_CAST")
    fun <T> list(n: Int): MutableList<T> = fields.getOrPut(n) { ArrayList<T>() } as MutableList<T>
    fun num(n: Int) = get(n) as? ULong ?: 0uL
    fun u8(n: Int) = num(n).toInt() and 255
    fun text(n: Int) = get(n) as? String ?: ""
    fun bytes(n: Int) = get(n) as? ByteArray ?: byteArrayOf()
    fun sub(n: Int) = get(n) as? Proto
}
private fun Bytes.key(): Pair<Int, Int> {
    val key = varint()
    val field = key shr 3
    requireWire(field in 1uL..536870911uL, "Invalid protobuf field")
    return field.toInt() to (key.toInt() and 7)
}
private fun Bytes.skipProto(n: Int, wire: Int, depth: Int) {
    requireWire(depth <= 128)
    when (wire) {
        0 -> varint()
        1 -> skip(8)
        2 -> skip(count(varint()))
        3 -> while (true) {
            val (field, child) = key()
            if (child == 4) {
                requireWire(field == n)
                break
            }
            skipProto(field, child, depth + 1)
        }
        5 -> skip(4)
        else -> throw DecodeFailure("Invalid protobuf wire type")
    }
}
private fun protobuf(r: Bytes, schema: Field.Message, out: Proto = Proto()): Proto {
    while (r.remaining > 0) {
        val (n, wire) = r.key()
        val spec = schema.fields.getOrNull(n - 1)
        if (spec == null) {
            r.skipProto(n, wire, 0)
            continue
        }
        if (spec == Field.Packed) {
            val values = out.list<ULong>(n)
            when (wire) {
                0 -> values.add(r.varint())
                2 -> {
                    val part = r.part(r.count(r.varint()))
                    while (part.remaining > 0) values.add(part.varint())
                }
                else -> throw DecodeFailure("Invalid protobuf packed wire type")
            }
            continue
        }
        val kind = (spec as? Field.Repeated)?.field ?: spec
        val expected = when (kind) {
            Field.Varint -> 0
            Field.Fixed64 -> 1
            else -> 2
        }
        requireWire(wire == expected, "Unexpected protobuf wire type")
        val value = when (kind) {
            Field.Varint -> r.varint()
            Field.Fixed64 -> Double.fromBits(r.u64().toLong())
            Field.Bytes -> r.bytes(r.count(r.varint()))
            Field.Text -> utf8(r.bytes(r.count(r.varint())))
            is Field.Message -> protobuf(r.part(r.count(r.varint())), kind,
                if (spec is Field.Repeated) Proto() else out.sub(n) ?: Proto())
            else -> error("Invalid protobuf schema")
        }
        if (spec is Field.Repeated) out.list<Any>(n).add(value) else out.set(n, value)
    }
    return out
}
private fun Proto.reward(): Obj {
    val commission = unsignedText(text(5))?.takeIf { it <= 255uL }?.toInt() ?:
        unsignedText(text(6))?.takeIf { it <= 25_599uL }?.toInt()?.div(100)
    return reward(text(1), num(2).toLong(), num(3), rewardTypes.getOrNull(num(4).toInt() - 1), commission)
}
private fun Proto.token(): Obj {
    val amount = sub(3) ?: Proto()
    val ui = (amount.get(1) as? Double)?.takeIf { kotlin.math.abs(it) > Math.ulp(1.0) }
    return token(u8(1), text(2), ui, amount.u8(2), amount.text(3), text(4), text(5), amount.text(4))
}
private fun Proto.meta() = Meta(
    error = sub(1)?.let { Bytes(it.bytes(1)).txError() },
    fee = num(2), pre = list(3), post = list(4),
    inner = if (num(10) != 0uL) null else list<Proto>(5).map { group ->
        Inner(group.u8(1), group.list<Proto>(2).map {
            Instruction(it.u8(1), it.bytes(2), it.bytes(3), (it.get(4) as? ULong)?.toUInt()?.toLong())
        })
    },
    logs = if (num(11) != 0uL) null else list(6),
    preTokens = list<Proto>(7).map { it.token() }, postTokens = list<Proto>(8).map { it.token() },
    rewards = list<Proto>(9).map { it.reward() },
    writable = list<ByteArray>(12).map(ByteArray::pubkey), readonly = list<ByteArray>(13).map(ByteArray::pubkey),
    returned = sub(14)?.takeIf { num(15) == 0uL }?.let {
        obj("programId" to it.bytes(1).pubkey(), "data" to listOf(it.bytes(2).b64(), "base64"))
    },
    compute = get(16) as? ULong, cost = get(17) as? ULong,
)
private fun Proto.rewards() = obj("rewards" to list<Proto>(1).map { it.reward() }).also { out ->
    sub(2)?.let { out["numRewardPartitions"] = unsigned(it.num(1)) }
}

private fun <T> payload(slot: ULong, bytes: ByteArray, schema: Field.Message, legacy: (ByteArray) -> T,
                        convert: (Proto) -> T): T {
    fun decode(data: ByteArray): T {
        if (slot < 67_824_000uL) {
            try { return legacy(data) } catch (_: Exception) { }
            return convert(protobuf(Bytes(data), schema))
        }
        val proto = try { protobuf(Bytes(data), schema) } catch (_: Exception) { return legacy(data) }
        return convert(proto)
    }
    if (bytes.size >= 4 && Bytes(bytes).le(4) == 0xfd2fb528uL) {
        val plain = try { Zstd.decode(bytes) } catch (_: DecodeFailure) { bytes }
        return decode(plain)
    }
    return try { decode(bytes) } catch (first: Exception) {
        val plain = try { Zstd.decode(bytes) } catch (_: DecodeFailure) { throw first }
        decode(plain)
    }
}
internal fun metadata(slot: ULong, bytes: ByteArray): Meta? =
    if (bytes.isEmpty()) null else payload(slot, bytes, metaSchema, ::legacyMeta, Proto::meta)
internal fun rewards(slot: ULong, bytes: ByteArray): Obj =
    if (bytes.isEmpty()) obj("rewards" to emptyList<Obj>())
    else payload(slot, bytes, rewardsSchema, ::legacyRewards, Proto::rewards)
