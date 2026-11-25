import Foundation

func nullable(_ value: Any?) -> Any { value ?? null }

struct Options {
    let encoding: String
    let details: String
    let rewards: Bool
    let maxVersion: UInt64?
}
struct Instruction {
    let program: Int
    let accounts: [UInt8]
    let data: [UInt8]
    let height: Int?
    func json(_ keys: [String]?) throws -> Object {
        var out: Object = ["data": data.b58, "stackHeight": nullable(height)]
        if let keys {
            try check(program < keys.count && accounts.allSatisfy { Int($0) < keys.count })
            out["programId"] = keys[program]
            out["accounts"] = accounts.map { keys[Int($0)] }
        } else {
            out["programIdIndex"] = program
            out["accounts"] = accounts
        }
        return out
    }
}
func instruction(_ r: Bytes, _ height: Int?) throws -> Instruction {
    try Instruction(program: r.u8(), accounts: r.bytes(r.short()), data: r.bytes(r.short()), height: height)
}
struct Inner {
    let index: Int
    let instructions: [Instruction]
    func json(_ keys: [String]?) throws -> Object {
        ["index": index, "instructions": try instructions.map { try $0.json(keys) }]
    }
}

struct Transaction {
    private struct InstructionHeader {
        let program: Int
        let accounts: Int
        let dataLength: Int
    }

    let signatures: [[UInt8]]
    let version: UInt64?
    let signers: Int
    let readonlySigned: Int
    let readonlyUnsigned: Int
    let keys: [String]
    let hash: String
    let instructions: [Instruction]
    let lookups: [Object]?
    let config: Object?
    let raw: [UInt8]
    init(_ bytes: [UInt8]) throws {
        let r = Bytes(bytes)
        let first = try r.u8()
        if first == 0x81 {
            version = 1
            signers = try r.u8()
            readonlySigned = try r.u8()
            readonlyUnsigned = try r.u8()
            let mask = try r.u32()
            let priorityBits = mask & 3
            try check(mask & ~0x1f == 0 && (priorityBits == 0 || priorityBits == 3))
            hash = try r.bytes(32).b58
            let numInstructions = try r.u8()
            keys = try items(r.u8()) { try r.bytes(32).b58 }
            config = [
                "priorityFee": nullable(priorityBits == 3 ? try r.u64() : nil),
                "computeUnitLimit": nullable(mask & 4 != 0 ? try r.u32() : nil),
                "loadedAccountsDataSizeLimit": nullable(mask & 8 != 0 ? try r.u32() : nil),
                "heapSize": nullable(mask & 16 != 0 ? try r.u32() : nil),
            ]
            let headers = try items(numInstructions) {
                try InstructionHeader(program: r.u8(), accounts: r.u8(), dataLength: Int(r.le(2)))
            }
            instructions = try headers.map {
                try Instruction(program: $0.program, accounts: r.bytes($0.accounts), data: r.bytes($0.dataLength), height: 1)
            }
            signatures = try items(signers) { try r.bytes(64) }
            lookups = nil
        } else {
            try check(first < 0x80)
            signatures = try items(first) { try r.bytes(64) }
            let prefix = try r.u8()
            try check(prefix <= 0x80)
            let v0 = prefix == 0x80
            version = v0 ? 0 : nil
            signers = v0 ? try r.u8() : prefix
            readonlySigned = try r.u8()
            readonlyUnsigned = try r.u8()
            keys = try items(r.short()) { try r.bytes(32).b58 }
            hash = try r.bytes(32).b58
            instructions = try items(r.short()) { try instruction(r, 1) }
            lookups = v0 ? try items(r.short()) {
                ["accountKey": try r.bytes(32).b58,
                 "writableIndexes": try r.bytes(r.short()),
                 "readonlyIndexes": try r.bytes(r.short())]
            } : nil
            config = nil
        }
        raw = Array(bytes[..<r.pos])
    }

    func json(_ input: Meta?, _ options: Options) throws -> Object {
        if let version, options.maxVersion.map({ $0 >= version }) != true {
            throw RpcFailure(-32015, "Transaction version (\(version)) requires maxSupportedTransactionVersion >= \(version)")
        }
        let meta = input ?? (version != nil ? Meta() : nil)
        let parsed = options.encoding == "jsonParsed"
        let accountsOnly = options.details == "accounts"
        let writable = version == 0 ? meta?.writable ?? [] : []
        let combined = keys + writable + (version == 0 ? meta?.readonly ?? [] : [])
        let parsedKeys = parsed ? combined : nil
        let tx: Any
        if options.encoding == "base64" { tx = [raw.b64, "base64"] }
        else if options.encoding == "base58" { tx = [raw.b58, "base58"] }
        else {
            let signatures = signatures.map(\.b58)
            let accounts: Any
            if parsed || accountsOnly {
                let programs = Set(instructions.map(\.program))
                let upgradeable = combined.contains(upgradeableLoader)
                accounts = combined.enumerated().map { (i, key) -> Object in
                    let lookup = i >= keys.count
                    let signer = i < signers
                    let canWrite = lookup ? i - keys.count < writable.count :
                        signer ? i < signers - readonlySigned : i < keys.count - readonlyUnsigned
                    return ["pubkey": key, "signer": signer,
                            "writable": canWrite && !reserved.contains(key) && (upgradeable || !programs.contains(i)),
                            "source": lookup ? "lookupTable" : "transaction"]
                }
            } else { accounts = keys }
            if accountsOnly { tx = ["signatures": signatures, "accountKeys": accounts] as Object }
            else {
                var message: Object = ["accountKeys": accounts, "recentBlockhash": hash,
                    "instructions": try instructions.map { try $0.json(parsedKeys) }]
                if !parsed {
                    message["header"] = ["numRequiredSignatures": signers,
                        "numReadonlySignedAccounts": readonlySigned, "numReadonlyUnsignedAccounts": readonlyUnsigned]
                }
                if let lookups { message["addressTableLookups"] = lookups }
                if let config { message["transactionConfig"] = config }
                tx = ["signatures": signatures, "message": message] as Object
            }
        }
        let output = try meta?.json(options, parsedKeys)
        var result: Object = ["transaction": tx, "meta": nullable(output)]
        if meta != nil && options.maxVersion != nil { result["version"] = (version as Any?) ?? "legacy" }
        return result
    }
}

private let upgradeableLoader = "BPFLoaderUpgradeab1e11111111111111111111111"
private let reserved = Set("""
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
""".split(whereSeparator: \.isWhitespace).map(String.init))

struct Meta {
    var error: Any?
    var fee: UInt64 = 0
    var pre: [UInt64] = [], post: [UInt64] = []
    var inner: [Inner]?
    var logs: [String]?
    var preTokens: [Object]?, postTokens: [Object]?
    var rewards: [Object]?
    var writable: [String] = [], readonly: [String] = []
    var returned: Object?
    var compute: UInt64?, cost: UInt64?
    func json(_ options: Options, _ keys: [String]?) throws -> Object {
        let status: Object = error.map { ["Err": $0] } ?? ["Ok": null]
        let accounts = options.details == "accounts"
        var result: Object = ["err": nullable(error), "status": status, "fee": fee,
            "preBalances": pre, "postBalances": post, "preTokenBalances": nullable(preTokens),
            "postTokenBalances": nullable(postTokens)]
        if options.rewards || !accounts { result["rewards"] = nullable(options.rewards ? rewards : nil) }
        if !accounts {
            let inner = try inner?.map { try $0.json(keys) }
            result["innerInstructions"] = nullable(inner)
            result["logMessages"] = nullable(logs)
            if keys == nil { result["loadedAddresses"] = ["writable": writable, "readonly": readonly] }
            result["returnData"] = returned
            result["computeUnitsConsumed"] = compute
            result["costUnits"] = cost
        }
        return result
    }
}

private let instructionErrors = """
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
""".split(whereSeparator: \.isWhitespace).map(String.init)
private let transactionErrors = """
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
""".split(whereSeparator: \.isWhitespace).map(String.init)
private let rewardTypes = ["Fee", "Rent", "Staking", "Voting"]

private func txError(_ r: Bytes) throws -> Any {
    let kind = try r.u32()
    try check(kind < transactionErrors.count)
    let name = transactionErrors[kind]
    switch kind {
    case 8:
        let index = try r.u8(), sub = try r.u32()
        try check(sub < instructionErrors.count)
        let err: Any = sub == 25 ? ["Custom": try r.u32()] : instructionErrors[sub]
        return [name: [index, err] as [Any]]
    case 30: return [name: try r.u8()]
    case 31, 35: return [name: ["account_index": try r.u8()]]
    default: return name
    }
}
private func token(_ index: Int, _ mint: String, _ ui: Double?, _ decimals: Int, _ amount: String,
                   _ owner: String, _ program: String, _ display: String = "") -> Object {
    var text = display
    if text.isEmpty {
        var digits = String(UInt64(amount) ?? 0)
        if decimals > 0 {
            digits = String(repeating: "0", count: max(0, decimals + 1 - digits.count)) + digits
            text = digits.dropLast(decimals) + "." + digits.suffix(decimals)
            while text.last == "0" { text.removeLast() }
            if text.last == "." { text.removeLast() }
        } else { text = digits }
    }
    var result: Object = ["accountIndex": index, "mint": mint, "uiTokenAmount": [
        "uiAmount": nullable(ui.flatMap { $0.isFinite ? $0 : nil }), "decimals": decimals,
        "amount": amount, "uiAmountString": text
    ] as Object]
    if !owner.isEmpty { result["owner"] = owner }
    if !program.isEmpty { result["programId"] = program }
    return result
}
private func reward(_ key: String, _ lamports: UInt64, _ balance: UInt64, _ type: String?, _ commission: Int?) -> Object {
    ["pubkey": key, "lamports": Int64(bitPattern: lamports), "postBalance": balance,
     "rewardType": nullable(type), "commission": nullable(commission)]
}
private func returned(_ program: [UInt8], _ data: [UInt8]) throws -> Object {
    ["programId": try program.pubkey(), "data": [data.b64, "base64"]]
}
private func storedReward(_ r: Bytes, _ extended: Bool) throws -> Object {
    let key = try r.text(), lamports = try r.u64()
    let balance = extended && r.left == 0 ? 0 : try r.u64()
    try check(extended || r.left > 0)
    let type = try r.option {
        let i = try r.u32()
        try check(i < rewardTypes.count)
        return rewardTypes[i]
    }
    return try reward(key, lamports, balance, type, extended ? r.option(r.u8) : nil)
}
private func storedToken(_ r: Bytes, _ layout: Int) throws -> Object {
    let index = try r.u8(), mint = try r.text(), amountUI = Double(bitPattern: try r.u64())
    let decimals = try r.u8(), amount = try r.text()
    let owner = layout >= 2 && r.left > 0 ? try r.text() : ""
    let program = layout >= 3 && r.left > 0 ? try r.text() : ""
    return token(index, mint, amountUI, decimals, amount, owner, program)
}
private func storedMeta(_ r: Bytes, _ legacy: Bool, _ layout: Int) throws -> Meta {
    let status = try r.u32()
    try check(status <= 1)
    var m = Meta()
    if status == 1 { m.error = try txError(r) }
    m.fee = try r.u64()
    m.pre = try r.list(r.u64)
    m.post = try r.list(r.u64)
    m.inner = try r.option { try r.list {
        let index = try r.u8()
        let instructions = try r.list {
            let ix = try instruction(r, nil)
            if legacy { return ix }
            return try Instruction(program: ix.program, accounts: ix.accounts, data: ix.data, height: r.option(r.u32))
        }
        return Inner(index: index, instructions: instructions)
    } }
    m.logs = try r.option { try r.list(r.text) }
    m.preTokens = try r.option { try r.list { try storedToken(r, layout) } }
    m.postTokens = try r.option { try r.list { try storedToken(r, layout) } }
    m.rewards = try r.option { try r.list { try storedReward(r, true) } }
    m.returned = try r.option { try returned(r.bytes(32), r.vector()) }
    m.compute = try r.option(r.u64)
    m.cost = try r.option(r.u64)
    return m
}
private func bincode<T>(_ bytes: [UInt8], _ layouts: [(Bytes) throws -> T]) throws -> T {
    for read in layouts {
        let r = Bytes(bytes)
        if let output = try? read(r), r.left == 0 { return output }
    }
    return try layouts[0](Bytes(bytes))
}
private func legacyMeta(_ bytes: [UInt8]) throws -> Meta {
    try bincode(bytes, [{ try storedMeta($0, false, 3) }, { try storedMeta($0, true, 1) },
                        { try storedMeta($0, true, 2) }, { try storedMeta($0, true, 3) }])
}
private func legacyRewards(_ bytes: [UInt8]) throws -> Object {
    let rewards = try bincode(bytes, [
        { r in try r.list { try storedReward(r, true) } },
        { r in try r.list { try storedReward(r, false) } }
    ])
    return ["rewards": rewards]
}

private indirect enum Field: Sendable {
    case varint, fixed64, bytes, text, packed, message([Field]), repeated(Field)
    var wire: Int {
        switch self {
        case .varint: return 0
        case .fixed64: return 1
        default: return 2
        }
    }
}
private let instructionSchema: [Field] = [.varint, .bytes, .bytes, .varint]
private let tokenSchema: Field = .message([.varint, .text, .message([.fixed64, .varint, .text, .text]), .text, .text])
private let rewardSchema: Field = .message([.text, .varint, .varint, .varint, .text, .text])
private let rewardsSchema: [Field] = [.repeated(rewardSchema), .message([.varint])]
private let metaSchema: [Field] = [.message([.bytes]), .varint, .packed, .packed,
    .repeated(.message([.varint, .repeated(.message(instructionSchema))])),
    .repeated(.text), .repeated(tokenSchema), .repeated(tokenSchema), .repeated(rewardSchema), .varint, .varint,
    .repeated(.bytes), .repeated(.bytes), .message([.bytes, .bytes]), .varint, .varint, .varint]

private final class Proto {
    var values: [Int: Any] = [:]
    var repeated: [Int: [Any]] = [:]
    func list<T>(_ n: Int) -> [T] { repeated[n] as? [T] ?? [] }
    func num(_ n: Int) -> UInt64 { values[n] as? UInt64 ?? 0 }
    func u8(_ n: Int) -> Int { Int(num(n) & 255) }
    func bytes(_ n: Int) -> [UInt8] { values[n] as? [UInt8] ?? [] }
    func text(_ n: Int) -> String { values[n] as? String ?? "" }
    func sub(_ n: Int) -> Proto? { values[n] as? Proto }
}
private func key(_ r: Bytes) throws -> (Int, Int) {
    let key = try r.varint(), field = key >> 3
    try check(field > 0 && field <= 0x1fffffff)
    return (Int(field), Int(key & 7))
}
private func skip(_ r: Bytes, _ n: Int, _ wire: Int, _ depth: Int) throws {
    try check(depth <= 128)
    switch wire {
    case 0: _ = try r.varint()
    case 1: try r.skip(8)
    case 2: try r.skip(r.count(r.varint()))
    case 3:
        while true {
            let (field, child) = try key(r)
            if child == 4 { try check(field == n); break }
            try skip(r, field, child, depth + 1)
        }
    case 5: try r.skip(4)
    default: throw DecodeFailure()
    }
}
private func protobuf(_ r: Bytes, _ schema: [Field], _ out: Proto = Proto()) throws -> Proto {
    while r.left > 0 {
        let (n, wire) = try key(r)
        if n > schema.count { try skip(r, n, wire, 0); continue }
        let spec = schema[n - 1]
        if case .packed = spec {
            if wire == 0 { out.repeated[n, default: []].append(try r.varint()) }
            else {
                try check(wire == 2)
                let part = try r.part(r.count(r.varint()))
                while part.left > 0 { out.repeated[n, default: []].append(try part.varint()) }
            }
            continue
        }
        let kind: Field
        let repeated: Bool
        if case .repeated(let field) = spec { kind = field; repeated = true }
        else { kind = spec; repeated = false }
        try check(wire == kind.wire)
        let value: Any
        switch kind {
        case .varint: value = try r.varint()
        case .fixed64: value = Double(bitPattern: try r.u64())
        case .bytes: value = try r.bytes(r.count(r.varint()))
        case .text: value = try utf8(r.bytes(r.count(r.varint())))
        case .message(let fields):
            value = try protobuf(r.part(r.count(r.varint())), fields,
                                 (repeated ? nil : out.sub(n)) ?? Proto())
        default: throw DecodeFailure()
        }
        if repeated { out.repeated[n, default: []].append(value) }
        else { out.values[n] = value }
    }
    return out
}
private func protoReward(_ p: Proto) -> Object {
    let type = Int(p.num(4) & 0xffffffff)
    let commission = UInt8(p.text(5)).map(Int.init) ??
        UInt16(p.text(6)).map { Int($0) / 100 }.flatMap { $0 <= 255 ? $0 : nil }
    return reward(p.text(1), p.num(2), p.num(3), (1...4).contains(type) ? rewardTypes[type - 1] : nil, commission)
}
private func protoToken(_ p: Proto) -> Object {
    let a = p.sub(3) ?? Proto()
    let ui = (a.values[1] as? Double).flatMap { abs($0) > Double.ulpOfOne ? $0 : nil }
    return token(p.u8(1), p.text(2), ui, a.u8(2), a.text(3), p.text(4), p.text(5), a.text(4))
}
private func protoMeta(_ p: Proto) throws -> Meta {
    var m = Meta()
    if let err = p.sub(1) { m.error = try txError(Bytes(err.bytes(1))) }
    m.fee = p.num(2)
    m.pre = p.list(3)
    m.post = p.list(4)
    if p.num(10) == 0 {
        m.inner = (p.list(5) as [Proto]).map { group in
            Inner(index: group.u8(1), instructions: (group.list(2) as [Proto]).map { ix in
                Instruction(program: ix.u8(1), accounts: ix.bytes(2), data: ix.bytes(3),
                            height: (ix.values[4] as? UInt64).map { Int($0 & 0xffffffff) })
            })
        }
    }
    if p.num(11) == 0 { m.logs = p.list(6) }
    m.preTokens = (p.list(7) as [Proto]).map(protoToken)
    m.postTokens = (p.list(8) as [Proto]).map(protoToken)
    m.rewards = (p.list(9) as [Proto]).map(protoReward)
    m.writable = try (p.list(12) as [[UInt8]]).map { try $0.pubkey() }
    m.readonly = try (p.list(13) as [[UInt8]]).map { try $0.pubkey() }
    if p.num(15) == 0, let ret = p.sub(14) { m.returned = try returned(ret.bytes(1), ret.bytes(2)) }
    m.compute = p.values[16] as? UInt64
    m.cost = p.values[17] as? UInt64
    return m
}
private func protoRewards(_ p: Proto) -> Object {
    var out: Object = ["rewards": (p.list(1) as [Proto]).map(protoReward)]
    if let partitions = p.sub(2) { out["numRewardPartitions"] = partitions.num(1) }
    return out
}
private func payload<T>(_ slot: UInt64, _ bytes: [UInt8], _ schema: [Field],
                        _ legacy: ([UInt8]) throws -> T, _ convert: (Proto) throws -> T) throws -> T {
    func decode(_ bytes: [UInt8]) throws -> T {
        if slot < 67_824_000 {
            if let result = try? legacy(bytes) { return result }
            return try convert(protobuf(Bytes(bytes), schema))
        }
        guard let message = try? protobuf(Bytes(bytes), schema) else { return try legacy(bytes) }
        return try convert(message)
    }
    if bytes.starts(with: [0x28, 0xb5, 0x2f, 0xfd]) { return try decode((try? Zstd.decode(bytes)) ?? bytes) }
    do { return try decode(bytes) }
    catch {
        guard let plain = try? Zstd.decode(bytes) else { throw error }
        return try decode(plain)
    }
}
func metadata(_ slot: UInt64, _ bytes: [UInt8]) throws -> Meta? {
    if bytes.isEmpty { return nil }
    return try payload(slot, bytes, metaSchema, legacyMeta, protoMeta)
}
func rewards(_ slot: UInt64, _ bytes: [UInt8]) throws -> Object {
    if bytes.isEmpty { return ["rewards": [Object]()] }
    return try payload(slot, bytes, rewardsSchema, legacyRewards, protoRewards)
}
