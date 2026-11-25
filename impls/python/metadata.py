"""Protobuf and historical bincode metadata and rewards."""
import math
import re
import sys

from wire import DecodeError, Reader, U64_MAX, b64, instruction, pubkey, require, utf8
from zstd import ZstdError, zstd_decompress

INSTRUCTION_ERRORS = '''
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
'''.split()

TRANSACTION_ERRORS = '''
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
'''.split()

REWARD_TYPES = ('Fee', 'Rent', 'Staking', 'Voting')
CUTOFF = 157 * 432000


def transaction_error(reader):
    variant = reader.u32()
    require(variant < len(TRANSACTION_ERRORS), 'Unknown TransactionError variant')
    name = TRANSACTION_ERRORS[variant]
    if variant == 8:
        index, kind = reader.u8(), reader.u32()
        require(kind < len(INSTRUCTION_ERRORS), 'Unknown InstructionError variant')
        return {name: [index, {'Custom': reader.u32()} if kind == 25 else INSTRUCTION_ERRORS[kind]]}
    if variant == 30:
        return {name: reader.u8()}
    if variant in (31, 35):
        return {name: {'account_index': reader.u8()}}
    return name


def unsigned_text(text, maximum=U64_MAX):
    if not re.fullmatch(r'\+?[0-9]+', text):
        return None
    digits = text.lstrip('+').lstrip('0')
    if len(digits) > 20:
        return None
    value = int(digits or '0')
    return value if value <= maximum else None


def token_balance(index, mint, ui, decimals, amount, owner='', program='', display=''):
    if not display:
        digits = str(unsigned_text(amount) or 0).zfill(decimals + 1)
        display = (digits[:-decimals] + '.' + digits[-decimals:]).rstrip('0').rstrip('.') if decimals else digits
    balance = dict(accountIndex=index, mint=mint,
                   uiTokenAmount=dict(uiAmount=ui if ui is not None and math.isfinite(ui) else None,
                                      decimals=decimals, amount=amount, uiAmountString=display))
    if owner:
        balance['owner'] = owner
    if program:
        balance['programId'] = program
    return balance


def empty_meta():
    return dict(err=None, fee=0, preBalances=[], postBalances=[], innerInstructions=None,
                logMessages=None, preTokenBalances=None, postTokenBalances=None, rewards=None,
                loadedAddresses=dict(writable=[], readonly=[]))


# A field is (name, scalar type or nested descriptor, optional repeated flag).
INSTRUCTION = {1: ('programIdIndex', 'v'), 2: ('accounts', 'b'), 3: ('data', 'b'),
               4: ('stackHeight', 'v')}
INNER = {1: ('index', 'v'), 2: ('instructions', INSTRUCTION, True)}
AMOUNT = {1: ('uiAmount', 'd'), 2: ('decimals', 'v'), 3: ('amount', 's'), 4: ('uiAmountString', 's')}
TOKEN = {1: ('accountIndex', 'v'), 2: ('mint', 's'), 3: ('uiTokenAmount', AMOUNT),
         4: ('owner', 's'), 5: ('programId', 's')}
REWARD = {1: ('pubkey', 's'), 2: ('lamports', 'v'), 3: ('postBalance', 'v'),
          4: ('rewardType', 'v'), 5: ('commission', 's'), 6: ('commissionBps', 's')}
REWARDS = {1: ('rewards', REWARD, True), 2: ('partitions', {1: ('count', 'v')})}
META = {
    1: ('error', {1: ('bytes', 'b')}), 2: ('fee', 'v'), 3: ('preBalances', 'v', True),
    4: ('postBalances', 'v', True), 5: ('innerInstructions', INNER, True),
    6: ('logMessages', 's', True), 7: ('preTokenBalances', TOKEN, True),
    8: ('postTokenBalances', TOKEN, True), 9: ('rewards', REWARD, True),
    10: ('innerInstructionsNone', 'v'), 11: ('logMessagesNone', 'v'),
    12: ('loadedWritable', 'b', True), 13: ('loadedReadonly', 'b', True),
    14: ('returnData', {1: ('programId', 'b'), 2: ('data', 'b')}),
    15: ('returnDataNone', 'v'), 16: ('computeUnitsConsumed', 'v'), 17: ('costUnits', 'v'),
}


def proto_key(reader):
    key = reader.varint()
    require(8 <= key <= 0xffffffff, 'Invalid protobuf key')
    return key >> 3, key & 7


def skip_proto(reader, field, wire, depth=0):
    if wire == 0:
        reader.varint()
    elif wire == 1:
        reader.take(8)
    elif wire == 2:
        reader.take(reader.varint())
    elif wire == 3:
        require(depth < 100, 'Protobuf group nesting limit')
        while True:
            tag, mode = proto_key(reader)
            if mode == 4:
                require(tag == field, 'Mismatched protobuf group')
                break
            skip_proto(reader, tag, mode, depth + 1)
    elif wire == 5:
        reader.take(4)
    else:
        raise DecodeError('Invalid protobuf wire type')


def protobuf(data, schema, target=None):
    reader = Reader(data)
    if target is None:
        target = {}
    while reader.left:
        field, wire = proto_key(reader)
        descriptor = schema.get(field)
        if descriptor is None:
            skip_proto(reader, field, wire)
            continue
        name, mode, *repeated = descriptor
        if repeated and mode == 'v' and wire == 2:
            packed = Reader(reader.take(reader.varint()))
            values = target.setdefault(name, [])
            while packed.left:
                values.append(packed.varint())
            continue
        require(wire == (0 if mode == 'v' else 1 if mode == 'd' else 2), 'Wrong protobuf wire type')
        if wire == 0:
            value = reader.varint()
        elif wire == 1:
            value = reader.f64()
        else:
            value = reader.take(reader.varint())
            if isinstance(mode, dict):
                value = protobuf(value, mode, None if repeated else target.get(name))
            elif mode == 's':
                value = utf8(value)
        if repeated:
            target.setdefault(name, []).append(value)
        else:
            target[name] = value
    return target


def proto_reward(value):
    bps = unsigned_text(value.get('commissionBps', ''), 65535)
    commission = unsigned_text(value.get('commission', ''), 255)
    if commission is None and bps is not None and bps // 100 <= 255:
        commission = bps // 100
    kind = value.get('rewardType', 0) & 0xffffffff
    lamports = value.get('lamports', 0)
    if lamports >= 1 << 63:
        lamports -= 1 << 64
    return dict(pubkey=value.get('pubkey', ''), lamports=lamports, postBalance=value.get('postBalance', 0),
                rewardType=REWARD_TYPES[kind - 1] if 1 <= kind <= 4 else None, commission=commission)


def proto_token(value):
    amount = value.get('uiTokenAmount', {})
    ui = amount.get('uiAmount', 0)
    return token_balance(value.get('accountIndex', 0) & 255, value.get('mint', ''),
                         ui if abs(ui) > sys.float_info.epsilon else None, amount.get('decimals', 0) & 255,
                         amount.get('amount', ''), value.get('owner', ''), value.get('programId', ''),
                         amount.get('uiAmountString', ''))


def proto_instruction(value):
    height = value.get('stackHeight')
    return dict(programIdIndex=value.get('programIdIndex', 0) & 255,
                accounts=value.get('accounts', b''), data=value.get('data', b''),
                stackHeight=None if height is None else height & 0xffffffff)


def proto_meta(value):
    result = empty_meta()
    result['err'] = transaction_error(Reader(value['error'].get('bytes', b''))) if 'error' in value else None
    for field, default in (('fee', 0), ('preBalances', []), ('postBalances', [])):
        result[field] = value.get(field, default)
    if not value.get('innerInstructionsNone'):
        result['innerInstructions'] = [
            dict(index=group.get('index', 0) & 255,
                 instructions=list(map(proto_instruction, group.get('instructions', []))))
            for group in value.get('innerInstructions', [])
        ]
    if not value.get('logMessagesNone'):
        result['logMessages'] = value.get('logMessages', [])
    for key in ('preTokenBalances', 'postTokenBalances'):
        result[key] = list(map(proto_token, value.get(key, [])))
    result['rewards'] = list(map(proto_reward, value.get('rewards', [])))
    result['loadedAddresses'] = dict(writable=list(map(pubkey, value.get('loadedWritable', []))),
                                     readonly=list(map(pubkey, value.get('loadedReadonly', []))))
    if 'returnData' in value and not value.get('returnDataNone'):
        data = value['returnData']
        result['returnData'] = dict(programId=pubkey(data.get('programId')),
                                    data=[b64(data.get('data', b'')), 'base64'])
    for key in ('computeUnitsConsumed', 'costUnits'):
        if key in value:
            result[key] = value[key]
    return result


def proto_rewards(value):
    result = dict(rewards=list(map(proto_reward, value.get('rewards', []))))
    if 'partitions' in value:
        result['numRewardPartitions'] = value['partitions'].get('count', 0)
    return result


def stored_reward(reader, extended=True):
    key, lamports = reader.string(), reader.i64()
    post = reader.u64() if reader.left or not extended else 0

    def reward_type():
        index = reader.u32()
        require(index < len(REWARD_TYPES), 'Unknown RewardType')
        return REWARD_TYPES[index]

    kind = reader.option(reward_type) if reader.left or not extended else None
    commission = reader.option(reader.u8) if reader.left and extended else None
    return dict(pubkey=key, lamports=lamports, postBalance=post, rewardType=kind, commission=commission)


def stored_token(reader, layout):
    index, mint, ui, decimals, amount = reader.u8(), reader.string(), reader.f64(), reader.u8(), reader.string()
    owner = reader.string() if layout >= 2 and reader.left else ''
    program = reader.string() if layout >= 3 and reader.left else ''
    return token_balance(index, mint, ui, decimals, amount, owner, program)


def stored_meta(reader, legacy=False, layout=3):
    status = reader.u32()
    require(status <= 1, 'Invalid bincode result tag')
    result = empty_meta()
    result['err'] = transaction_error(reader) if status else None
    result['fee'] = reader.u64()
    for field in ('preBalances', 'postBalances'):
        result[field] = reader.vec(reader.u64, 8)

    def inner_instruction():
        ix = instruction(reader)
        if not legacy:
            ix['stackHeight'] = reader.option(reader.u32)
        return ix

    def inner():
        return dict(index=reader.u8(), instructions=reader.vec(inner_instruction, 3 if legacy else 4))

    fields = (
        ('innerInstructions', lambda: reader.vec(inner, 9)),
        ('logMessages', lambda: reader.vec(reader.string, 8)),
        ('preTokenBalances', lambda: reader.vec(lambda: stored_token(reader, layout), 26)),
        ('postTokenBalances', lambda: reader.vec(lambda: stored_token(reader, layout), 26)),
        ('rewards', lambda: reader.vec(lambda: stored_reward(reader), 16)),
        ('returnData', lambda: dict(programId=pubkey(reader.take(32)),
                                    data=[b64(reader.take(reader.u64())), 'base64'])),
        ('computeUnitsConsumed', reader.u64),
        ('costUnits', reader.u64),
    )
    for name, read in fields:
        if not reader.left:
            break
        value = reader.option(read)
        if value is not None:
            result[name] = value
    return result


def bincode(data, layouts):
    for decode in layouts:
        reader = Reader(data)
        try:
            result = decode(reader)
        except DecodeError:
            continue
        if not reader.left:
            return result
    return layouts[0](Reader(data))


def bincode_meta(data):
    layouts = [stored_meta] + [lambda reader, layout=n: stored_meta(reader, True, layout) for n in (1, 2, 3)]
    return bincode(data, layouts)


def bincode_rewards(data):
    layouts = [lambda reader: reader.vec(lambda: stored_reward(reader), 16),
               lambda reader: reader.vec(lambda: stored_reward(reader, False), 25)]
    return dict(rewards=bincode(data, layouts))


def decode_payload(slot, data, schema, convert, stored):
    if slot < CUTOFF:
        try:
            return stored(data)
        except DecodeError:
            pass
    try:
        parsed = protobuf(data, schema)
    except DecodeError:
        if slot < CUTOFF:
            raise
        return stored(data)
    return convert(parsed)


def unwrap(slot, data, schema, convert, stored):
    def decode(payload):
        return decode_payload(slot, payload, schema, convert, stored)

    if data.startswith(b'\x28\xb5\x2f\xfd'):
        try:
            data = zstd_decompress(data)
        except ZstdError:
            pass
        return decode(data)
    try:
        return decode(data)
    except DecodeError as original:
        try:
            plain = zstd_decompress(data)
        except ZstdError:
            raise original from None
        return decode(plain)


def metadata(slot, data):
    return unwrap(slot, data, META, proto_meta, bincode_meta) if data else None


def rewards(slot, data):
    return unwrap(slot, data, REWARDS, proto_rewards, bincode_rewards) if data else dict(rewards=[])
