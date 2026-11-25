export const MiB = 1024 * 1024;
const MAX_SLICE = 128 * MiB;
const MAX_DECOMPRESSED = 512 * MiB;
export const U64_MAX = (1n << 64n) - 1n;
const SLOTS_PER_EPOCH = 432000n;
const BINCODE_CUTOFF = 157n * SLOTS_PER_EPOCH;
export type Bytes = Uint8Array<ArrayBuffer>;
const EMPTY: Bytes = new Uint8Array();
const MAX_CAR_SECTION = 32n * BigInt(MiB);
const ZERO_HASH = '1'.repeat(32);
export const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export class RpcError extends Error {
  constructor(readonly code: number, message: string) {
    super(message);
  }
}

export function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function joinBytes(chunks: Bytes[], length = chunks.reduce((sum, chunk) => sum + chunk.length, 0)): Bytes {
  if (chunks.length === 1) return chunks[0];
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

// Every cursor is bounded by its enclosing section or field.
class Reader {
  readonly view: DataView<ArrayBuffer>;
  pos = 0;

  constructor(readonly bytes: Bytes) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get left() {
    return this.bytes.length - this.pos;
  }
  peek() {
    return this.bytes[this.pos];
  }

  take(count: number) {
    check(Number.isInteger(count) && count >= 0 && count <= this.left, 'Truncated binary value');
    const start = this.pos;
    this.pos += count;
    return this.bytes.subarray(start, this.pos);
  }

  fixed(getter: 'getBigUint64' | 'getBigInt64', size: number, littleEndian?: boolean): bigint;
  fixed(
    getter: 'getUint8' | 'getUint16' | 'getUint32' | 'getFloat16' | 'getFloat32' | 'getFloat64',
    size: number,
    littleEndian?: boolean,
  ): number;
  fixed(
    getter:
      | 'getBigUint64'
      | 'getBigInt64'
      | 'getUint8'
      | 'getUint16'
      | 'getUint32'
      | 'getFloat16'
      | 'getFloat32'
      | 'getFloat64',
    size: number,
    littleEndian = true,
  ) {
    check(size <= this.left, 'Truncated fixed-width integer');
    const value = this.view[getter](this.pos, littleEndian);
    this.pos += size;
    return value;
  }

  u8() {
    return this.fixed('getUint8', 1);
  }
  u16() {
    return this.fixed('getUint16', 2);
  }
  u32() {
    return this.fixed('getUint32', 4);
  }
  u64() {
    return this.fixed('getBigUint64', 8);
  }
  i64() {
    return this.fixed('getBigInt64', 8);
  }
  f64() {
    return this.fixed('getFloat64', 8);
  }

  varint() {
    let value = 0n;
    for (let shift = 0n; shift <= 63n; shift += 7n) {
      const byte = this.u8();
      check(shift < 63n || byte <= 1, 'Varint overflow');
      value |= BigInt(byte & 0x7f) << shift;
      if (byte < 128) return value;
    }
    throw new Error('Varint overflow');
  }

  sized(length: bigint) {
    check(length <= BigInt(this.left), 'Length exceeds enclosing field');
    return this.take(Number(length));
  }

  compact() {
    let count = 0;
    for (let shift = 0; shift <= 14; shift += 7) {
      const byte = this.u8();
      check(shift === 0 || byte !== 0, 'Non-canonical compact-u16');
      check(shift < 14 || byte <= 3, 'Compact-u16 overflow');
      count |= (byte & 0x7f) << shift;
      if (byte < 128) return count;
    }
    throw new Error('Compact-u16 overflow');
  }

  list<T>(count: number, read: (reader: Reader) => T, minSize = 1) {
    check(count <= Math.floor(this.left / minSize), 'Count exceeds enclosing field');
    const items = [];
    for (let i = 0; i < count; i++) items.push(read(this));
    return items;
  }

  vec<T>(read: (reader: Reader) => T, minSize = 1) {
    const count = this.u64();
    check(count <= BigInt(this.left), 'Vector length exceeds input');
    return this.list(Number(count), read, minSize);
  }

  string() {
    return utf8.decode(this.sized(this.u64()));
  }

  option<T>(read: (reader: Reader) => T) {
    const tag = this.u8();
    check(tag <= 1, 'Invalid bincode option tag');
    return tag ? read(this) : null;
  }
}

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58(bytes: Bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return '1'.repeat(zeros) + digits.reverse().map((digit) => BASE58[digit]).join('');
}

function pubkey(bytes: Bytes | undefined) {
  check(bytes?.length === 32, 'Expected a 32-byte public key or hash');
  return base58(bytes);
}

function base64(bytes: Bytes) {
  return bytes.toBase64();
}

function cborArgument(reader: Reader, info: number) {
  if (info < 24) return BigInt(info);
  switch (info) {
    case 24:
      return BigInt(reader.u8());
    case 25:
      return BigInt(reader.fixed('getUint16', 2, false));
    case 26:
      return BigInt(reader.fixed('getUint32', 4, false));
    case 27:
      return reader.fixed('getBigUint64', 8, false);
    case 31:
      return null;
    default:
      throw new Error('Reserved CBOR argument');
  }
}

type Cbor = bigint | number | boolean | null | string | Bytes | Cbor[] | Map<Cbor, Cbor>;

function cborItem(reader: Reader, depth = 0): Cbor {
  check(depth <= 128, 'CBOR nesting limit exceeded');
  const head = reader.u8();
  const major = head >> 5;
  const info = head & 31;
  if (major === 7) {
    switch (info) {
      case 20:
        return false;
      case 21:
        return true;
      case 22:
      case 23:
        return null;
      case 25:
        return reader.fixed('getFloat16', 2, false);
      case 26:
        return reader.fixed('getFloat32', 4, false);
      case 27:
        return reader.fixed('getFloat64', 8, false);
      default:
        throw new Error('Unsupported CBOR simple value');
    }
  }
  const arg = cborArgument(reader, info);
  if (major < 2 || major === 6) {
    check(arg !== null, 'Invalid indefinite CBOR item');
    if (major === 0) return arg;
    if (major === 1) return -1n - arg;
    return cborItem(reader, depth + 1);
  }

  if (major === 2 || major === 3) {
    if (arg !== null) {
      const bytes = reader.sized(arg);
      return major === 2 ? bytes : utf8.decode(bytes);
    }
    const chunks = [];
    while (reader.peek() !== 0xff) {
      const chunk = reader.u8();
      check(chunk >> 5 === major && (chunk & 31) !== 31, 'Invalid CBOR string chunk');
      const length = cborArgument(reader, chunk & 31);
      check(length !== null, 'Indefinite CBOR chunk');
      chunks.push(reader.sized(length));
    }
    reader.u8();
    return major === 2 ? joinBytes(chunks) : chunks.map((chunk) => utf8.decode(chunk)).join('');
  }

  const array = major === 4;
  const value: Cbor[] | Map<Cbor, Cbor> = array ? [] : new Map();
  if (arg !== null) check(arg * (array ? 1n : 2n) <= BigInt(reader.left), 'CBOR count exceeds input');
  for (let i = 0; arg === null ? reader.peek() !== 0xff : i < Number(arg); i++) {
    const item = cborItem(reader, depth + 1);
    if (Array.isArray(value)) value.push(item);
    else value.set(item, cborItem(reader, depth + 1));
  }
  if (arg === null) reader.u8();
  return value;
}

function cbor(bytes: Bytes) {
  const reader = new Reader(bytes);
  const value = cborItem(reader);
  check(!reader.left, 'Trailing CBOR bytes');
  return value;
}

function readCid(reader: Reader) {
  const start = reader.pos;
  const version = reader.varint();
  const codec = reader.varint();
  let absent = false;
  if (version === 0x12n && codec === 0x20n) {
    reader.take(32);
  } else {
    check(version === 1n, 'Unsupported CID version');
    const hash = reader.varint();
    const length = reader.varint();
    check(length <= 64n, 'CID digest too long');
    reader.sized(length);
    absent = hash === 0n && length === 0n;
  }
  return { key: reader.bytes.subarray(start, reader.pos).toHex(), absent };
}

function link(value: Cbor | undefined) {
  check(value instanceof Uint8Array && value[0] === 0, 'Invalid CID link');
  return readCid(new Reader(value.subarray(1)));
}

function links(items: Cbor | undefined) {
  return Array.isArray(items) ? items.map((item) => link(item).key) : [];
}

function isCarHeader(bytes: Bytes) {
  if (bytes[0] >> 5 !== 5) return false;
  try {
    const header = cbor(bytes);
    return header instanceof Map && header.has('version');
  } catch {
    return false;
  }
}

function indexCar(bytes: Bytes) {
  const reader = new Reader(bytes);
  const index: CarIndex = new Map();
  let block: Bytes | undefined;
  let first = true;
  while (reader.left) {
    const size = reader.varint();
    if (size === 0n) continue;
    check(size <= MAX_CAR_SECTION, 'Oversize CAR section');
    const section = new Reader(reader.sized(size));
    const header = first && isCarHeader(section.bytes);
    first = false;
    if (header) continue;
    const { key } = readCid(section);
    const node = section.take(section.left);
    index.set(key, node);
    if (node[0] >> 5 === 4) {
      const info = node[0] & 31;
      const headerSize = info < 24 || info === 31 ? 1 : [2, 3, 5, 9][info - 24];
      if (node[headerSize] === 2) block = node;
    }
  }
  check(block, 'CAR slice is missing its Block node');
  return { index, block: requireKind(cbor(block), 2n) };
}

function requireKind(node: Cbor | undefined, kind: bigint): Cbor[] {
  check(Array.isArray(node) && node[0] === kind, `Expected IPLD node kind ${kind}`);
  return node;
}

type CarIndex = Map<string, Bytes>;

function indexedNode(index: CarIndex, key: string, kind: bigint) {
  const bytes = index.get(key);
  check(bytes, 'CID missing from CAR slice');
  return requireKind(cbor(bytes), kind);
}

function unsigned(value: Cbor | undefined) {
  return typeof value === 'bigint' && value >= 0n ? value : null;
}

function signed(value: Cbor | undefined) {
  return typeof value === 'bigint' && BigInt.asIntN(64, value) === value ? value : null;
}

// GO-ISO's reflected polynomial has set bits only in the high word.
const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, byte) => {
  let crc = BigInt(byte);
  for (let i = 0; i < 8; i++) crc = (crc >> 1n) ^ ((crc & 1n) ? 0xd800000000000000n : 0n);
  return Number(crc >> 32n);
});

function crc64(bytes: Bytes): bigint {
  let high = -1;
  let low = -1;
  for (const byte of bytes) {
    const index = (low ^ byte) & 255;
    low = (low >>> 8) | (high << 24);
    high = (high >>> 8) ^ CRC_TABLE[index];
  }
  return (BigInt(~high >>> 0) << 32n) | BigInt(~low >>> 0);
}

function fnv1a(bytes: Bytes): bigint {
  let high = 0xcbf29ce4;
  let low = 0x84222325;
  for (const byte of bytes) {
    low = (low ^ byte) >>> 0;
    const product = low * 0x1b3;
    // The FNV prime is 0x100 * 2^32 + 0x1b3.
    high = (Math.imul(high, 0x1b3) + (low << 8) + Math.floor(product / 0x100000000)) >>> 0;
    low = product >>> 0;
  }
  return (BigInt(high) << 32n) | BigInt(low);
}

function framePayload(index: CarIndex, root: Cbor | undefined) {
  const frame = requireKind(root, 6n);
  const bytes = frame[4] instanceof Uint8Array ? frame[4] : EMPTY;
  const stack = links(frame[5]).reverse();
  let result = bytes;
  if (stack.length) {
    const chunks = [bytes];
    const seen = new Set<string>();
    while (stack.length) {
      const key = stack.pop()!;
      check(!seen.has(key), 'Repeated DataFrame CID');
      seen.add(key);
      const frame = indexedNode(index, key, 6n);
      if (frame[4] instanceof Uint8Array) chunks.push(frame[4]);
      const next = links(frame[5]);
      for (let i = next.length - 1; i >= 0; i--) stack.push(next[i]);
    }
    result = joinBytes(chunks);
  }
  const expected = unsigned(frame[1]);
  check(
    expected === null || crc64(result) === expected || fnv1a(result) === expected,
    'DataFrame hash mismatch',
  );
  return result;
}

type Instruction = { programIdIndex: number; accounts: Bytes; data: Bytes; stackHeight: number | null };

function compiledInstruction(reader: Reader, stackHeight: number | null): Instruction {
  return {
    programIdIndex: reader.u8(),
    accounts: reader.take(reader.compact()),
    data: reader.take(reader.compact()),
    stackHeight,
  };
}

function transactionV1(reader: Reader) {
  const header = {
    numRequiredSignatures: reader.u8(),
    numReadonlySignedAccounts: reader.u8(),
    numReadonlyUnsignedAccounts: reader.u8(),
  };
  const mask = reader.u32();
  const priorityBits = mask & 0x03;
  check(mask <= 0x1f && (priorityBits === 0 || priorityBits === 0x03), 'Invalid v1 transaction config mask');
  const recentBlockhash = pubkey(reader.take(32));
  const instructionCount = reader.u8();
  const accountKeys = reader.list(reader.u8(), (r) => pubkey(r.take(32)), 32);
  const transactionConfig = {
    priorityFee: priorityBits === 0x03 ? reader.u64() : null,
    computeUnitLimit: mask & 0x04 ? reader.u32() : null,
    loadedAccountsDataSizeLimit: mask & 0x08 ? reader.u32() : null,
    heapSize: mask & 0x10 ? reader.u32() : null,
  };
  // All headers precede the payloads, which are laid out in instruction order.
  const instructionHeaders = reader.list(instructionCount, (r) => ({
    programIdIndex: r.u8(),
    accountCount: r.u8(),
    dataLength: r.u16(),
  }), 4);
  const instructions = instructionHeaders.map(({ programIdIndex, accountCount, dataLength }) => ({
    programIdIndex,
    accounts: reader.take(accountCount),
    data: reader.take(dataLength),
    stackHeight: 1,
  }));
  const signatures = reader.list(header.numRequiredSignatures, (r) => r.take(64), 64);
  return {
    version: 1 as const,
    signatures,
    header,
    accountKeys,
    recentBlockhash,
    instructions,
    addressTableLookups: undefined,
    transactionConfig,
    raw: reader.bytes.subarray(0, reader.pos),
  };
}

function transaction(bytes: Bytes) {
  const reader = new Reader(bytes);
  const discriminator = reader.u8();
  if (discriminator === 0x81) return transactionV1(reader);
  check(discriminator < 0x80, 'Invalid transaction discriminator');
  const signatures = reader.list(discriminator, (r) => r.take(64), 64);
  const prefix = reader.u8();
  check(prefix <= 128, 'Unsupported transaction wire version');
  const version: 0 | 'legacy' = prefix === 128 ? 0 : 'legacy';
  const header = {
    numRequiredSignatures: version === 0 ? reader.u8() : prefix,
    numReadonlySignedAccounts: reader.u8(),
    numReadonlyUnsignedAccounts: reader.u8(),
  };
  const accountKeys = reader.list(reader.compact(), (r) => pubkey(r.take(32)), 32);
  const recentBlockhash = pubkey(reader.take(32));
  const instructions = reader.list(reader.compact(), (r) => compiledInstruction(r, 1), 3);
  const addressTableLookups = version === 0
    ? reader.list(reader.compact(), (r) => ({
      accountKey: pubkey(r.take(32)),
      writableIndexes: Array.from(r.take(r.compact())),
      readonlyIndexes: Array.from(r.take(r.compact())),
    }), 34)
    : undefined;
  return {
    version,
    signatures,
    header,
    accountKeys,
    recentBlockhash,
    instructions,
    addressTableLookups,
    transactionConfig: undefined,
    raw: bytes.subarray(0, reader.pos),
  };
}

const INSTRUCTION_ERRORS = `
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
`.trim().split(/\s+/);

const TRANSACTION_ERRORS = `
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
`.trim().split(/\s+/);

function transactionError(reader: Reader) {
  const variant = reader.u32();
  const name = TRANSACTION_ERRORS[variant];
  check(name, 'Unknown TransactionError variant');
  switch (variant) {
    case 8: {
      const index = reader.u8();
      const kind = reader.u32();
      check(INSTRUCTION_ERRORS[kind], 'Unknown InstructionError variant');
      const instruction = kind === 25 ? { Custom: reader.u32() } : INSTRUCTION_ERRORS[kind];
      return { InstructionError: [index, instruction] };
    }
    case 30:
      return { DuplicateInstruction: reader.u8() };
    case 31:
    case 35:
      return { [name]: { account_index: reader.u8() } };
    default:
      return name;
  }
}

function parseUnsignedText(value: string, max = U64_MAX) {
  if (!/^\+?[0-9]+$/.test(value)) return null;
  const digits = value.replace(/^\+?0*/, '');
  if (digits.length > 20) return null;
  const number = BigInt(digits);
  return number <= max ? number : null;
}

function uiAmountString(amount: string, decimals: number) {
  const digits = String(parseUnsignedText(amount) ?? 0n);
  if (!decimals) return digits;
  const padded = digits.padStart(decimals + 1, '0');
  return `${padded.slice(0, -decimals)}.${padded.slice(-decimals)}`.replace(/0+$/, '').replace(/\.$/, '');
}

function tokenBalance(
  accountIndex: number,
  mint: string,
  uiAmount: number | null,
  decimals: number,
  amount: string,
  owner?: string,
  programId?: string,
  displayAmount?: string,
) {
  return {
    accountIndex,
    mint,
    uiTokenAmount: {
      uiAmount,
      decimals,
      amount,
      uiAmountString: displayAmount || uiAmountString(amount, decimals),
    },
    owner: owner || undefined,
    programId: programId || undefined,
  };
}

const REWARD_TYPES = ['Fee', 'Rent', 'Staking', 'Voting'];

type Addresses = { writable: string[]; readonly: string[] };
type Meta = {
  err: ReturnType<typeof transactionError> | null;
  fee: bigint;
  preBalances: bigint[];
  postBalances: bigint[];
  innerInstructions: { index: number; instructions: Instruction[] }[] | null;
  logMessages: string[] | null;
  preTokenBalances: ReturnType<typeof tokenBalance>[] | null;
  postTokenBalances: ReturnType<typeof tokenBalance>[] | null;
  rewards: ReturnType<typeof storedReward>[] | null;
  loadedAddresses: Addresses;
  returnData?: { programId: string; data: string[] };
  computeUnitsConsumed?: bigint;
  costUnits?: bigint;
};

function emptyMeta(): Meta {
  return {
    err: null,
    fee: 0n,
    preBalances: [],
    postBalances: [],
    innerInstructions: null,
    logMessages: null,
    preTokenBalances: null,
    postTokenBalances: null,
    rewards: null,
    loadedAddresses: { writable: [], readonly: [] },
  };
}

// Protobuf field descriptors are [name, scalar type or nested schema, repeated].
const PROTO_INSTRUCTION = {
  1: ['programIdIndex', 'varint'],
  2: ['accounts', 'bytes'],
  3: ['data', 'bytes'],
  4: ['stackHeight', 'varint'],
} as const satisfies ProtoSchema;
const PROTO_INNER = {
  1: ['index', 'varint'],
  2: ['instructions', PROTO_INSTRUCTION, true],
} as const satisfies ProtoSchema;
const PROTO_TOKEN_AMOUNT = {
  1: ['uiAmount', 'double'],
  2: ['decimals', 'varint'],
  3: ['amount', 'string'],
  4: ['uiAmountString', 'string'],
} as const satisfies ProtoSchema;
const PROTO_TOKEN_BALANCE = {
  1: ['accountIndex', 'varint'],
  2: ['mint', 'string'],
  3: ['uiTokenAmount', PROTO_TOKEN_AMOUNT],
  4: ['owner', 'string'],
  5: ['programId', 'string'],
} as const satisfies ProtoSchema;
const PROTO_REWARD = {
  1: ['pubkey', 'string'],
  2: ['lamports', 'varint'],
  3: ['postBalance', 'varint'],
  4: ['rewardType', 'varint'],
  5: ['commission', 'string'],
  6: ['commissionBps', 'string'],
} as const satisfies ProtoSchema;
const PROTO_REWARDS = {
  1: ['rewards', PROTO_REWARD, true],
  2: ['partitions', { 1: ['count', 'varint'] }],
} as const satisfies ProtoSchema;
const PROTO_META = {
  1: ['error', { 1: ['bytes', 'bytes'] }],
  2: ['fee', 'varint'],
  3: ['preBalances', 'varint', true],
  4: ['postBalances', 'varint', true],
  5: ['innerInstructions', PROTO_INNER, true],
  6: ['logMessages', 'string', true],
  7: ['preTokenBalances', PROTO_TOKEN_BALANCE, true],
  8: ['postTokenBalances', PROTO_TOKEN_BALANCE, true],
  9: ['rewards', PROTO_REWARD, true],
  10: ['innerInstructionsNone', 'varint'],
  11: ['logMessagesNone', 'varint'],
  12: ['loadedWritable', 'bytes', true],
  13: ['loadedReadonly', 'bytes', true],
  14: ['returnData', { 1: ['programId', 'bytes'], 2: ['data', 'bytes'] }],
  15: ['returnDataNone', 'varint'],
  16: ['computeUnitsConsumed', 'varint'],
  17: ['costUnits', 'varint'],
} as const satisfies ProtoSchema;

function protoKey(reader: Reader) {
  const key = reader.varint();
  check(key >= 8n && key <= 0xffffffffn, 'Invalid protobuf key');
  return [Number(key >> 3n), Number(key & 7n)];
}

function skipProto(reader: Reader, field: number, wire: number, depth: number) {
  switch (wire) {
    case 0:
      reader.varint();
      return;
    case 1:
      reader.take(8);
      return;
    case 2:
      reader.sized(reader.varint());
      return;
    case 3: {
      check(depth < 100, 'Protobuf group nesting limit exceeded');
      while (true) {
        const [tag, type] = protoKey(reader);
        if (type === 4) {
          check(tag === field, 'Mismatched protobuf group');
          return;
        }
        skipProto(reader, tag, type, depth + 1);
      }
    }
    case 5:
      reader.take(4);
      return;
    default:
      throw new Error('Invalid protobuf wire type');
  }
}

type ProtoScalar = 'varint' | 'double' | 'string' | 'bytes';
type ProtoSchema = { readonly [field: number]: readonly [string, ProtoScalar | ProtoSchema, true?] };
type ProtoValue<T> = T extends ProtoSchema ? Proto<T>
  : T extends 'varint' ? bigint
  : T extends 'double' ? number
  : T extends 'string' ? string
  : Bytes;
type Proto<S extends ProtoSchema> = {
  [D in S[keyof S & number] as D[0]]?: D extends readonly [string, unknown, true] ? ProtoValue<D[1]>[]
    : ProtoValue<D[1]>;
};
type WireValue = bigint | number | string | Bytes | WireMessage;
type WireMessage = { [name: string]: WireValue | WireValue[] | undefined };

function parseProto<S extends ProtoSchema>(bytes: Bytes, schema: S): Proto<S> {
  // Field names and types come from the same descriptors as the mapped result type.
  return protobuf(bytes, schema) as Proto<S>;
}

function protobuf(bytes: Bytes, schema: ProtoSchema, target: WireMessage = {}): WireMessage {
  const reader = new Reader(bytes);
  while (reader.left) {
    const [field, wire] = protoKey(reader);
    const descriptor = schema[field];
    if (!descriptor) {
      skipProto(reader, field, wire, 0);
      continue;
    }
    const [name, type, repeated] = descriptor;
    const prior = target[name];
    if (repeated && type === 'varint' && wire === 2) {
      const packed = new Reader(reader.sized(reader.varint()));
      const items = Array.isArray(prior) ? prior : [];
      while (packed.left) items.push(packed.varint());
      target[name] = items;
      continue;
    }
    const expectedWire = type === 'varint' ? 0 : type === 'double' ? 1 : 2;
    check(wire === expectedWire, `Wrong protobuf wire type for ${name}`);
    let value: WireValue;
    if (type === 'varint') value = reader.varint();
    else if (type === 'double') value = reader.f64();
    else {
      const payload = reader.sized(reader.varint());
      if (typeof type === 'object') {
        value = protobuf(payload, type, repeated ? undefined : prior as WireMessage);
      } else value = type === 'string' ? utf8.decode(payload) : payload;
    }
    if (repeated) {
      const items = Array.isArray(prior) ? prior : [];
      items.push(value);
      target[name] = items;
    } else target[name] = value;
  }
  return target;
}

const low8 = (value?: bigint) => Number((value ?? 0n) & 255n);
const low32 = (value: bigint) => Number(value & 0xffffffffn);

function protoReward(value: Proto<typeof PROTO_REWARD>) {
  const bps = parseUnsignedText(value.commissionBps ?? '', 65535n);
  const commission = parseUnsignedText(value.commission ?? '', 255n) ??
    (bps !== null && bps / 100n <= 255n ? bps / 100n : null);
  return {
    pubkey: value.pubkey ?? '',
    lamports: BigInt.asIntN(64, value.lamports ?? 0n),
    postBalance: value.postBalance ?? 0n,
    rewardType: REWARD_TYPES[low32(value.rewardType ?? 0n) - 1] ?? null,
    commission: commission === null ? null : Number(commission),
  };
}

function protoTokenBalance(balance: Proto<typeof PROTO_TOKEN_BALANCE>) {
  const amount = balance.uiTokenAmount ?? {};
  const uiAmount = Math.abs(amount.uiAmount ?? 0) > Number.EPSILON ? amount.uiAmount! : null;
  return tokenBalance(
    low8(balance.accountIndex),
    balance.mint ?? '',
    uiAmount,
    low8(amount.decimals),
    amount.amount ?? '',
    balance.owner,
    balance.programId,
    amount.uiAmountString,
  );
}

function protoMeta(value: Proto<typeof PROTO_META>): Meta {
  const inner = value.innerInstructionsNone ? null : (value.innerInstructions ?? []).map((group) => ({
    index: low8(group.index),
    instructions: (group.instructions ?? []).map((ix) => ({
      programIdIndex: low8(ix.programIdIndex),
      accounts: ix.accounts ?? EMPTY,
      data: ix.data ?? EMPTY,
      stackHeight: ix.stackHeight === undefined ? null : low32(ix.stackHeight),
    })),
  }));
  return {
    err: value.error ? transactionError(new Reader(value.error.bytes ?? EMPTY)) : null,
    fee: value.fee ?? 0n,
    preBalances: value.preBalances ?? [],
    postBalances: value.postBalances ?? [],
    innerInstructions: inner,
    logMessages: value.logMessagesNone ? null : (value.logMessages ?? []),
    preTokenBalances: (value.preTokenBalances ?? []).map(protoTokenBalance),
    postTokenBalances: (value.postTokenBalances ?? []).map(protoTokenBalance),
    rewards: (value.rewards ?? []).map(protoReward),
    loadedAddresses: {
      writable: (value.loadedWritable ?? []).map(pubkey),
      readonly: (value.loadedReadonly ?? []).map(pubkey),
    },
    returnData: value.returnDataNone || !value.returnData ? undefined : {
      programId: pubkey(value.returnData.programId),
      data: [base64(value.returnData.data ?? EMPTY), 'base64'],
    },
    computeUnitsConsumed: value.computeUnitsConsumed,
    costUnits: value.costUnits,
  };
}

function storedReward(reader: Reader, extended = true) {
  const pubkey = reader.string();
  const lamports = reader.i64();
  const postBalance = extended && !reader.left ? 0n : reader.u64();
  const rewardType = extended && !reader.left ? null : reader.option((r) => {
    const kind = REWARD_TYPES[r.u32()];
    check(kind, 'Unknown RewardType variant');
    return kind;
  });
  const commission = extended && reader.left ? reader.option((r) => r.u8()) : null;
  return { pubkey, lamports, postBalance, rewardType, commission };
}

function storedTokenBalance(reader: Reader, tokenLayout: number) {
  const index = reader.u8();
  const mint = reader.string();
  const uiAmount = reader.f64();
  const decimals = reader.u8();
  const amount = reader.string();
  const owner = tokenLayout >= 2 && reader.left ? reader.string() : '';
  const programId = tokenLayout >= 3 && reader.left ? reader.string() : '';
  return tokenBalance(index, mint, uiAmount, decimals, amount, owner, programId);
}

function storedMeta(reader: Reader, legacy: boolean, tokenLayout: number) {
  const status = reader.u32();
  check(status <= 1, 'Invalid bincode result tag');
  const meta = emptyMeta();
  meta.err = status ? transactionError(reader) : null;
  meta.fee = reader.u64();
  meta.preBalances = reader.vec((r) => r.u64(), 8);
  meta.postBalances = reader.vec((r) => r.u64(), 8);

  const optional = <T>(read: (reader: Reader) => T) => reader.left ? reader.option(read) : null;
  meta.innerInstructions = optional((r) =>
    r.vec((group) => ({
      index: group.u8(),
      instructions: group.vec((item) => {
        const ix = compiledInstruction(item, null);
        if (!legacy) ix.stackHeight = item.option((t) => t.u32());
        return ix;
      }, legacy ? 3 : 4),
    }), 9)
  );
  meta.logMessages = optional((r) => r.vec((item) => item.string(), 8));
  meta.preTokenBalances = optional((r) => r.vec((item) => storedTokenBalance(item, tokenLayout)));
  meta.postTokenBalances = optional((r) => r.vec((item) => storedTokenBalance(item, tokenLayout)));
  meta.rewards = optional((r) => r.vec((item) => storedReward(item), 16));
  meta.returnData = optional((r) => ({
    programId: pubkey(r.take(32)),
    data: [base64(r.sized(r.u64())), 'base64'],
  })) ?? undefined;
  meta.computeUnitsConsumed = optional((r) => r.u64()) ?? undefined;
  meta.costUnits = optional((r) => r.u64()) ?? undefined;
  return meta;
}

function strictBincode<T>(bytes: Bytes, layouts: ((reader: Reader) => T)[], lenient: (reader: Reader) => T) {
  for (const read of layouts) {
    const reader = new Reader(bytes);
    try {
      const result = read(reader);
      if (!reader.left) return result;
    } catch {
      // Older records omit fields or use different layouts.
    }
  }
  return lenient(new Reader(bytes));
}

function bincodeMeta(bytes: Bytes) {
  const current = (reader: Reader) => storedMeta(reader, false, 3);
  const legacy = [1, 2, 3].map((layout) => (reader: Reader) => storedMeta(reader, true, layout));
  return strictBincode(bytes, [current, ...legacy], current);
}

type Rewards = { rewards: ReturnType<typeof storedReward>[]; numRewardPartitions?: bigint };

function bincodeRewards(bytes: Bytes): Rewards {
  const current = (reader: Reader) => reader.vec((item) => storedReward(item), 16);
  const legacy = (reader: Reader) => reader.vec((item) => storedReward(item, false), 25);
  return { rewards: strictBincode(bytes, [current, legacy], current) };
}

function decodePayload<S extends ProtoSchema, T>(
  slot: bigint,
  bytes: Bytes,
  schema: S,
  convert: (message: Proto<S>) => T,
  bincode: (bytes: Bytes) => T,
) {
  // A protobuf conversion error is final once the wire message was parsed.
  if (slot < BINCODE_CUTOFF) {
    try {
      return bincode(bytes);
    } catch { /* Try the newer codec. */ }
    return convert(parseProto(bytes, schema));
  }
  let message;
  try {
    message = parseProto(bytes, schema);
  } catch {
    return bincode(bytes);
  }
  return convert(message);
}

// RFC 8878 frame headers bound the window and identify complete native inputs.
const ZSTD_MAGIC = 0xfd2fb528;
const ZSTD_BLOCK_MAX = 128 * 1024;
const ZSTD_WINDOW_MAX = 128 * MiB;

function nextFrame(reader: Reader): { size: number | null; window: number; checksum: boolean } | null {
  const magic = reader.u32();
  if ((magic & 0xfffffff0) === 0x184d2a50) {
    reader.take(reader.u32());
    return null;
  }
  check(magic === ZSTD_MAGIC, 'Invalid Zstd frame magic');
  const descriptor = reader.u8();
  check(!(descriptor & 8), 'Reserved Zstd frame bit set');
  const single = Boolean(descriptor & 32);
  let window = 0;
  if (!single) {
    const descriptor = reader.u8();
    const base = 2 ** (10 + (descriptor >> 3));
    window = base + (base / 8) * (descriptor & 7);
  }
  const dictionary = reader.take([0, 1, 2, 4][descriptor & 3]);
  check(dictionary.every((byte) => byte === 0), 'Zstd dictionaries are unsupported');
  const sizeBytes = [single ? 1 : 0, 2, 4, 8][descriptor >> 6];
  let size: number | null = null;
  if (sizeBytes === 8) {
    const value = reader.u64();
    check(value <= BigInt(MAX_DECOMPRESSED), 'Zstd frame content size exceeds limit');
    size = Number(value);
  } else if (sizeBytes) {
    size = littleEndian(reader.take(sizeBytes), 0, sizeBytes) + (sizeBytes === 2 ? 256 : 0);
  }
  if (single) window = size!;
  check(window <= ZSTD_WINDOW_MAX, 'Zstd frame window exceeds limit');
  return { size, window, checksum: Boolean(descriptor & 4) };
}

function littleEndian(bytes: Bytes, start: number, width: number): number {
  let value = 0;
  for (let i = width - 1; i >= 0; i--) value = value * 256 + bytes[start + i];
  return value;
}

declare const Bun: { zstdDecompressSync(input: Bytes): Uint8Array };

function blockHeader(reader: Reader, max: number) {
  const header = littleEndian(reader.take(3), 0, 3);
  const kind = (header >>> 1) & 3;
  const size = header >>> 3;
  check(kind !== 3 && size <= max && (kind !== 2 || size >= 2), 'Invalid Zstd block header');
  reader.take(kind === 1 ? 1 : size);
  return { last: Boolean(header & 1), maxOutput: kind === 2 ? max : size };
}

// Feed one complete block at a time for frames whose worst-case expansion
// exceeds the remaining budget. Counting output after a sync decode would
// be too late for these frames, including frames without a content size.
function frameStream(bytes: Bytes, headerEnd: number, blockMax: number): ReadableStream<Bytes> {
  const reader = new Reader(bytes);
  let last = false;
  return new ReadableStream({
    start(controller) {
      controller.enqueue(reader.take(headerEnd));
    },
    pull(controller) {
      if (last) {
        if (reader.left) controller.enqueue(reader.take(reader.left));
        controller.close();
        return;
      }
      const start = reader.pos;
      last = blockHeader(reader, blockMax).last;
      controller.enqueue(bytes.subarray(start, reader.pos));
    },
  });
}

async function decompress(bytes: Bytes): Promise<Bytes> {
  const reader = new Reader(bytes);
  const frames: Bytes[] = [];
  let total = 0;
  // Preflight frame boundaries before invoking native code. Each invocation
  // gets exactly one frame, including its checksum, and skippable frames
  // never enter the native decoder.
  while (reader.left) {
    const start = reader.pos;
    const frame = nextFrame(reader);
    if (!frame) continue;
    const budget = MAX_DECOMPRESSED - total;
    check(frame.size === null || frame.size <= budget, 'Zstd frame content size exceeds limit');
    const headerEnd = reader.pos - start;
    const blockMax = Math.min(frame.window, ZSTD_BLOCK_MAX);
    let upperBound = 0;
    for (;;) {
      const block = blockHeader(reader, blockMax);
      upperBound += block.maxOutput;
      if (block.last) break;
    }
    if (frame.checksum) reader.take(4);
    const encoded = bytes.subarray(start, reader.pos);
    let output: Bytes;
    if (upperBound <= budget) {
      const native = Bun.zstdDecompressSync(encoded);
      // Bun returns a Uint8Array backed by a regular ArrayBuffer.
      check(native.buffer instanceof ArrayBuffer, 'Unexpected native buffer');
      output = new Uint8Array(native.buffer, native.byteOffset, native.byteLength);
    } else {
      const stream = frameStream(encoded, headerEnd, blockMax).pipeThrough(
        new DecompressionStream('zstd' as CompressionFormat),
      );
      const body = await readBody(stream, Math.min(frame.size ?? budget, budget));
      output = body.bytes;
    }
    check(
      output.length <= budget && (frame.size === null || output.length === frame.size),
      'Zstd frame output size mismatch',
    );
    total += output.length;
    if (output.length) frames.push(output);
  }
  return joinBytes(frames, total);
}

async function unwrapFrame<T>(bytes: Bytes, decode: (plain: Bytes) => T): Promise<T> {
  if (bytes.length >= 4 && new Reader(bytes).u32() === ZSTD_MAGIC) {
    let plain: Bytes;
    try {
      plain = await decompress(bytes);
    } catch {
      return decode(bytes);
    }
    return decode(plain);
  }
  try {
    return decode(bytes);
  } catch (error) {
    let plain: Bytes;
    try {
      plain = await decompress(bytes);
    } catch {
      throw error;
    }
    return decode(plain);
  }
}

function metadata(slot: bigint, bytes: Bytes): Promise<Meta> | null {
  return bytes.length
    ? unwrapFrame(bytes, (plain) => decodePayload(slot, plain, PROTO_META, protoMeta, bincodeMeta))
    : null;
}

function rewards(slot: bigint, bytes: Bytes): Promise<Rewards> | Rewards {
  if (!bytes.length) return { rewards: [] };
  return unwrapFrame(bytes, (plain) =>
    decodePayload(slot, plain, PROTO_REWARDS, (value) => ({
      rewards: (value.rewards ?? []).map(protoReward),
      numRewardPartitions: value.partitions ? value.partitions.count ?? 0n : undefined,
    }), bincodeRewards));
}

const UPGRADEABLE_LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111';
const RESERVED_ACCOUNTS = new Set(
  `
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
`.trim().split(/\s+/),
);

type Transaction = ReturnType<typeof transaction>;

function parsedAccounts(tx: Transaction, loaded: Addresses) {
  const { accountKeys, header, instructions } = tx;
  const writable = tx.version === 0 ? loaded.writable : [];
  const readonly = tx.version === 0 ? loaded.readonly : [];
  const keys = [...accountKeys, ...writable, ...readonly];
  const programs = new Set(instructions.map((ix) => ix.programIdIndex));
  const upgradeable = keys.includes(UPGRADEABLE_LOADER);
  const signers = header.numRequiredSignatures;
  const staticCount = accountKeys.length;
  return keys.map((pubkey, i) => {
    const fromLookup = i >= staticCount;
    const writableIndex = fromLookup
      ? i - staticCount < writable.length
      : i < signers
      ? i < signers - header.numReadonlySignedAccounts
      : i < staticCount - header.numReadonlyUnsignedAccounts;
    return {
      pubkey,
      signer: i < signers,
      writable: writableIndex && !RESERVED_ACCOUNTS.has(pubkey) && (upgradeable || !programs.has(i)),
      source: fromLookup ? 'lookupTable' : 'transaction',
    };
  });
}

function instructionJson(ix: Instruction, keys?: string[]) {
  const { programIdIndex, stackHeight } = ix;
  const data = base58(ix.data);
  if (!keys) return { programIdIndex, accounts: Array.from(ix.accounts), data, stackHeight };
  const address = (index: number) => {
    check(index < keys.length, 'Instruction account index out of range');
    return keys[index];
  };
  return {
    programId: address(programIdIndex),
    accounts: Array.from(ix.accounts, address),
    data,
    stackHeight,
  };
}

function transactionJson(tx: Transaction, meta: Meta | null, options: BlockOptions) {
  const { version } = tx;
  if (version !== 'legacy') {
    if (options.maxVersion === null || version > options.maxVersion) {
      throw new RpcError(-32015, `Transaction version (${version}) requires "maxSupportedTransactionVersion": ${version}`);
    }
    meta ??= emptyMeta();
  }
  const { encoding, details } = options;
  const parsed = encoding === 'jsonParsed';
  const accountsOnly = details === 'accounts';
  const loaded = meta?.loadedAddresses ?? { writable: [], readonly: [] };
  const accounts = parsed || accountsOnly ? parsedAccounts(tx, loaded) : undefined;
  const keys = parsed ? accounts?.map((account) => account.pubkey) : undefined;
  let transaction;
  if (encoding === 'base64' || encoding === 'base58') {
    transaction = [encoding === 'base64' ? base64(tx.raw) : base58(tx.raw), encoding];
  } else {
    const signatures = tx.signatures.map(base58);
    const accountKeys = accounts ?? tx.accountKeys;
    transaction = accountsOnly ? { signatures, accountKeys } : {
      signatures,
      message: {
        header: parsed ? undefined : tx.header,
        accountKeys,
        recentBlockhash: tx.recentBlockhash,
        instructions: tx.instructions.map((ix) => instructionJson(ix, keys)),
        addressTableLookups: tx.addressTableLookups,
        transactionConfig: tx.transactionConfig,
      },
    };
  }
  const outputMeta = meta && {
    err: meta.err,
    status: meta.err === null ? { Ok: null } : { Err: meta.err },
    fee: meta.fee,
    preBalances: meta.preBalances,
    postBalances: meta.postBalances,
    preTokenBalances: meta.preTokenBalances,
    postTokenBalances: meta.postTokenBalances,
    rewards: options.rewards ? meta.rewards : accountsOnly ? undefined : null,
    ...(!accountsOnly && {
      innerInstructions: meta.innerInstructions?.map((group) => ({
        index: group.index,
        instructions: group.instructions.map((ix) => instructionJson(ix, keys)),
      })) ?? null,
      logMessages: meta.logMessages,
      loadedAddresses: parsed ? undefined : meta.loadedAddresses,
      returnData: meta.returnData,
      computeUnitsConsumed: meta.computeUnitsConsumed,
      costUnits: meta.costUnits,
    }),
  };
  return {
    transaction,
    meta: outputMeta,
    version: meta && options.maxVersion !== null ? tx.version : undefined,
  };
}

// Map insertion order doubles as the eviction order.
class Lru<K, V> {
  private readonly items = new Map<K, V>();

  get(key: K): V | undefined {
    const value = this.items.get(key);
    if (value !== undefined) {
      this.items.delete(key);
      this.items.set(key, value);
    }
    return value;
  }

  set(key: K, value: V): void {
    this.items.delete(key);
    this.items.set(key, value);
    if (this.items.size > 100_000) {
      const oldest = this.items.keys().next();
      if (!oldest.done) this.items.delete(oldest.value);
    }
  }
}

class AttemptPool {
  private active = 0;
  private readonly waiting: (() => void)[] = [];

  async run<T>(attempt: () => Promise<T>): Promise<T> {
    if (this.active >= 32) await new Promise<void>((resolve) => this.waiting.push(resolve));
    else this.active++;
    try {
      return await attempt();
    } finally {
      const next = this.waiting.shift();
      if (next) next();
      else this.active--;
    }
  }
}

export class BodyTooLarge extends Error {}

export async function readBody(
  stream: ReadableStream<Bytes> | null,
  cap: number,
  keep = cap,
): Promise<{ length: number; bytes: Bytes }> {
  if (!stream) return { length: 0, bytes: EMPTY };
  const reader = stream.getReader();
  const chunks: Bytes[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > cap) {
        void reader.cancel().catch(() => {});
        throw new BodyTooLarge();
      }
      if (length <= keep) chunks.push(value);
      else chunks.length = 0;
    }
  } finally {
    reader.releaseLock();
  }
  return { length, bytes: joinBytes(chunks, length <= keep ? length : 0) };
}

type RangeReply = { body: Bytes } | { status: number; retryAfter: string | null };
type RangeEntry = { offset: bigint; length: number };

function retryDelay(header: string | null | undefined, attempt: number): number {
  if (header) {
    if (/^[0-9]+$/.test(header)) return Math.min(10_000, Number(header) * 1000);
    const date = /^[A-Za-z]+[, ]/.test(header) ? Date.parse(header) : NaN;
    if (Number.isFinite(date)) return Math.max(0, Math.min(10_000, date - Date.now()));
  }
  return 200 * (2 ** attempt) * (0.5 + Math.random() * 0.5);
}

function waitForRetry(delay: number, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', abort);
      resolve();
    }, delay);
    signal.addEventListener('abort', abort, { once: true });
  });
}

export class Archive {
  private readonly ranges = new Lru<bigint, RangeEntry>();
  private readonly hashes = new Lru<bigint, string>();
  private readonly attempts = new AttemptPool();

  constructor(
    private readonly base: URL,
    private readonly signal: AbortSignal,
  ) {}

  private async attempt(
    url: URL,
    start: bigint,
    end: bigint,
    length: number,
    cap: number,
  ): Promise<RangeReply> {
    const response = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.any([this.signal, AbortSignal.timeout(60_000)]),
      headers: {
        Range: `bytes=${start}-${end}`,
        'User-Agent': 'onlyblocks/bun',
        'Accept-Encoding': 'identity',
        Connection: 'close',
      },
    });
    if (response.status !== 206) {
      void response.body?.cancel().catch(() => {});
      return { status: response.status, retryAfter: response.headers.get('retry-after') };
    }
    const contentEncoding = response.headers.get('content-encoding');
    if (
      Number(response.headers.get('content-length')) > cap ||
      (contentEncoding && contentEncoding !== 'identity')
    ) {
      void response.body?.cancel().catch(() => {});
      throw new RpcError(-32603, 'Invalid archive range headers');
    }
    try {
      const body = await readBody(response.body, cap, length);
      if (body.length !== length) throw new RpcError(-32603, 'Archive range body has the wrong length');
      return { body: body.bytes };
    } catch (error) {
      if (error instanceof BodyTooLarge) throw new RpcError(-32603, 'Archive body exceeds range cap');
      throw error;
    }
  }

  private async readRange(
    slot: bigint,
    suffix: string,
    start: bigint,
    length: number,
    cap: number,
  ): Promise<Bytes> {
    const end = start + BigInt(length) - 1n;
    check(end <= U64_MAX, 'Archive range end overflows u64');
    const epoch = slot / SLOTS_PER_EPOCH;
    const url = new URL(this.base);
    url.pathname = `${url.pathname.replace(/\/+$/, '')}/${epoch}/epoch-${epoch}${suffix}`;
    for (let attempt = 0; attempt < 5; attempt++) {
      this.signal.throwIfAborted();
      let reply: RangeReply | undefined;
      try {
        reply = await this.attempts.run(() => this.attempt(url, start, end, length, cap));
      } catch (error) {
        if (error instanceof RpcError) throw error;
        // Fetch rejects both transport failures and prematurely closed framed bodies.
      }
      if (reply && 'body' in reply) return reply.body;
      if (reply?.status === 404) {
        throw new RpcError(-32004, `Block not available for slot ${slot}: epoch ${epoch} is not archived`);
      }
      if (reply && reply.status !== 429 && (reply.status < 500 || reply.status >= 600)) {
        throw new RpcError(-32603, `Unexpected archive HTTP status ${reply.status}`);
      }
      if (attempt < 4) {
        const delay = retryDelay(reply?.retryAfter, attempt);
        if (delay > 0) await waitForRetry(delay, this.signal);
      }
    }
    throw new RpcError(-32603, 'Archive range retries exhausted');
  }

  private async loadBlock(slot: bigint) {
    let range = this.ranges.get(slot);
    if (range === undefined) {
      const start = (slot % SLOTS_PER_EPOCH) * 12n;
      const record = new Reader(await this.readRange(slot, '-slot-ranges.raw', start, 12, 12));
      range = { offset: record.u64(), length: record.u32() };
      this.ranges.set(slot, range);
    }
    if (!range.length) {
      throw new RpcError(-32007, `Slot ${slot} was skipped, or missing in long-term storage`);
    }
    check(range.length <= MAX_SLICE, 'Archive slice exceeds 128 MiB');
    return indexCar(await this.readRange(slot, '.car', range.offset, range.length, MAX_SLICE));
  }

  private rememberHash(slot: bigint, index: CarIndex, entries: string[]): string {
    const last = entries.at(-1);
    const hash = last === undefined ? ZERO_HASH : pubkey(entryNode(index, last).hash);
    this.hashes.set(slot, hash);
    return hash;
  }

  private async previousHash(slot: bigint, parentSlot: bigint): Promise<string> {
    if (slot === 0n) return ZERO_HASH;
    const cached = this.hashes.get(parentSlot);
    if (cached !== undefined) return cached;
    const { index, block } = await this.loadBlock(parentSlot);
    check(unsigned(block[1]) !== null, 'Missing parent Block slot');
    return this.rememberHash(parentSlot, index, links(block[3]));
  }

  async getBlock(slot: bigint, options: BlockOptions) {
    const { index, block } = await this.loadBlock(slot);
    check(block[1] === slot, 'Block slot differs from requested slot');
    const entries = links(block[3]);
    const info: Cbor[] = Array.isArray(block[4]) ? block[4] : [];
    const parentSlot = unsigned(info[0]) ?? 0n;
    const blockhash = this.rememberHash(slot, index, entries);
    const result: BlockResult = {
      previousBlockhash: await this.previousHash(slot, parentSlot),
      blockhash,
      parentSlot,
      blockTime: signed(info[1]) || null,
      blockHeight: unsigned(info[2]),
    };
    if (options.details !== 'none') {
      const signatures: string[] = [];
      const transactions: ReturnType<typeof transactionJson>[] = [];
      for (const key of entries) {
        for (const txKey of links(entryNode(index, key).transactions)) {
          const node = indexedNode(index, txKey, 0n);
          const tx = transaction(framePayload(index, node[1]));
          if (options.details === 'signatures') {
            check(tx.signatures.length, 'Transaction has no signature');
            signatures.push(base58(tx.signatures[0]));
          } else {
            const meta = Array.isArray(node[2]) ? await metadata(slot, framePayload(index, node[2])) : null;
            transactions.push(transactionJson(tx, meta, options));
          }
        }
      }
      if (options.details === 'signatures') result.signatures = signatures;
      else result.transactions = transactions;
    }
    if (options.rewards) {
      const cid = block[5] instanceof Uint8Array ? link(block[5]) : null;
      const node = cid && !cid.absent && index.has(cid.key) ? indexedNode(index, cid.key, 5n) : [];
      Object.assign(result, await rewards(slot, node.length > 2 ? framePayload(index, node[2]) : EMPTY));
    }
    return result;
  }
}

function entryNode(index: CarIndex, key: string) {
  const entry = indexedNode(index, key, 1n);
  const hash = entry[2];
  check(hash instanceof Uint8Array && hash.length === 32, 'Invalid Entry hash');
  return { hash, transactions: entry[3] };
}

type BlockResult = Partial<Rewards> & {
  previousBlockhash: string;
  blockhash: string;
  parentSlot: bigint;
  blockTime: bigint | null;
  blockHeight: bigint | null;
  transactions?: ReturnType<typeof transactionJson>[];
  signatures?: string[];
};

export const ENCODINGS = ['json', 'jsonParsed', 'base64', 'base58'] as const;
export const DETAILS = ['full', 'accounts', 'signatures', 'none'] as const;
export type BlockOptions = {
  encoding: typeof ENCODINGS[number];
  details: typeof DETAILS[number];
  rewards: boolean;
  maxVersion: bigint | null;
};
