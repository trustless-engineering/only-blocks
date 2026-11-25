import http from 'node:http';
import https from 'node:https';
import { setTimeout as delay } from 'node:timers/promises';
import { constants as zstd, zstdDecompressSync } from 'node:zlib';

const MiB = 1024 * 1024;
const MAX_SLICE = 128 * MiB;
const MAX_DECOMPRESSED = 512 * MiB;
const U64_MAX = (1n << 64n) - 1n;
const SLOTS_PER_EPOCH = 432000n;
const BINCODE_CUTOFF = 157n * SLOTS_PER_EPOCH;
const EMPTY = Buffer.alloc(0);
const ZERO_HASH = '1'.repeat(32);
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

class RpcError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function check(condition, message) {
  if (!condition) throw new Error(message);
}

// Offsets are relative to the enclosing section or field, even for Buffer views.
class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = 0;
  }

  get left() { return this.bytes.length - this.pos; }
  peek() { return this.bytes[this.pos]; }

  take(count) {
    check(count >= 0 && count <= this.left, 'Truncated binary value');
    const start = this.pos;
    this.pos += count;
    return this.bytes.subarray(start, this.pos);
  }

  fixed(getter, size, littleEndian = true) {
    check(size <= this.left, 'Truncated fixed-width integer');
    const value = this.view[getter](this.pos, littleEndian);
    this.pos += size;
    return value;
  }

  u8() { return this.fixed('getUint8', 1); }
  u16() { return this.fixed('getUint16', 2); }
  u32() { return this.fixed('getUint32', 4); }
  u64() { return this.fixed('getBigUint64', 8); }
  i64() { return this.fixed('getBigInt64', 8); }
  f64() { return this.fixed('getFloat64', 8); }

  varint() {
    let value = 0n;
    for (let shift = 0n; shift <= 63n; shift += 7n) {
      const byte = this.u8();
      check(shift < 63n || byte <= 1, 'Varint overflow');
      value |= BigInt(byte & 0x7f) << shift;
      if (byte < 128) return value;
    }
  }

  sized(length) {
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
  }

  list(count, read, minSize = 1) {
    check(count <= Math.floor(this.left / minSize), 'Count exceeds enclosing field');
    const items = [];
    for (let i = 0; i < count; i++) items.push(read(this));
    return items;
  }

  vec(read, minSize = 1) {
    const count = this.u64();
    check(count <= BigInt(this.left), 'Vector length exceeds input');
    return this.list(Number(count), read, minSize);
  }

  string() { return utf8.decode(this.sized(this.u64())); }

  option(read) {
    const tag = this.u8();
    check(tag <= 1, 'Invalid bincode option tag');
    return tag ? read(this) : null;
  }
}

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58(bytes) {
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
  return '1'.repeat(zeros) + digits.reverse().map(digit => BASE58[digit]).join('');
}

function pubkey(bytes) {
  check(bytes?.length === 32, 'Expected a 32-byte public key or hash');
  return base58(bytes);
}

function base64(bytes) {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
}

function cborArgument(reader, info) {
  if (info < 24) return BigInt(info);
  switch (info) {
    case 24: return BigInt(reader.u8());
    case 25: return BigInt(reader.fixed('getUint16', 2, false));
    case 26: return BigInt(reader.fixed('getUint32', 4, false));
    case 27: return reader.fixed('getBigUint64', 8, false);
    case 31: return null;
    default: throw new Error('Reserved CBOR argument');
  }
}

function cborItem(reader, depth = 0) {
  check(depth <= 128, 'CBOR nesting limit exceeded');
  const head = reader.u8();
  const major = head >> 5;
  const info = head & 31;
  if (major === 7) {
    switch (info) {
      case 20: return false;
      case 21: return true;
      case 22:
      case 23: return null;
      case 25: return reader.fixed('getFloat16', 2, false);
      case 26: return reader.fixed('getFloat32', 4, false);
      case 27: return reader.fixed('getFloat64', 8, false);
      default: throw new Error('Unsupported CBOR simple value');
    }
  }
  const arg = cborArgument(reader, info);
  check(arg !== null || (major >= 2 && major <= 5), 'Invalid indefinite CBOR item');
  if (major === 0) return arg;
  if (major === 1) return -1n - arg;
  if (major === 6) return cborItem(reader, depth + 1);

  if (major === 2 || major === 3) {
    if (arg !== null) {
      const bytes = reader.sized(arg);
      return major === 2 ? bytes : utf8.decode(bytes);
    }
    const chunks = [];
    while (reader.peek() !== 0xff) {
      const chunk = reader.u8();
      check(chunk >> 5 === major && (chunk & 31) !== 31, 'Invalid CBOR string chunk');
      const bytes = reader.sized(cborArgument(reader, chunk & 31));
      chunks.push(major === 2 ? bytes : utf8.decode(bytes));
    }
    reader.u8();
    return major === 2 ? Buffer.concat(chunks) : chunks.join('');
  }

  const array = major === 4;
  const value = array ? [] : new Map();
  if (arg !== null) check(arg * (array ? 1n : 2n) <= BigInt(reader.left), 'CBOR count exceeds input');
  for (let i = 0; arg === null ? reader.peek() !== 0xff : i < Number(arg); i++) {
    const item = cborItem(reader, depth + 1);
    if (array) value.push(item);
    else value.set(item, cborItem(reader, depth + 1));
  }
  if (arg === null) reader.u8();
  return value;
}

function cbor(bytes) {
  const reader = new Reader(bytes);
  const value = cborItem(reader);
  check(!reader.left, 'Trailing CBOR bytes');
  return value;
}

function readCid(reader) {
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
  return { key: reader.bytes.subarray(start, reader.pos).toString('hex'), absent };
}

function link(value) {
  check(Buffer.isBuffer(value) && value[0] === 0, 'Invalid CID link');
  return readCid(new Reader(value.subarray(1)));
}

function links(items) {
  return Array.isArray(items) ? items.map(item => link(item).key) : [];
}

function isCarHeader(bytes) {
  if (bytes[0] >> 5 !== 5) return false;
  try {
    const header = cbor(bytes);
    return header instanceof Map && header.has('version');
  } catch {
    return false;
  }
}

function indexCar(bytes) {
  const reader = new Reader(bytes);
  const index = new Map();
  let block;
  let first = true;
  while (reader.left) {
    const size = reader.varint();
    if (size === 0n) continue;
    check(size <= 32n * BigInt(MiB), 'Oversize CAR section');
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

function requireKind(node, kind) {
  check(Array.isArray(node) && node[0] === kind, `Expected IPLD node kind ${kind}`);
  return node;
}

function indexedNode(index, key, kind) {
  const bytes = index.get(key);
  check(bytes, 'CID missing from CAR slice');
  return requireKind(cbor(bytes), kind);
}

function unsigned(value) {
  return typeof value === 'bigint' && value >= 0n ? value : null;
}

function signed(value) {
  return typeof value === 'bigint' && BigInt.asIntN(64, value) === value ? value : null;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, byte) => {
  let crc = BigInt(byte);
  for (let i = 0; i < 8; i++) crc = (crc >> 1n) ^ (crc & 1n ? 0xd800000000000000n : 0n);
  return crc;
});

function crc64(bytes) {
  let crc = U64_MAX;
  for (const byte of bytes) crc = (crc >> 8n) ^ CRC_TABLE[Number(crc & 255n) ^ byte];
  return crc ^ U64_MAX;
}

function fnv1a(bytes) {
  let hash = 0xcbf29ce484222325n;
  for (const byte of bytes) hash = ((hash ^ BigInt(byte)) * 0x100000001b3n) & U64_MAX;
  return hash;
}

function framePayload(index, root) {
  requireKind(root, 6n);
  const bytes = Buffer.isBuffer(root[4]) ? root[4] : EMPTY;
  const stack = links(root[5]).reverse();
  let result = bytes;
  if (stack.length) {
    const chunks = [bytes];
    const seen = new Set();
    while (stack.length) {
      const key = stack.pop();
      check(!seen.has(key), 'Repeated DataFrame CID');
      seen.add(key);
      const frame = indexedNode(index, key, 6n);
      if (Buffer.isBuffer(frame[4])) chunks.push(frame[4]);
      const next = links(frame[5]);
      for (let i = next.length - 1; i >= 0; i--) stack.push(next[i]);
    }
    result = Buffer.concat(chunks);
  }
  const expected = unsigned(root[1]);
  check(expected === null || crc64(result) === expected || fnv1a(result) === expected, 'DataFrame hash mismatch');
  return result;
}

function compiledInstruction(reader, stackHeight) {
  return {
    programIdIndex: reader.u8(),
    accounts: reader.take(reader.compact()),
    data: reader.take(reader.compact()),
    stackHeight,
  };
}

function transactionV1(reader) {
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
  const accountKeys = reader.list(reader.u8(), r => pubkey(r.take(32)), 32);
  const transactionConfig = {
    priorityFee: priorityBits === 0x03 ? reader.u64() : null,
    computeUnitLimit: mask & 0x04 ? reader.u32() : null,
    loadedAccountsDataSizeLimit: mask & 0x08 ? reader.u32() : null,
    heapSize: mask & 0x10 ? reader.u32() : null,
  };
  // All headers precede the payloads, which are laid out in instruction order.
  const instructionHeaders = reader.list(instructionCount, r => ({
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
  const signatures = reader.list(header.numRequiredSignatures, r => r.take(64), 64);
  return { version: 1, signatures, header, accountKeys, recentBlockhash, instructions,
    transactionConfig, raw: reader.bytes.subarray(0, reader.pos) };
}

function transaction(bytes) {
  const reader = new Reader(bytes);
  const discriminator = reader.u8();
  if (discriminator === 0x81) return transactionV1(reader);
  check(discriminator < 0x80, 'Invalid transaction discriminator');
  const signatures = reader.list(discriminator, r => r.take(64), 64);
  const prefix = reader.u8();
  check(prefix <= 128, 'Unsupported transaction wire version');
  const version = prefix === 128 ? 0 : 'legacy';
  const header = {
    numRequiredSignatures: version === 0 ? reader.u8() : prefix,
    numReadonlySignedAccounts: reader.u8(),
    numReadonlyUnsignedAccounts: reader.u8(),
  };
  const accountKeys = reader.list(reader.compact(), r => pubkey(r.take(32)), 32);
  const recentBlockhash = pubkey(reader.take(32));
  const instructions = reader.list(reader.compact(), r => compiledInstruction(r, 1), 3);
  const addressTableLookups = version === 0 ? reader.list(reader.compact(), r => ({
    accountKey: pubkey(r.take(32)),
    writableIndexes: Array.from(r.take(r.compact())),
    readonlyIndexes: Array.from(r.take(r.compact())),
  }), 34) : undefined;
  return { version, signatures, header, accountKeys, recentBlockhash, instructions,
    addressTableLookups, raw: bytes.subarray(0, reader.pos) };
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

function transactionError(reader) {
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
    case 30: return { DuplicateInstruction: reader.u8() };
    case 31:
    case 35: return { [name]: { account_index: reader.u8() } };
    default: return name;
  }
}

function parseUnsignedText(value, max = U64_MAX) {
  if (!/^\+?[0-9]+$/.test(value)) return null;
  const digits = value.replace(/^\+?0*/, '');
  if (digits.length > 20) return null;
  const number = BigInt(digits);
  return number <= max ? number : null;
}

function uiAmountString(amount, decimals) {
  const digits = String(parseUnsignedText(amount) ?? 0n);
  if (!decimals) return digits;
  const padded = digits.padStart(decimals + 1, '0');
  return `${padded.slice(0, -decimals)}.${padded.slice(-decimals)}`.replace(/0+$/, '').replace(/\.$/, '');
}

function tokenBalance(accountIndex, mint, uiAmount, decimals, amount, owner, programId, displayAmount) {
  return {
    accountIndex, mint,
    uiTokenAmount: { uiAmount, decimals, amount, uiAmountString: displayAmount || uiAmountString(amount, decimals) },
    owner: owner || undefined,
    programId: programId || undefined,
  };
}

const REWARD_TYPES = ['Fee', 'Rent', 'Staking', 'Voting'];

function emptyMeta() {
  return {
    err: null, fee: 0n, preBalances: [], postBalances: [],
    innerInstructions: null, logMessages: null, preTokenBalances: null, postTokenBalances: null,
    rewards: null, loadedAddresses: { writable: [], readonly: [] },
  };
}

// Protobuf field descriptors are [name, scalar type or nested schema, repeated].
const PROTO_INSTRUCTION = {
  1: ['programIdIndex', 'varint'],
  2: ['accounts', 'bytes'],
  3: ['data', 'bytes'],
  4: ['stackHeight', 'varint'],
};
const PROTO_INNER = {
  1: ['index', 'varint'],
  2: ['instructions', PROTO_INSTRUCTION, true],
};
const PROTO_TOKEN_AMOUNT = {
  1: ['uiAmount', 'double'],
  2: ['decimals', 'varint'],
  3: ['amount', 'string'],
  4: ['uiAmountString', 'string'],
};
const PROTO_TOKEN_BALANCE = {
  1: ['accountIndex', 'varint'],
  2: ['mint', 'string'],
  3: ['uiTokenAmount', PROTO_TOKEN_AMOUNT],
  4: ['owner', 'string'],
  5: ['programId', 'string'],
};
const PROTO_REWARD = {
  1: ['pubkey', 'string'],
  2: ['lamports', 'varint'],
  3: ['postBalance', 'varint'],
  4: ['rewardType', 'varint'],
  5: ['commission', 'string'],
  6: ['commissionBps', 'string'],
};
const PROTO_REWARDS = {
  1: ['rewards', PROTO_REWARD, true],
  2: ['partitions', { 1: ['count', 'varint'] }],
};
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
};

function protoKey(reader) {
  const key = reader.varint();
  check(key >= 8n && key <= 0xffffffffn, 'Invalid protobuf key');
  return [Number(key >> 3n), Number(key & 7n)];
}

function skipProto(reader, field, wire, depth) {
  switch (wire) {
    case 0: reader.varint(); return;
    case 1: reader.take(8); return;
    case 2: reader.sized(reader.varint()); return;
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
    case 5: reader.take(4); return;
    default: throw new Error('Invalid protobuf wire type');
  }
}

function protobuf(bytes, schema, target = {}) {
  const reader = new Reader(bytes);
  while (reader.left) {
    const [field, wire] = protoKey(reader);
    const descriptor = schema[field];
    if (!descriptor) {
      skipProto(reader, field, wire, 0);
      continue;
    }
    const [name, type, repeated] = descriptor;
    if (repeated && type === 'varint' && wire === 2) {
      const packed = new Reader(reader.sized(reader.varint()));
      const list = target[name] ??= [];
      while (packed.left) list.push(packed.varint());
      continue;
    }
    const message = typeof type === 'object';
    const expectedWire = type === 'varint' ? 0 : type === 'double' ? 1 : 2;
    check(wire === expectedWire, `Wrong protobuf wire type for ${name}`);
    let value;
    if (wire === 0) value = reader.varint();
    else if (wire === 1) value = reader.f64();
    else {
      const payload = reader.sized(reader.varint());
      if (message) value = protobuf(payload, type, repeated ? undefined : target[name]);
      else value = type === 'string' ? utf8.decode(payload) : payload;
    }
    if (repeated) (target[name] ??= []).push(value);
    else target[name] = value;
  }
  return target;
}

const low8 = value => Number((value ?? 0n) & 255n);
const low32 = value => Number(value & 0xffffffffn);

function protoReward(value) {
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

function protoTokenBalance(balance) {
  const amount = balance.uiTokenAmount ?? {};
  const uiAmount = Math.abs(amount.uiAmount) > Number.EPSILON ? amount.uiAmount : null;
  return tokenBalance(low8(balance.accountIndex), balance.mint ?? '', uiAmount, low8(amount.decimals),
    amount.amount ?? '', balance.owner, balance.programId, amount.uiAmountString);
}

function protoMeta(value) {
  const inner = value.innerInstructionsNone ? null : (value.innerInstructions ?? []).map(group => ({
    index: low8(group.index),
    instructions: (group.instructions ?? []).map(ix => ({
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

function storedReward(reader, extended = true) {
  const pubkey = reader.string();
  const lamports = reader.i64();
  const postBalance = extended && !reader.left ? 0n : reader.u64();
  const rewardType = extended && !reader.left ? null : reader.option(r => {
    const kind = REWARD_TYPES[r.u32()];
    check(kind, 'Unknown RewardType variant');
    return kind;
  });
  const commission = extended && reader.left ? reader.option(r => r.u8()) : null;
  return { pubkey, lamports, postBalance, rewardType, commission };
}

function storedTokenBalance(reader, tokenLayout) {
  const index = reader.u8();
  const mint = reader.string();
  const uiAmount = reader.f64();
  const decimals = reader.u8();
  const amount = reader.string();
  const owner = tokenLayout >= 2 && reader.left ? reader.string() : '';
  const programId = tokenLayout >= 3 && reader.left ? reader.string() : '';
  return tokenBalance(index, mint, uiAmount, decimals, amount, owner, programId);
}

function storedMeta(reader, legacy, tokenLayout) {
  const status = reader.u32();
  check(status <= 1, 'Invalid bincode result tag');
  const meta = emptyMeta();
  meta.err = status ? transactionError(reader) : null;
  meta.fee = reader.u64();
  meta.preBalances = reader.vec(r => r.u64(), 8);
  meta.postBalances = reader.vec(r => r.u64(), 8);

  const optional = read => reader.left ? reader.option(read) : null;
  meta.innerInstructions = optional(r => r.vec(group => ({
    index: group.u8(),
    instructions: group.vec(item => {
      const ix = compiledInstruction(item, null);
      if (!legacy) ix.stackHeight = item.option(t => t.u32());
      return ix;
    }, legacy ? 3 : 4),
  }), 9));
  meta.logMessages = optional(r => r.vec(item => item.string(), 8));
  meta.preTokenBalances = optional(r => r.vec(item => storedTokenBalance(item, tokenLayout)));
  meta.postTokenBalances = optional(r => r.vec(item => storedTokenBalance(item, tokenLayout)));
  meta.rewards = optional(r => r.vec(item => storedReward(item), 16));
  meta.returnData = optional(r => ({
    programId: pubkey(r.take(32)), data: [base64(r.sized(r.u64())), 'base64'],
  })) ?? undefined;
  meta.computeUnitsConsumed = optional(r => r.u64()) ?? undefined;
  meta.costUnits = optional(r => r.u64()) ?? undefined;
  return meta;
}

function strictBincode(bytes, layouts, lenient) {
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

function bincodeMeta(bytes) {
  const current = reader => storedMeta(reader, false, 3);
  const legacy = [1, 2, 3].map(layout => reader => storedMeta(reader, true, layout));
  return strictBincode(bytes, [current, ...legacy], current);
}

function bincodeRewards(bytes) {
  const current = reader => reader.vec(item => storedReward(item), 16);
  const legacy = reader => reader.vec(item => storedReward(item, false), 25);
  return { rewards: strictBincode(bytes, [current, legacy], current) };
}

function decodePayload(slot, bytes, schema, convert, bincode) {
  // A protobuf conversion error is final once the wire message was parsed.
  if (slot < BINCODE_CUTOFF) {
    try { return bincode(bytes); } catch { /* Try the newer codec. */ }
    return convert(protobuf(bytes, schema));
  }
  let message;
  try { message = protobuf(bytes, schema); } catch { return bincode(bytes); }
  return convert(message);
}

const ZSTD_MAGIC = 0xfd2fb528;

function decompress(bytes) {
  const reader = new Reader(bytes);
  const frames = [];
  let total = 0;
  // Node's synchronous decoder stops at one frame and accepts partial input.
  // Walk the frame boundaries so each call gets one complete, checked frame.
  while (reader.left) {
    const start = reader.pos;
    const magic = reader.u32();
    if ((magic & 0xfffffff0) === 0x184d2a50) {
      reader.take(reader.u32());
      continue;
    }
    check(magic === ZSTD_MAGIC, 'Invalid Zstd frame magic');
    const descriptor = reader.u8();
    check(!(descriptor & 8), 'Reserved Zstd frame bit set');
    const single = Boolean(descriptor & 32);
    if (!single) reader.u8();
    const dictionary = reader.take([0, 1, 2, 4][descriptor & 3]);
    check(dictionary.every(byte => byte === 0), 'Zstd dictionaries are unsupported');
    reader.take([single ? 1 : 0, 2, 4, 8][descriptor >> 6]);
    let header;
    do {
      header = reader.u8() | (reader.u16() << 8);
      const type = (header >> 1) & 3;
      const size = header >> 3;
      check(type !== 3 && size <= 128 * 1024, 'Invalid Zstd block header');
      reader.take(type === 1 ? 1 : size);
    } while (!(header & 1));
    if (descriptor & 4) reader.take(4);
    const frame = zstdDecompressSync(bytes.subarray(start, reader.pos), {
      maxOutputLength: Math.max(1, MAX_DECOMPRESSED - total),
      params: { [zstd.ZSTD_d_windowLogMax]: 27 },
    });
    total += frame.length;
    check(total <= MAX_DECOMPRESSED, 'Zstd output limit exceeded');
    if (frame.length) frames.push(frame);
  }
  return frames.length === 1 ? frames[0] : Buffer.concat(frames, total);
}

function unwrapFrame(bytes, decode) {
  if (bytes.length >= 4 && bytes.readUInt32LE() === ZSTD_MAGIC) {
    let plain;
    try { plain = decompress(bytes); } catch { return decode(bytes); }
    return decode(plain);
  }
  try { return decode(bytes); } catch (error) {
    let plain;
    try { plain = decompress(bytes); } catch { throw error; }
    return decode(plain);
  }
}

function metadata(slot, bytes) {
  return bytes.length ? unwrapFrame(bytes, plain => decodePayload(slot, plain, PROTO_META, protoMeta, bincodeMeta))
    : null;
}

function rewards(slot, bytes) {
  if (!bytes.length) return { rewards: [] };
  return unwrapFrame(bytes, plain => decodePayload(slot, plain, PROTO_REWARDS, value => ({
    rewards: (value.rewards ?? []).map(protoReward),
    numRewardPartitions: value.partitions ? value.partitions.count ?? 0n : undefined,
  }), bincodeRewards));
}

const UPGRADEABLE_LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111';
const RESERVED_ACCOUNTS = new Set(`
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
`.trim().split(/\s+/));

function parsedAccounts(tx, loaded) {
  const { accountKeys, header, instructions } = tx;
  const writable = tx.version === 0 ? loaded.writable : [];
  const readonly = tx.version === 0 ? loaded.readonly : [];
  const keys = [...accountKeys, ...writable, ...readonly];
  const programs = new Set(instructions.map(ix => ix.programIdIndex));
  const upgradeable = keys.includes(UPGRADEABLE_LOADER);
  const signers = header.numRequiredSignatures;
  const staticCount = accountKeys.length;
  return keys.map((pubkey, i) => {
    const fromLookup = i >= staticCount;
    const writableIndex = fromLookup ? i - staticCount < writable.length
      : i < signers ? i < signers - header.numReadonlySignedAccounts
        : i < staticCount - header.numReadonlyUnsignedAccounts;
    return {
      pubkey,
      signer: i < signers,
      writable: writableIndex && !RESERVED_ACCOUNTS.has(pubkey) && (upgradeable || !programs.has(i)),
      source: fromLookup ? 'lookupTable' : 'transaction',
    };
  });
}

function instructionJson(ix, keys) {
  const { programIdIndex, stackHeight } = ix;
  const data = base58(ix.data);
  if (!keys) return { programIdIndex, accounts: Array.from(ix.accounts), data, stackHeight };
  const address = index => {
    check(index < keys.length, 'Instruction account index out of range');
    return keys[index];
  };
  return { programId: address(programIdIndex), accounts: Array.from(ix.accounts, address), data, stackHeight };
}

function transactionJson(tx, meta, options) {
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
  const keys = parsed ? accounts.map(account => account.pubkey) : undefined;
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
        instructions: tx.instructions.map(ix => instructionJson(ix, keys)),
        addressTableLookups: tx.addressTableLookups,
        transactionConfig: tx.transactionConfig,
      },
    };
  }
  let outputMeta = null;
  if (meta) {
    outputMeta = {
      err: meta.err,
      status: meta.err === null ? { Ok: null } : { Err: meta.err },
      fee: meta.fee,
      preBalances: meta.preBalances,
      postBalances: meta.postBalances,
      preTokenBalances: meta.preTokenBalances,
      postTokenBalances: meta.postTokenBalances,
      rewards: options.rewards ? meta.rewards : accountsOnly ? undefined : null,
    };
    if (!accountsOnly) {
      outputMeta.innerInstructions = meta.innerInstructions?.map(group => ({
        index: group.index,
        instructions: group.instructions.map(ix => instructionJson(ix, keys)),
      })) ?? null;
      outputMeta.logMessages = meta.logMessages;
      if (!parsed) outputMeta.loadedAddresses = meta.loadedAddresses;
      outputMeta.returnData = meta.returnData;
      outputMeta.computeUnitsConsumed = meta.computeUnitsConsumed;
      outputMeta.costUnits = meta.costUnits;
    }
  }
  return { transaction, meta: outputMeta, version: meta && options.maxVersion !== null ? tx.version : undefined };
}

class Lru extends Map {
  get(key) {
    if (!this.has(key)) return undefined;
    const value = super.get(key);
    this.delete(key);
    super.set(key, value);
    return value;
  }

  set(key, value) {
    this.delete(key);
    super.set(key, value);
    if (this.size > 100_000) this.delete(this.keys().next().value);
    return this;
  }
}

class Semaphore {
  active = 0;
  waiting = [];

  async run(attempt) {
    if (this.active === 32) await new Promise(resolve => this.waiting.push(resolve));
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

const shutdown = new AbortController();
const agents = {
  'http:': new http.Agent({ keepAlive: true, maxSockets: 32 }),
  'https:': new https.Agent({ keepAlive: true, maxSockets: 32 }),
};

async function rangeAttempt(url, start, end, length, cap) {
  const signal = AbortSignal.any([shutdown.signal, AbortSignal.timeout(60_000)]);
  const transport = url.protocol === 'https:' ? https : http;
  let connectTimer;
  try {
    const response = await new Promise((resolve, reject) => {
      const request = transport.get(url, {
        agent: agents[url.protocol],
        signal,
        headers: { Range: `bytes=${start}-${end}`, 'User-Agent': 'onlyblocks/javascript-node' },
      }, resolve);
      request.once('error', reject);
      request.once('socket', socket => {
        if (!socket.connecting && !socket.secureConnecting) return;
        connectTimer = setTimeout(() => request.destroy(new Error('Archive connect timeout')), 10_000);
        const connected = url.protocol === 'https:' ? 'secureConnect' : 'connect';
        socket.once(connected, () => clearTimeout(connectTimer));
      });
    });

    if (response.statusCode !== 206) {
      response.destroy();
      return { status: response.statusCode, retryAfter: response.headers['retry-after'] };
    }
    if (Number(response.headers['content-length']) > cap) {
      response.destroy();
      throw new RpcError(-32603, 'Archive Content-Length exceeds range cap');
    }
    const chunks = [];
    let received = 0;
    for await (const chunk of response) {
      received += chunk.length;
      if (received > cap) throw new RpcError(-32603, 'Archive body exceeds range cap');
      if (received <= length) chunks.push(chunk);
    }
    if (!response.complete) throw new Error('Incomplete HTTP range response');
    if (received !== length) throw new RpcError(-32603, 'Archive range body has the wrong length');
    return { status: 206, body: chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, received) };
  } finally {
    clearTimeout(connectTimer);
  }
}

function retryDelay(header, failures) {
  if (header !== undefined) {
    if (/^[0-9]+$/.test(header)) return Math.min(10_000, Number(header) * 1000);
    // HTTP dates start with a weekday in all three accepted wire formats.
    const date = /^[A-Z][a-z]+[, ]/.test(header) ? Date.parse(header) : NaN;
    if (Number.isFinite(date)) return Math.max(0, Math.min(10_000, date - Date.now()));
  }
  return Math.min(10_000, 200 * 2 ** failures) * (0.5 + Math.random() * 0.5);
}

class Archive {
  ranges = new Lru();
  hashes = new Lru();
  semaphore = new Semaphore();

  constructor(base) {
    this.base = base;
  }

  async readRange(slot, suffix, start, length, cap) {
    const end = start + BigInt(length) - 1n;
    check(end <= U64_MAX, 'Archive range end overflows u64');
    const epoch = slot / SLOTS_PER_EPOCH;
    const url = new URL(this.base);
    url.pathname = `${url.pathname.replace(/\/+$/, '')}/${epoch}/epoch-${epoch}${suffix}`;
    for (let failures = 0; ; failures++) {
      shutdown.signal.throwIfAborted();
      let response;
      try {
        response = await this.semaphore.run(() => rangeAttempt(url, start, end, length, cap));
      } catch (error) {
        if (error instanceof RpcError) throw error;
        // Connection errors and premature EOF share the retry budget.
      }
      const status = response?.status;
      if (status === 206) return response.body;
      if (status === 404) throw new RpcError(-32004, `Block not available for slot ${slot}: epoch ${epoch} is not archived`);
      if (status !== undefined && status !== 429 && (status < 500 || status >= 600)) {
        throw new RpcError(-32603, `Unexpected archive HTTP status ${status}`);
      }
      if (failures === 4) throw new RpcError(-32603, 'Archive range retries exhausted');
      const wait = retryDelay(response?.retryAfter, failures);
      if (wait === 0) continue;
      await delay(wait, undefined, {
        signal: shutdown.signal,
      });
    }
  }

  async loadBlock(slot) {
    let range = this.ranges.get(slot);
    if (range === undefined) {
      const start = (slot % SLOTS_PER_EPOCH) * 12n;
      const record = new Reader(await this.readRange(slot, '-slot-ranges.raw', start, 12, 12));
      range = { offset: record.u64(), length: record.u32() };
      this.ranges.set(slot, range);
    }
    if (!range.length) throw new RpcError(-32007, `Slot ${slot} was skipped, or missing in long-term storage`);
    check(range.length <= MAX_SLICE, 'Archive slice exceeds 128 MiB');
    return indexCar(await this.readRange(slot, '.car', range.offset, range.length, MAX_SLICE));
  }

  blockhash(slot, index, entries) {
    let hash = ZERO_HASH;
    if (entries.length) {
      const entry = indexedNode(index, entries.at(-1), 1n);
      check(Buffer.isBuffer(entry[2]), 'Invalid Entry hash');
      hash = pubkey(entry[2]);
    }
    this.hashes.set(slot, hash);
    return hash;
  }

  async previousHash(slot, parentSlot) {
    if (slot === 0n) return ZERO_HASH;
    const cached = this.hashes.get(parentSlot);
    if (cached !== undefined) return cached;
    const { index, block } = await this.loadBlock(parentSlot);
    check(unsigned(block[1]) !== null, 'Missing parent Block slot');
    return this.blockhash(parentSlot, index, links(block[3]));
  }

  async getBlock(slot, options) {
    const { index, block } = await this.loadBlock(slot);
    check(block[1] === slot, 'Block slot differs from requested slot');
    const entries = links(block[3]);
    const info = Array.isArray(block[4]) ? block[4] : [];
    const parentSlot = unsigned(info[0]) ?? 0n;
    const blockhash = this.blockhash(slot, index, entries);
    const result = {
      previousBlockhash: await this.previousHash(slot, parentSlot),
      blockhash,
      parentSlot,
      blockTime: signed(info[1]) || null,
      blockHeight: unsigned(info[2]),
    };
    if (options.details !== 'none') {
      const items = [];
      for (const key of entries) {
        const entry = indexedNode(index, key, 1n);
        check(Buffer.isBuffer(entry[2]) && entry[2].length === 32, 'Invalid Entry hash');
        for (const txKey of links(entry[3])) {
          const node = indexedNode(index, txKey, 0n);
          const tx = transaction(framePayload(index, node[1]));
          if (options.details === 'signatures') {
            check(tx.signatures.length, 'Transaction has no signature');
            items.push(base58(tx.signatures[0]));
          } else {
            const meta = Array.isArray(node[2]) ? metadata(slot, framePayload(index, node[2])) : null;
            items.push(transactionJson(tx, meta, options));
          }
        }
      }
      result[options.details === 'signatures' ? 'signatures' : 'transactions'] = items;
    }
    if (options.rewards) {
      const cid = Buffer.isBuffer(block[5]) ? link(block[5]) : null;
      const node = cid && !cid.absent && index.has(cid.key) ? indexedNode(index, cid.key, 5n) : [];
      const bytes = node.length > 2 ? framePayload(index, node[2]) : EMPTY;
      Object.assign(result, rewards(slot, bytes));
    }
    return result;
  }
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && !JSON.isRawJSON(value);
}

function jsonUnsigned(value, max) {
  if (!JSON.isRawJSON(value) || !/^(0|[1-9][0-9]{0,19})$/.test(value.rawJSON)) return null;
  const number = BigInt(value.rawJSON);
  return number <= max ? number : null;
}

function blockParams(params) {
  const invalid = () => new RpcError(-32602, 'Invalid getBlock params');
  if (!Array.isArray(params) || params.length < 1 || params.length > 2) throw invalid();
  const slot = jsonUnsigned(params[0], U64_MAX);
  if (slot === null) throw invalid();
  const config = typeof params[1] === 'string' ? { encoding: params[1] } : params[1] ?? {};
  if (!object(config)) throw invalid();
  const encoding = config.encoding ?? 'json';
  const details = config.transactionDetails ?? 'full';
  const rewards = config.rewards ?? true;
  const maxVersion = jsonUnsigned(config.maxSupportedTransactionVersion, 255n);
  if (!['json', 'jsonParsed', 'base64', 'base58'].includes(encoding) ||
      !['full', 'accounts', 'signatures', 'none'].includes(details) ||
      typeof rewards !== 'boolean' ||
      (config.maxSupportedTransactionVersion != null && maxVersion === null) ||
      (config.commitment != null && !['finalized', 'confirmed'].includes(config.commitment))) {
    throw invalid();
  }
  if (encoding === 'base58' && maxVersion !== null && maxVersion >= 1n) {
    throw new RpcError(-32602, 'base58 encoding is not supported with maxSupportedTransactionVersion >= 1');
  }
  if (details === 'accounts' && encoding !== 'json') throw invalid();
  return { slot, encoding, details, rewards, maxVersion };
}

function rpcError(id, code, message) {
  return { jsonrpc: '2.0', error: { code, message }, id };
}

async function dispatch(archive, request) {
  if (!object(request)) return rpcError(null, -32600, 'Invalid Request');
  const { jsonrpc, method, params, id = null } = request;
  if ((Object.hasOwn(request, 'jsonrpc') && typeof jsonrpc !== 'string') ||
      (Object.hasOwn(request, 'method') && typeof method !== 'string') ||
      (id !== null && typeof id !== 'string' && !JSON.isRawJSON(id))) {
    return rpcError(null, -32600, 'Invalid Request');
  }
  if (jsonrpc !== '2.0' || typeof method !== 'string') return rpcError(id, -32600, 'Invalid Request');

  try {
    let result;
    if (method === 'getHealth') {
      if (params != null && !(Array.isArray(params) && params.length === 0)) {
        throw new RpcError(-32602, 'Invalid getHealth params');
      }
      result = 'ok';
    } else if (method === 'getBlock') {
      const options = blockParams(params);
      result = await archive.getBlock(options.slot, options);
    } else {
      return rpcError(id, -32601, `Method not found: ${method}`);
    }
    return { jsonrpc: '2.0', result, id };
  } catch (error) {
    return error instanceof RpcError ? rpcError(id, error.code, error.message)
      : rpcError(id, -32603, `Internal error: ${error.message}`);
  }
}

async function rpc(archive, body) {
  let request;
  try {
    // The reviver sees the original lexeme even when Number rounded it.
    request = JSON.parse(utf8.decode(body), (_, value, context) =>
      typeof value === 'number' ? JSON.rawJSON(context.source) : value);
  } catch {
    return rpcError(null, -32700, 'Parse error');
  }
  if (!Array.isArray(request)) return dispatch(archive, request);
  if (!request.length || request.length > 100) return rpcError(null, -32600, 'Invalid Request');
  const responses = [];
  for (const item of request) responses.push(await dispatch(archive, item));
  return responses;
}

function sendJson(response, value) {
  if (response.destroyed) return;
  let body;
  try {
    body = JSON.stringify(value, (_, entry) => typeof entry === 'bigint' ? JSON.rawJSON(String(entry)) : entry);
  } catch {
    body = JSON.stringify(rpcError(value?.id ?? null, -32603, 'Response could not be serialized'));
  }
  response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  response.end(body);
}

function serve(archive, request, response) {
  if (request.url !== '/' || request.method !== 'POST') {
    response.writeHead(request.url !== '/' ? 404 : 405, { Connection: 'close' }).end();
    return;
  }
  const tooLarge = () => {
    request.pause();
    response.writeHead(413, { Connection: 'close' }).end();
  };
  if (Number(request.headers['content-length']) > MiB) {
    tooLarge();
    return;
  }
  const chunks = [];
  let total = 0;
  request.on('error', () => response.destroy());
  request.on('data', chunk => {
    total += chunk.length;
    if (total > MiB) tooLarge();
    else chunks.push(chunk);
  });
  request.on('end', () => {
    if (total > MiB) return;
    rpc(archive, Buffer.concat(chunks, total)).then(
      value => sendJson(response, value),
      () => sendJson(response, rpcError(null, -32603, 'Internal error')),
    );
  });
}

function options(args, env) {
  let bind = env.ONLYBLOCKS_BIND ?? '127.0.0.1:8899';
  let baseUrl = env.OLD_FAITHFUL_BASE_URL ?? 'https://files.old-faithful.net';
  for (let i = 0; i < args.length; i++) {
    const match = /^(--bind|--base-url)(?:=(.*))?$/s.exec(args[i]);
    check(match, `Unknown option: ${args[i]}`);
    const value = match[2] ?? args[++i];
    check(value !== undefined && !value.startsWith('--'), `Missing value for ${match[1]}`);
    if (match[1] === '--bind') bind = value;
    else baseUrl = value;
  }
  const address = /^(?:\[([^\]]+)\]|([^:]+)):([0-9]+)$/.exec(bind);
  check(address && Number(address[3]) <= 65535, 'Bind address must be HOST:PORT');
  const base = new URL(baseUrl.trim().replace(/\/+$/, ''));
  check(base.protocol === 'http:' || base.protocol === 'https:', 'Base URL must use HTTP or HTTPS');
  return { host: address[1] ?? address[2], port: Number(address[3]), base };
}

function main() {
  const { host, port, base } = options(process.argv.slice(2), process.env);
  const archive = new Archive(base);
  const server = http.createServer((request, response) => serve(archive, request, response));
  server.listen({ host, port });
  const stop = () => {
    shutdown.abort();
    server.close();
    server.closeAllConnections();
    for (const agent of Object.values(agents)) agent.destroy();
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

main();
