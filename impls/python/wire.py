"""CARv1, DAG-CBOR, DataFrame and Solana transaction decoding."""
import base64
import struct

U64_MAX = (1 << 64) - 1
EMPTY = memoryview(b'')
ZERO_HASH = '1' * 32
BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


class DecodeError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise DecodeError(message)


def utf8(data):
    try:
        return bytes(data).decode('utf-8')
    except UnicodeDecodeError as exc:
        raise DecodeError('Invalid UTF-8') from exc


class Reader:
    def __init__(self, data):
        self.data = memoryview(data)
        self.pos = 0

    @property
    def left(self):
        return len(self.data) - self.pos

    def take(self, size):
        require(0 <= size <= self.left, 'Truncated binary value')
        start = self.pos
        self.pos += size
        return self.data[start:self.pos]

    def fixed(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return self.fixed('<I')

    def u64(self):
        return self.fixed('<Q')

    def i64(self):
        return self.fixed('<q')

    def f64(self):
        return self.fixed('<d')

    def varint(self):
        value = 0
        for shift in range(0, 64, 7):
            byte = self.u8()
            require(shift < 63 or byte <= 1, 'Varint overflow')
            value |= (byte & 127) << shift
            if byte < 128:
                return value

    def compact(self):
        value = 0
        for shift in (0, 7, 14):
            byte = self.u8()
            require(not shift or byte != 0, 'Noncanonical compact-u16')
            require(shift < 14 or byte <= 3, 'Compact-u16 overflow')
            value |= (byte & 127) << shift
            if byte < 128:
                return value

    def items(self, count, read, minimum=1):
        require(count <= self.left // minimum, 'Count exceeds enclosing field')
        return [read() for _ in range(count)]

    def vec(self, read, minimum=1):
        return self.items(self.u64(), read, minimum)

    def string(self):
        return utf8(self.take(self.u64()))

    def option(self, read):
        tag = self.u8()
        require(tag <= 1, 'Invalid bincode option')
        return read() if tag else None


def at(items, index):
    return items[index] if index < len(items) else None


def unsigned(value):
    return value if type(value) is int and 0 <= value <= U64_MAX else None


def signed(value):
    return value if type(value) is int and -(1 << 63) <= value < (1 << 63) else None


def base58(data):
    zeros = 0
    for byte in data:
        if byte:
            break
        zeros += 1
    value = int.from_bytes(data, 'big')
    digits = []
    while value:
        value, digit = divmod(value, 58)
        digits.append(BASE58[digit])
    return '1' * zeros + ''.join(reversed(digits))


def b64(data):
    return base64.b64encode(data).decode('ascii')


def pubkey(data):
    require(isinstance(data, (bytes, memoryview)) and len(data) == 32,
            'Expected 32-byte hash or public key')
    return base58(data)


def cbor_argument(reader, info):
    if info < 24:
        return info
    if info == 31:
        return None
    require(info <= 27, 'Reserved CBOR argument')
    return int.from_bytes(reader.take(1 << (info - 24)), 'big')


def cbor_item(reader, depth=0):
    require(depth <= 128, 'CBOR nesting limit')
    head = reader.u8()
    major, info = head >> 5, head & 31
    if major == 7:
        if info in (20, 21, 22, 23):
            return (False, True, None, None)[info - 20]
        require(25 <= info <= 27, 'Unsupported CBOR simple value')
        return reader.fixed(('>e', '>f', '>d')[info - 25])
    argument = cbor_argument(reader, info)
    require(argument is not None or 2 <= major <= 5, 'Invalid indefinite CBOR item')
    if major == 0:
        return argument
    if major == 1:
        return -1 - argument
    if major == 6:
        return cbor_item(reader, depth + 1)

    def more():
        require(reader.left, 'Missing CBOR break')
        return reader.data[reader.pos] != 255

    if major in (2, 3):
        convert = bytes if major == 2 else utf8
        if argument is not None:
            return convert(reader.take(argument))
        chunks = []
        while more():
            head = reader.u8()
            require(head >> 5 == major and head & 31 != 31, 'Invalid CBOR string chunk')
            chunks.append(convert(reader.take(cbor_argument(reader, head & 31))))
        reader.u8()
        return (b'' if major == 2 else '').join(chunks)

    # Maps only need lookup of a text key for the optional CAR header.
    result = [] if major == 4 else {}
    require(argument is None or argument <= reader.left // (1 if major == 4 else 2),
            'CBOR count exceeds enclosing field')
    while (more() if argument is None else argument > 0):
        item = cbor_item(reader, depth + 1)
        if major == 4:
            result.append(item)
        else:
            value = cbor_item(reader, depth + 1)
            if isinstance(item, str):
                result[item] = value
        if argument is not None:
            argument -= 1
    if argument is None:
        reader.u8()
    return result


def cbor(data):
    reader = Reader(data)
    value = cbor_item(reader)
    require(not reader.left, 'Trailing CBOR bytes')
    return value


def cid(reader):
    start = reader.pos
    version, codec = reader.varint(), reader.varint()
    absent = False
    if (version, codec) == (0x12, 0x20):
        reader.take(32)
    else:
        require(version == 1, 'Unsupported CID version')
        code, size = reader.varint(), reader.varint()
        require(size <= 64, 'CID digest too long')
        reader.take(size)
        absent = code == size == 0
    return bytes(reader.data[start:reader.pos]), absent


def link(value):
    require(isinstance(value, bytes) and value.startswith(b'\0'), 'Invalid CID link')
    return cid(Reader(memoryview(value)[1:]))


def links(items):
    return [link(item)[0] for item in items] if isinstance(items, list) else []


def kind(node, number):
    require(isinstance(node, list) and unsigned(at(node, 0)) == number,
            f'Expected IPLD node kind {number}')
    return node


def indexed(index, key, number):
    require(key in index, 'CID missing from CAR slice')
    return kind(cbor(index[key]), number)


def index_car(data):
    reader = Reader(data)
    index, block, first = {}, None, True
    while reader.left:
        size = reader.varint()
        if size == 0:
            continue
        require(size <= 32 << 20, 'Oversize CAR section')
        section = Reader(reader.take(size))
        if first and section.data[0] >> 5 == 5:
            try:
                header = cbor(section.data)
            except DecodeError:
                header = None
            if isinstance(header, dict) and 'version' in header:
                first = False
                continue
        first = False
        key, _ = cid(section)
        node = section.take(section.left)
        index[key] = node
        if node and node[0] >> 5 == 4:
            info = node[0] & 31
            if info < 28 or info == 31:
                head = 1 if info < 24 or info == 31 else 1 + (1 << (info - 24))
                if head < len(node) and node[head] == 2:
                    block = node
    require(block is not None, 'No Block node in CAR slice')
    return index, kind(cbor(block), 2)


def crc_entry(value):
    for _ in range(8):
        value = (value >> 1) ^ (0xD800000000000000 if value & 1 else 0)
    return value


CRC_TABLE = tuple(map(crc_entry, range(256)))


def crc64(data):
    value = U64_MAX
    for byte in data:
        value = (value >> 8) ^ CRC_TABLE[(value & 255) ^ byte]
    return value ^ U64_MAX


def fnv1a(data):
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & U64_MAX
    return value


def frame_payload(index, root):
    def data(frame):
        value = at(frame, 4)
        return value if isinstance(value, bytes) else b''

    kind(root, 6)
    chunks = [data(root)]
    size = len(chunks[0])
    stack = links(at(root, 5))[::-1]
    seen = set()
    while stack:
        key = stack.pop()
        require(key not in seen, 'Repeated DataFrame CID')
        seen.add(key)
        frame = indexed(index, key, 6)
        chunk = data(frame)
        size += len(chunk)
        require(size <= 128 << 20, 'Oversize reassembled DataFrame')
        chunks.append(chunk)
        stack.extend(reversed(links(at(frame, 5))))
    payload = b''.join(chunks)
    expected = unsigned(at(root, 1))
    require(expected is None or crc64(payload) == expected or fnv1a(payload) == expected,
            'DataFrame hash mismatch')
    return payload


def instruction(reader, height=None):
    return dict(programIdIndex=reader.u8(), accounts=reader.take(reader.compact()),
                data=reader.take(reader.compact()), stackHeight=height)


def transaction(data):
    reader = Reader(data)
    require(reader.left > 0, 'Empty transaction')
    first = reader.data[0]
    if first == 0x81:
        reader.u8()
        header = dict(numRequiredSignatures=reader.u8(),
                      numReadonlySignedAccounts=reader.u8(),
                      numReadonlyUnsignedAccounts=reader.u8())
        mask = reader.u32()
        require((mask & ~0x1f) == 0 and (mask & 3) in (0, 3), 'Invalid v1 transaction config mask')
        recent = pubkey(reader.take(32))
        num_ix, num_keys = reader.u8(), reader.u8()
        keys = reader.items(num_keys, lambda: pubkey(reader.take(32)), 32)
        config = dict(
            priorityFee=reader.u64() if (mask & 3) == 3 else None,
            computeUnitLimit=reader.u32() if mask & 4 else None,
            loadedAccountsDataSizeLimit=reader.u32() if mask & 8 else None,
            heapSize=reader.u32() if mask & 16 else None,
        )
        headers = reader.items(num_ix, lambda: (reader.u8(), reader.u8(), reader.fixed('<H')), 4)
        instructions = [
            dict(programIdIndex=prog, accounts=reader.take(n_acc),
                 data=reader.take(d_len), stackHeight=1)
            for prog, n_acc, d_len in headers
        ]
        signatures = reader.items(header['numRequiredSignatures'], lambda: reader.take(64), 64)
        message = dict(header=header, accountKeys=keys, recentBlockhash=recent,
                       instructions=instructions, transactionConfig=config)
        return 1, signatures, message, reader.data[:reader.pos]
    require(first < 0x80, 'Unsupported wire transaction discriminator')
    signatures = reader.items(reader.compact(), lambda: reader.take(64), 64)
    prefix = reader.u8()
    require(prefix <= 128, 'Unsupported wire transaction version')
    version = 0 if prefix == 128 else 'legacy'
    header = dict(numRequiredSignatures=reader.u8() if version == 0 else prefix,
                  numReadonlySignedAccounts=reader.u8(),
                  numReadonlyUnsignedAccounts=reader.u8())
    keys = reader.items(reader.compact(), lambda: pubkey(reader.take(32)), 32)
    recent = pubkey(reader.take(32))
    instructions = reader.items(reader.compact(), lambda: instruction(reader, 1), 3)
    message = dict(header=header, accountKeys=keys, recentBlockhash=recent,
                   instructions=instructions)
    if version == 0:
        def lookup():
            return dict(accountKey=pubkey(reader.take(32)),
                        writableIndexes=list(reader.take(reader.compact())),
                        readonlyIndexes=list(reader.take(reader.compact())))
        message['addressTableLookups'] = reader.items(reader.compact(), lookup, 34)
    return version, signatures, message, reader.data[:reader.pos]
