"""RFC 8878 decoding, based on docs/ZSTD_MINI_SPEC.md."""

MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024
ZSTD_MAGIC = 0xFD2FB528            # bytes 28 B5 2F FD
SKIPPABLE_MAGIC_MASK = 0xFFFFFFF0  # 0x184D2A50 .. 0x184D2A5F
SKIPPABLE_MAGIC = 0x184D2A50       # bytes 5? 2A 4D 18
BLOCK_SIZE_MAX = 128 * 1024


class ZstdError(Exception):
    pass


def highbit(x):
    return x.bit_length() - 1


def le(data, pos, n):
    """Little-endian unsigned integer of n bytes at data[pos]."""
    if pos < 0 or pos + n > len(data):
        raise ZstdError("truncated input")
    v = 0
    for i in range(n):
        v |= data[pos + i] << (8 * i)
    return v


LL_BASE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
           16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
           8192, 16384, 32768, 65536]
LL_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
           13, 14, 15, 16]
ML_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
           19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
           35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
           4099, 8195, 16387, 32771, 65539]
ML_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
           12, 13, 14, 15, 16]


LL_DEFAULT = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
              2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
              -1, -1, -1, -1]                             # accuracy log 6
ML_DEFAULT = [1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
              -1, -1, -1, -1, -1]                         # accuracy log 6
OF_DEFAULT = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1]  # accuracy log 5

# kind -> (default distribution, default accuracy log, max symbol, max accuracy log)
SEQ_KINDS = {
    "ll": (LL_DEFAULT, 6, 35, 9),
    "of": (OF_DEFAULT, 5, 31, 8),
    "ml": (ML_DEFAULT, 6, 52, 9),
}


class BackwardBits:
    def __init__(self, data, start, end):
        if start < 0 or end > len(data) or end <= start:
            raise ZstdError("empty or out-of-range bitstream")
        if data[end - 1] == 0:
            raise ZstdError("bitstream end marker missing")
        self.data = data
        self.start = start
        self.bits = 8 * (end - start - 1) + highbit(data[end - 1])

    def _window(self, lo, hi):
        """Bits [lo, hi) of the stream, 0 <= lo < hi."""
        first, last = lo >> 3, (hi - 1) >> 3
        word = le(self.data, self.start + first, last - first + 1)
        return (word >> (lo & 7)) & ((1 << (hi - lo)) - 1)

    def peek(self, n):
        lo, hi = self.bits - n, self.bits
        if n == 0 or hi <= 0:
            return 0
        if lo < 0:                      # pad missing low bits with zeros
            return self._window(0, hi) << (-lo)
        return self._window(lo, hi)

    def read(self, n):
        v = self.peek(n)
        self.bits -= n
        return v


def read_fse_description(data, pos, limit, max_symbol, max_log):
    bitpos = pos * 8

    def peek(n):
        v = 0
        for i in range(n):
            p = bitpos + i
            if (p >> 3) < limit:
                v |= ((data[p >> 3] >> (p & 7)) & 1) << i
        return v

    def take(n):
        nonlocal bitpos
        if bitpos + n > limit * 8:
            raise ZstdError("truncated FSE description")
        v = peek(n)
        bitpos += n
        return v

    accuracy_log = take(4) + 5
    if accuracy_log > max_log:
        raise ZstdError("FSE accuracy log too large")
    remaining = (1 << accuracy_log) + 1
    threshold = 1 << accuracy_log
    nbits = accuracy_log + 1
    probs = []
    while remaining > 1:
        if len(probs) > max_symbol:
            raise ZstdError("FSE description has too many symbols")
        biggest = 2 * threshold - 1 - remaining
        low = peek(nbits - 1)
        if low < biggest:
            value = low
            take(nbits - 1)
        else:
            value = take(nbits)
            if value >= threshold:
                value -= biggest
        prob = value - 1
        probs.append(prob)
        remaining -= abs(prob)
        if prob == 0:
            while True:
                repeat = take(2)
                probs.extend([0] * repeat)
                if len(probs) > max_symbol + 1:
                    raise ZstdError("FSE description has too many symbols")
                if repeat != 3:
                    break
        if remaining < 1:
            raise ZstdError("invalid FSE probability")
        while remaining < threshold:
            nbits -= 1
            threshold >>= 1
    if remaining != 1 or len(probs) > max_symbol + 1:
        raise ZstdError("corrupt FSE description")
    end = (bitpos + 7) >> 3
    if end > limit:
        raise ZstdError("FSE description overruns its section")
    return probs, accuracy_log, end


def build_fse_table(probs, accuracy_log):
    size = 1 << accuracy_log
    if sum(map(abs, probs)) != size:
        raise ZstdError("invalid FSE distribution")
    cell_symbol = [0] * size
    counter = [0] * len(probs)
    high = size - 1
    for s, p in enumerate(probs):
        if p == -1:
            cell_symbol[high] = s
            high -= 1
            counter[s] = 1
        else:
            counter[s] = p
    step = (size >> 1) + (size >> 3) + 3
    mask = size - 1
    pos = 0
    for s, p in enumerate(probs):
        for _ in range(max(p, 0)):
            cell_symbol[pos] = s
            pos = (pos + step) & mask
            while pos > high:
                pos = (pos + step) & mask
    if pos != 0:
        raise ZstdError("corrupt FSE distribution")
    table = []
    for cell in range(size):
        s = cell_symbol[cell]
        x = counter[s]
        counter[s] += 1
        nb = accuracy_log - highbit(x)
        table.append((s, nb, (x << nb) - size))
    return table


PREDEFINED = {kind: (build_fse_table(probs, log), log)
              for kind, (probs, log, _, _) in SEQ_KINDS.items()}


def build_huffman_table(weights):
    if len(weights) > 255:
        raise ZstdError("too many Huffman weights")
    total = 0
    for w in weights:
        if w > 11:
            raise ZstdError("Huffman weight too large")
        if w > 0:
            total += 1 << (w - 1)
    if total == 0:
        raise ZstdError("empty Huffman table")
    max_bits = highbit(total) + 1
    if max_bits > 11:
        raise ZstdError("Huffman code too long")
    rest = (1 << max_bits) - total
    if rest & (rest - 1):
        raise ZstdError("corrupt Huffman weights")
    weights = weights + [highbit(rest) + 1]
    next_cell = [0] * (max_bits + 1)
    start = 0
    for w in range(1, max_bits + 1):
        next_cell[w] = start
        start += weights.count(w) << (w - 1)
    table = [None] * (1 << max_bits)
    for sym, w in enumerate(weights):
        if w == 0:
            continue
        for i in range(next_cell[w], next_cell[w] + (1 << (w - 1))):
            table[i] = (sym, max_bits + 1 - w)
        next_cell[w] += 1 << (w - 1)
    return table, max_bits


def read_huffman_description(data, pos, limit):
    if pos >= limit:
        raise ZstdError("missing Huffman description")
    h = data[pos]
    pos += 1
    weights = []
    if h < 128:
        end = pos + h
        if end > limit:
            raise ZstdError("Huffman description overruns literals")
        probs, al, p = read_fse_description(data, pos, end, 255, 6)
        table = build_fse_table(probs, al)
        br = BackwardBits(data, p, end)
        s1 = br.read(al)
        s2 = br.read(al)
        if br.bits < 0:
            raise ZstdError("truncated Huffman initial states")
        while True:
            if len(weights) > 255:
                raise ZstdError("too many Huffman weights")
            sym, nb, base = table[s1]
            weights.append(sym)
            s1 = base + br.read(nb)
            if br.bits < 0:
                weights.append(table[s2][0])
                break
            sym, nb, base = table[s2]
            weights.append(sym)
            s2 = base + br.read(nb)
            if br.bits < 0:
                weights.append(table[s1][0])
                break
        pos = end
    else:
        n = h - 127
        end = pos + (n + 1) // 2
        if end > limit:
            raise ZstdError("Huffman description overruns literals")
        for i in range(n):
            b = data[pos + i // 2]
            weights.append(b >> 4 if i % 2 == 0 else b & 15)
        pos = end
    return build_huffman_table(weights), pos


def decode_huffman_stream(data, start, end, huffman, count, out):
    table, max_bits = huffman
    br = BackwardBits(data, start, end)
    for _ in range(count):
        sym, nb = table[br.peek(max_bits)]
        out.append(sym)
        br.bits -= nb
    if br.bits != 0:
        raise ZstdError("Huffman stream not fully consumed")


def decode_literals(data, pos, end, frame, maximum):
    if pos >= end:
        raise ZstdError("missing literals section")
    b0 = data[pos]
    ltype = b0 & 3
    size_format = (b0 >> 2) & 3
    if ltype in (0, 1):
        width = (1, 2, 1, 3)[size_format]
        if pos + width > end:
            raise ZstdError("truncated literal header")
        size = le(data, pos, width) >> (3 if width == 1 else 4)
        pos += width
        if size > maximum:
            raise ZstdError("literal output exceeds block limit")
        if ltype == 0:
            if pos + size > end:
                raise ZstdError("raw literals overrun block")
            return bytes(data[pos:pos + size]), pos + size
        if pos >= end:
            raise ZstdError("RLE literals overrun block")
        return bytes([data[pos]]) * size, pos + 1

    streams, header_len, width = {0: (1, 3, 10), 1: (4, 3, 10),
                                  2: (4, 4, 14), 3: (4, 5, 18)}[size_format]
    if pos + header_len > end:
        raise ZstdError("truncated compressed literal header")
    h = le(data, pos, header_len)
    regenerated = (h >> 4) & ((1 << width) - 1)
    compressed = (h >> (4 + width)) & ((1 << width) - 1)
    pos += header_len
    lit_end = pos + compressed
    if lit_end > end:
        raise ZstdError("compressed literals overrun block")
    if regenerated > maximum:
        raise ZstdError("literal output exceeds block limit")
    if ltype == 2:
        frame.huffman, pos = read_huffman_description(data, pos, lit_end)
    elif frame.huffman is None:
        raise ZstdError("treeless literals without a previous Huffman table")
    out = bytearray()
    if streams == 1:
        decode_huffman_stream(data, pos, lit_end, frame.huffman, regenerated, out)
    else:
        if pos + 6 > lit_end:
            raise ZstdError("truncated Huffman jump table")
        sizes = [le(data, pos, 2), le(data, pos + 2, 2), le(data, pos + 4, 2)]
        pos += 6
        sizes.append(lit_end - pos - sum(sizes))
        quarter = (regenerated + 3) // 4
        counts = [quarter, quarter, quarter, regenerated - 3 * quarter]
        if sizes[3] < 1 or counts[3] < 0:
            raise ZstdError("corrupt 4-stream literals")
        for size, count in zip(sizes, counts):
            decode_huffman_stream(data, pos, pos + size, frame.huffman, count, out)
            pos += size
    return bytes(out), lit_end


def read_sequence_table(data, pos, end, mode, kind, frame):
    _, _, max_symbol, max_log = SEQ_KINDS[kind]
    if mode == 0:
        t = PREDEFINED[kind]
    elif mode == 1:
        if pos >= end or data[pos] > max_symbol:
            raise ZstdError("bad RLE sequence symbol")
        t = ([(data[pos], 0, 0)], 0)
        pos += 1
    elif mode == 2:
        probs, al, pos = read_fse_description(data, pos, end, max_symbol, max_log)
        t = (build_fse_table(probs, al), al)
    else:
        t = frame.tables[kind]
        if t is None:
            raise ZstdError("repeat mode without a previous table")
    frame.tables[kind] = t
    return t, pos


def decode_sequences(data, pos, end, frame, maximum):
    if pos >= end:
        raise ZstdError("missing sequences section")
    b0 = data[pos]
    if b0 == 0:
        if pos + 1 != end:
            raise ZstdError("data after empty sequences section")
        return
    if b0 < 128:
        count, pos = b0, pos + 1
    elif b0 < 255:
        count, pos = ((b0 - 128) << 8) + le(data, pos + 1, 1), pos + 2
    else:
        count, pos = le(data, pos + 1, 2) + 0x7F00, pos + 3
    if pos >= end:
        raise ZstdError("missing compression modes")
    if count == 0 or count * 3 > maximum:
        raise ZstdError("invalid sequence count")
    modes = data[pos]
    pos += 1
    if modes & 3:
        raise ZstdError("reserved compression-mode bits set")
    (ll_t, ll_log), pos = read_sequence_table(data, pos, end, (modes >> 6) & 3, "ll", frame)
    (of_t, of_log), pos = read_sequence_table(data, pos, end, (modes >> 4) & 3, "of", frame)
    (ml_t, ml_log), pos = read_sequence_table(data, pos, end, (modes >> 2) & 3, "ml", frame)
    br = BackwardBits(data, pos, end)
    ll_s = br.read(ll_log)
    of_s = br.read(of_log)
    ml_s = br.read(ml_log)
    for i in range(count):
        of_code, ml_code, ll_code = of_t[of_s][0], ml_t[ml_s][0], ll_t[ll_s][0]
        offset_value = (1 << of_code) + br.read(of_code)
        ml = ML_BASE[ml_code] + br.read(ML_BITS[ml_code])
        ll = LL_BASE[ll_code] + br.read(LL_BITS[ll_code])
        if br.bits < 0:
            raise ZstdError("truncated sequence bits")
        yield ll, offset_value, ml
        if i != count - 1:
            ll_s = ll_t[ll_s][2] + br.read(ll_t[ll_s][1])
            ml_s = ml_t[ml_s][2] + br.read(ml_t[ml_s][1])
            of_s = of_t[of_s][2] + br.read(of_t[of_s][1])
    if br.bits != 0:
        raise ZstdError("sequence bitstream not fully consumed")


def execute_sequences(sequences, literals, out, frame_start, frame, maximum):
    block_end = len(out) + maximum
    rep = frame.rep
    lit = 0
    for ll, offset_value, ml in sequences:
        if lit + ll > len(literals):
            raise ZstdError("sequence consumes more literals than available")
        if len(out) + ll + ml > block_end:
            raise ZstdError("block output exceeds limit")
        out += literals[lit:lit + ll]
        lit += ll
        if offset_value > 3:
            offset = offset_value - 3
            rep[:] = [offset, rep[0], rep[1]]
        else:
            idx = offset_value - 1 + (1 if ll == 0 else 0)
            if idx == 0:
                offset = rep[0]
            elif idx == 1:
                offset = rep[1]
                rep[:] = [rep[1], rep[0], rep[2]]
            elif idx == 2:
                offset = rep[2]
                rep[:] = [rep[2], rep[0], rep[1]]
            else:
                offset = rep[0] - 1
                rep[:] = [offset, rep[0], rep[1]]
        if offset <= 0 or offset > frame.window or offset > len(out) - frame_start:
            raise ZstdError("match offset out of range")
        src = len(out) - offset
        if ml <= offset:
            out += out[src:src + ml]
        else:
            pattern = out[src:]
            repeats, remainder = divmod(ml, offset)
            out += pattern * repeats + pattern[:remainder]
    if len(out) + len(literals) - lit > block_end:
        raise ZstdError("block output exceeds limit")
    out += literals[lit:]


class FrameState:
    def __init__(self, window):
        self.window = window
        self.rep = [1, 4, 8]
        self.huffman = None
        self.tables = {"ll": None, "of": None, "ml": None}


def decode_frame(data, pos, out):
    fhd = le(data, pos, 1)
    pos += 1
    fcs_flag, single = fhd >> 6, (fhd >> 5) & 1
    has_checksum, did_flag = (fhd >> 2) & 1, fhd & 3
    if fhd & 0x08:
        raise ZstdError("reserved frame header bit set")
    if not single:
        descriptor = le(data, pos, 1)
        base = 1 << (10 + (descriptor >> 3))
        window = base + (base >> 3) * (descriptor & 7)
        pos += 1
    did_size = (0, 1, 2, 4)[did_flag]
    if did_size and le(data, pos, did_size) != 0:
        raise ZstdError("zstd dictionaries are not supported")
    pos += did_size
    fcs_size = (1 if single else 0, 2, 4, 8)[fcs_flag]
    content_size = None
    if fcs_size:
        content_size = le(data, pos, fcs_size) + (256 if fcs_size == 2 else 0)
        pos += fcs_size
        if content_size > MAX_DECOMPRESSED_BYTES - len(out):
            raise ZstdError("decompressed size limit exceeded")
    if single:
        window = content_size
    block_max = min(window, BLOCK_SIZE_MAX)
    frame_start = len(out)
    frame = FrameState(window)
    while True:
        header = le(data, pos, 3)
        pos += 3
        last, block_type, block_size = header & 1, (header >> 1) & 3, header >> 3
        if block_size > block_max:
            raise ZstdError("block too large")
        maximum = min(block_max, MAX_DECOMPRESSED_BYTES - len(out))
        if content_size is not None:
            maximum = min(maximum, content_size - (len(out) - frame_start))
        if block_type in (0, 1) and block_size > maximum:
            raise ZstdError("block output exceeds limit")
        if block_type == 0:
            if pos + block_size > len(data):
                raise ZstdError("truncated raw block")
            out += data[pos:pos + block_size]
            pos += block_size
        elif block_type == 1:
            out += bytes([le(data, pos, 1)]) * block_size
            pos += 1
        elif block_type == 2:
            end = pos + block_size
            if end > len(data):
                raise ZstdError("truncated compressed block")
            literals, p = decode_literals(data, pos, end, frame, maximum)
            sequences = decode_sequences(data, p, end, frame, maximum)
            execute_sequences(sequences, literals, out, frame_start, frame, maximum)
            pos = end
        else:
            raise ZstdError("reserved block type")
        if last:
            break
    if content_size is not None and len(out) - frame_start != content_size:
        raise ZstdError("frame content size mismatch")
    if has_checksum:
        expected = le(data, pos, 4)
        pos += 4
        if xxh64(memoryview(out)[frame_start:]) & 0xFFFFFFFF != expected:
            raise ZstdError("content checksum mismatch")
    return pos


def zstd_decompress(data):
    out = bytearray()
    pos = 0
    while pos < len(data):
        magic = le(data, pos, 4)
        if magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC:
            size = le(data, pos + 4, 4)
            if pos + 8 + size > len(data):
                raise ZstdError("truncated skippable frame")
            pos += 8 + size
        elif magic == ZSTD_MAGIC:
            pos = decode_frame(data, pos + 4, out)
        else:
            raise ZstdError("unknown frame magic")
    return bytes(out)


M64 = (1 << 64) - 1
P1, P2 = 0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F
P3, P4, P5 = 0x165667B19E3779F9, 0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5


def rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def xxh64_round(acc, lane):
    acc = (acc + lane * P2) & M64
    return (rotl64(acc, 31) * P1) & M64


def xxh64(data, seed=0):
    n, i = len(data), 0
    if n >= 32:
        v = [(seed + P1 + P2) & M64, (seed + P2) & M64, seed & M64, (seed - P1) & M64]
        while i + 32 <= n:
            for j in range(4):
                v[j] = xxh64_round(v[j], le(data, i + 8 * j, 8))
            i += 32
        h = (rotl64(v[0], 1) + rotl64(v[1], 7) + rotl64(v[2], 12) + rotl64(v[3], 18)) & M64
        for lane in v:
            h = ((h ^ xxh64_round(0, lane)) * P1 + P4) & M64
    else:
        h = (seed + P5) & M64
    h = (h + n) & M64
    while i + 8 <= n:
        h = (rotl64(h ^ xxh64_round(0, le(data, i, 8)), 27) * P1 + P4) & M64
        i += 8
    if i + 4 <= n:
        h = (rotl64(h ^ ((le(data, i, 4) * P1) & M64), 23) * P2 + P3) & M64
        i += 4
    while i < n:
        h = (rotl64(h ^ ((data[i] * P5) & M64), 11) * P1) & M64
        i += 1
    h ^= h >> 33
    h = (h * P2) & M64
    h ^= h >> 29
    h = (h * P3) & M64
    h ^= h >> 32
    return h
