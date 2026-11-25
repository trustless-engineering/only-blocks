# OnlyBlocks Zstandard Mini-Spec (RFC 8878 decoder blueprint)

Status: **normative** for every OnlyBlocks implementation whose language
standard library does not ship a Zstandard decoder (almost all of them).

Old Faithful stores modern transaction metadata and block rewards as Zstandard
frames (magic bytes `28 B5 2F FD`). This document is a self-contained,
decode-only blueprint of RFC 8878 Zstandard: everything needed to turn those
frames back into bytes, and nothing else. It covers no compression, no
dictionaries, and no streaming. The whole input is in RAM and the whole output
goes into one growable byte buffer.

All pseudocode below is **executable Python 3** (stdlib only). It was
extracted verbatim from this file and run against a corpus built with the
reference `zstd` CLI. That corpus covers every block type, every literals type,
1- and 4-stream Huffman, direct and FSE-compressed Huffman weights, all four
sequence modes, repeat offsets (including the `literals_length == 0` rule),
checksums, concatenated frames and skippable frames. Port it line by line. The
code is about 490 non-blank lines including the constant tables and XXH64
(roughly 400 lines of logic), and a port lands near 450-600 lines in most
languages.

Conventions:

* All multi-byte integers in the frame/block headers are **little-endian**.
* `highbit(x)` is the index of the most significant set bit (`highbit(1) == 0`,
  `highbit(8) == 3`). `x` is always `> 0` where it is used.
* Every bounds or format violation raises `ZstdError`. In OnlyBlocks, a failed
  zstd decode of a metadata or rewards frame falls back to decoding the raw
  bytes (see `docs/WIRE_FORMATS.md` §9.1), and the request fails with `-32603`
  only if that also fails.

---

## 1. Constants and helpers

`MAX_DECOMPRESSED_BYTES` is the OnlyBlocks decompression-bomb limit: **512 MiB
total output across all frames of one input**. Exceeding it is an error. It
must never be silently truncated.

```python
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
```

### 1.1 Sequence code tables (RFC 8878 §3.1.1.3.2.1.1)

Literals-length codes `0..35` and match-length codes `0..52` map to a baseline
plus a number of extra bits read from the sequence bitstream. These tables are
copied from libzstd 1.6.0 (`zstd_internal.h`, `zstd_decompress_internal.h`).

```python
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
```

Offset codes need no table: `Offset_Value = (1 << code) + read_bits(code)`
(§6.2).

### 1.2 Predefined FSE distributions (RFC 8878 §3.1.1.3.2.2)

These are used by `Predefined_Mode` (mode `0`). A probability of `-1` means
"less than 1" (see §3.2).

```python
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
```

Sanity check for porters: the absolute values sum to `64`, `32` and `64`
respectively (`2^accuracy_log`).

---

## 2. Bitstreams

Zstandard uses two kinds of bit readers.

**Forward** (FSE table headers only): bits are consumed starting at bit 0 (the
LSB) of the first byte and moving upward through the bytes. That is, the input
is one little-endian integer read from its low end.

**Backward** (Huffman streams, FSE-compressed Huffman weights, sequences): the
encoder wrote bits forward and then appended a `1` marker bit followed by `0`
padding up to a byte boundary. The decoder starts at the **end**. The last byte
must be non-zero. Its highest set bit is the marker and is discarded together
with the zero bits above it. Bits are then read from the most significant
remaining position downward. A read of `n` bits returns them as an integer
whose MSB is the first bit read. Reading past the start of the stream yields
`0` bits and drives `bits` negative. Callers use that as the "overflow"
signal (§4.2) or treat it as corruption.

Concretely, treat the stream bytes `data[start:end]` as one little-endian
integer `W`. Then `bits` starts at `8*(end-start-1) + highbit(data[end-1])`, and
`read(n)` returns bits `[bits-n, bits)` of `W` and does `bits -= n`.

```python
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
```

Porting note: a 64-bit "bit container" implementation (like libzstd's) is
equivalent. Reads are at most 31 bits at a time, except initial FSE states,
which are at most 9 bits.

---

## 3. FSE (tANS) tables

### 3.1 Table description (`FSE_Compressed_Mode` header, RFC 8878 §4.1.1)

Read with a **forward** bit reader starting at byte `pos`:

1. `accuracy_log = read(4) + 5`. It must be `<= max_log` (`9` for LL/ML, `8`
   for OF, `6` for Huffman weights).
2. `remaining = (1 << accuracy_log) + 1`, `threshold = 1 << accuracy_log`,
   `nbits = accuracy_log + 1`.
3. While `remaining > 1`, decode one symbol's probability:
   * `max = 2*threshold - 1 - remaining`.
   * Peek `nbits - 1` bits as `low`. If `low < max`, the value is `low` and
     `nbits - 1` bits are consumed. Otherwise peek `nbits` bits as `value`,
     consume `nbits`, and if `value >= threshold` then `value -= max`.
   * `prob = value - 1`. `-1` means "less than 1": it occupies one table cell
     and counts as `1` against `remaining`.
   * If `prob == 0`, read 2-bit repeat flags: each gives `0..3` additional
     zero-probability symbols. Keep reading 2 more bits while the flag was `3`.
   * While `remaining < threshold`: `nbits -= 1; threshold >>= 1`.
4. At the end `remaining` must be exactly `1`, and the symbol count must not
   exceed `max_symbol + 1`.
5. The header occupies `ceil(bits_consumed / 8)` bytes. The next field starts
   at that byte.

```python
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
                if repeat != 3:
                    break
        while remaining < threshold:
            nbits -= 1
            threshold >>= 1
    if remaining != 1 or len(probs) > max_symbol + 1:
        raise ZstdError("corrupt FSE description")
    end = (bitpos + 7) >> 3
    if end > limit:
        raise ZstdError("FSE description overruns its section")
    return probs, accuracy_log, end
```

### 3.2 Building the decoding table (RFC 8878 §4.1.1, "FSE table construction")

Each of the `size = 1 << accuracy_log` table cells holds `(symbol, nb_bits,
baseline)`:

1. Symbols with probability `-1` are placed one per cell from the **top** of
   the table downward (`high` starts at `size - 1`). Their counter starts at
   `1`.
2. All other symbols, in increasing symbol order, are each written `prob`
   times. The write position starts at `0` and advances by
   `step = (size >> 1) + (size >> 3) + 3` modulo `size`. Any position
   `> high` (already taken by a `-1` symbol) is skipped. After all symbols,
   the position must be back at `0`.
3. For each cell in increasing index order, with `s = symbol[cell]`: take
   `x = counter[s]` (starting at `prob[s]`, or `1` for `-1` symbols) and
   increment the counter. Then `nb_bits = accuracy_log - highbit(x)` and
   `baseline = (x << nb_bits) - size`.

Decoding: `symbol = table[state].symbol`. To advance,
`state = table[state].baseline + read(table[state].nb_bits)`. The initial
state is `read(accuracy_log)`.

```python
def build_fse_table(probs, accuracy_log):
    size = 1 << accuracy_log
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
```

An **RLE table** (sequence mode `1`) is the single cell `[(symbol, 0, 0)]`
with accuracy log `0`. Its state is always `0` and it never reads bits.

---

## 4. Huffman literals (RFC 8878 §4.2)

### 4.1 Table description

The first byte `h` of a Huffman tree description selects the weight encoding:

* `h < 128`: **FSE-compressed weights**. The next `h` bytes hold an FSE table
  description (`max_log 6`, `max_symbol 255`) followed by a backward bitstream.
  Decode it with **two interleaved states** (`state1`, then `state2`, each
  initialized with `accuracy_log` bits) as follows. Emit `state1`'s symbol,
  advance `state1`, and if the stream is now overflowed (`bits < 0`), emit
  `state2`'s symbol and stop. Otherwise emit `state2`'s symbol, advance
  `state2`, and if overflowed, emit `state1`'s symbol and stop. Repeat. Ending
  exactly at `bits == 0` is *not* an overflow.
* `h >= 128`: **direct 4-bit weights**. There are `n = h - 127` weights packed
  two per byte, **high nibble first**, occupying `(n + 1) // 2` bytes.

Weights are `0..11`. `0` means the symbol is absent. Symbol `i` gets weight
`i` of the list, and the **last** symbol's weight is implied:

* `total = sum(2^(w-1) for w > 0)`.
* `max_bits = highbit(total) + 1`, which must be `<= 11`.
* `rest = 2^max_bits - total` must be a power of two. The last weight is
  `highbit(rest) + 1`.

A symbol with weight `w > 0` has a code of `max_bits + 1 - w` bits.
Decoding uses a flat table of `2^max_bits` cells. Fill cells starting at
index 0 with the **lowest weights (longest codes) first**. Within equal
weights, go in increasing symbol order. Each symbol of weight `w` fills
`2^(w-1)` consecutive cells.

```python
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
```

### 4.2 Huffman streams

Each stream is a **backward** bitstream decoding a known number of symbols.
For each symbol, `peek(max_bits)` (zero-padded at the very end) indexes the
table, the symbol is emitted, and only that cell's `nb_bits` are consumed.
After the last symbol, exactly all bits must be consumed (`bits == 0`).

```python
def decode_huffman_stream(data, start, end, huffman, count, out):
    table, max_bits = huffman
    br = BackwardBits(data, start, end)
    for _ in range(count):
        sym, nb = table[br.peek(max_bits)]
        out.append(sym)
        br.bits -= nb
    if br.bits != 0:
        raise ZstdError("Huffman stream not fully consumed")
```

---

## 5. Literals section (RFC 8878 §3.1.1.3.1)

Byte 0: bits `0-1` are `Literals_Block_Type`, bits `2-3` are `Size_Format`.

| Type | Name | Payload |
|---|---|---|
| `0` | `Raw_Literals_Block` | `Regenerated_Size` raw bytes |
| `1` | `RLE_Literals_Block` | 1 byte, repeated `Regenerated_Size` times |
| `2` | `Compressed_Literals_Block` | Huffman description, then 1 or 4 Huffman streams |
| `3` | `Treeless_Literals_Block` | 1 or 4 streams reusing the **previous** Huffman table of this frame |

Header sizes for **Raw/RLE**:

| `Size_Format` | Header bytes | `Regenerated_Size` |
|---|---|---|
| `00` or `10` | 1 | `b0 >> 3` (5 bits) |
| `01` | 2 | `(b0 >> 4) + (b1 << 4)` (12 bits) |
| `11` | 3 | `(b0 >> 4) + (b1 << 4) + (b2 << 12)` (20 bits) |

Header sizes for **Compressed/Treeless**. Let `H` be the little-endian header
integer:

| `Size_Format` | Streams | Header bytes | `Regenerated_Size` | `Compressed_Size` |
|---|---|---|---|---|
| `00` | 1 | 3 | `(H >> 4) & 0x3FF` | `(H >> 14) & 0x3FF` |
| `01` | 4 | 3 | `(H >> 4) & 0x3FF` | `(H >> 14) & 0x3FF` |
| `10` | 4 | 4 | `(H >> 4) & 0x3FFF` | `(H >> 18) & 0x3FFF` |
| `11` | 4 | 5 | `(H >> 4) & 0x3FFFF` | `(H >> 22) & 0x3FFFF` |

`Compressed_Size` counts everything after the header: the Huffman description
(type 2 only), the jump table (4 streams) and the streams. With 4 streams, a
6-byte **jump table** (three little-endian `u16`: sizes of streams 1-3)
precedes the streams. Stream 4's size is whatever remains. Streams 1-3 each
decode `(Regenerated_Size + 3) // 4` bytes and stream 4 decodes the rest.

```python
def decode_literals(data, pos, end, frame):
    if pos >= end:
        raise ZstdError("missing literals section")
    b0 = data[pos]
    ltype = b0 & 3
    size_format = (b0 >> 2) & 3
    if ltype in (0, 1):
        if size_format in (0, 2):
            size = b0 >> 3
            pos += 1
        elif size_format == 1:
            size = (b0 >> 4) + (le(data, pos + 1, 1) << 4)
            pos += 2
        else:
            size = (b0 >> 4) + (le(data, pos + 1, 1) << 4) + (le(data, pos + 2, 1) << 12)
            pos += 3
        if ltype == 0:
            if pos + size > end:
                raise ZstdError("raw literals overrun block")
            return bytes(data[pos:pos + size]), pos + size
        if pos >= end:
            raise ZstdError("RLE literals overrun block")
        return bytes([data[pos]]) * size, pos + 1

    streams, header_len, width = {0: (1, 3, 10), 1: (4, 3, 10),
                                  2: (4, 4, 14), 3: (4, 5, 18)}[size_format]
    h = le(data, pos, header_len)
    regenerated = (h >> 4) & ((1 << width) - 1)
    compressed = (h >> (4 + width)) & ((1 << width) - 1)
    pos += header_len
    lit_end = pos + compressed
    if lit_end > end:
        raise ZstdError("compressed literals overrun block")
    if ltype == 2:
        frame.huffman, pos = read_huffman_description(data, pos, lit_end)
    elif frame.huffman is None:
        raise ZstdError("treeless literals without a previous Huffman table")
    out = bytearray()
    if streams == 1:
        decode_huffman_stream(data, pos, lit_end, frame.huffman, regenerated, out)
    else:
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
```

---

## 6. Sequences section (RFC 8878 §3.1.1.3.2)

### 6.1 Header and table modes

`Number_of_Sequences`:

| Byte 0 | Header bytes | Value |
|---|---|---|
| `0` | 1 | `0`. The section ends here and must end the block. |
| `1..127` | 1 | `b0` |
| `128..254` | 2 | `((b0 - 128) << 8) + b1` |
| `255` | 3 | `b1 + (b2 << 8) + 0x7F00` |

Then one `Symbol_Compression_Modes` byte: bits `7-6` select the literals-length
mode, bits `5-4` the offset mode, bits `3-2` the match-length mode, and bits
`1-0` are reserved and must be `0`. Table descriptions follow in the order
**LL, OF, ML**:

| Mode | Name | Bytes | Table |
|---|---|---|---|
| `0` | `Predefined_Mode` | 0 | §1.2 default distribution |
| `1` | `RLE_Mode` | 1 (the symbol) | single-cell RLE table |
| `2` | `FSE_Compressed_Mode` | FSE description (§3.1) | built from it |
| `3` | `Repeat_Mode` | 0 | the table used by the **previous** block of this frame for this kind (error if none) |

Every block's chosen table (including Predefined and RLE) becomes the
"previous" table for `Repeat_Mode` in later blocks of the same frame.

### 6.2 Decoding sequences

The rest of the block is one **backward** bitstream:

1. Initialize states in the order **LL, OF, ML**, each `read(accuracy_log)`.
2. For each sequence:
   * Take the current symbols: `of_code`, `ml_code`, `ll_code`.
   * Read extra bits in the order **offset, match length, literals length**:
     `offset_value = (1 << of_code) + read(of_code)`,
     `ml = ML_BASE[ml_code] + read(ML_BITS[ml_code])`,
     `ll = LL_BASE[ll_code] + read(LL_BITS[ll_code])`.
   * Unless this is the last sequence, advance states in the order
     **LL, ML, OF**.
3. At the end, all bits must be consumed (`bits == 0`).

```python
def read_sequence_table(data, pos, end, mode, kind, frame):
    default, default_log, max_symbol, max_log = SEQ_KINDS[kind]
    if mode == 0:
        t = (build_fse_table(default, default_log), default_log)
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


def decode_sequences(data, pos, end, frame):
    if pos >= end:
        raise ZstdError("missing sequences section")
    b0 = data[pos]
    if b0 == 0:
        if pos + 1 != end:
            raise ZstdError("data after empty sequences section")
        return []
    if b0 < 128:
        count, pos = b0, pos + 1
    elif b0 < 255:
        count, pos = ((b0 - 128) << 8) + le(data, pos + 1, 1), pos + 2
    else:
        count, pos = le(data, pos + 1, 2) + 0x7F00, pos + 3
    if pos >= end:
        raise ZstdError("missing compression modes")
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
    sequences = []
    for i in range(count):
        of_code, ml_code, ll_code = of_t[of_s][0], ml_t[ml_s][0], ll_t[ll_s][0]
        offset_value = (1 << of_code) + br.read(of_code)
        ml = ML_BASE[ml_code] + br.read(ML_BITS[ml_code])
        ll = LL_BASE[ll_code] + br.read(LL_BITS[ll_code])
        sequences.append((ll, offset_value, ml))
        if i != count - 1:
            ll_s = ll_t[ll_s][2] + br.read(ll_t[ll_s][1])
            ml_s = ml_t[ml_s][2] + br.read(ml_t[ml_s][1])
            of_s = of_t[of_s][2] + br.read(of_t[of_s][1])
    if br.bits != 0:
        raise ZstdError("sequence bitstream not fully consumed")
    return sequences
```

### 6.3 Repeat offsets and sequence execution (RFC 8878 §3.1.2.5)

The frame keeps `rep = [1, 4, 8]` at frame start. It persists across blocks
and resets for every frame.

* `offset_value > 3`: a new offset, `offset = offset_value - 3`. Then
  `rep = [offset, rep[0], rep[1]]`.
* `offset_value` in `1..3`: a repeat. Let `idx = offset_value - 1`, plus `1`
  if `ll == 0`:
  * `idx 0`: `offset = rep[0]`, history unchanged.
  * `idx 1`: `offset = rep[1]`, then `rep = [rep[1], rep[0], rep[2]]`.
  * `idx 2`: `offset = rep[2]`, then `rep = [rep[2], rep[0], rep[1]]`.
  * `idx 3` (only reachable when `ll == 0`): `offset = rep[0] - 1`, then
    `rep = [offset, rep[0], rep[1]]`.

Execution: for each `(ll, offset, ml)`, append `ll` literals, then copy `ml`
bytes **one byte at a time** from `offset` bytes back in the output (overlap is
legal and common). After the last sequence, append all remaining literals. An
offset of `0`, or one reaching before the start of the current frame's output,
is corruption (OnlyBlocks never uses dictionaries).

```python
def execute_sequences(sequences, literals, out, frame_start, rep):
    lit = 0
    for ll, offset_value, ml in sequences:
        if lit + ll > len(literals):
            raise ZstdError("sequence consumes more literals than available")
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
        if offset <= 0 or offset > len(out) - frame_start:
            raise ZstdError("match offset out of range")
        if len(out) + ml > MAX_DECOMPRESSED_BYTES:
            raise ZstdError("decompressed size limit exceeded")
        src = len(out) - offset
        for k in range(ml):
            out.append(out[src + k])
    out += literals[lit:]
```

---

## 7. Frames and blocks (RFC 8878 §3.1)

### 7.1 Frame header

```
Magic_Number        4 bytes  28 B5 2F FD
Frame_Header_Descriptor 1 byte
  bits 7-6 Frame_Content_Size_Flag (FCS_Flag)
  bit  5   Single_Segment_Flag
  bit  4   unused (ignore)
  bit  3   reserved, must be 0
  bit  2   Content_Checksum_Flag
  bits 1-0 Dictionary_ID_Flag
Window_Descriptor   1 byte, present iff Single_Segment_Flag == 0
Dictionary_ID       0/1/2/4 bytes for Dictionary_ID_Flag 0/1/2/3 (LE)
Frame_Content_Size  0/2/4/8 bytes for FCS_Flag 0/1/2/3 (LE);
                    FCS_Flag 0 with Single_Segment_Flag 1 means 1 byte.
                    The 2-byte form stores (size - 256).
```

* `Window_Descriptor`: `exponent = b >> 3`, `mantissa = b & 7`,
  `base = 1 << (10 + exponent)`, `Window_Size = base + (base >> 3) * mantissa`.
  With `Single_Segment_Flag`, `Window_Size = Frame_Content_Size`. A
  whole-buffer decoder needs the window only for validation. For parity with
  libzstd's default streaming limit, implementations MAY reject
  `Window_Size > 2^27`.
* A **non-zero** `Dictionary_ID` is an error (no dictionaries).
* When `Frame_Content_Size` is present, the frame's output length must equal
  it.

### 7.2 Blocks

Each block starts with a 3-byte little-endian header: bit `0` is
`Last_Block`, bits `1-2` are `Block_Type`, and bits `3-23` are `Block_Size`.

| `Block_Type` | Name | Content |
|---|---|---|
| `0` | `Raw_Block` | `Block_Size` bytes copied verbatim |
| `1` | `RLE_Block` | 1 byte repeated `Block_Size` times |
| `2` | `Compressed_Block` | `Block_Size` bytes: literals section, then sequences section |
| `3` | `Reserved` | error |

`Block_Size` (and the regenerated size of every block) must be
`<= 128 KiB`.

### 7.3 Content checksum and multiple frames

If `Content_Checksum_Flag` is set, 4 more bytes follow the last block. They
hold the **low 32 bits of XXH64(frame output, seed 0)**, little-endian.
OnlyBlocks implementations SHOULD verify it (libzstd, the Rust reference's
decoder, does) and MUST at least consume the 4 bytes.

An input may contain **several concatenated frames**. Their outputs are
concatenated. **Skippable frames** (`magic & 0xFFFFFFF0 == 0x184D2A50`, i.e.
bytes `5? 2A 4D 18`) are followed by a 4-byte LE `Frame_Size`, and that many
bytes are skipped. Anything else after a frame (including fewer than 4
trailing bytes) is an error.

```python
class FrameState:
    def __init__(self):
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
        le(data, pos, 1)                  # Window_Descriptor (validation only)
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
    frame_start = len(out)
    frame = FrameState()
    while True:
        header = le(data, pos, 3)
        pos += 3
        last, block_type, block_size = header & 1, (header >> 1) & 3, header >> 3
        if block_size > BLOCK_SIZE_MAX:
            raise ZstdError("block too large")
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
            literals, p = decode_literals(data, pos, end, frame)
            sequences = decode_sequences(data, p, end, frame)
            execute_sequences(sequences, literals, out, frame_start, frame.rep)
            pos = end
        else:
            raise ZstdError("reserved block type")
        if len(out) > MAX_DECOMPRESSED_BYTES:
            raise ZstdError("decompressed size limit exceeded")
        if last:
            break
    if content_size is not None and len(out) - frame_start != content_size:
        raise ZstdError("frame content size mismatch")
    if has_checksum:
        expected = le(data, pos, 4)
        pos += 4
        if xxh64(out[frame_start:]) & 0xFFFFFFFF != expected:
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
```

---

## 8. XXH64 (for the optional content checksum)

64-bit arithmetic modulo `2^64` throughout. Test vectors:
`XXH64(b"", 0) == 0xEF46DB3751D8E999`, `XXH64(b"a", 0) == 0xD24EC4F1A98C6E5B`.

```python
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
```

---

## 9. Porting checklist

1. Use unsigned 64-bit (or arbitrary-precision) integers for bit windows and
   XXH64. In languages without unsigned 64-bit arithmetic (Java, Erlang,
   Tcl, AWK, Fortran), mask after every multiply/add or emulate with two
   32-bit halves.
2. `BackwardBits.read(n)` must return zeros for bits before the stream start
   **and** let `bits` go negative. Huffman-weight decoding (§4.1) depends on
   it.
3. Match copies must be byte-by-byte (or chunked only when
   `offset >= chunk`). Overlapping copies such as `offset = 1` produce runs.
4. Repeat-offset history and Huffman/FSE "previous" tables are **per frame**:
   reset them at every frame header.
5. Enforce `MAX_DECOMPRESSED_BYTES` *before* growing the output buffer.
6. Old Faithful frames observed in practice: single frame, no dictionary,
   usually no checksum, Compressed + Raw blocks, both literal stream layouts.
   Do not special-case this. Implement the whole decoder.

Self-test vectors. Each one was checked against both `zstd -d` and the code
above:

| Input (hex) | What it exercises | Output |
|---|---|---|
| `28b52ffd2000010000` | single-segment frame, one empty raw block | empty |
| `28b52ffd200a5100006f6e6c79626c6f636b73` | raw block | `onlyblocks` (10 bytes) |
| `28b52ffd2064230300aa` | RLE block | byte `0xAA` × 100 |
| `502a4d180300000001020328b52ffd2000010000` | skippable frame, then an empty frame | empty |
| `28b52ffd0068950000606f6e6c79626c6f636b7320210100fe8a17` | `zstd -19 --no-check`: compressed block, raw literals, predefined tables | `onlyblocks onlyblocks onlyblocks!` (33 bytes) |
| `28b52ffd04584d00001861626301007e6e0848c3d30e` | `zstd -3 --check`: overlapping match, XXH64 checksum | `abc` × 8 (24 bytes) |

How this blueprint was verified: every ```` ```python ```` block in this file
was concatenated, executed, and run against two sets of frames.

* 126 frames produced by the `zstd` v1.5.7 CLI. They covered levels
  `--fast=5` through `--ultra -22`, `--long=27`, `--check`,
  `--no-content-size`, inputs from 0 bytes to 1.2 MB, concatenated and
  skippable frames, a block with 42 653 sequences (3-byte
  `Number_of_Sequences`), direct-weight Huffman tables, RLE literals,
  treeless literals, and RLE/Repeat sequence modes.
* All 141 zstd frames of mainnet slot `302400001` from Old Faithful
  (140 transaction-metadata frames and 1 rewards frame).
* The epoch-boundary rewards payload of mainnet slot `302400000`: 56 369 821
  bytes reassembled from 4 DataFrames, decompressing to 75 677 186 bytes.

All outputs were byte-identical to `zstd -d`, and random bit-flips raised only
`ZstdError`. A line-coverage trace confirmed that every branch of the code
above ran, except some `raise` statements.
