//! A decode-only RFC 8878 Zstandard decompressor, ported from `docs/ZSTD_MINI_SPEC.md`.
//!
//! Covers Raw/RLE/Compressed blocks, Raw/RLE/Huffman (1- and 4-stream, direct and
//! FSE-compressed weights, treeless) literals, all four FSE sequence modes, repeat offsets,
//! XXH64 content checksums, concatenated frames, skippable frames and the 512 MiB bomb limit.

use std::fmt;

pub const MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;
const ZSTD_MAGIC: u32 = 0xFD2F_B528;
const SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
const BLOCK_SIZE_MAX: usize = 128 * 1024;
/// libzstd's default streaming window limit (`ZSTD_MAXWINDOWSIZE_DEFAULT`), for parity
/// with the reference's streaming decoder.
const MAX_WINDOW_SIZE: u64 = (1 << 27) + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZstdError(pub &'static str);

impl fmt::Display for ZstdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zstd: {}", self.0)
    }
}

type ZResult<T> = Result<T, ZstdError>;

fn err<T>(msg: &'static str) -> ZResult<T> {
    Err(ZstdError(msg))
}

#[inline]
fn highbit(x: u32) -> u32 {
    31 - x.leading_zeros()
}

/// Little-endian unsigned integer of `n <= 8` bytes at `data[pos..]`.
#[inline]
fn le(data: &[u8], pos: usize, n: usize) -> ZResult<u64> {
    if pos > data.len() || n > data.len() - pos {
        return err("truncated input");
    }
    let mut v = 0u64;
    for i in 0..n {
        v |= (data[pos + i] as u64) << (8 * i);
    }
    Ok(v)
}

// ---------------------------------------------------------------------------------------
// Constant tables (RFC 8878 §3.1.1.3.2.1.1 and §3.1.1.3.2.2)
// ---------------------------------------------------------------------------------------

const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const LL_BITS: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
    4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];
const LL_DEFAULT: [i32; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const ML_DEFAULT: [i32; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT: [i32; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

#[derive(Clone, Copy)]
enum Kind {
    LiteralLength,
    Offset,
    MatchLength,
}

impl Kind {
    /// (default distribution, default accuracy log, max symbol, max accuracy log)
    fn params(self) -> (&'static [i32], u32, usize, u32) {
        match self {
            Kind::LiteralLength => (&LL_DEFAULT, 6, 35, 9),
            Kind::Offset => (&OF_DEFAULT, 5, 31, 8),
            Kind::MatchLength => (&ML_DEFAULT, 6, 52, 9),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Backward bitstream (§2)
// ---------------------------------------------------------------------------------------

struct BackwardBits<'a> {
    data: &'a [u8],
    start: usize,
    /// Number of unread bits; goes negative when reading past the start ("overflow").
    bits: i64,
}

impl<'a> BackwardBits<'a> {
    fn new(data: &'a [u8], start: usize, end: usize) -> ZResult<Self> {
        if end > data.len() || end <= start {
            return err("empty or out-of-range bitstream");
        }
        let last = data[end - 1];
        if last == 0 {
            return err("bitstream end marker missing");
        }
        Ok(BackwardBits { data, start, bits: 8 * (end - start - 1) as i64 + highbit(last as u32) as i64 })
    }

    /// Bits `[lo, hi)` of the stream, `0 <= lo < hi`, `hi - lo <= 56`.
    #[inline]
    fn window(&self, lo: i64, hi: i64) -> u64 {
        let first = (lo >> 3) as usize;
        let base = self.start + first;
        let word = if base + 8 <= self.data.len() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&self.data[base..base + 8]);
            u64::from_le_bytes(w)
        } else {
            let mut w = 0u64;
            for (i, &b) in self.data[base..].iter().enumerate().take(8) {
                w |= (b as u64) << (8 * i);
            }
            w
        };
        let width = (hi - lo) as u32;
        (word >> (lo & 7)) & ((1u64 << width) - 1)
    }

    #[inline]
    fn peek(&self, n: u32) -> u64 {
        let hi = self.bits;
        if n == 0 || hi <= 0 {
            return 0;
        }
        let lo = hi - n as i64;
        if lo < 0 {
            self.window(0, hi) << (-lo)
        } else {
            self.window(lo, hi)
        }
    }

    #[inline]
    fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.bits -= n as i64;
        v
    }
}

// ---------------------------------------------------------------------------------------
// FSE tables (§3)
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct FseCell {
    symbol: u16,
    nb_bits: u8,
    baseline: u16,
}

#[derive(Clone)]
struct FseTable {
    cells: Vec<FseCell>,
    log: u32,
}

/// Read an FSE table description with a forward bit reader (§3.1).
fn read_fse_description(
    data: &[u8],
    pos: usize,
    limit: usize,
    max_symbol: usize,
    max_log: u32,
) -> ZResult<(Vec<i32>, u32, usize)> {
    let mut bitpos = pos * 8;
    let peek = |bitpos: usize, n: u32| -> u32 {
        let byte = bitpos >> 3;
        let mut w = 0u64;
        for i in 0..4 {
            if byte + i < limit && byte + i < data.len() {
                w |= (data[byte + i] as u64) << (8 * i);
            }
        }
        ((w >> (bitpos & 7)) & ((1u64 << n) - 1)) as u32
    };
    let accuracy_log = peek(bitpos, 4) + 5;
    bitpos += 4;
    if accuracy_log > max_log {
        return err("FSE accuracy log too large");
    }
    let mut remaining: i32 = (1 << accuracy_log) + 1;
    let mut threshold: i32 = 1 << accuracy_log;
    let mut nbits: u32 = accuracy_log + 1;
    let mut probs: Vec<i32> = Vec::with_capacity(max_symbol + 1);
    while remaining > 1 {
        if probs.len() > max_symbol {
            return err("FSE description has too many symbols");
        }
        let biggest = 2 * threshold - 1 - remaining;
        let low = peek(bitpos, nbits - 1) as i32;
        let value = if low < biggest {
            bitpos += (nbits - 1) as usize;
            low
        } else {
            let mut v = peek(bitpos, nbits) as i32;
            bitpos += nbits as usize;
            if v >= threshold {
                v -= biggest;
            }
            v
        };
        let prob = value - 1;
        probs.push(prob);
        remaining -= prob.abs();
        if prob == 0 {
            loop {
                let repeat = peek(bitpos, 2);
                bitpos += 2;
                for _ in 0..repeat {
                    probs.push(0);
                }
                if probs.len() > max_symbol + 1 {
                    return err("FSE description has too many symbols");
                }
                if repeat != 3 {
                    break;
                }
            }
        }
        while remaining < threshold && nbits > 1 {
            nbits -= 1;
            threshold >>= 1;
        }
    }
    if remaining != 1 || probs.len() > max_symbol + 1 {
        return err("corrupt FSE description");
    }
    let end = bitpos.div_ceil(8);
    if end > limit {
        return err("FSE description overruns its section");
    }
    Ok((probs, accuracy_log, end))
}

/// Build the decoding table (§3.2).
fn build_fse_table(probs: &[i32], accuracy_log: u32) -> ZResult<FseTable> {
    let size: i64 = 1 << accuracy_log;
    let mut cell_symbol = vec![0u16; size as usize];
    let mut counter = vec![0u32; probs.len()];
    let mut high: i64 = size - 1;
    for (s, &p) in probs.iter().enumerate() {
        if p == -1 {
            if high < 0 {
                return err("corrupt FSE distribution");
            }
            cell_symbol[high as usize] = s as u16;
            high -= 1;
            counter[s] = 1;
        } else if p < -1 {
            return err("corrupt FSE distribution");
        } else {
            counter[s] = p as u32;
        }
    }
    let step = (size >> 1) + (size >> 3) + 3;
    let mask = size - 1;
    let mut pos: i64 = 0;
    for (s, &p) in probs.iter().enumerate() {
        for _ in 0..p.max(0) {
            cell_symbol[pos as usize] = s as u16;
            pos = (pos + step) & mask;
            while pos > high {
                pos = (pos + step) & mask;
            }
        }
    }
    if pos != 0 {
        return err("corrupt FSE distribution");
    }
    let mut cells = Vec::with_capacity(size as usize);
    for &s in &cell_symbol {
        let x = counter[s as usize];
        if x == 0 {
            return err("corrupt FSE distribution");
        }
        counter[s as usize] += 1;
        let nb = accuracy_log as i64 - highbit(x) as i64;
        if nb < 0 {
            return err("corrupt FSE distribution");
        }
        let baseline = ((x as i64) << nb) - size;
        cells.push(FseCell { symbol: s, nb_bits: nb as u8, baseline: baseline as u16 });
    }
    Ok(FseTable { cells, log: accuracy_log })
}

// ---------------------------------------------------------------------------------------
// Huffman literals (§4)
// ---------------------------------------------------------------------------------------

#[derive(Clone)]
struct Huffman {
    /// `(symbol, nb_bits)` for each of the `2^max_bits` cells.
    table: Vec<(u8, u8)>,
    max_bits: u32,
}

fn build_huffman_table(mut weights: Vec<u8>) -> ZResult<Huffman> {
    if weights.len() > 255 {
        return err("too many Huffman weights");
    }
    let mut total: u32 = 0;
    for &w in &weights {
        if w > 11 {
            return err("Huffman weight too large");
        }
        if w > 0 {
            total += 1 << (w - 1);
        }
    }
    if total == 0 {
        return err("empty Huffman table");
    }
    let max_bits = highbit(total) + 1;
    if max_bits > 11 {
        return err("Huffman code too long");
    }
    let rest = (1u32 << max_bits) - total;
    if rest & (rest.wrapping_sub(1)) != 0 || rest == 0 {
        return err("corrupt Huffman weights");
    }
    weights.push((highbit(rest) + 1) as u8);
    let mut next_cell = [0usize; 13];
    let mut start = 0usize;
    for w in 1..=max_bits as usize {
        next_cell[w] = start;
        start += weights.iter().filter(|&&x| x as usize == w).count() << (w - 1);
    }
    let mut table = vec![(0u8, 0u8); 1 << max_bits];
    for (sym, &w) in weights.iter().enumerate() {
        if w == 0 {
            continue;
        }
        let w = w as usize;
        if w > max_bits as usize {
            return err("corrupt Huffman weights");
        }
        let span = 1usize << (w - 1);
        let from = next_cell[w];
        if from + span > table.len() {
            return err("corrupt Huffman weights");
        }
        for cell in &mut table[from..from + span] {
            *cell = (sym as u8, (max_bits as usize + 1 - w) as u8);
        }
        next_cell[w] += span;
    }
    Ok(Huffman { table, max_bits })
}

fn read_huffman_description(data: &[u8], mut pos: usize, limit: usize) -> ZResult<(Huffman, usize)> {
    if pos >= limit {
        return err("missing Huffman description");
    }
    let h = data[pos] as usize;
    pos += 1;
    let mut weights: Vec<u8> = Vec::with_capacity(256);
    if h < 128 {
        let end = pos + h;
        if end > limit {
            return err("Huffman description overruns literals");
        }
        let (probs, al, p) = read_fse_description(data, pos, end, 255, 6)?;
        let table = build_fse_table(&probs, al)?;
        let mut br = BackwardBits::new(data, p, end)?;
        let mut s1 = br.read(al) as usize;
        let mut s2 = br.read(al) as usize;
        loop {
            if weights.len() > 255 {
                return err("too many Huffman weights");
            }
            let c = table.cells[s1];
            weights.push(c.symbol as u8);
            s1 = c.baseline as usize + br.read(c.nb_bits as u32) as usize;
            if br.bits < 0 {
                weights.push(table.cells[s2].symbol as u8);
                break;
            }
            let c = table.cells[s2];
            weights.push(c.symbol as u8);
            s2 = c.baseline as usize + br.read(c.nb_bits as u32) as usize;
            if br.bits < 0 {
                weights.push(table.cells[s1].symbol as u8);
                break;
            }
        }
        pos = end;
    } else {
        let n = h - 127;
        let end = pos + n.div_ceil(2);
        if end > limit {
            return err("Huffman description overruns literals");
        }
        for i in 0..n {
            let b = data[pos + i / 2];
            weights.push(if i % 2 == 0 { b >> 4 } else { b & 15 });
        }
        pos = end;
    }
    Ok((build_huffman_table(weights)?, pos))
}

fn decode_huffman_stream(
    data: &[u8],
    start: usize,
    end: usize,
    huffman: &Huffman,
    count: usize,
    out: &mut Vec<u8>,
) -> ZResult<()> {
    let mut br = BackwardBits::new(data, start, end)?;
    out.reserve(count);
    for _ in 0..count {
        let (sym, nb) = huffman.table[br.peek(huffman.max_bits) as usize];
        out.push(sym);
        br.bits -= nb as i64;
    }
    if br.bits != 0 {
        return err("Huffman stream not fully consumed");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Frame state, literals (§5) and sequences (§6)
// ---------------------------------------------------------------------------------------

struct FrameState {
    rep: [u64; 3],
    huffman: Option<Huffman>,
    tables: [Option<FseTable>; 3],
}

impl FrameState {
    fn new() -> Self {
        FrameState { rep: [1, 4, 8], huffman: None, tables: [None, None, None] }
    }
}

fn decode_literals(data: &[u8], mut pos: usize, end: usize, frame: &mut FrameState) -> ZResult<(Vec<u8>, usize)> {
    if pos >= end {
        return err("missing literals section");
    }
    let b0 = data[pos] as usize;
    let ltype = b0 & 3;
    let size_format = (b0 >> 2) & 3;
    if ltype <= 1 {
        let size = match size_format {
            0 | 2 => {
                pos += 1;
                b0 >> 3
            }
            1 => {
                let s = (b0 >> 4) + ((le(data, pos + 1, 1)? as usize) << 4);
                pos += 2;
                s
            }
            _ => {
                let s = (b0 >> 4) + ((le(data, pos + 1, 1)? as usize) << 4) + ((le(data, pos + 2, 1)? as usize) << 12);
                pos += 3;
                s
            }
        };
        if size > BLOCK_SIZE_MAX {
            return err("literals too large");
        }
        if ltype == 0 {
            if pos > end || size > end - pos {
                return err("raw literals overrun block");
            }
            return Ok((data[pos..pos + size].to_vec(), pos + size));
        }
        if pos >= end {
            return err("RLE literals overrun block");
        }
        return Ok((vec![data[pos]; size], pos + 1));
    }

    let (streams, header_len, width) = match size_format {
        0 => (1, 3, 10),
        1 => (4, 3, 10),
        2 => (4, 4, 14),
        _ => (4, 5, 18),
    };
    let h = le(data, pos, header_len)?;
    let regenerated = ((h >> 4) & ((1 << width) - 1)) as usize;
    let compressed = ((h >> (4 + width)) & ((1 << width) - 1)) as usize;
    pos += header_len;
    if regenerated > BLOCK_SIZE_MAX {
        return err("literals too large");
    }
    let lit_end = pos + compressed;
    if lit_end > end {
        return err("compressed literals overrun block");
    }
    if ltype == 2 {
        let (huffman, p) = read_huffman_description(data, pos, lit_end)?;
        frame.huffman = Some(huffman);
        pos = p;
    }
    let huffman = match &frame.huffman {
        Some(h) => h,
        None => return err("treeless literals without a previous Huffman table"),
    };
    let mut out = Vec::with_capacity(regenerated);
    if streams == 1 {
        decode_huffman_stream(data, pos, lit_end, huffman, regenerated, &mut out)?;
    } else {
        let s1 = le(data, pos, 2)? as usize;
        let s2 = le(data, pos + 2, 2)? as usize;
        let s3 = le(data, pos + 4, 2)? as usize;
        pos += 6;
        let used = pos + s1 + s2 + s3;
        if used >= lit_end {
            return err("corrupt 4-stream literals");
        }
        let sizes = [s1, s2, s3, lit_end - used];
        let quarter = regenerated.div_ceil(4);
        if 3 * quarter > regenerated {
            return err("corrupt 4-stream literals");
        }
        let counts = [quarter, quarter, quarter, regenerated - 3 * quarter];
        for (size, count) in sizes.into_iter().zip(counts) {
            decode_huffman_stream(data, pos, pos + size, huffman, count, &mut out)?;
            pos += size;
        }
    }
    Ok((out, lit_end))
}

fn read_sequence_table(
    data: &[u8],
    mut pos: usize,
    end: usize,
    mode: u8,
    kind: Kind,
    frame: &mut FrameState,
) -> ZResult<usize> {
    let (default, default_log, max_symbol, max_log) = kind.params();
    let table = match mode {
        0 => build_fse_table(default, default_log)?,
        1 => {
            if pos >= end || data[pos] as usize > max_symbol {
                return err("bad RLE sequence symbol");
            }
            let t = FseTable { cells: vec![FseCell { symbol: data[pos] as u16, nb_bits: 0, baseline: 0 }], log: 0 };
            pos += 1;
            t
        }
        2 => {
            let (probs, al, p) = read_fse_description(data, pos, end, max_symbol, max_log)?;
            pos = p;
            build_fse_table(&probs, al)?
        }
        _ => match &frame.tables[kind as usize] {
            Some(t) => t.clone(),
            None => return err("repeat mode without a previous table"),
        },
    };
    frame.tables[kind as usize] = Some(table);
    Ok(pos)
}

/// `(literals_length, offset_value, match_length)`
type Sequence = (u32, u64, u32);

fn decode_sequences(data: &[u8], mut pos: usize, end: usize, frame: &mut FrameState) -> ZResult<Vec<Sequence>> {
    if pos >= end {
        return err("missing sequences section");
    }
    let b0 = data[pos] as usize;
    if b0 == 0 {
        if pos + 1 != end {
            return err("data after empty sequences section");
        }
        return Ok(Vec::new());
    }
    let count = if b0 < 128 {
        pos += 1;
        b0
    } else if b0 < 255 {
        let c = ((b0 - 128) << 8) + le(data, pos + 1, 1)? as usize;
        pos += 2;
        c
    } else {
        let c = le(data, pos + 1, 2)? as usize + 0x7F00;
        pos += 3;
        c
    };
    if pos >= end {
        return err("missing compression modes");
    }
    let modes = data[pos];
    pos += 1;
    if modes & 3 != 0 {
        return err("reserved compression-mode bits set");
    }
    pos = read_sequence_table(data, pos, end, (modes >> 6) & 3, Kind::LiteralLength, frame)?;
    pos = read_sequence_table(data, pos, end, (modes >> 4) & 3, Kind::Offset, frame)?;
    pos = read_sequence_table(data, pos, end, (modes >> 2) & 3, Kind::MatchLength, frame)?;
    let ll_t = frame.tables[Kind::LiteralLength as usize].as_ref().ok_or(ZstdError("missing table"))?;
    let of_t = frame.tables[Kind::Offset as usize].as_ref().ok_or(ZstdError("missing table"))?;
    let ml_t = frame.tables[Kind::MatchLength as usize].as_ref().ok_or(ZstdError("missing table"))?;
    let mut br = BackwardBits::new(data, pos, end)?;
    let mut ll_s = br.read(ll_t.log) as usize;
    let mut of_s = br.read(of_t.log) as usize;
    let mut ml_s = br.read(ml_t.log) as usize;
    let mut sequences = Vec::with_capacity(count);
    for i in 0..count {
        let of_code = of_t.cells[of_s].symbol as u32;
        let ml_code = ml_t.cells[ml_s].symbol as usize;
        let ll_code = ll_t.cells[ll_s].symbol as usize;
        if of_code > 31 || ml_code >= ML_BASE.len() || ll_code >= LL_BASE.len() {
            return err("sequence code out of range");
        }
        let offset_value = (1u64 << of_code) + br.read(of_code);
        let ml = ML_BASE[ml_code] + br.read(ML_BITS[ml_code] as u32) as u32;
        let ll = LL_BASE[ll_code] + br.read(LL_BITS[ll_code] as u32) as u32;
        sequences.push((ll, offset_value, ml));
        if i != count - 1 {
            let c = ll_t.cells[ll_s];
            ll_s = c.baseline as usize + br.read(c.nb_bits as u32) as usize;
            let c = ml_t.cells[ml_s];
            ml_s = c.baseline as usize + br.read(c.nb_bits as u32) as usize;
            let c = of_t.cells[of_s];
            of_s = c.baseline as usize + br.read(c.nb_bits as u32) as usize;
            if ll_s >= ll_t.cells.len() || ml_s >= ml_t.cells.len() || of_s >= of_t.cells.len() {
                return err("FSE state out of range");
            }
        }
    }
    if br.bits != 0 {
        return err("sequence bitstream not fully consumed");
    }
    Ok(sequences)
}

fn execute_sequences(
    sequences: &[Sequence],
    literals: &[u8],
    out: &mut Vec<u8>,
    frame_start: usize,
    rep: &mut [u64; 3],
) -> ZResult<()> {
    let mut lit = 0usize;
    for &(ll, offset_value, ml) in sequences {
        let ll = ll as usize;
        let ml = ml as usize;
        if ll > literals.len() - lit {
            return err("sequence consumes more literals than available");
        }
        if out.len() + ll + ml > MAX_DECOMPRESSED_BYTES {
            return err("decompressed size limit exceeded");
        }
        out.extend_from_slice(&literals[lit..lit + ll]);
        lit += ll;
        let offset = if offset_value > 3 {
            let o = offset_value - 3;
            *rep = [o, rep[0], rep[1]];
            o
        } else {
            let idx = offset_value - 1 + u64::from(ll == 0);
            match idx {
                0 => rep[0],
                1 => {
                    let o = rep[1];
                    *rep = [rep[1], rep[0], rep[2]];
                    o
                }
                2 => {
                    let o = rep[2];
                    *rep = [rep[2], rep[0], rep[1]];
                    o
                }
                _ => {
                    let o = rep[0].wrapping_sub(1);
                    *rep = [o, rep[0], rep[1]];
                    o
                }
            }
        };
        if offset == 0 || offset > (out.len() - frame_start) as u64 {
            return err("match offset out of range");
        }
        let offset = offset as usize;
        let src = out.len() - offset;
        if offset >= ml {
            out.extend_from_within(src..src + ml);
        } else {
            out.reserve(ml);
            for k in 0..ml {
                let b = out[src + k];
                out.push(b);
            }
        }
    }
    if out.len() + (literals.len() - lit) > MAX_DECOMPRESSED_BYTES {
        return err("decompressed size limit exceeded");
    }
    out.extend_from_slice(&literals[lit..]);
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Frames (§7)
// ---------------------------------------------------------------------------------------

fn decode_frame(data: &[u8], mut pos: usize, out: &mut Vec<u8>) -> ZResult<usize> {
    let fhd = le(data, pos, 1)? as u8;
    pos += 1;
    let fcs_flag = fhd >> 6;
    let single = (fhd >> 5) & 1 == 1;
    let has_checksum = (fhd >> 2) & 1 == 1;
    let did_flag = fhd & 3;
    if fhd & 0x08 != 0 {
        return err("reserved frame header bit set");
    }
    let mut window_size: Option<u64> = None;
    if !single {
        let wd = le(data, pos, 1)?;
        pos += 1;
        let exponent = wd >> 3;
        let mantissa = wd & 7;
        let base = 1u64 << (10 + exponent);
        window_size = Some(base + (base >> 3) * mantissa);
    }
    let did_size = [0, 1, 2, 4][did_flag as usize];
    if did_size > 0 && le(data, pos, did_size)? != 0 {
        return err("zstd dictionaries are not supported");
    }
    pos += did_size;
    let fcs_size = [if single { 1 } else { 0 }, 2, 4, 8][fcs_flag as usize];
    let mut content_size: Option<u64> = None;
    if fcs_size > 0 {
        let v = le(data, pos, fcs_size)? + if fcs_size == 2 { 256 } else { 0 };
        content_size = Some(v);
        pos += fcs_size;
    }
    if single {
        window_size = content_size;
    }
    if window_size.is_some_and(|w| w > MAX_WINDOW_SIZE) {
        return err("frame window too large");
    }
    if content_size.is_some_and(|c| c > (MAX_DECOMPRESSED_BYTES - out.len()) as u64) {
        return err("decompressed size limit exceeded");
    }
    if let Some(cs) = content_size {
        // Bounded hint only: a hostile header must not be able to force a huge allocation.
        let hint = (cs as usize).min((data.len() - pos).saturating_mul(8) + 65_536);
        out.reserve(hint);
    }
    let frame_start = out.len();
    let mut frame = FrameState::new();
    loop {
        let header = le(data, pos, 3)? as usize;
        pos += 3;
        let last = header & 1 == 1;
        let block_type = (header >> 1) & 3;
        let block_size = header >> 3;
        if block_size > BLOCK_SIZE_MAX {
            return err("block too large");
        }
        let block_start = out.len();
        match block_type {
            0 => {
                if block_size > data.len() - pos {
                    return err("truncated raw block");
                }
                if out.len() + block_size > MAX_DECOMPRESSED_BYTES {
                    return err("decompressed size limit exceeded");
                }
                out.extend_from_slice(&data[pos..pos + block_size]);
                pos += block_size;
            }
            1 => {
                let byte = le(data, pos, 1)? as u8;
                if out.len() + block_size > MAX_DECOMPRESSED_BYTES {
                    return err("decompressed size limit exceeded");
                }
                out.resize(out.len() + block_size, byte);
                pos += 1;
            }
            2 => {
                if block_size > data.len() - pos {
                    return err("truncated compressed block");
                }
                let end = pos + block_size;
                let (literals, p) = decode_literals(data, pos, end, &mut frame)?;
                let sequences = decode_sequences(data, p, end, &mut frame)?;
                let mut rep = frame.rep;
                execute_sequences(&sequences, &literals, out, frame_start, &mut rep)?;
                frame.rep = rep;
                pos = end;
            }
            _ => return err("reserved block type"),
        }
        if out.len() - block_start > BLOCK_SIZE_MAX {
            return err("block output too large");
        }
        if out.len() > MAX_DECOMPRESSED_BYTES {
            return err("decompressed size limit exceeded");
        }
        if last {
            break;
        }
    }
    if let Some(cs) = content_size {
        if (out.len() - frame_start) as u64 != cs {
            return err("frame content size mismatch");
        }
    }
    if has_checksum {
        let expected = le(data, pos, 4)?;
        pos += 4;
        if xxh64(&out[frame_start..], 0) & 0xFFFF_FFFF != expected {
            return err("content checksum mismatch");
        }
    }
    Ok(pos)
}

/// Decompress every (possibly concatenated or skippable) frame in `data`.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, ZstdError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let magic = le(data, pos, 4)? as u32;
        if magic & SKIPPABLE_MASK == SKIPPABLE_MAGIC {
            let size = le(data, pos + 4, 4)? as usize;
            if size > data.len() - (pos + 8) {
                return err("truncated skippable frame");
            }
            pos += 8 + size;
        } else if magic == ZSTD_MAGIC {
            pos = decode_frame(data, pos + 4, &mut out)?;
        } else {
            return err("unknown frame magic");
        }
    }
    Ok(out)
}

pub fn has_magic(data: &[u8]) -> bool {
    data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD])
}

// ---------------------------------------------------------------------------------------
// XXH64 (§8)
// ---------------------------------------------------------------------------------------

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

#[inline]
fn round(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1)
}

#[inline]
fn u64_at(data: &[u8], i: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&data[i..i + 8]);
    u64::from_le_bytes(w)
}

pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let n = data.len();
    let mut i = 0usize;
    let mut h: u64;
    if n >= 32 {
        let mut v = [
            seed.wrapping_add(P1).wrapping_add(P2),
            seed.wrapping_add(P2),
            seed,
            seed.wrapping_sub(P1),
        ];
        while i + 32 <= n {
            for (j, lane) in v.iter_mut().enumerate() {
                *lane = round(*lane, u64_at(data, i + 8 * j));
            }
            i += 32;
        }
        h = v[0]
            .rotate_left(1)
            .wrapping_add(v[1].rotate_left(7))
            .wrapping_add(v[2].rotate_left(12))
            .wrapping_add(v[3].rotate_left(18));
        for lane in v {
            h = (h ^ round(0, lane)).wrapping_mul(P1).wrapping_add(P4);
        }
    } else {
        h = seed.wrapping_add(P5);
    }
    h = h.wrapping_add(n as u64);
    while i + 8 <= n {
        h = (h ^ round(0, u64_at(data, i))).rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        i += 8;
    }
    if i + 4 <= n {
        let mut w = [0u8; 4];
        w.copy_from_slice(&data[i..i + 4]);
        h = (h ^ (u32::from_le_bytes(w) as u64).wrapping_mul(P1)).rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
        i += 4;
    }
    while i < n {
        h = (h ^ (data[i] as u64).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1);
        i += 1;
    }
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^= h >> 32;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn mini_spec_vectors() {
        assert_eq!(decompress(&hex("28b52ffd2000010000")).unwrap(), b"");
        assert_eq!(decompress(&hex("28b52ffd200a5100006f6e6c79626c6f636b73")).unwrap(), b"onlyblocks");
        assert_eq!(decompress(&hex("28b52ffd2064230300aa")).unwrap(), vec![0xAA; 100]);
        assert_eq!(decompress(&hex("502a4d180300000001020328b52ffd2000010000")).unwrap(), b"");
        assert_eq!(
            decompress(&hex("28b52ffd0068950000606f6e6c79626c6f636b7320210100fe8a17")).unwrap(),
            b"onlyblocks onlyblocks onlyblocks!"
        );
        assert_eq!(decompress(&hex("28b52ffd04584d00001861626301007e6e0848c3d30e")).unwrap(), b"abc".repeat(8));
    }

    #[test]
    fn xxh64_vectors() {
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"a", 0), 0xD24E_C4F1_A98C_6E5B);
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        let base = hex("28b52ffd04584d00001861626301007e6e0848c3d30e");
        for i in 0..base.len() {
            for bit in 0..8 {
                let mut m = base.clone();
                m[i] ^= 1 << bit;
                let _ = decompress(&m);
            }
            let _ = decompress(&base[..i]);
        }
        assert!(decompress(b"\x28\xb5\x2f\xfd").is_err());
        assert!(decompress(b"abc").is_err());
    }
}
