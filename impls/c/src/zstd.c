/* RFC 8878 Zstandard decoder (docs/ZSTD_MINI_SPEC.md), whole-buffer, no dictionaries. */
#include "common.h"

#define ZSTD_MAGIC 0xFD2FB528u
#define SKIPPABLE_MASK 0xFFFFFFF0u
#define SKIPPABLE_MAGIC 0x184D2A50u
#define BLOCK_SIZE_MAX (128 * 1024)

#define ZERR(c, msg) fail((c), E_INTERNAL, "zstd: %s", (msg))

static const uint32_t LL_BASE[36] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                     16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
                                     8192, 16384, 32768, 65536};
static const uint8_t LL_BITS[36] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
                                    13, 14, 15, 16};
static const uint32_t ML_BASE[53] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                                     19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
                                     35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
                                     4099, 8195, 16387, 32771, 65539};
static const uint8_t ML_BITS[53] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
                                    12, 13, 14, 15, 16};
static const int16_t LL_DEFAULT[36] = {4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
                                       2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
                                       -1, -1, -1, -1};
static const int16_t ML_DEFAULT[53] = {1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
                                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
                                       -1, -1, -1, -1, -1};
static const int16_t OF_DEFAULT[29] = {1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
                                       1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1};

static inline int highbit(uint64_t x) { return 63 - __builtin_clzll(x); }

static uint64_t le(ctx_t *c, const uint8_t *d, size_t len, size_t pos, size_t n) {
    if (pos > len || n > len - pos) ZERR(c, "truncated input");
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v |= (uint64_t)d[pos + i] << (8 * i);
    return v;
}

/* ---------------------------------------------------------------- backward bits */

typedef struct {
    const uint8_t *d; /* stream start */
    size_t len;
    int64_t bits;
} bbits_t;

static void bb_init(ctx_t *c, bbits_t *b, const uint8_t *d, size_t start, size_t end, size_t dlen) {
    if (end <= start || end > dlen) ZERR(c, "empty or out-of-range bitstream");
    if (d[end - 1] == 0) ZERR(c, "bitstream end marker missing");
    b->d = d + start;
    b->len = end - start;
    b->bits = (int64_t)(8 * (b->len - 1)) + highbit(d[end - 1]);
}

/* Bits [lo, hi) of the stream as one little-endian integer, 0 <= lo < hi, hi - lo <= 32. */
static inline uint64_t bb_window(const bbits_t *b, int64_t lo, int64_t hi) {
    size_t last = (size_t)(hi - 1) >> 3;
    uint64_t w;
    int64_t base;
    if (last >= 7) {
        w = rd64le(b->d + last - 7);
        base = (int64_t)(last - 7) * 8;
    } else {
        w = 0;
        for (size_t i = last + 1; i-- > 0;) w = (w << 8) | b->d[i];
        base = 0;
    }
    return (w >> (lo - base)) & ((1ULL << (hi - lo)) - 1);
}

static inline uint64_t bb_peek(const bbits_t *b, int n) {
    int64_t hi = b->bits, lo = hi - n;
    if (n == 0 || hi <= 0) return 0;
    if (lo < 0) return bb_window(b, 0, hi) << (-lo);
    return bb_window(b, lo, hi);
}

static inline uint64_t bb_read(bbits_t *b, int n) {
    uint64_t v = bb_peek(b, n);
    b->bits -= n;
    return v;
}

/* ---------------------------------------------------------------- FSE */

typedef struct {
    uint8_t sym, nb;
    uint16_t base;
} fse_cell_t;

typedef struct {
    fse_cell_t cells[512];
    int log;
    bool valid;
} fse_t;

/* Returns the byte position after the description. */
static size_t read_fse_description(ctx_t *c, const uint8_t *d, size_t pos, size_t limit, int max_symbol,
                                   int max_log, int16_t *probs, int *nprobs, int *log_out) {
    size_t bitpos = pos * 8;
#define FPEEK(n) fpeek(d, limit, bitpos, (n))
    int accuracy_log;
    {
        uint32_t v = 0;
        for (int i = 0; i < 4; i++) {
            size_t p = bitpos + (size_t)i;
            if ((p >> 3) < limit) v |= (uint32_t)((d[p >> 3] >> (p & 7)) & 1) << i;
        }
        bitpos += 4;
        accuracy_log = (int)v + 5;
    }
    if (accuracy_log > max_log) ZERR(c, "FSE accuracy log too large");
    int remaining = (1 << accuracy_log) + 1;
    int threshold = 1 << accuracy_log;
    int nbits = accuracy_log + 1;
    int n = 0;
    while (remaining > 1) {
        if (n > max_symbol) ZERR(c, "FSE description has too many symbols");
        int biggest = 2 * threshold - 1 - remaining;
        uint32_t low = 0, full = 0;
        for (int i = 0; i < nbits; i++) {
            size_t p = bitpos + (size_t)i;
            uint32_t bit = ((p >> 3) < limit) ? (uint32_t)((d[p >> 3] >> (p & 7)) & 1) : 0;
            full |= bit << i;
            if (i < nbits - 1) low |= bit << i;
        }
        int value;
        if ((int)low < biggest) {
            value = (int)low;
            bitpos += (size_t)(nbits - 1);
        } else {
            value = (int)full;
            bitpos += (size_t)nbits;
            if (value >= threshold) value -= biggest;
        }
        int prob = value - 1;
        probs[n++] = (int16_t)prob;
        remaining -= prob < 0 ? -prob : prob;
        if (prob == 0) {
            for (;;) {
                uint32_t rep = 0;
                for (int i = 0; i < 2; i++) {
                    size_t p = bitpos + (size_t)i;
                    if ((p >> 3) < limit) rep |= (uint32_t)((d[p >> 3] >> (p & 7)) & 1) << i;
                }
                bitpos += 2;
                for (uint32_t k = 0; k < rep; k++) {
                    if (n > max_symbol) ZERR(c, "FSE description has too many symbols");
                    probs[n++] = 0;
                }
                if (rep != 3) break;
            }
        }
        while (remaining < threshold) {
            nbits--;
            threshold >>= 1;
        }
    }
#undef FPEEK
    if (remaining != 1 || n > max_symbol + 1) ZERR(c, "corrupt FSE description");
    size_t end = (bitpos + 7) >> 3;
    if (end > limit) ZERR(c, "FSE description overruns its section");
    *nprobs = n;
    *log_out = accuracy_log;
    return end;
}

static void build_fse_table(ctx_t *c, const int16_t *probs, int nprobs, int accuracy_log, fse_t *t) {
    int size = 1 << accuracy_log;
    uint8_t cell_symbol[512];
    uint16_t counter[256];
    int high = size - 1;
    for (int s = 0; s < nprobs; s++) {
        if (probs[s] == -1) {
            if (high < 0) ZERR(c, "corrupt FSE distribution");
            cell_symbol[high--] = (uint8_t)s;
            counter[s] = 1;
        } else {
            counter[s] = (uint16_t)probs[s];
        }
    }
    int step = (size >> 1) + (size >> 3) + 3;
    int mask = size - 1;
    int pos = 0;
    for (int s = 0; s < nprobs; s++) {
        for (int k = 0; k < probs[s]; k++) {
            cell_symbol[pos] = (uint8_t)s;
            pos = (pos + step) & mask;
            while (pos > high) pos = (pos + step) & mask;
        }
    }
    if (pos != 0) ZERR(c, "corrupt FSE distribution");
    for (int cell = 0; cell < size; cell++) {
        int s = cell_symbol[cell];
        uint32_t x = counter[s]++;
        int nb = accuracy_log - highbit(x);
        t->cells[cell].sym = (uint8_t)s;
        t->cells[cell].nb = (uint8_t)nb;
        t->cells[cell].base = (uint16_t)((x << nb) - (uint32_t)size);
    }
    t->log = accuracy_log;
    t->valid = true;
}

/* ---------------------------------------------------------------- Huffman */

typedef struct {
    uint8_t sym, nb;
} huf_cell_t;

typedef struct {
    huf_cell_t cells[2048];
    int max_bits;
    bool valid;
} huf_t;

static void build_huffman_table(ctx_t *c, uint8_t *weights, int n, huf_t *h) {
    if (n > 255) ZERR(c, "too many Huffman weights");
    uint32_t total = 0;
    for (int i = 0; i < n; i++) {
        if (weights[i] > 11) ZERR(c, "Huffman weight too large");
        if (weights[i] > 0) total += 1u << (weights[i] - 1);
    }
    if (total == 0) ZERR(c, "empty Huffman table");
    int max_bits = highbit(total) + 1;
    if (max_bits > 11) ZERR(c, "Huffman code too long");
    uint32_t rest = (1u << max_bits) - total;
    if (rest & (rest - 1)) ZERR(c, "corrupt Huffman weights");
    weights[n++] = (uint8_t)(highbit(rest) + 1);
    uint32_t next_cell[13] = {0};
    uint32_t start = 0;
    for (int w = 1; w <= max_bits; w++) {
        next_cell[w] = start;
        uint32_t count = 0;
        for (int i = 0; i < n; i++) count += weights[i] == w;
        start += count << (w - 1);
    }
    for (int sym = 0; sym < n; sym++) {
        int w = weights[sym];
        if (w == 0) continue;
        for (uint32_t i = next_cell[w]; i < next_cell[w] + (1u << (w - 1)); i++) {
            h->cells[i].sym = (uint8_t)sym;
            h->cells[i].nb = (uint8_t)(max_bits + 1 - w);
        }
        next_cell[w] += 1u << (w - 1);
    }
    h->max_bits = max_bits;
    h->valid = true;
}

static size_t read_huffman_description(ctx_t *c, const uint8_t *d, size_t dlen, size_t pos, size_t limit, huf_t *h) {
    if (pos >= limit) ZERR(c, "missing Huffman description");
    uint8_t hb = d[pos++];
    uint8_t weights[260];
    int n = 0;
    if (hb < 128) {
        size_t end = pos + hb;
        if (end > limit) ZERR(c, "Huffman description overruns literals");
        int16_t probs[256];
        int nprobs, al;
        size_t p = read_fse_description(c, d, pos, end, 255, 6, probs, &nprobs, &al);
        fse_t *t = amalloc(c, sizeof *t);
        build_fse_table(c, probs, nprobs, al, t);
        bbits_t br;
        bb_init(c, &br, d, p, end, dlen);
        uint32_t s1 = (uint32_t)bb_read(&br, al);
        uint32_t s2 = (uint32_t)bb_read(&br, al);
        for (;;) {
            if (n > 255) ZERR(c, "too many Huffman weights");
            weights[n++] = t->cells[s1].sym;
            s1 = t->cells[s1].base + (uint32_t)bb_read(&br, t->cells[s1].nb);
            if (br.bits < 0) { weights[n++] = t->cells[s2].sym; break; }
            if (n > 255) ZERR(c, "too many Huffman weights");
            weights[n++] = t->cells[s2].sym;
            s2 = t->cells[s2].base + (uint32_t)bb_read(&br, t->cells[s2].nb);
            if (br.bits < 0) { weights[n++] = t->cells[s1].sym; break; }
        }
        pos = end;
    } else {
        int count = hb - 127;
        size_t end = pos + (size_t)(count + 1) / 2;
        if (end > limit) ZERR(c, "Huffman description overruns literals");
        for (int i = 0; i < count; i++) {
            uint8_t b = d[pos + (size_t)i / 2];
            weights[n++] = (i % 2 == 0) ? b >> 4 : b & 15;
        }
        pos = end;
    }
    build_huffman_table(c, weights, n, h);
    return pos;
}

static void decode_huffman_stream(ctx_t *c, const uint8_t *d, size_t dlen, size_t start, size_t end, const huf_t *h,
                                  size_t count, uint8_t *out) {
    bbits_t br;
    bb_init(c, &br, d, start, end, dlen);
    int mb = h->max_bits;
    for (size_t i = 0; i < count; i++) {
        const huf_cell_t *cell = &h->cells[bb_peek(&br, mb)];
        out[i] = cell->sym;
        br.bits -= cell->nb;
    }
    if (br.bits != 0) ZERR(c, "Huffman stream not fully consumed");
}

/* ---------------------------------------------------------------- frame state */

typedef struct {
    uint64_t rep[3];
    huf_t huf;
    fse_t ll, of, ml;
    uint8_t *lit; /* literal scratch, BLOCK_SIZE_MAX bytes */
} frame_t;

typedef struct {
    buf_t out;
} zout_t;

static size_t decode_literals(ctx_t *c, const uint8_t *d, size_t dlen, size_t pos, size_t end, frame_t *f,
                              const uint8_t **lit, size_t *nlit) {
    if (pos >= end) ZERR(c, "missing literals section");
    uint8_t b0 = d[pos];
    int ltype = b0 & 3, size_format = (b0 >> 2) & 3;
    if (ltype == 0 || ltype == 1) {
        size_t size;
        if (size_format == 0 || size_format == 2) {
            size = b0 >> 3;
            pos += 1;
        } else if (size_format == 1) {
            size = (size_t)(b0 >> 4) + ((size_t)le(c, d, end, pos + 1, 1) << 4);
            pos += 2;
        } else {
            size = (size_t)(b0 >> 4) + ((size_t)le(c, d, end, pos + 1, 1) << 4) + ((size_t)le(c, d, end, pos + 2, 1) << 12);
            pos += 3;
        }
        if (ltype == 0) {
            if (pos > end || size > end - pos) ZERR(c, "raw literals overrun block");
            *lit = d + pos;
            *nlit = size;
            return pos + size;
        }
        if (pos >= end) ZERR(c, "RLE literals overrun block");
        if (size > BLOCK_SIZE_MAX) ZERR(c, "literals too large");
        memset(f->lit, d[pos], size);
        *lit = f->lit;
        *nlit = size;
        return pos + 1;
    }
    static const int streams_tab[4] = {1, 4, 4, 4}, header_tab[4] = {3, 3, 4, 5}, width_tab[4] = {10, 10, 14, 18};
    int streams = streams_tab[size_format], header_len = header_tab[size_format], width = width_tab[size_format];
    uint64_t hv = le(c, d, end, pos, (size_t)header_len);
    size_t regenerated = (size_t)((hv >> 4) & ((1u << width) - 1));
    size_t compressed = (size_t)((hv >> (4 + width)) & ((1u << width) - 1));
    pos += (size_t)header_len;
    if (compressed > end - pos) ZERR(c, "compressed literals overrun block");
    size_t lit_end = pos + compressed;
    if (regenerated > BLOCK_SIZE_MAX) ZERR(c, "literals too large");
    if (ltype == 2) {
        pos = read_huffman_description(c, d, dlen, pos, lit_end, &f->huf);
    } else if (!f->huf.valid) {
        ZERR(c, "treeless literals without a previous Huffman table");
    }
    if (streams == 1) {
        decode_huffman_stream(c, d, dlen, pos, lit_end, &f->huf, regenerated, f->lit);
    } else {
        if (lit_end < pos || lit_end - pos < 6) ZERR(c, "corrupt 4-stream literals");
        size_t sizes[4] = {rd16le(d + pos), rd16le(d + pos + 2), rd16le(d + pos + 4), 0};
        pos += 6;
        size_t used = sizes[0] + sizes[1] + sizes[2];
        if (used > lit_end - pos) ZERR(c, "corrupt 4-stream literals");
        sizes[3] = lit_end - pos - used;
        size_t quarter = (regenerated + 3) / 4;
        if (sizes[3] < 1 || regenerated < 3 * quarter) ZERR(c, "corrupt 4-stream literals");
        size_t counts[4] = {quarter, quarter, quarter, regenerated - 3 * quarter};
        size_t o = 0;
        for (int i = 0; i < 4; i++) {
            decode_huffman_stream(c, d, dlen, pos, pos + sizes[i], &f->huf, counts[i], f->lit + o);
            pos += sizes[i];
            o += counts[i];
        }
    }
    *lit = f->lit;
    *nlit = regenerated;
    return lit_end;
}

static size_t read_sequence_table(ctx_t *c, const uint8_t *d, size_t pos, size_t end, int mode, int kind, frame_t *f) {
    static const int16_t *defaults[3] = {LL_DEFAULT, OF_DEFAULT, ML_DEFAULT};
    static const int default_n[3] = {36, 29, 53}, default_log[3] = {6, 5, 6};
    static const int max_symbol[3] = {35, 31, 52}, max_log[3] = {9, 8, 9};
    fse_t *t = kind == 0 ? &f->ll : kind == 1 ? &f->of : &f->ml;
    if (mode == 0) {
        build_fse_table(c, defaults[kind], default_n[kind], default_log[kind], t);
    } else if (mode == 1) {
        if (pos >= end || d[pos] > max_symbol[kind]) ZERR(c, "bad RLE sequence symbol");
        t->cells[0].sym = d[pos];
        t->cells[0].nb = 0;
        t->cells[0].base = 0;
        t->log = 0;
        t->valid = true;
        pos++;
    } else if (mode == 2) {
        int16_t probs[64];
        int nprobs, al;
        pos = read_fse_description(c, d, pos, end, max_symbol[kind], max_log[kind], probs, &nprobs, &al);
        build_fse_table(c, probs, nprobs, al, t);
    } else if (!t->valid) {
        ZERR(c, "repeat mode without a previous table");
    }
    return pos;
}

static void decode_sequences_and_execute(ctx_t *c, const uint8_t *d, size_t dlen, size_t pos, size_t end, frame_t *f,
                                         const uint8_t *lit, size_t nlit, buf_t *out, size_t frame_start) {
    if (pos >= end) ZERR(c, "missing sequences section");
    uint8_t b0 = d[pos];
    size_t count;
    if (b0 == 0) {
        if (pos + 1 != end) ZERR(c, "data after empty sequences section");
        count = 0;
    } else if (b0 < 128) {
        count = b0;
        pos += 1;
    } else if (b0 < 255) {
        count = ((size_t)(b0 - 128) << 8) + (size_t)le(c, d, end, pos + 1, 1);
        pos += 2;
    } else {
        count = (size_t)le(c, d, end, pos + 1, 2) + 0x7F00;
        pos += 3;
    }
    size_t li = 0;
    if (count) {
        if (pos >= end) ZERR(c, "missing compression modes");
        uint8_t modes = d[pos++];
        if (modes & 3) ZERR(c, "reserved compression-mode bits set");
        pos = read_sequence_table(c, d, pos, end, (modes >> 6) & 3, 0, f);
        pos = read_sequence_table(c, d, pos, end, (modes >> 4) & 3, 1, f);
        pos = read_sequence_table(c, d, pos, end, (modes >> 2) & 3, 2, f);
        bbits_t br;
        bb_init(c, &br, d, pos, end, dlen);
        uint32_t ll_s = (uint32_t)bb_read(&br, f->ll.log);
        uint32_t of_s = (uint32_t)bb_read(&br, f->of.log);
        uint32_t ml_s = (uint32_t)bb_read(&br, f->ml.log);
        for (size_t i = 0; i < count; i++) {
            const fse_cell_t *llc = &f->ll.cells[ll_s], *ofc = &f->of.cells[of_s], *mlc = &f->ml.cells[ml_s];
            int of_code = ofc->sym, ml_code = mlc->sym, ll_code = llc->sym;
            if (of_code > 31 || ml_code > 52 || ll_code > 35) ZERR(c, "bad sequence code");
            uint64_t offset_value = (1ULL << of_code) + bb_read(&br, of_code);
            size_t ml = ML_BASE[ml_code] + (size_t)bb_read(&br, ML_BITS[ml_code]);
            size_t ll = LL_BASE[ll_code] + (size_t)bb_read(&br, LL_BITS[ll_code]);
            if (i != count - 1) {
                ll_s = llc->base + (uint32_t)bb_read(&br, llc->nb);
                ml_s = mlc->base + (uint32_t)bb_read(&br, mlc->nb);
                of_s = ofc->base + (uint32_t)bb_read(&br, ofc->nb);
            }
            /* execute */
            if (ll > nlit - li) ZERR(c, "sequence consumes more literals than available");
            uint64_t offset;
            if (offset_value > 3) {
                offset = offset_value - 3;
                f->rep[2] = f->rep[1];
                f->rep[1] = f->rep[0];
                f->rep[0] = offset;
            } else {
                int idx = (int)offset_value - 1 + (ll == 0 ? 1 : 0);
                if (idx == 0) {
                    offset = f->rep[0];
                } else if (idx == 1) {
                    offset = f->rep[1];
                    f->rep[1] = f->rep[0];
                    f->rep[0] = offset;
                } else if (idx == 2) {
                    offset = f->rep[2];
                    f->rep[2] = f->rep[1];
                    f->rep[1] = f->rep[0];
                    f->rep[0] = offset;
                } else {
                    offset = f->rep[0] - 1;
                    f->rep[2] = f->rep[1];
                    f->rep[1] = f->rep[0];
                    f->rep[0] = offset;
                }
            }
            if (ll > MAX_DECOMPRESSED_BYTES - out->n) ZERR(c, "decompressed size limit exceeded");
            buf_append(c, out, lit + li, ll);
            li += ll;
            if (offset == 0 || offset > out->n - frame_start) ZERR(c, "match offset out of range");
            if (ml > MAX_DECOMPRESSED_BYTES - out->n) ZERR(c, "decompressed size limit exceeded");
            buf_reserve(c, out, ml);
            uint8_t *dst = out->p + out->n;
            const uint8_t *src = dst - offset;
            if (offset >= ml) {
                memcpy(dst, src, ml);
            } else {
                for (size_t k = 0; k < ml; k++) dst[k] = src[k];
            }
            out->n += ml;
        }
        if (br.bits != 0) ZERR(c, "sequence bitstream not fully consumed");
    }
    if (nlit - li > MAX_DECOMPRESSED_BYTES - out->n) ZERR(c, "decompressed size limit exceeded");
    buf_append(c, out, lit + li, nlit - li);
}

static size_t decode_frame(ctx_t *c, const uint8_t *d, size_t dlen, size_t pos, buf_t *out, frame_t *f) {
    uint8_t fhd = (uint8_t)le(c, d, dlen, pos, 1);
    pos += 1;
    int fcs_flag = fhd >> 6, single = (fhd >> 5) & 1, has_checksum = (fhd >> 2) & 1, did_flag = fhd & 3;
    if (fhd & 0x08) ZERR(c, "reserved frame header bit set");
    if (!single) {
        le(c, d, dlen, pos, 1);
        pos += 1;
    }
    static const size_t did_sizes[4] = {0, 1, 2, 4};
    size_t did_size = did_sizes[did_flag];
    if (did_size && le(c, d, dlen, pos, did_size) != 0) ZERR(c, "zstd dictionaries are not supported");
    pos += did_size;
    size_t fcs_sizes[4] = {single ? 1u : 0u, 2, 4, 8};
    size_t fcs_size = fcs_sizes[fcs_flag];
    bool has_size = false;
    uint64_t content_size = 0;
    if (fcs_size) {
        content_size = le(c, d, dlen, pos, fcs_size) + (fcs_size == 2 ? 256 : 0);
        has_size = true;
        pos += fcs_size;
        if (content_size > MAX_DECOMPRESSED_BYTES) ZERR(c, "decompressed size limit exceeded");
        /* Preallocate a bounded hint; hostile sizes only cost what the input can justify. */
        uint64_t hint = content_size;
        uint64_t cap = (uint64_t)(dlen - pos) * 64 + 4096;
        if (hint > cap) hint = cap;
        buf_reserve(c, out, (size_t)hint);
    }
    size_t frame_start = out->n;
    f->rep[0] = 1;
    f->rep[1] = 4;
    f->rep[2] = 8;
    f->huf.valid = f->ll.valid = f->of.valid = f->ml.valid = false;
    for (;;) {
        uint32_t header = (uint32_t)le(c, d, dlen, pos, 3);
        pos += 3;
        int last = header & 1, block_type = (header >> 1) & 3;
        size_t block_size = header >> 3;
        if (block_size > BLOCK_SIZE_MAX) ZERR(c, "block too large");
        if (block_type == 0) {
            if (block_size > dlen - pos) ZERR(c, "truncated raw block");
            if (block_size > MAX_DECOMPRESSED_BYTES - out->n) ZERR(c, "decompressed size limit exceeded");
            buf_append(c, out, d + pos, block_size);
            pos += block_size;
        } else if (block_type == 1) {
            uint8_t b = (uint8_t)le(c, d, dlen, pos, 1);
            if (block_size > MAX_DECOMPRESSED_BYTES - out->n) ZERR(c, "decompressed size limit exceeded");
            buf_reserve(c, out, block_size);
            memset(out->p + out->n, b, block_size);
            out->n += block_size;
            pos += 1;
        } else if (block_type == 2) {
            if (block_size > dlen - pos) ZERR(c, "truncated compressed block");
            size_t end = pos + block_size;
            const uint8_t *lit;
            size_t nlit;
            size_t p = decode_literals(c, d, dlen, pos, end, f, &lit, &nlit);
            decode_sequences_and_execute(c, d, end, p, end, f, lit, nlit, out, frame_start);
            pos = end;
        } else {
            ZERR(c, "reserved block type");
        }
        if (out->n > MAX_DECOMPRESSED_BYTES) ZERR(c, "decompressed size limit exceeded");
        if (last) break;
    }
    if (has_size && out->n - frame_start != content_size) ZERR(c, "frame content size mismatch");
    if (has_checksum) {
        uint32_t expected = (uint32_t)le(c, d, dlen, pos, 4);
        pos += 4;
        if ((uint32_t)xxh64(out->p + frame_start, out->n - frame_start) != expected) ZERR(c, "content checksum mismatch");
    }
    return pos;
}

bytes_t zstd_decompress(ctx_t *c, const uint8_t *d, size_t dlen) {
    buf_t out = {0};
    frame_t *f = amalloc(c, sizeof *f);
    f->lit = amalloc(c, BLOCK_SIZE_MAX);
    size_t pos = 0;
    while (pos < dlen) {
        uint32_t magic = (uint32_t)le(c, d, dlen, pos, 4);
        if ((magic & SKIPPABLE_MASK) == SKIPPABLE_MAGIC) {
            uint64_t size = le(c, d, dlen, pos + 4, 4);
            if (size > dlen - pos - 8) ZERR(c, "truncated skippable frame");
            pos += 8 + (size_t)size;
        } else if (magic == ZSTD_MAGIC) {
            pos = decode_frame(c, d, dlen, pos + 4, &out, f);
        } else {
            ZERR(c, "unknown frame magic");
        }
    }
    bytes_t r = {out.p ? out.p : (const uint8_t *)"", out.n};
    return r;
}
