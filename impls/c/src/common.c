/* Arena, error traps, buffers, the JSON writer and the small codecs. */
#include "common.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>

/* ------------------------------------------------------------------ arena */

#define CHUNK_BYTES (64 * 1024)
#define BIG_THRESHOLD (8 * 1024)
#define ALIGN 16

struct arena_chunk {
    arena_chunk *next;
    size_t cap, used;
    _Alignas(ALIGN) unsigned char data[];
};

struct arena_big {
    arena_big *next, *prev;
    _Alignas(ALIGN) unsigned char data[];
};

void ctx_init(ctx_t *c) {
    memset(c, 0, sizeof *c);
}

void ctx_reset(ctx_t *c) {
    for (arena_chunk *k = c->arena.chunks; k;) {
        arena_chunk *next = k->next;
        free(k);
        k = next;
    }
    for (arena_big *b = c->arena.bigs; b;) {
        arena_big *next = b->next;
        free(b);
        b = next;
    }
    c->arena.chunks = NULL;
    c->arena.bigs = NULL;
    c->trap = NULL;
    c->code = 0;
    c->msg[0] = 0;
}

_Noreturn void fail(ctx_t *c, int code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->msg, sizeof c->msg, fmt, ap);
    va_end(ap);
    c->code = code;
    if (!c->trap) abort(); /* programming error: every entry point installs a trap */
    longjmp(c->trap->jb, 1);
}

int attempt(ctx_t *c, thunk_fn fn, void *arg) {
    trap_t t;
    t.prev = c->trap;
    c->trap = &t;
    if (setjmp(t.jb) == 0) {
        fn(c, arg);
        c->trap = t.prev;
        return 0;
    }
    c->trap = t.prev;
    return c->code ? c->code : E_INTERNAL;
}

static void *big_alloc(ctx_t *c, size_t n) {
    if (n > SIZE_MAX - sizeof(arena_big)) DIE(c, "allocation too large");
    arena_big *b = malloc(sizeof(arena_big) + n);
    if (!b) DIE(c, "out of memory");
    b->prev = NULL;
    b->next = c->arena.bigs;
    if (b->next) b->next->prev = b;
    c->arena.bigs = b;
    return b->data;
}

void *amalloc(ctx_t *c, size_t n) {
    if (n == 0) n = 1;
    if (n > BIG_THRESHOLD) return big_alloc(c, n);
    size_t need = (n + ALIGN - 1) & ~(size_t)(ALIGN - 1);
    arena_chunk *k = c->arena.chunks;
    if (!k || k->cap - k->used < need) {
        k = malloc(sizeof(arena_chunk) + CHUNK_BYTES);
        if (!k) DIE(c, "out of memory");
        k->cap = CHUNK_BYTES;
        k->used = 0;
        k->next = c->arena.chunks;
        c->arena.chunks = k;
    }
    void *p = k->data + k->used;
    k->used += need;
    return p;
}

void *acalloc(ctx_t *c, size_t count, size_t size) {
    if (size && count > SIZE_MAX / size) DIE(c, "allocation too large");
    void *p = amalloc(c, count * size);
    memset(p, 0, count * size ? count * size : 1);
    return p;
}

void *arealloc(ctx_t *c, void *p, size_t old, size_t n) {
    if (!p) return amalloc(c, n);
    if (old > BIG_THRESHOLD) {
        arena_big *b = (arena_big *)((unsigned char *)p - offsetof(arena_big, data));
        if (n > SIZE_MAX - sizeof(arena_big)) DIE(c, "allocation too large");
        arena_big *nb = realloc(b, sizeof(arena_big) + n);
        if (!nb) DIE(c, "out of memory");
        if (nb->prev) nb->prev->next = nb;
        else c->arena.bigs = nb;
        if (nb->next) nb->next->prev = nb;
        return nb->data;
    }
    void *q = amalloc(c, n);
    memcpy(q, p, old < n ? old : n);
    return q;
}

void *vec_grow_(ctx_t *c, void *v, size_t *cap, size_t elem) {
    size_t ncap = *cap ? *cap * 2 : 4;
    if (ncap > SIZE_MAX / elem / 2) DIE(c, "vector too large");
    void *nv = arealloc(c, v, *cap * elem, ncap * elem);
    *cap = ncap;
    return nv;
}

char *astrdup(ctx_t *c, const char *s, size_t n) {
    char *p = amalloc(c, n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

void buf_reserve(ctx_t *c, buf_t *b, size_t extra) {
    if (extra <= b->cap - b->n) return;
    if (extra > SIZE_MAX / 2 - b->n) DIE(c, "buffer too large");
    size_t ncap = b->cap ? b->cap : 64;
    while (ncap - b->n < extra) ncap *= 2;
    b->p = arealloc(c, b->p, b->cap, ncap);
    b->cap = ncap;
}

void buf_append(ctx_t *c, buf_t *b, const void *p, size_t n) {
    if (!n) return;
    buf_reserve(c, b, n);
    memcpy(b->p + b->n, p, n);
    b->n += n;
}

/* ------------------------------------------------------------------ sb */

void sb_free(sb_t *s) {
    free(s->p);
    memset(s, 0, sizeof *s);
}

void sb_grow(sb_t *s, size_t extra) {
    if (s->oom) return;
    if (extra <= s->cap - s->n) return;
    size_t ncap = s->cap ? s->cap : 256;
    while (ncap - s->n < extra) {
        if (ncap > SIZE_MAX / 2) { s->oom = true; return; }
        ncap *= 2;
    }
    char *np = realloc(s->p, ncap);
    if (!np) { s->oom = true; return; }
    s->p = np;
    s->cap = ncap;
}

void sb_raw(sb_t *s, const void *p, size_t n) {
    if (!n) return;
    sb_grow(s, n);
    if (s->oom) return;
    memcpy(s->p + s->n, p, n);
    s->n += n;
}

void sb_u64(sb_t *s, uint64_t v) {
    char tmp[24];
    int i = 24;
    do { tmp[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    sb_raw(s, tmp + i, (size_t)(24 - i));
}

void sb_i64(sb_t *s, int64_t v) {
    if (v < 0) {
        sb_putc(s, '-');
        sb_u64(s, (uint64_t)0 - (uint64_t)v);
    } else {
        sb_u64(s, (uint64_t)v);
    }
}

void sb_f64(sb_t *s, double v) {
    if (!isfinite(v)) { sb_puts(s, "null"); return; }
    char tmp[40];
    for (int prec = 15; prec <= 17; prec++) {
        snprintf(tmp, sizeof tmp, "%.*g", prec, v);
        if (prec == 17 || strtod(tmp, NULL) == v) break;
    }
    sb_puts(s, tmp);
}

void sb_jstr(sb_t *s, const char *p, size_t n) {
    static const char hex[] = "0123456789abcdef";
    sb_grow(s, n + 2);
    sb_putc(s, '"');
    size_t run = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)p[i];
        if (ch >= 0x20 && ch != '"' && ch != '\\') continue;
        sb_raw(s, p + run, i - run);
        run = i + 1;
        switch (ch) {
        case '"': sb_raw(s, "\\\"", 2); break;
        case '\\': sb_raw(s, "\\\\", 2); break;
        case '\n': sb_raw(s, "\\n", 2); break;
        case '\r': sb_raw(s, "\\r", 2); break;
        case '\t': sb_raw(s, "\\t", 2); break;
        case '\b': sb_raw(s, "\\b", 2); break;
        case '\f': sb_raw(s, "\\f", 2); break;
        default: {
            char esc[6] = {'\\', 'u', '0', '0', hex[ch >> 4], hex[ch & 15]};
            sb_raw(s, esc, 6);
        }
        }
    }
    sb_raw(s, p + run, n - run);
    sb_putc(s, '"');
}

static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Base58 with base-58^5 limbs: each limb holds a value below 656 356 768. */
static size_t b58_core(uint32_t *limbs, const uint8_t *p, size_t n, char *out) {
    const uint32_t BIG = 656356768u; /* 58^5 */
    size_t zeros = 0;
    while (zeros < n && p[zeros] == 0) zeros++;
    size_t nl = 0;
    for (size_t i = zeros; i < n; i++) {
        uint64_t carry = p[i];
        for (size_t j = 0; j < nl; j++) {
            carry += (uint64_t)limbs[j] << 8;
            limbs[j] = (uint32_t)(carry % BIG);
            carry /= BIG;
        }
        while (carry) {
            limbs[nl++] = (uint32_t)(carry % BIG);
            carry /= BIG;
        }
    }
    size_t o = 0;
    for (size_t i = 0; i < zeros; i++) out[o++] = '1';
    /* Most significant limb without leading zero digits, the rest as 5 digits each. */
    for (size_t j = nl; j-- > 0;) {
        char d[5];
        uint32_t v = limbs[j];
        for (int k = 4; k >= 0; k--) { d[k] = B58[v % 58]; v /= 58; }
        int start = 0;
        if (j == nl - 1) while (start < 4 && d[start] == '1') start++;
        for (int k = start; k < 5; k++) out[o++] = d[k];
    }
    return o;
}

static size_t b58_limbs_for(size_t n) { return n * 8 / 29 + 2; }   /* log(256^n)/log(58^5) */
static size_t b58_chars_for(size_t n) { return n * 138 / 100 + 6 + 5; }

void b58_encode(ctx_t *c, buf_t *out, const uint8_t *p, size_t n) {
    uint32_t stack_limbs[64];
    uint32_t *limbs = b58_limbs_for(n) <= 64 ? stack_limbs : amalloc(c, b58_limbs_for(n) * 4);
    buf_reserve(c, out, b58_chars_for(n));
    out->n += b58_core(limbs, p, n, (char *)out->p + out->n);
}

size_t b58_32(char out[45], const uint8_t *p) {
    uint32_t limbs[16];
    size_t len = b58_core(limbs, p, 32, out);
    out[len] = 0;
    return len;
}

void sb_b58(ctx_t *c, sb_t *s, const uint8_t *p, size_t n) {
    uint32_t stack_limbs[64];
    uint32_t *limbs = b58_limbs_for(n) <= 64 ? stack_limbs : amalloc(c, b58_limbs_for(n) * 4);
    sb_grow(s, b58_chars_for(n));
    if (s->oom) return;
    s->n += b58_core(limbs, p, n, s->p + s->n);
}

void sb_jb58(ctx_t *c, sb_t *s, const uint8_t *p, size_t n) {
    sb_putc(s, '"');
    sb_b58(c, s, p, n);
    sb_putc(s, '"');
}

void sb_b64(sb_t *s, const uint8_t *p, size_t n) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    sb_grow(s, (n + 2) / 3 * 4);
    if (s->oom) return;
    char *o = s->p + s->n;
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8 | p[i + 2];
        *o++ = A[v >> 18]; *o++ = A[(v >> 12) & 63]; *o++ = A[(v >> 6) & 63]; *o++ = A[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)p[i] << 16;
        *o++ = A[v >> 18]; *o++ = A[(v >> 12) & 63]; *o++ = '='; *o++ = '=';
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8;
        *o++ = A[v >> 18]; *o++ = A[(v >> 12) & 63]; *o++ = A[(v >> 6) & 63]; *o++ = '=';
    }
    s->n = (size_t)(o - s->p);
}

/* ------------------------------------------------------------------ JSON writer */

void jw_init(jw_t *w, sb_t *s) {
    memset(w, 0, sizeof *w);
    w->s = s;
}

static void jw_pre(jw_t *w) {
    if (w->after_key) { w->after_key = false; return; }
    if (w->comma[w->depth]) sb_putc(w->s, ',');
    w->comma[w->depth] = true;
}

void jw_obj(jw_t *w) { jw_pre(w); sb_putc(w->s, '{'); w->comma[++w->depth] = false; }
void jw_arr(jw_t *w) { jw_pre(w); sb_putc(w->s, '['); w->comma[++w->depth] = false; }
void jw_end_obj(jw_t *w) { w->depth--; sb_putc(w->s, '}'); }
void jw_end_arr(jw_t *w) { w->depth--; sb_putc(w->s, ']'); }

void jw_key(jw_t *w, const char *k) {
    if (w->comma[w->depth]) sb_putc(w->s, ',');
    w->comma[w->depth] = true;
    sb_putc(w->s, '"');
    sb_puts(w->s, k);
    sb_raw(w->s, "\":", 2);
    w->after_key = true;
}

void jw_null(jw_t *w) { jw_pre(w); sb_raw(w->s, "null", 4); }
void jw_bool(jw_t *w, bool v) { jw_pre(w); sb_puts(w->s, v ? "true" : "false"); }
void jw_u64(jw_t *w, uint64_t v) { jw_pre(w); sb_u64(w->s, v); }
void jw_i64(jw_t *w, int64_t v) { jw_pre(w); sb_i64(w->s, v); }
void jw_f64(jw_t *w, double v) { jw_pre(w); sb_f64(w->s, v); }
void jw_str(jw_t *w, const char *p, size_t n) { jw_pre(w); sb_jstr(w->s, p, n); }
void jw_cstr(jw_t *w, const char *z) { jw_str(w, z, strlen(z)); }
void jw_b58(ctx_t *c, jw_t *w, const uint8_t *p, size_t n) { jw_pre(w); sb_jb58(c, w->s, p, n); }
void jw_b64(jw_t *w, const uint8_t *p, size_t n) {
    jw_pre(w);
    sb_putc(w->s, '"');
    sb_b64(w->s, p, n);
    sb_putc(w->s, '"');
}
void jw_rawval(jw_t *w, const char *p, size_t n) { jw_pre(w); sb_raw(w->s, p, n); }

/* ------------------------------------------------------------------ hashes */

static uint64_t CRC_TABLE[8][256];
static void crc_init(void) {
    for (int b = 0; b < 256; b++) {
        uint64_t crc = (uint64_t)b;
        for (int i = 0; i < 8; i++) crc = (crc >> 1) ^ ((crc & 1) ? 0xD800000000000000ULL : 0);
        CRC_TABLE[0][b] = crc;
    }
    for (int b = 0; b < 256; b++)
        for (int t = 1; t < 8; t++)
            CRC_TABLE[t][b] = (CRC_TABLE[t - 1][b] >> 8) ^ CRC_TABLE[0][CRC_TABLE[t - 1][b] & 0xFF];
}

#include <pthread.h>
static pthread_once_t crc_once = PTHREAD_ONCE_INIT;

/* Slicing-by-8: eight table lookups per 8 input bytes. */
uint64_t crc64_go_iso(const uint8_t *p, size_t n) {
    pthread_once(&crc_once, crc_init);
    uint64_t crc = ~0ULL;
    while (n >= 8) {
        crc ^= rd64le(p);
        crc = CRC_TABLE[7][crc & 0xFF] ^ CRC_TABLE[6][(crc >> 8) & 0xFF] ^ CRC_TABLE[5][(crc >> 16) & 0xFF] ^
              CRC_TABLE[4][(crc >> 24) & 0xFF] ^ CRC_TABLE[3][(crc >> 32) & 0xFF] ^
              CRC_TABLE[2][(crc >> 40) & 0xFF] ^ CRC_TABLE[1][(crc >> 48) & 0xFF] ^ CRC_TABLE[0][crc >> 56];
        p += 8;
        n -= 8;
    }
    while (n--) crc = (crc >> 8) ^ CRC_TABLE[0][(crc ^ *p++) & 0xFF];
    return ~crc;
}

uint64_t fnv1a64(const uint8_t *p, size_t n) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x100000001B3ULL;
    return h;
}

#define P1 0x9E3779B185EBCA87ULL
#define P2 0xC2B2AE3D27D4EB4FULL
#define P3 0x165667B19E3779F9ULL
#define P4 0x85EBCA77C2B2AE63ULL
#define P5 0x27D4EB2F165667C5ULL
static inline uint64_t rotl64(uint64_t x, int r) { return (x << r) | (x >> (64 - r)); }
static inline uint64_t xround(uint64_t acc, uint64_t lane) { return rotl64(acc + lane * P2, 31) * P1; }

uint64_t xxh64(const uint8_t *p, size_t n) {
    size_t i = 0;
    uint64_t h;
    if (n >= 32) {
        uint64_t v[4] = {P1 + P2, P2, 0, (uint64_t)0 - P1};
        for (; i + 32 <= n; i += 32)
            for (int j = 0; j < 4; j++) v[j] = xround(v[j], rd64le(p + i + 8 * (size_t)j));
        h = rotl64(v[0], 1) + rotl64(v[1], 7) + rotl64(v[2], 12) + rotl64(v[3], 18);
        for (int j = 0; j < 4; j++) h = (h ^ xround(0, v[j])) * P1 + P4;
    } else {
        h = P5;
    }
    h += (uint64_t)n;
    for (; i + 8 <= n; i += 8) h = rotl64(h ^ xround(0, rd64le(p + i)), 27) * P1 + P4;
    if (i + 4 <= n) { h = rotl64(h ^ ((uint64_t)rd32le(p + i) * P1), 23) * P2 + P3; i += 4; }
    for (; i < n; i++) h = rotl64(h ^ (p[i] * P5), 11) * P1;
    h ^= h >> 33; h *= P2; h ^= h >> 29; h *= P3; h ^= h >> 32;
    return h;
}

/* ------------------------------------------------------------------ text helpers */

bool utf8_valid(const uint8_t *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t b = p[i];
        if (b < 0x80) { i++; continue; }
        size_t len;
        uint32_t cp;
        if (b >= 0xC2 && b <= 0xDF) { len = 2; cp = b & 0x1F; }
        else if (b >= 0xE0 && b <= 0xEF) { len = 3; cp = b & 0x0F; }
        else if (b >= 0xF0 && b <= 0xF4) { len = 4; cp = b & 0x07; }
        else return false;
        if (n - i < len) return false;
        for (size_t k = 1; k < len; k++) {
            if ((p[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if ((len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)))
            return false;
        i += len;
    }
    return true;
}

bool parse_unsigned(const char *p, size_t n, uint64_t max, uint64_t *out) {
    size_t i = 0;
    if (n && p[0] == '+') i = 1;
    if (i == n) return false;
    uint64_t v = 0;
    for (; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return false;
        unsigned d = (unsigned)(p[i] - '0');
        if (v > (max - d) / 10) return false;
        v = v * 10 + d;
    }
    *out = v;
    return true;
}

char *ui_amount_string(ctx_t *c, uint64_t amount, unsigned decimals, size_t *len) {
    char digits[24];
    int k = 24;
    uint64_t a = amount;
    do { digits[--k] = (char)('0' + a % 10); a /= 10; } while (a);
    size_t nd = (size_t)(24 - k);
    const char *d = digits + k;
    char *s = amalloc(c, nd + decimals + 3);
    size_t o = 0;
    if (decimals == 0) {
        memcpy(s, d, nd);
        o = nd;
    } else {
        if (nd <= decimals) {
            s[o++] = '0';
            s[o++] = '.';
            for (size_t i = 0; i < decimals - nd; i++) s[o++] = '0';
            memcpy(s + o, d, nd);
            o += nd;
        } else {
            memcpy(s, d, nd - decimals);
            o = nd - decimals;
            s[o++] = '.';
            memcpy(s + o, d + nd - decimals, decimals);
            o += decimals;
        }
        while (o > 0 && s[o - 1] == '0') o--;
        if (o > 0 && s[o - 1] == '.') o--;
    }
    s[o] = 0;
    *len = o;
    return s;
}
