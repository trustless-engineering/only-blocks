/* OnlyBlocks C11 server: shared types, per-request arenas, error traps, builders. */
#ifndef ONLYBLOCKS_COMMON_H
#define ONLYBLOCKS_COMMON_H

#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1

#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MIB ((size_t)1024 * 1024)
#define SLOTS_PER_EPOCH 432000ULL
#define BINCODE_SLOT_CUTOFF (157ULL * SLOTS_PER_EPOCH)
#define MAX_SLICE_BYTES (128 * MIB)
#define MAX_DECOMPRESSED_BYTES (512 * MIB)
#define MAX_BODY_BYTES MIB

enum {
    E_PARSE = -32700,
    E_INVALID_REQUEST = -32600,
    E_METHOD = -32601,
    E_PARAMS = -32602,
    E_INTERNAL = -32603,
    E_UNARCHIVED = -32004,
    E_SKIPPED = -32007,
    E_VERSION = -32015,
};

typedef struct {
    const uint8_t *p;
    size_t n;
} bytes_t;

/* ---- Arena: every allocation made while serving one request lives here. ---- */
typedef struct arena_chunk arena_chunk;
typedef struct arena_big arena_big;
typedef struct {
    arena_chunk *chunks;
    arena_big *bigs;
} arena_t;

/* ---- Error traps: setjmp/longjmp over arena-only state (no locks, fds or handles). ---- */
typedef struct trap {
    jmp_buf jb;
    struct trap *prev;
} trap_t;

typedef struct ctx {
    arena_t arena;
    trap_t *trap;
    int code;
    char msg[256];
} ctx_t;

void ctx_init(ctx_t *c);
void ctx_reset(ctx_t *c); /* frees the arena */

_Noreturn void fail(ctx_t *c, int code, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
#define DIE(c, ...) fail((c), E_INTERNAL, __VA_ARGS__)
#define CHECK(c, cond, msg) do { if (!(cond)) DIE((c), "%s", (msg)); } while (0)

/* Run fn under a trap. Returns 0 on success, else the RPC error code (c->msg holds the text). */
typedef void (*thunk_fn)(ctx_t *c, void *arg);
int attempt(ctx_t *c, thunk_fn fn, void *arg);

void *amalloc(ctx_t *c, size_t n);              /* uninitialised */
void *acalloc(ctx_t *c, size_t count, size_t size);
void *arealloc(ctx_t *c, void *p, size_t old, size_t n);
void *vec_grow_(ctx_t *c, void *v, size_t *cap, size_t elem);
char *astrdup(ctx_t *c, const char *s, size_t n);

#define VEC(T) struct { T *v; size_t n, cap; }
#define VRESERVE(c, vec) do { if ((vec).n == (vec).cap) (vec).v = vec_grow_((c), (vec).v, &(vec).cap, sizeof *(vec).v); } while (0)
#define VPUSH(c, vec, val) do { VRESERVE((c), (vec)); (vec).v[(vec).n++] = (val); } while (0)

/* ---- Growable byte buffer in the arena. ---- */
typedef struct {
    uint8_t *p;
    size_t n, cap;
} buf_t;
void buf_reserve(ctx_t *c, buf_t *b, size_t extra);
void buf_append(ctx_t *c, buf_t *b, const void *p, size_t n);

/* ---- String builder on malloc (outlives per-item arenas). ---- */
typedef struct {
    char *p;
    size_t n, cap;
    bool oom;
} sb_t;
void sb_free(sb_t *s);
void sb_grow(sb_t *s, size_t extra);
void sb_raw(sb_t *s, const void *p, size_t n);
static inline void sb_putc(sb_t *s, char ch) {
    if (s->n + 1 > s->cap) sb_grow(s, 1);
    if (!s->oom) s->p[s->n++] = ch;
}
static inline void sb_puts(sb_t *s, const char *z) { sb_raw(s, z, strlen(z)); }
void sb_u64(sb_t *s, uint64_t v);
void sb_i64(sb_t *s, int64_t v);
void sb_f64(sb_t *s, double v);
void sb_jstr(sb_t *s, const char *p, size_t n);           /* JSON string literal */
void sb_b58(ctx_t *c, sb_t *s, const uint8_t *p, size_t n); /* raw Base58 text */
void sb_b64(sb_t *s, const uint8_t *p, size_t n);           /* raw Base64 text */
void sb_jb58(ctx_t *c, sb_t *s, const uint8_t *p, size_t n); /* quoted Base58 */

/* ---- Streaming JSON writer with automatic commas. ---- */
typedef struct {
    sb_t *s;
    int depth;
    bool after_key;
    bool comma[48];
} jw_t;
void jw_init(jw_t *w, sb_t *s);
void jw_obj(jw_t *w);
void jw_arr(jw_t *w);
void jw_end_obj(jw_t *w);
void jw_end_arr(jw_t *w);
void jw_key(jw_t *w, const char *k);
void jw_null(jw_t *w);
void jw_bool(jw_t *w, bool v);
void jw_u64(jw_t *w, uint64_t v);
void jw_i64(jw_t *w, int64_t v);
void jw_f64(jw_t *w, double v);
void jw_str(jw_t *w, const char *p, size_t n);
void jw_cstr(jw_t *w, const char *z);
void jw_b58(ctx_t *c, jw_t *w, const uint8_t *p, size_t n);
void jw_b64(jw_t *w, const uint8_t *p, size_t n);
void jw_rawval(jw_t *w, const char *p, size_t n);

/* ---- Codecs. ---- */
void b58_encode(ctx_t *c, buf_t *out, const uint8_t *p, size_t n);
size_t b58_32(char out[45], const uint8_t *p); /* 32-byte key/hash to NUL-terminated Base58 */
uint64_t crc64_go_iso(const uint8_t *p, size_t n);
uint64_t fnv1a64(const uint8_t *p, size_t n);
uint64_t xxh64(const uint8_t *p, size_t n);
bool utf8_valid(const uint8_t *p, size_t n);
/* Rust from_str for unsigned ints: optional '+', ASCII digits only, must fit max. */
bool parse_unsigned(const char *p, size_t n, uint64_t max, uint64_t *out);
/* real_number_string_trimmed(amount, decimals) as an arena string. */
char *ui_amount_string(ctx_t *c, uint64_t amount, unsigned decimals, size_t *len);

static inline uint16_t rd16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t rd32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t rd64le(const uint8_t *p) {
    return (uint64_t)rd32le(p) | ((uint64_t)rd32le(p + 4) << 32);
}

/* ---- Zstandard (zstd.c). Fails through the trap on any error. ---- */
bytes_t zstd_decompress(ctx_t *c, const uint8_t *p, size_t n);

#endif
