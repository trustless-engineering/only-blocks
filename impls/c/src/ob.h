/* OnlyBlocks C11 server: module interfaces. */
#ifndef ONLYBLOCKS_OB_H
#define ONLYBLOCKS_OB_H

#include "common.h"

/* ------------------------------------------------------------------ json.c */
enum { J_NULL, J_FALSE, J_TRUE, J_NUM, J_STR, J_ARR, J_OBJ };
typedef struct jv {
    uint8_t kind;
    const char *raw; /* source lexeme (numbers, strings) */
    size_t raw_n;
    const char *s;   /* decoded string content */
    size_t s_n;
    struct jv *items; /* array items; objects interleave key, value */
    size_t n;         /* item count (objects: number of pairs) */
} jv;

/* Parses a complete body; fails with E_PARSE through the trap. */
jv *json_parse(ctx_t *c, const char *p, size_t n);
/* Last occurrence of key in an object, or NULL. */
const jv *json_get(const jv *obj, const char *key);
bool json_str_is(const jv *v, const char *z);

/* ------------------------------------------------------------------ upstream.c */
typedef struct archive archive_t;

typedef struct {
    bool skipped;
    uint64_t offset;
    uint32_t length;
} slot_range_t;

archive_t *archive_new(const char *base_url, char *err, size_t errn);
/* Both reads of the 2-range-read protocol, with caches and retries. Fails through the trap. */
bytes_t archive_slot_slice(ctx_t *c, archive_t *a, uint64_t slot);
bool archive_hash_get(archive_t *a, uint64_t slot, char out[45]);
void archive_hash_put(archive_t *a, uint64_t slot, const char *b58);

/* ------------------------------------------------------------------ block.c */
enum { ENC_JSON, ENC_PARSED, ENC_BASE64, ENC_BASE58 };
enum { TD_FULL, TD_ACCOUNTS, TD_SIGNATURES, TD_NONE };

typedef struct {
    uint64_t slot;
    int encoding;
    int details;
    bool rewards;
    int max_version; /* -1: none */
} block_opts_t;

/* Writes the getBlock result value into w (fails through the trap). */
void get_block(ctx_t *c, archive_t *a, const block_opts_t *o, jw_t *w);

#endif
