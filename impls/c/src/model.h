/* OnlyBlocks C11 server: decoded block, transaction and metadata model (WIRE_FORMATS.md §12). */
#ifndef ONLYBLOCKS_MODEL_H
#define ONLYBLOCKS_MODEL_H

#include "ob.h"

/* ------------------------------------------------------------------ CBOR (ipld.c) */
enum { CB_UINT, CB_NEG, CB_BYTES, CB_TEXT, CB_ARR, CB_MAP, CB_FALSE, CB_TRUE, CB_NULL, CB_FLOAT };
typedef struct cbor {
    uint8_t t;
    uint64_t u;    /* CB_UINT value, CB_NEG n (value = -1 - n) */
    double f;
    bytes_t b;     /* CB_BYTES / CB_TEXT */
    struct cbor *a; /* CB_ARR items, CB_MAP key/value pairs (2n) */
    size_t n;
} cbor_t;

cbor_t *cbor_decode(ctx_t *c, bytes_t in);
bool cbor_u64(const cbor_t *v, uint64_t *out);
bool cbor_i64(const cbor_t *v, int64_t *out);
const cbor_t *cbor_at(const cbor_t *arr, size_t i); /* NULL when missing */

/* ------------------------------------------------------------------ CAR index (ipld.c) */
typedef struct {
    bytes_t key, node;
} car_entry_t;

typedef struct {
    car_entry_t *t;
    size_t cap, n;
    bytes_t block; /* last section that looks like a Block node */
    bool has_block;
} car_t;

typedef struct {
    bytes_t key;
    bool absent; /* identity hash, zero length (bafkqaaa) */
} cid_t;

void car_index(ctx_t *c, bytes_t slice, car_t *out);
bool car_get(const car_t *car, bytes_t key, bytes_t *node);
cid_t parse_link(ctx_t *c, const cbor_t *v);
/* The node for key, decoded and checked to be an array of the given kind. */
const cbor_t *car_node(ctx_t *c, const car_t *car, bytes_t key, uint64_t kind);
const cbor_t *require_kind(ctx_t *c, const cbor_t *v, uint64_t kind);

typedef VEC(bytes_t) bytes_vec_t;
typedef VEC(uint64_t) u64_vec_t;

typedef struct {
    bool has_hash;
    uint64_t hash;
    bytes_t data;
    bytes_vec_t next;
} dataframe_t;

void parse_dataframe(ctx_t *c, const cbor_t *v, dataframe_t *out);
bytes_t reassemble(ctx_t *c, const car_t *car, const dataframe_t *first);

typedef struct {
    uint64_t slot;
    bytes_vec_t entries;
    uint64_t parent_slot;
    bool has_blocktime;
    int64_t blocktime;
    bool has_height;
    uint64_t height;
    bool has_rewards;
    bytes_t rewards;
} block_node_t;

void parse_block_node(ctx_t *c, const cbor_t *v, block_node_t *out);

/* ------------------------------------------------------------------ transactions (ipld.c) */
typedef struct {
    uint8_t program;
    bytes_t accounts, data;
} cix_t;

typedef struct {
    const uint8_t *key;
    bytes_t writable, readonly;
} lookup_t;

typedef struct {
    bool v0;
    const uint8_t *sigs; /* nsigs × 64 bytes */
    size_t nsigs;
    uint8_t nrs, nros, nrou;
    const uint8_t *keys; /* nkeys × 32 bytes */
    size_t nkeys;
    const uint8_t *blockhash;
    cix_t *ix;
    size_t nix;
    lookup_t *lookups;
    size_t nlookups;
    bytes_t raw;
} tx_t;

void parse_transaction(ctx_t *c, bytes_t in, tx_t *out);

/* ------------------------------------------------------------------ metadata (meta.c) */
typedef struct {
    const char *p;
    size_t n;
} str_t;

typedef struct {
    str_t pubkey;
    int64_t lamports;
    uint64_t post_balance;
    uint8_t reward_type; /* 0 none, 1 Fee, 2 Rent, 3 Staking, 4 Voting */
    bool has_commission;
    uint8_t commission;
} reward_t;

typedef struct {
    uint8_t account_index;
    str_t mint, owner, program_id;
    bool has_ui;
    double ui;
    uint8_t decimals;
    str_t amount, ui_string;
} token_t;

typedef struct {
    uint8_t program;
    bytes_t accounts, data;
    bool has_stack;
    uint32_t stack;
} iix_t;

typedef struct {
    uint8_t index;
    VEC(iix_t) ix;
} inner_t;

typedef VEC(reward_t) rewards_vec_t;
typedef VEC(token_t) tokens_vec_t;

typedef struct {
    const char *err_json; /* NULL: Ok */
    uint64_t fee;
    u64_vec_t pre, post;
    bool has_inner;
    VEC(inner_t) inner;
    bool has_logs;
    VEC(str_t) logs;
    bool has_pre_tokens, has_post_tokens;
    tokens_vec_t pre_tokens, post_tokens;
    bool has_rewards;
    rewards_vec_t rewards;
    VEC(const uint8_t *) loaded_w, loaded_r;
    bool has_return;
    const uint8_t *return_program;
    bytes_t return_data;
    bool has_cu, has_cost;
    uint64_t cu, cost;
} meta_t;

typedef struct {
    rewards_vec_t list;
    bool has_partitions;
    uint64_t partitions;
} block_rewards_t;

/* Metadata frame (§9): NULL for an empty frame. */
meta_t *decode_metadata(ctx_t *c, uint64_t slot, bytes_t frame);
void decode_rewards(ctx_t *c, uint64_t slot, bytes_t frame, block_rewards_t *out);

#endif
