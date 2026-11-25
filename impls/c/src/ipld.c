/* CARv1 sections, CIDs, DAG-CBOR, Old Faithful nodes, DataFrames and VersionedTransaction. */
#include "model.h"

#define MAX_SECTION (32 * MIB)
#define CBOR_MAX_DEPTH 128

/* ------------------------------------------------------------------ uvarint */

static uint64_t uvarint(ctx_t *c, const uint8_t *p, size_t n, size_t *pos) {
    uint64_t x = 0;
    int shift = 0;
    for (int i = 0; i < 10; i++) {
        if (*pos >= n) DIE(c, "truncated varint");
        uint8_t b = p[(*pos)++];
        if (b < 0x80) {
            if (i == 9 && b > 1) DIE(c, "varint overflow");
            return x | ((uint64_t)b << shift);
        }
        x |= (uint64_t)(b & 0x7F) << shift;
        shift += 7;
    }
    DIE(c, "varint overflow");
}

/* ------------------------------------------------------------------ CBOR */

typedef struct {
    ctx_t *c;
    const uint8_t *p;
    size_t n, pos;
} cr_t;

static uint8_t cr_u8(cr_t *r) {
    if (r->pos >= r->n) DIE(r->c, "truncated CBOR");
    return r->p[r->pos++];
}

static uint64_t cr_be(cr_t *r, int bytes) {
    if ((size_t)bytes > r->n - r->pos) DIE(r->c, "truncated CBOR");
    uint64_t v = 0;
    for (int i = 0; i < bytes; i++) v = v << 8 | r->p[r->pos++];
    return v;
}

/* Returns false for the indefinite marker. */
static bool cr_arg(cr_t *r, int info, uint64_t *out) {
    if (info < 24) { *out = (uint64_t)info; return true; }
    switch (info) {
    case 24: *out = cr_be(r, 1); return true;
    case 25: *out = cr_be(r, 2); return true;
    case 26: *out = cr_be(r, 4); return true;
    case 27: *out = cr_be(r, 8); return true;
    case 31: return false;
    default: DIE(r->c, "reserved CBOR additional info");
    }
}

static double half_to_double(uint16_t h) {
    int exp = (h >> 10) & 0x1F, mant = h & 0x3FF;
    double v;
    if (exp == 0) v = mant * 0x1p-24;
    else if (exp == 31) v = mant ? __builtin_nan("") : __builtin_inf();
    else v = (mant + 1024) * __builtin_ldexp(1.0, exp - 25);
    return (h & 0x8000) ? -v : v;
}

static void cbor_item(cr_t *r, cbor_t *v, int depth);

static void cbor_string(cr_t *r, cbor_t *v, int major, int info) {
    uint64_t len;
    if (cr_arg(r, info, &len)) {
        if (len > r->n - r->pos) DIE(r->c, "CBOR string exceeds input");
        v->b.p = r->p + r->pos;
        v->b.n = (size_t)len;
        r->pos += (size_t)len;
    } else {
        buf_t b = {0};
        for (;;) {
            if (r->pos >= r->n) DIE(r->c, "truncated CBOR");
            if (r->p[r->pos] == 0xFF) { r->pos++; break; }
            uint8_t head = cr_u8(r);
            if ((head >> 5) != major || (head & 31) == 31) DIE(r->c, "invalid CBOR string chunk");
            uint64_t clen;
            cr_arg(r, head & 31, &clen);
            if (clen > r->n - r->pos) DIE(r->c, "CBOR string exceeds input");
            if (major == 3 && !utf8_valid(r->p + r->pos, (size_t)clen)) DIE(r->c, "invalid UTF-8 in CBOR text");
            buf_append(r->c, &b, r->p + r->pos, (size_t)clen);
            r->pos += (size_t)clen;
        }
        v->b.p = b.p ? b.p : (const uint8_t *)"";
        v->b.n = b.n;
    }
    if (major == 3 && !utf8_valid(v->b.p, v->b.n)) DIE(r->c, "invalid UTF-8 in CBOR text");
    v->t = major == 2 ? CB_BYTES : CB_TEXT;
}

static void cbor_container(cr_t *r, cbor_t *v, int major, int info, int depth) {
    uint64_t count;
    size_t per = major == 4 ? 1 : 2;
    v->t = major == 4 ? CB_ARR : CB_MAP;
    if (cr_arg(r, info, &count)) {
        if (count > (r->n - r->pos) / per) DIE(r->c, "CBOR count exceeds input");
        size_t items = (size_t)count * per;
        v->a = acalloc(r->c, items ? items : 1, sizeof(cbor_t));
        for (size_t i = 0; i < items; i++) cbor_item(r, &v->a[i], depth + 1);
        v->n = (size_t)count;
    } else {
        VEC(cbor_t) items = {0};
        for (;;) {
            if (r->pos >= r->n) DIE(r->c, "truncated CBOR");
            if (r->p[r->pos] == 0xFF) { r->pos++; break; }
            for (size_t k = 0; k < per; k++) {
                VRESERVE(r->c, items);
                cbor_t *it = &items.v[items.n++];
                memset(it, 0, sizeof *it);
                cbor_item(r, it, depth + 1);
            }
        }
        v->a = items.v;
        v->n = items.n / per;
    }
}

static void cbor_item(cr_t *r, cbor_t *v, int depth) {
    if (depth > CBOR_MAX_DEPTH) DIE(r->c, "CBOR nesting limit exceeded");
    uint8_t head = cr_u8(r);
    int major = head >> 5, info = head & 31;
    memset(v, 0, sizeof *v);
    if (major == 7) {
        switch (info) {
        case 20: v->t = CB_FALSE; return;
        case 21: v->t = CB_TRUE; return;
        case 22:
        case 23: v->t = CB_NULL; return;
        case 25: v->t = CB_FLOAT; v->f = half_to_double((uint16_t)cr_be(r, 2)); return;
        case 26: {
            uint32_t bits = (uint32_t)cr_be(r, 4);
            float f;
            memcpy(&f, &bits, 4);
            v->t = CB_FLOAT;
            v->f = f;
            return;
        }
        case 27: {
            uint64_t bits = cr_be(r, 8);
            memcpy(&v->f, &bits, 8);
            v->t = CB_FLOAT;
            return;
        }
        default: DIE(r->c, "unsupported CBOR simple value");
        }
    }
    if (major == 2 || major == 3) { cbor_string(r, v, major, info); return; }
    if (major == 4 || major == 5) { cbor_container(r, v, major, info, depth); return; }
    uint64_t arg;
    if (!cr_arg(r, info, &arg)) DIE(r->c, "invalid indefinite CBOR item");
    if (major == 0) { v->t = CB_UINT; v->u = arg; return; }
    if (major == 1) { v->t = CB_NEG; v->u = arg; return; }
    /* major 6: the tag is discarded and the item is returned as is (tag 42 links are byte strings). */
    cbor_item(r, v, depth + 1);
}

cbor_t *cbor_decode(ctx_t *c, bytes_t in) {
    cr_t r = {c, in.p, in.n, 0};
    cbor_t *v = amalloc(c, sizeof *v);
    cbor_item(&r, v, 0);
    if (r.pos != r.n) DIE(c, "trailing CBOR bytes");
    return v;
}

bool cbor_u64(const cbor_t *v, uint64_t *out) {
    if (!v || v->t != CB_UINT) return false;
    *out = v->u;
    return true;
}

bool cbor_i64(const cbor_t *v, int64_t *out) {
    if (!v) return false;
    if (v->t == CB_UINT && v->u <= (uint64_t)INT64_MAX) { *out = (int64_t)v->u; return true; }
    if (v->t == CB_NEG && v->u <= (uint64_t)INT64_MAX) { *out = -1 - (int64_t)v->u; return true; }
    return false;
}

const cbor_t *cbor_at(const cbor_t *arr, size_t i) {
    if (!arr || arr->t != CB_ARR || i >= arr->n) return NULL;
    return &arr->a[i];
}

/* ------------------------------------------------------------------ CIDs and the CAR index */

/* Parses a CID at p[0..n); returns its byte length. */
static size_t parse_cid(ctx_t *c, const uint8_t *p, size_t n, bool *absent) {
    size_t pos = 0;
    uint64_t a = uvarint(c, p, n, &pos);
    uint64_t b = uvarint(c, p, n, &pos);
    *absent = false;
    if (a == 0x12 && b == 0x20) {
        if (32 > n - pos) DIE(c, "truncated CIDv0 digest");
        return pos + 32;
    }
    if (a == 0) DIE(c, "explicit CIDv0 is not supported");
    if (a >= 2) DIE(c, "unsupported CID version");
    uint64_t hash_code = uvarint(c, p, n, &pos);
    uint64_t hash_len = uvarint(c, p, n, &pos);
    if (hash_len > 64) DIE(c, "CID digest too long");
    if (hash_len > n - pos) DIE(c, "truncated CID digest");
    *absent = hash_code == 0 && hash_len == 0;
    return pos + (size_t)hash_len;
}

cid_t parse_link(ctx_t *c, const cbor_t *v) {
    if (!v || v->t != CB_BYTES || v->b.n == 0 || v->b.p[0] != 0) DIE(c, "invalid CID link");
    cid_t cid;
    size_t len = parse_cid(c, v->b.p + 1, v->b.n - 1, &cid.absent);
    cid.key.p = v->b.p + 1;
    cid.key.n = len;
    return cid;
}

static uint64_t key_hash(bytes_t k) { return fnv1a64(k.p, k.n); }

static void car_put(ctx_t *c, car_t *car, bytes_t key, bytes_t node) {
    if ((car->n + 1) * 2 > car->cap) {
        size_t ncap = car->cap ? car->cap * 2 : 64;
        car_entry_t *nt = acalloc(c, ncap, sizeof *nt);
        for (size_t i = 0; i < car->cap; i++) {
            if (!car->t[i].key.p) continue;
            size_t h = (size_t)key_hash(car->t[i].key) & (ncap - 1);
            while (nt[h].key.p) h = (h + 1) & (ncap - 1);
            nt[h] = car->t[i];
        }
        car->t = nt;
        car->cap = ncap;
    }
    size_t h = (size_t)key_hash(key) & (car->cap - 1);
    while (car->t[h].key.p) {
        if (car->t[h].key.n == key.n && memcmp(car->t[h].key.p, key.p, key.n) == 0) {
            car->t[h].node = node; /* a later duplicate overwrites */
            return;
        }
        h = (h + 1) & (car->cap - 1);
    }
    car->t[h].key = key;
    car->t[h].node = node;
    car->n++;
}

bool car_get(const car_t *car, bytes_t key, bytes_t *node) {
    if (!car->cap) return false;
    size_t h = (size_t)key_hash(key) & (car->cap - 1);
    while (car->t[h].key.p) {
        if (car->t[h].key.n == key.n && memcmp(car->t[h].key.p, key.p, key.n) == 0) {
            *node = car->t[h].node;
            return true;
        }
        h = (h + 1) & (car->cap - 1);
    }
    return false;
}

typedef struct {
    bytes_t section;
    bool is_header;
} header_probe_t;

static void probe_header(ctx_t *c, void *arg) {
    header_probe_t *h = arg;
    cbor_t *v = cbor_decode(c, h->section);
    if (v->t != CB_MAP) return;
    for (size_t i = 0; i < v->n; i++) {
        const cbor_t *k = &v->a[2 * i];
        if (k->t == CB_TEXT && k->b.n == 7 && memcmp(k->b.p, "version", 7) == 0) h->is_header = true;
    }
}

void car_index(ctx_t *c, bytes_t slice, car_t *car) {
    memset(car, 0, sizeof *car);
    size_t pos = 0;
    bool first = true;
    while (pos < slice.n) {
        uint64_t len = uvarint(c, slice.p, slice.n, &pos);
        if (len == 0) continue;
        if (len > MAX_SECTION) DIE(c, "oversize CAR section");
        if (len > slice.n - pos) DIE(c, "truncated CAR section");
        bytes_t section = {slice.p + pos, (size_t)len};
        pos += (size_t)len;
        if (first) {
            first = false;
            if ((section.p[0] & 0xE0) == 0xA0) {
                header_probe_t h = {section, false};
                if (attempt(c, probe_header, &h) == 0 && h.is_header) continue;
            }
        }
        bool absent;
        size_t cid_len = parse_cid(c, section.p, section.n, &absent);
        bytes_t key = {section.p, cid_len};
        bytes_t node = {section.p + cid_len, section.n - cid_len};
        car_put(c, car, key, node);
        if (node.n > 0 && (node.p[0] >> 5) == 4) {
            int info = node.p[0] & 31;
            size_t hdr = 0;
            if (info < 24 || info == 31) hdr = 1;
            else if (info == 24) hdr = 2;
            else if (info == 25) hdr = 3;
            else if (info == 26) hdr = 5;
            else if (info == 27) hdr = 9;
            if (hdr && hdr < node.n && node.p[hdr] == 0x02) {
                car->block = node;
                car->has_block = true;
            }
        }
    }
}

const cbor_t *require_kind(ctx_t *c, const cbor_t *v, uint64_t kind) {
    uint64_t k;
    if (!v || v->t != CB_ARR || !cbor_u64(cbor_at(v, 0), &k) || k != kind)
        DIE(c, "expected IPLD node kind %llu", (unsigned long long)kind);
    return v;
}

const cbor_t *car_node(ctx_t *c, const car_t *car, bytes_t key, uint64_t kind) {
    bytes_t node;
    if (!car_get(car, key, &node)) DIE(c, "CID missing from CAR slice");
    return require_kind(c, cbor_decode(c, node), kind);
}

/* ------------------------------------------------------------------ nodes */

static void link_list(ctx_t *c, const cbor_t *v, bytes_vec_t *out) {
    if (!v || v->t != CB_ARR) return;
    for (size_t i = 0; i < v->n; i++) {
        cid_t cid = parse_link(c, &v->a[i]);
        VPUSH(c, *out, cid.key);
    }
}

void parse_dataframe(ctx_t *c, const cbor_t *v, dataframe_t *out) {
    require_kind(c, v, 6);
    memset(out, 0, sizeof *out);
    out->has_hash = cbor_u64(cbor_at(v, 1), &out->hash);
    const cbor_t *data = cbor_at(v, 4);
    if (data && data->t == CB_BYTES) out->data = data->b;
    else out->data.p = (const uint8_t *)"";
    const cbor_t *next = cbor_at(v, 5);
    if (next && next->t == CB_ARR && next->n > 0) link_list(c, next, &out->next);
}

static void verify_hash(ctx_t *c, bytes_t data, uint64_t expected) {
    if (crc64_go_iso(data.p, data.n) == expected) return;
    if (fnv1a64(data.p, data.n) == expected) return;
    DIE(c, "DataFrame hash mismatch");
}

typedef struct {
    bytes_t *t;
    size_t cap, n;
} keyset_t;

static bool keyset_add(ctx_t *c, keyset_t *s, bytes_t key) {
    if ((s->n + 1) * 2 > s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 16;
        bytes_t *nt = acalloc(c, ncap, sizeof *nt);
        for (size_t i = 0; i < s->cap; i++) {
            if (!s->t[i].p) continue;
            size_t h = (size_t)key_hash(s->t[i]) & (ncap - 1);
            while (nt[h].p) h = (h + 1) & (ncap - 1);
            nt[h] = s->t[i];
        }
        s->t = nt;
        s->cap = ncap;
    }
    size_t h = (size_t)key_hash(key) & (s->cap - 1);
    while (s->t[h].p) {
        if (s->t[h].n == key.n && memcmp(s->t[h].p, key.p, key.n) == 0) return false;
        h = (h + 1) & (s->cap - 1);
    }
    s->t[h] = key;
    s->n++;
    return true;
}

bytes_t reassemble(ctx_t *c, const car_t *car, const dataframe_t *first) {
    if (first->next.n == 0) {
        if (first->has_hash) verify_hash(c, first->data, first->hash);
        return first->data;
    }
    buf_t out = {0};
    buf_append(c, &out, first->data.p, first->data.n);
    keyset_t visited = {0};
    bytes_vec_t stack = {0};
    for (size_t i = first->next.n; i-- > 0;) VPUSH(c, stack, first->next.v[i]);
    while (stack.n) {
        bytes_t key = stack.v[--stack.n];
        if (!keyset_add(c, &visited, key)) DIE(c, "cyclic DataFrame");
        dataframe_t frame;
        parse_dataframe(c, car_node(c, car, key, 6), &frame);
        buf_append(c, &out, frame.data.p, frame.data.n);
        for (size_t i = frame.next.n; i-- > 0;) VPUSH(c, stack, frame.next.v[i]);
    }
    bytes_t r = {out.p ? out.p : (const uint8_t *)"", out.n};
    if (first->has_hash) verify_hash(c, r, first->hash);
    return r;
}

void parse_block_node(ctx_t *c, const cbor_t *v, block_node_t *out) {
    require_kind(c, v, 2);
    memset(out, 0, sizeof *out);
    if (!cbor_u64(cbor_at(v, 1), &out->slot)) DIE(c, "Block node has no slot");
    link_list(c, cbor_at(v, 3), &out->entries);
    const cbor_t *meta = cbor_at(v, 4);
    if (meta && meta->t == CB_ARR) {
        if (!cbor_u64(cbor_at(meta, 0), &out->parent_slot)) out->parent_slot = 0;
        int64_t bt;
        if (cbor_i64(cbor_at(meta, 1), &bt) && bt != 0) {
            out->has_blocktime = true;
            out->blocktime = bt;
        }
        out->has_height = cbor_u64(cbor_at(meta, 2), &out->height);
    }
    const cbor_t *rw = cbor_at(v, 5);
    if (rw && rw->t == CB_BYTES) {
        cid_t cid = parse_link(c, rw);
        if (!cid.absent) {
            out->has_rewards = true;
            out->rewards = cid.key;
        }
    }
}

/* ------------------------------------------------------------------ VersionedTransaction */

typedef struct {
    ctx_t *c;
    const uint8_t *p;
    size_t n, pos;
} tr_t;

static const uint8_t *tr_take(tr_t *r, size_t n) {
    if (n > r->n - r->pos) DIE(r->c, "truncated transaction");
    const uint8_t *p = r->p + r->pos;
    r->pos += n;
    return p;
}

static uint8_t tr_u8(tr_t *r) { return *tr_take(r, 1); }

static size_t compact_u16(tr_t *r) {
    uint32_t v = 0;
    for (int k = 0; k < 3; k++) {
        uint8_t b = tr_u8(r);
        if (k > 0 && b == 0) DIE(r->c, "non-canonical compact-u16");
        v |= (uint32_t)(b & 0x7F) << (7 * k);
        if (!(b & 0x80)) {
            if (v > 0xFFFF) DIE(r->c, "compact-u16 overflow");
            return v;
        }
    }
    DIE(r->c, "compact-u16 continues past the third byte");
}

static bytes_t short_vec(tr_t *r) {
    size_t n = compact_u16(r);
    bytes_t b = {tr_take(r, n), n};
    return b;
}

void parse_transaction(ctx_t *c, bytes_t in, tx_t *tx) {
    tr_t r = {c, in.p, in.n, 0};
    memset(tx, 0, sizeof *tx);
    tx->nsigs = compact_u16(&r);
    tx->sigs = tr_take(&r, tx->nsigs * 64);
    uint8_t prefix = tr_u8(&r);
    if (prefix & 0x80) {
        int version = prefix & 0x7F;
        if (version == 127) DIE(c, "off-chain messages are not accepted");
        if (version != 0) DIE(c, "unsupported transaction version %d", version);
        tx->v0 = true;
        tx->nrs = tr_u8(&r);
    } else {
        tx->nrs = prefix;
    }
    tx->nros = tr_u8(&r);
    tx->nrou = tr_u8(&r);
    tx->nkeys = compact_u16(&r);
    tx->keys = tr_take(&r, tx->nkeys * 32);
    tx->blockhash = tr_take(&r, 32);
    tx->nix = compact_u16(&r);
    if (tx->nix > (r.n - r.pos) / 3) DIE(c, "instruction count exceeds input");
    tx->ix = acalloc(c, tx->nix ? tx->nix : 1, sizeof *tx->ix);
    for (size_t i = 0; i < tx->nix; i++) {
        tx->ix[i].program = tr_u8(&r);
        tx->ix[i].accounts = short_vec(&r);
        tx->ix[i].data = short_vec(&r);
    }
    if (tx->v0) {
        tx->nlookups = compact_u16(&r);
        if (tx->nlookups > (r.n - r.pos) / 34) DIE(c, "lookup count exceeds input");
        tx->lookups = acalloc(c, tx->nlookups ? tx->nlookups : 1, sizeof *tx->lookups);
        for (size_t i = 0; i < tx->nlookups; i++) {
            tx->lookups[i].key = tr_take(&r, 32);
            tx->lookups[i].writable = short_vec(&r);
            tx->lookups[i].readonly = short_vec(&r);
        }
    }
    tx->raw.p = in.p;
    tx->raw.n = r.pos; /* trailing bytes are ignored and not re-encoded */
}
