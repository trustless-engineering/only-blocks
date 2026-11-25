/* Strict RFC 8259 parser that keeps number and string lexemes (ids echo byte for byte). */
#include "ob.h"

#define MAX_DEPTH 128

typedef struct {
    ctx_t *c;
    const char *p, *end;
} jp_t;

#define PERR(j, what) fail((j)->c, E_PARSE, "Parse error: %s", (what))

static void ws(jp_t *j) {
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')) j->p++;
}

static int hexval(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static unsigned hex4(jp_t *j) {
    if (j->end - j->p < 4) PERR(j, "truncated \\u escape");
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hexval(j->p[i]);
        if (h < 0) PERR(j, "invalid \\u escape");
        v = v << 4 | (unsigned)h;
    }
    j->p += 4;
    return v;
}

static void put_utf8(buf_t *b, ctx_t *c, uint32_t cp) {
    uint8_t t[4];
    size_t n;
    if (cp < 0x80) { t[0] = (uint8_t)cp; n = 1; }
    else if (cp < 0x800) { t[0] = (uint8_t)(0xC0 | cp >> 6); t[1] = (uint8_t)(0x80 | (cp & 63)); n = 2; }
    else if (cp < 0x10000) {
        t[0] = (uint8_t)(0xE0 | cp >> 12); t[1] = (uint8_t)(0x80 | ((cp >> 6) & 63)); t[2] = (uint8_t)(0x80 | (cp & 63)); n = 3;
    } else {
        t[0] = (uint8_t)(0xF0 | cp >> 18); t[1] = (uint8_t)(0x80 | ((cp >> 12) & 63));
        t[2] = (uint8_t)(0x80 | ((cp >> 6) & 63)); t[3] = (uint8_t)(0x80 | (cp & 63)); n = 4;
    }
    buf_append(c, b, t, n);
}

static void string(jp_t *j, jv *v) {
    const char *start = j->p; /* at the opening quote */
    j->p++;
    const char *run = j->p;
    bool escaped = false;
    buf_t b = {0};
    for (;;) {
        if (j->p >= j->end) PERR(j, "unterminated string");
        unsigned char ch = (unsigned char)*j->p;
        if (ch == '"') break;
        if (ch < 0x20) PERR(j, "control character in string");
        if (ch != '\\') { j->p++; continue; }
        if (!escaped) { escaped = true; }
        buf_append(j->c, &b, run, (size_t)(j->p - run));
        j->p++;
        if (j->p >= j->end) PERR(j, "truncated escape");
        char e = *j->p++;
        switch (e) {
        case '"': buf_append(j->c, &b, "\"", 1); break;
        case '\\': buf_append(j->c, &b, "\\", 1); break;
        case '/': buf_append(j->c, &b, "/", 1); break;
        case 'b': buf_append(j->c, &b, "\b", 1); break;
        case 'f': buf_append(j->c, &b, "\f", 1); break;
        case 'n': buf_append(j->c, &b, "\n", 1); break;
        case 'r': buf_append(j->c, &b, "\r", 1); break;
        case 't': buf_append(j->c, &b, "\t", 1); break;
        case 'u': {
            uint32_t cp = hex4(j);
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (j->end - j->p < 2 || j->p[0] != '\\' || j->p[1] != 'u') PERR(j, "lone surrogate");
                j->p += 2;
                uint32_t lo = hex4(j);
                if (lo < 0xDC00 || lo > 0xDFFF) PERR(j, "invalid surrogate pair");
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                PERR(j, "lone surrogate");
            }
            put_utf8(&b, j->c, cp);
            break;
        }
        default: PERR(j, "invalid escape");
        }
        run = j->p;
    }
    const char *close = j->p;
    j->p++;
    if (!utf8_valid((const uint8_t *)start + 1, (size_t)(close - start - 1))) PERR(j, "invalid UTF-8");
    v->kind = J_STR;
    v->raw = start;
    v->raw_n = (size_t)(j->p - start);
    if (escaped) {
        buf_append(j->c, &b, run, (size_t)(close - run));
        v->s = b.n ? (const char *)b.p : "";
        v->s_n = b.n;
    } else {
        v->s = start + 1;
        v->s_n = (size_t)(close - start - 1);
    }
}

static bool digit(jp_t *j) { return j->p < j->end && *j->p >= '0' && *j->p <= '9'; }

static void number(jp_t *j, jv *v) {
    const char *start = j->p;
    if (*j->p == '-') j->p++;
    if (!digit(j)) PERR(j, "invalid number");
    if (*j->p == '0') j->p++;
    else while (digit(j)) j->p++;
    if (j->p < j->end && *j->p == '.') {
        j->p++;
        if (!digit(j)) PERR(j, "invalid fraction");
        while (digit(j)) j->p++;
    }
    if (j->p < j->end && (*j->p == 'e' || *j->p == 'E')) {
        j->p++;
        if (j->p < j->end && (*j->p == '+' || *j->p == '-')) j->p++;
        if (!digit(j)) PERR(j, "invalid exponent");
        while (digit(j)) j->p++;
    }
    v->kind = J_NUM;
    v->raw = start;
    v->raw_n = (size_t)(j->p - start);
}

static void literal(jp_t *j, const char *word, uint8_t kind, jv *v) {
    size_t n = strlen(word);
    if ((size_t)(j->end - j->p) < n || memcmp(j->p, word, n) != 0) PERR(j, "invalid literal");
    j->p += n;
    v->kind = kind;
}

static void value(jp_t *j, jv *v, int depth);

static void container(jp_t *j, jv *v, int depth, bool object) {
    if (depth >= MAX_DEPTH) PERR(j, "nesting too deep");
    j->p++;
    VEC(jv) items = {0};
    ws(j);
    char close = object ? '}' : ']';
    if (j->p < j->end && *j->p == close) {
        j->p++;
    } else {
        for (;;) {
            ws(j);
            if (object) {
                if (j->p >= j->end || *j->p != '"') PERR(j, "expected object key");
                VRESERVE(j->c, items);
                jv *k = &items.v[items.n++];
                memset(k, 0, sizeof *k);
                string(j, k);
                ws(j);
                if (j->p >= j->end || *j->p != ':') PERR(j, "expected ':'");
                j->p++;
                ws(j);
            }
            VRESERVE(j->c, items);
            jv *item = &items.v[items.n++];
            memset(item, 0, sizeof *item);
            value(j, item, depth + 1);
            ws(j);
            if (j->p < j->end && *j->p == ',') { j->p++; continue; }
            if (j->p < j->end && *j->p == close) { j->p++; break; }
            PERR(j, object ? "expected ',' or '}'" : "expected ',' or ']'");
        }
    }
    v->kind = object ? J_OBJ : J_ARR;
    v->items = items.v;
    v->n = object ? items.n / 2 : items.n;
}

static void value(jp_t *j, jv *v, int depth) {
    ws(j);
    if (j->p >= j->end) PERR(j, "unexpected end of input");
    switch (*j->p) {
    case '{': container(j, v, depth, true); break;
    case '[': container(j, v, depth, false); break;
    case '"': string(j, v); break;
    case 't': literal(j, "true", J_TRUE, v); break;
    case 'f': literal(j, "false", J_FALSE, v); break;
    case 'n': literal(j, "null", J_NULL, v); break;
    default:
        if (*j->p == '-' || (*j->p >= '0' && *j->p <= '9')) number(j, v);
        else PERR(j, "unexpected character");
    }
}

jv *json_parse(ctx_t *c, const char *p, size_t n) {
    jp_t j = {c, p, p + n};
    jv *v = acalloc(c, 1, sizeof *v);
    value(&j, v, 0);
    ws(&j);
    if (j.p != j.end) PERR(&j, "trailing characters");
    return v;
}

const jv *json_get(const jv *obj, const char *key) {
    if (!obj || obj->kind != J_OBJ) return NULL;
    size_t kn = strlen(key);
    const jv *found = NULL;
    for (size_t i = 0; i < obj->n; i++) {
        const jv *k = &obj->items[2 * i];
        if (k->s_n == kn && memcmp(k->s, key, kn) == 0) found = &obj->items[2 * i + 1];
    }
    return found;
}

bool json_str_is(const jv *v, const char *z) {
    size_t n = strlen(z);
    return v && v->kind == J_STR && v->s_n == n && memcmp(v->s, z, n) == 0;
}
