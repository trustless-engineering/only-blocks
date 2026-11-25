/* OnlyBlocks C11 server: CLI, HTTP/1.1 listener, connection threads and JSON-RPC 2.0 dispatch. */
#include "ob.h"

#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_HEADER_BYTES (64 * 1024)
#define IO_TIMEOUT_MS 60000
#define MAX_BATCH 100

static archive_t *g_archive;
static int g_wake[2] = {-1, -1};
static atomic_int g_active;

/* ================================================================== JSON-RPC */

static const char *ID_NULL = "null";

static void write_error(sb_t *out, int code, const char *msg, const char *id, size_t idn) {
    sb_puts(out, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":");
    sb_i64(out, code);
    sb_puts(out, ",\"message\":");
    sb_jstr(out, msg, strlen(msg));
    sb_puts(out, "},\"id\":");
    sb_raw(out, id, idn);
    sb_putc(out, '}');
}

static bool is_slot_text(const jv *v, uint64_t max, uint64_t *out) {
    if (!v || v->kind != J_NUM || v->raw_n == 0 || v->raw_n > 20) return false;
    if (v->raw[0] == '0' && v->raw_n != 1) return false;
    for (size_t i = 0; i < v->raw_n; i++)
        if (v->raw[i] < '0' || v->raw[i] > '9') return false;
    return parse_unsigned(v->raw, v->raw_n, max, out);
}

static bool one_of(const jv *v, const char *const *names, int n, int *out) {
    if (!v || v->kind != J_STR) return false;
    for (int i = 0; i < n; i++)
        if (json_str_is(v, names[i])) { *out = i; return true; }
    return false;
}

static bool block_params(const jv *params, block_opts_t *o) {
    static const char *const ENCODINGS[4] = {"json", "jsonParsed", "base64", "base58"};
    static const char *const DETAILS[4] = {"full", "accounts", "signatures", "none"};
    memset(o, 0, sizeof *o);
    o->encoding = ENC_JSON;
    o->details = TD_FULL;
    o->rewards = true;
    o->max_version = -1;
    if (!params || params->kind != J_ARR || params->n < 1 || params->n > 2) return false;
    if (!is_slot_text(&params->items[0], UINT64_MAX, &o->slot)) return false;
    if (params->n == 1) return true;
    const jv *cfg = &params->items[1];
    if (cfg->kind == J_NULL) return true;
    if (cfg->kind == J_STR) return one_of(cfg, ENCODINGS, 4, &o->encoding);
    if (cfg->kind != J_OBJ) return false;
    const jv *v;
    if ((v = json_get(cfg, "encoding")) && v->kind != J_NULL && !one_of(v, ENCODINGS, 4, &o->encoding)) return false;
    if ((v = json_get(cfg, "transactionDetails")) && v->kind != J_NULL && !one_of(v, DETAILS, 4, &o->details)) return false;
    if ((v = json_get(cfg, "rewards")) && v->kind != J_NULL) {
        if (v->kind != J_TRUE && v->kind != J_FALSE) return false;
        o->rewards = v->kind == J_TRUE;
    }
    if ((v = json_get(cfg, "maxSupportedTransactionVersion")) && v->kind != J_NULL) {
        uint64_t mv;
        if (!is_slot_text(v, 255, &mv)) return false;
        o->max_version = (int)mv;
    }
    if ((v = json_get(cfg, "commitment")) && v->kind != J_NULL && !json_str_is(v, "finalized") &&
        !json_str_is(v, "confirmed"))
        return false;
    return true;
}

typedef struct {
    const block_opts_t *opts;
    jw_t *w;
} block_call_t;

static void block_thunk(ctx_t *c, void *arg) {
    block_call_t *b = arg;
    get_block(c, g_archive, b->opts, b->w);
}

/* One request object (or a non-object batch item) into out. */
static void dispatch(ctx_t *item, const jv *req, sb_t *out) {
    if (!req || req->kind != J_OBJ) {
        write_error(out, E_INVALID_REQUEST, "Invalid Request", ID_NULL, 4);
        return;
    }
    const jv *jsonrpc = json_get(req, "jsonrpc"), *method = json_get(req, "method"), *id = json_get(req, "id");
    if ((jsonrpc && jsonrpc->kind != J_STR && jsonrpc->kind != J_NULL) ||
        (method && method->kind != J_STR && method->kind != J_NULL) ||
        (id && id->kind != J_STR && id->kind != J_NUM && id->kind != J_NULL)) {
        write_error(out, E_INVALID_REQUEST, "Invalid Request", ID_NULL, 4);
        return;
    }
    const char *idp = ID_NULL;
    size_t idn = 4;
    if (id && id->kind != J_NULL) {
        idp = id->raw;
        idn = id->raw_n;
    }
    if (!json_str_is(jsonrpc, "2.0") || !method || method->kind != J_STR) {
        write_error(out, E_INVALID_REQUEST, "Invalid Request", idp, idn);
        return;
    }
    const jv *params = json_get(req, "params");
    if (json_str_is(method, "getHealth")) {
        if (params && params->kind != J_NULL && !(params->kind == J_ARR && params->n == 0)) {
            write_error(out, E_PARAMS, "Invalid params: getHealth takes no parameters", idp, idn);
            return;
        }
        sb_puts(out, "{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":");
        sb_raw(out, idp, idn);
        sb_putc(out, '}');
        return;
    }
    if (!json_str_is(method, "getBlock")) {
        sb_t msg = {0};
        sb_puts(&msg, "Method not found: ");
        sb_raw(&msg, method->s, method->s_n);
        sb_putc(&msg, 0);
        write_error(out, E_METHOD, msg.oom ? "Method not found" : msg.p, idp, idn);
        sb_free(&msg);
        return;
    }
    block_opts_t opts;
    if (!block_params(params, &opts)) {
        write_error(out, E_PARAMS, "Invalid params", idp, idn);
        return;
    }
    if (opts.encoding == ENC_BASE58 && opts.max_version >= 1) {
        write_error(out, E_PARAMS, "base58 encoding is not supported with maxSupportedTransactionVersion >= 1", idp, idn);
        return;
    }
    if (opts.details == TD_ACCOUNTS && opts.encoding != ENC_JSON) {
        write_error(out, E_PARAMS, "Invalid params", idp, idn);
        return;
    }
    size_t mark = out->n;
    sb_puts(out, "{\"jsonrpc\":\"2.0\",\"result\":");
    jw_t w;
    jw_init(&w, out);
    block_call_t call = {&opts, &w};
    int code = attempt(item, block_thunk, &call);
    if (code == 0 && !out->oom) {
        sb_puts(out, ",\"id\":");
        sb_raw(out, idp, idn);
        sb_putc(out, '}');
        return;
    }
    out->n = mark;
    if (out->oom) {
        out->oom = false;
        write_error(out, E_INTERNAL, "Internal error: response too large", idp, idn);
        return;
    }
    char msg[300];
    if (code == E_INTERNAL) snprintf(msg, sizeof msg, "Internal error: %s", item->msg);
    else snprintf(msg, sizeof msg, "%s", item->msg[0] ? item->msg : "error");
    write_error(out, code, msg, idp, idn);
}

typedef struct {
    const char *body;
    size_t n;
    jv *root;
} parse_call_t;

static void parse_thunk(ctx_t *c, void *arg) {
    parse_call_t *p = arg;
    p->root = json_parse(c, p->body, p->n);
}

static void handle_rpc(const char *body, size_t n, sb_t *out) {
    ctx_t req, item;
    ctx_init(&req);
    ctx_init(&item);
    parse_call_t pc = {body, n, NULL};
    if (attempt(&req, parse_thunk, &pc) != 0) {
        write_error(out, E_PARSE, "Parse error", ID_NULL, 4);
    } else if (pc.root->kind == J_ARR) {
        if (pc.root->n == 0 || pc.root->n > MAX_BATCH) {
            write_error(out, E_INVALID_REQUEST, "Invalid Request", ID_NULL, 4);
        } else {
            sb_putc(out, '[');
            for (size_t i = 0; i < pc.root->n; i++) {
                if (i) sb_putc(out, ',');
                dispatch(&item, &pc.root->items[i], out);
                ctx_reset(&item); /* per-item decode memory never accumulates across a batch */
            }
            sb_putc(out, ']');
        }
    } else {
        dispatch(&item, pc.root, out);
    }
    ctx_reset(&item);
    ctx_reset(&req);
}

/* ================================================================== HTTP server */

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

typedef struct {
    int fd;
    int64_t deadline;
    char *buf;
    size_t len, pos, cap;
} conn_t;

static bool conn_fill(conn_t *k) {
    if (k->len == k->cap) return false;
    for (;;) {
        int64_t left = k->deadline - mono_ms();
        if (left <= 0) return false;
        struct pollfd p = {k->fd, POLLIN, 0};
        int r = poll(&p, 1, (int)left);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        ssize_t n = recv(k->fd, k->buf + k->len, k->cap - k->len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        k->len += (size_t)n;
        return true;
    }
}

static void send_all(int fd, const char *p, size_t n) {
    int64_t deadline = mono_ms() + IO_TIMEOUT_MS;
    while (n) {
        ssize_t w = send(fd, p, n, 0);
        if (w > 0) { p += w; n -= (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int64_t left = deadline - mono_ms();
            struct pollfd pf = {fd, POLLOUT, 0};
            if (left > 0 && poll(&pf, 1, (int)left) > 0) continue;
        }
        return;
    }
}

static void send_status(int fd, int code, const char *reason) {
    char head[256];
    int n = snprintf(head, sizeof head, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, reason);
    send_all(fd, head, (size_t)n);
}

/* After an early reply, drain what the client is still sending so close() does not reset. */
static void drain(int fd) {
    shutdown(fd, SHUT_WR);
    char tmp[16384];
    int64_t deadline = mono_ms() + 2000;
    size_t total = 0;
    while (total < 4 * MIB) {
        int64_t left = deadline - mono_ms();
        if (left <= 0) break;
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, (int)left) <= 0) break;
        ssize_t n = recv(fd, tmp, sizeof tmp, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
}

static bool header_is(const char *line, size_t n, const char *name, const char **value, size_t *vn) {
    size_t kn = strlen(name);
    if (n <= kn || line[kn] != ':' || strncasecmp(line, name, kn) != 0) return false;
    const char *v = line + kn + 1, *end = line + n;
    while (v < end && (*v == ' ' || *v == '\t')) v++;
    while (end > v && (end[-1] == ' ' || end[-1] == '\t')) end--;
    *value = v;
    *vn = (size_t)(end - v);
    return true;
}

/* Decodes a chunked body in place; returns false if malformed/incomplete, sets *too_big. */
static bool read_chunked(conn_t *k, size_t start, char **body, size_t *bodyn, bool *too_big) {
    size_t out = start, pos = start;
    *too_big = false;
    for (;;) {
        char *nl;
        while (!(nl = memchr(k->buf + pos, '\n', k->len - pos)))
            if (!conn_fill(k)) return false;
        size_t line_end = (size_t)(nl - k->buf);
        char *endp;
        unsigned long long size = strtoull(k->buf + pos, &endp, 16);
        if (endp == k->buf + pos) return false;
        pos = line_end + 1;
        if (size == 0) {
            for (;;) { /* trailers */
                while (!(nl = memchr(k->buf + pos, '\n', k->len - pos)))
                    if (!conn_fill(k)) return false;
                size_t len = (size_t)(nl - (k->buf + pos));
                pos = (size_t)(nl - k->buf) + 1;
                if (len == 0 || (len == 1 && k->buf[pos - 2] == '\r')) break;
            }
            *body = k->buf + start;
            *bodyn = out - start;
            return true;
        }
        if (size > MAX_BODY_BYTES || out - start + size > MAX_BODY_BYTES) { *too_big = true; return false; }
        while (k->len - pos < size + 2)
            if (!conn_fill(k)) return false;
        memmove(k->buf + out, k->buf + pos, (size_t)size);
        out += (size_t)size;
        pos += (size_t)size;
        if (k->buf[pos] == '\r') pos++;
        if (k->buf[pos] != '\n') return false;
        pos++;
    }
}

static void serve_connection(int fd) {
    conn_t k = {fd, mono_ms() + IO_TIMEOUT_MS, NULL, 0, 0, MAX_HEADER_BYTES + MAX_BODY_BYTES + 64 * 1024};
    k.buf = malloc(k.cap);
    if (!k.buf) return;
    char *end = NULL;
    for (;;) {
        if (k.len >= 4 && (end = memmem(k.buf, k.len, "\r\n\r\n", 4))) break;
        if (k.len > MAX_HEADER_BYTES || !conn_fill(&k)) goto out;
    }
    size_t head_len = (size_t)(end - k.buf) + 4;
    if (head_len > MAX_HEADER_BYTES) { send_status(fd, 431, "Request Header Fields Too Large"); goto out; }
    /* Request line. */
    char *line_end = memchr(k.buf, '\n', head_len);
    size_t ll = (size_t)(line_end - k.buf);
    if (ll && k.buf[ll - 1] == '\r') ll--;
    char method[16] = {0}, target[1024] = {0};
    {
        const char *sp1 = memchr(k.buf, ' ', ll);
        const char *sp2 = sp1 ? memchr(sp1 + 1, ' ', ll - (size_t)(sp1 + 1 - k.buf)) : NULL;
        if (!sp1 || !sp2 || (size_t)(sp1 - k.buf) >= sizeof method || (size_t)(sp2 - sp1 - 1) >= sizeof target) {
            send_status(fd, 400, "Bad Request");
            goto out;
        }
        memcpy(method, k.buf, (size_t)(sp1 - k.buf));
        memcpy(target, sp1 + 1, (size_t)(sp2 - sp1 - 1));
    }
    bool chunked = false, has_length = false, expect_continue = false;
    unsigned long long content_length = 0;
    for (char *p = line_end + 1; p < k.buf + head_len - 2;) {
        char *nl = memchr(p, '\n', (size_t)(k.buf + head_len - p));
        if (!nl) break;
        size_t n = (size_t)(nl - p);
        if (n && p[n - 1] == '\r') n--;
        const char *v;
        size_t vn;
        if (header_is(p, n, "content-length", &v, &vn)) {
            char tmp[32];
            if (vn == 0 || vn >= sizeof tmp) { send_status(fd, 400, "Bad Request"); goto out; }
            memcpy(tmp, v, vn);
            tmp[vn] = 0;
            for (size_t i = 0; i < vn; i++)
                if (tmp[i] < '0' || tmp[i] > '9') { send_status(fd, 400, "Bad Request"); goto out; }
            errno = 0;
            content_length = strtoull(tmp, NULL, 10);
            if (errno) content_length = ULLONG_MAX;
            has_length = true;
        } else if (header_is(p, n, "transfer-encoding", &v, &vn)) {
            for (size_t i = 0; i + 7 <= vn; i++)
                if (strncasecmp(v + i, "chunked", 7) == 0) chunked = true;
        } else if (header_is(p, n, "expect", &v, &vn)) {
            if (vn == 12 && strncasecmp(v, "100-continue", 12) == 0) expect_continue = true;
        }
        p = nl + 1;
    }
    if (strcmp(target, "/") != 0) { send_status(fd, 404, "Not Found"); drain(fd); goto out; }
    if (strcmp(method, "POST") != 0) { send_status(fd, 405, "Method Not Allowed"); drain(fd); goto out; }
    if (!chunked && has_length && content_length > MAX_BODY_BYTES) {
        send_status(fd, 413, "Payload Too Large");
        drain(fd);
        goto out;
    }
    if (expect_continue) send_all(fd, "HTTP/1.1 100 Continue\r\n\r\n", 25);
    char *body;
    size_t bodyn;
    if (chunked) {
        bool too_big;
        if (!read_chunked(&k, head_len, &body, &bodyn, &too_big)) {
            if (too_big) { send_status(fd, 413, "Payload Too Large"); drain(fd); }
            else send_status(fd, 400, "Bad Request");
            goto out;
        }
    } else {
        size_t want = has_length ? (size_t)content_length : 0;
        while (k.len - head_len < want)
            if (!conn_fill(&k)) goto out;
        body = k.buf + head_len;
        bodyn = want;
    }
    sb_t resp = {0};
    handle_rpc(body, bodyn, &resp);
    if (resp.oom) {
        sb_free(&resp);
        send_status(fd, 500, "Internal Server Error");
        goto out;
    }
    char head[256];
    int hn = snprintf(head, sizeof head,
                      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                      resp.n);
    send_all(fd, head, (size_t)hn);
    send_all(fd, resp.p, resp.n);
    sb_free(&resp);
    shutdown(fd, SHUT_WR);
out:
    free(k.buf);
}

static void *connection_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    serve_connection(fd);
    close(fd);
    atomic_fetch_sub(&g_active, 1);
    return NULL;
}

/* ================================================================== startup */

static void on_signal(int sig) {
    (void)sig;
    char b = 1;
    ssize_t r = write(g_wake[1], &b, 1);
    (void)r;
}

static int listen_on(const char *bind_addr, char *err, size_t errn) {
    char host[256];
    const char *port;
    if (bind_addr[0] == '[') {
        const char *close = strchr(bind_addr, ']');
        if (!close || close[1] != ':') { snprintf(err, errn, "bind address must be HOST:PORT"); return -1; }
        snprintf(host, sizeof host, "%.*s", (int)(close - bind_addr - 1), bind_addr + 1);
        port = close + 2;
    } else {
        const char *colon = strrchr(bind_addr, ':');
        if (!colon) { snprintf(err, errn, "bind address must be HOST:PORT"); return -1; }
        snprintf(host, sizeof host, "%.*s", (int)(colon - bind_addr), bind_addr);
        port = colon + 1;
    }
    char *endp;
    long pn = strtol(port, &endp, 10);
    if (!*port || *endp || pn < 0 || pn > 65535) { snprintf(err, errn, "invalid port in bind address"); return -1; }
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    int rc = getaddrinfo(host[0] ? host : NULL, port, &hints, &res);
    if (rc) { snprintf(err, errn, "resolve %s: %s", host, gai_strerror(rc)); return -1; }
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 512) == 0) break;
        snprintf(err, errn, "bind %s: %s", bind_addr, strerror(errno));
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void usage(void) {
    fprintf(stderr, "usage: onlyblocks [--bind HOST:PORT] [--base-url URL]\n"
                    "  env fallbacks: ONLYBLOCKS_BIND (127.0.0.1:8899), OLD_FAITHFUL_BASE_URL (https://files.old-faithful.net)\n");
}

int main(int argc, char **argv) {
    const char *bind_addr = getenv("ONLYBLOCKS_BIND");
    const char *base_url = getenv("OLD_FAITHFUL_BASE_URL");
    if (!bind_addr) bind_addr = "127.0.0.1:8899";
    if (!base_url) base_url = "https://files.old-faithful.net";
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char **target = NULL;
        const char *value = NULL;
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) { usage(); return 0; }
        if (strncmp(arg, "--bind", 6) == 0 && (arg[6] == 0 || arg[6] == '=')) { target = &bind_addr; value = arg[6] ? arg + 7 : NULL; }
        else if (strncmp(arg, "--base-url", 10) == 0 && (arg[10] == 0 || arg[10] == '=')) { target = &base_url; value = arg[10] ? arg + 11 : NULL; }
        else { fprintf(stderr, "onlyblocks: unknown option %s\n", arg); usage(); return 2; }
        if (!value) {
            if (i + 1 >= argc) { fprintf(stderr, "onlyblocks: missing value for %s\n", arg); return 2; }
            value = argv[++i];
        }
        *target = value;
    }
    char err[512] = {0};
    g_archive = archive_new(base_url, err, sizeof err);
    if (!g_archive) { fprintf(stderr, "onlyblocks: %s\n", err); return 2; }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) { fprintf(stderr, "onlyblocks: curl init failed\n"); return 1; }
    signal(SIGPIPE, SIG_IGN);
    if (pipe(g_wake) != 0) { perror("pipe"); return 1; }
    fcntl(g_wake[1], F_SETFL, O_NONBLOCK);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    int lfd = listen_on(bind_addr, err, sizeof err);
    if (lfd < 0) { fprintf(stderr, "onlyblocks: %s\n", err); return 1; }
    fprintf(stderr, "onlyblocks/c listening on %s (archive %s)\n", bind_addr, base_url);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 4 * MIB);
    for (;;) {
        struct pollfd p[2] = {{lfd, POLLIN, 0}, {g_wake[0], POLLIN, 0}};
        int r = poll(p, 2, -1);
        if (r < 0 && errno == EINTR) continue;
        if (p[1].revents) break;
        if (!(p[0].revents & POLLIN)) continue;
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
        atomic_fetch_add(&g_active, 1);
        pthread_t t;
        if (pthread_create(&t, &attr, connection_thread, (void *)(intptr_t)fd) != 0) {
            atomic_fetch_sub(&g_active, 1);
            close(fd);
        }
    }
    close(lfd);
    /* Give in-flight requests a moment, then exit well inside the 3 s budget. */
    int64_t deadline = mono_ms() + 1500;
    while (atomic_load(&g_active) > 0 && mono_ms() < deadline) {
        struct timespec ts = {0, 20 * 1000000L};
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "onlyblocks/c shutting down\n");
    _exit(0);
}
