/* Old Faithful 2-range-read protocol: HTTP/1.1 Range client, retries, semaphore, RAM-only LRUs. */
#include "ob.h"

#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_INFLIGHT 32
#define MAX_RETRIES 4
#define INITIAL_BACKOFF_MS 200
#define MAX_BACKOFF_MS 10000
#define CONNECT_TIMEOUT_MS 10000
#define ATTEMPT_TIMEOUT_MS 60000
#define CACHE_CAPACITY 100000
#define USER_AGENT "onlyblocks/c"

/* ================================================================== LRU (slot -> fixed value) */

typedef struct {
    uint64_t key;
    int32_t prev, next;   /* recency list */
    int32_t chain;        /* hash bucket chain */
    unsigned char value[48];
} lru_node_t;

typedef struct {
    pthread_mutex_t mu;
    lru_node_t *nodes;
    int32_t *buckets;
    size_t nbuckets, cap, used;
    int32_t head, tail; /* head = most recent */
    size_t vsize;
} lru_t;

static void lru_init(lru_t *l, size_t cap, size_t vsize) {
    pthread_mutex_init(&l->mu, NULL);
    l->cap = cap;
    l->vsize = vsize;
    l->nbuckets = 1;
    while (l->nbuckets < cap * 2) l->nbuckets <<= 1;
    l->nodes = calloc(cap, sizeof *l->nodes);
    l->buckets = malloc(l->nbuckets * sizeof *l->buckets);
    if (!l->nodes || !l->buckets) abort();
    for (size_t i = 0; i < l->nbuckets; i++) l->buckets[i] = -1;
    l->head = l->tail = -1;
    l->used = 0;
}

static size_t lru_bucket(const lru_t *l, uint64_t key) {
    key ^= key >> 33;
    key *= 0xFF51AFD7ED558CCDULL;
    key ^= key >> 33;
    return (size_t)key & (l->nbuckets - 1);
}

static void lru_unlink(lru_t *l, int32_t i) {
    lru_node_t *n = &l->nodes[i];
    if (n->prev >= 0) l->nodes[n->prev].next = n->next;
    else l->head = n->next;
    if (n->next >= 0) l->nodes[n->next].prev = n->prev;
    else l->tail = n->prev;
}

static void lru_push_front(lru_t *l, int32_t i) {
    lru_node_t *n = &l->nodes[i];
    n->prev = -1;
    n->next = l->head;
    if (l->head >= 0) l->nodes[l->head].prev = i;
    l->head = i;
    if (l->tail < 0) l->tail = i;
}

static int32_t lru_find(lru_t *l, uint64_t key) {
    for (int32_t i = l->buckets[lru_bucket(l, key)]; i >= 0; i = l->nodes[i].chain)
        if (l->nodes[i].key == key) return i;
    return -1;
}

static bool lru_get(lru_t *l, uint64_t key, void *out) {
    pthread_mutex_lock(&l->mu);
    int32_t i = lru_find(l, key);
    if (i >= 0) {
        lru_unlink(l, i);
        lru_push_front(l, i);
        memcpy(out, l->nodes[i].value, l->vsize);
    }
    pthread_mutex_unlock(&l->mu);
    return i >= 0;
}

static void lru_put(lru_t *l, uint64_t key, const void *value) {
    pthread_mutex_lock(&l->mu);
    int32_t i = lru_find(l, key);
    if (i >= 0) {
        lru_unlink(l, i);
    } else {
        if (l->used < l->cap) {
            i = (int32_t)l->used++;
        } else {
            i = l->tail; /* evict the least recently used */
            lru_unlink(l, i);
            int32_t *pp = &l->buckets[lru_bucket(l, l->nodes[i].key)];
            while (*pp != i) pp = &l->nodes[*pp].chain;
            *pp = l->nodes[i].chain;
        }
        size_t b = lru_bucket(l, key);
        l->nodes[i].key = key;
        l->nodes[i].chain = l->buckets[b];
        l->buckets[b] = i;
    }
    memcpy(l->nodes[i].value, value, l->vsize);
    lru_push_front(l, i);
    pthread_mutex_unlock(&l->mu);
}

/* ================================================================== archive */

struct archive {
    char base[2048];  /* normalized base URL */
    bool https;
    char host[256];   /* connect host (no brackets) */
    char authority[300];
    char port[8];
    char prefix[1700]; /* path prefix without trailing '/' */
    lru_t ranges, hashes;
    pthread_mutex_t sem_mu;
    pthread_cond_t sem_cv;
    int inflight;
    pthread_mutex_t rng_mu;
    uint64_t rng;
};

archive_t *archive_new(const char *url, char *err, size_t errn) {
    archive_t *a = calloc(1, sizeof *a);
    if (!a) abort();
    while (*url == ' ' || *url == '\t' || *url == '\n' || *url == '\r') url++;
    size_t n = strlen(url);
    while (n && (url[n - 1] == ' ' || url[n - 1] == '\t' || url[n - 1] == '\n' || url[n - 1] == '\r')) n--;
    while (n && url[n - 1] == '/') n--;
    if (n >= sizeof a->base) { snprintf(err, errn, "base URL too long"); free(a); return NULL; }
    memcpy(a->base, url, n);
    a->base[n] = 0;
    const char *rest;
    if (strncasecmp(a->base, "http://", 7) == 0) { a->https = false; rest = a->base + 7; strcpy(a->port, "80"); }
    else if (strncasecmp(a->base, "https://", 8) == 0) { a->https = true; rest = a->base + 8; strcpy(a->port, "443"); }
    else { snprintf(err, errn, "base URL must use http:// or https://"); free(a); return NULL; }
    const char *slash = strchr(rest, '/');
    size_t alen = slash ? (size_t)(slash - rest) : strlen(rest);
    if (alen == 0 || alen >= sizeof a->authority) { snprintf(err, errn, "base URL has no host"); free(a); return NULL; }
    memcpy(a->authority, rest, alen);
    a->authority[alen] = 0;
    snprintf(a->prefix, sizeof a->prefix, "%s", slash ? slash : "");
    const char *auth = a->authority;
    const char *at = strrchr(auth, '@');
    if (at) auth = at + 1;
    const char *port = NULL;
    if (auth[0] == '[') {
        const char *close = strchr(auth, ']');
        if (!close) { snprintf(err, errn, "invalid IPv6 host in base URL"); free(a); return NULL; }
        snprintf(a->host, sizeof a->host, "%.*s", (int)(close - auth - 1), auth + 1);
        if (close[1] == ':') port = close + 2;
    } else {
        const char *colon = strrchr(auth, ':');
        if (colon) {
            snprintf(a->host, sizeof a->host, "%.*s", (int)(colon - auth), auth);
            port = colon + 1;
        } else {
            snprintf(a->host, sizeof a->host, "%s", auth);
        }
    }
    if (port && *port) snprintf(a->port, sizeof a->port, "%s", port);
    if (!a->host[0]) { snprintf(err, errn, "base URL has no host"); free(a); return NULL; }
    lru_init(&a->ranges, CACHE_CAPACITY, sizeof(slot_range_t));
    lru_init(&a->hashes, CACHE_CAPACITY, 45);
    pthread_mutex_init(&a->sem_mu, NULL);
    pthread_cond_init(&a->sem_cv, NULL);
    pthread_mutex_init(&a->rng_mu, NULL);
    a->rng = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32) ^ 0x9E3779B97F4A7C15ULL;
    return a;
}

bool archive_hash_get(archive_t *a, uint64_t slot, char out[45]) { return lru_get(&a->hashes, slot, out); }

void archive_hash_put(archive_t *a, uint64_t slot, const char *b58) {
    char v[45] = {0};
    snprintf(v, sizeof v, "%s", b58);
    lru_put(&a->hashes, slot, v);
}

static void sem_acquire(archive_t *a) {
    pthread_mutex_lock(&a->sem_mu);
    while (a->inflight >= MAX_INFLIGHT) pthread_cond_wait(&a->sem_cv, &a->sem_mu);
    a->inflight++;
    pthread_mutex_unlock(&a->sem_mu);
}

static void sem_release(archive_t *a) {
    pthread_mutex_lock(&a->sem_mu);
    a->inflight--;
    pthread_cond_signal(&a->sem_cv);
    pthread_mutex_unlock(&a->sem_mu);
}

static double jitter(archive_t *a) {
    pthread_mutex_lock(&a->rng_mu);
    a->rng ^= a->rng >> 12;
    a->rng ^= a->rng << 25;
    a->rng ^= a->rng >> 27;
    uint64_t r = a->rng * 0x2545F4914F6CDD1DULL;
    pthread_mutex_unlock(&a->rng_mu);
    return 0.5 + 0.5 * ((double)(r >> 11) / 9007199254740992.0);
}

/* ================================================================== one attempt */

enum { AT_OK, AT_STATUS, AT_TRANSPORT, AT_FATAL };

typedef struct {
    int kind;          /* AT_* */
    int status;        /* HTTP status (AT_OK / AT_STATUS) */
    bool has_retry_after;
    int64_t retry_after_ms;
    char why[160];
} attempt_t;

typedef struct {
    uint8_t *dst;       /* exactly `length` bytes */
    uint64_t length, cap, received;
    bool over_cap;
} sink_t;

static void sink_write(sink_t *s, const uint8_t *p, size_t n) {
    if (s->received < s->length) {
        uint64_t room = s->length - s->received;
        memcpy(s->dst + s->received, p, n < room ? n : (size_t)room);
    }
    s->received += n;
    if (s->received > s->cap) s->over_cap = true;
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void parse_retry_after(attempt_t *at, const char *v, size_t n) {
    while (n && (*v == ' ' || *v == '\t')) { v++; n--; }
    while (n && (v[n - 1] == ' ' || v[n - 1] == '\t' || v[n - 1] == '\r' || v[n - 1] == '\n')) n--;
    if (!n || n > 64) return;
    char tmp[65];
    memcpy(tmp, v, n);
    tmp[n] = 0;
    bool digits = true;
    for (size_t i = 0; i < n; i++) digits = digits && tmp[i] >= '0' && tmp[i] <= '9';
    if (digits) {
        uint64_t secs = 0;
        for (size_t i = 0; i < n && secs < 1000000; i++) secs = secs * 10 + (uint64_t)(tmp[i] - '0');
        at->has_retry_after = true;
        at->retry_after_ms = (int64_t)(secs > 1000000 ? 1000000 : secs) * 1000;
        return;
    }
    static const char *const formats[] = {"%a, %d %b %Y %H:%M:%S GMT", "%A, %d-%b-%y %H:%M:%S GMT", "%a %b %e %H:%M:%S %Y"};
    for (size_t f = 0; f < 3; f++) {
        struct tm tm;
        memset(&tm, 0, sizeof tm);
        const char *end = strptime(tmp, formats[f], &tm);
        if (end && *end == 0) {
            time_t when = timegm(&tm);
            int64_t delta = ((int64_t)when - (int64_t)time(NULL)) * 1000;
            at->has_retry_after = true;
            at->retry_after_ms = delta > 0 ? delta : 0;
            return;
        }
    }
}

/* ---------------------------------------------------------------- plain HTTP over TCP */

static int wait_fd(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t left = deadline - now_ms();
        if (left <= 0) return 0;
        struct pollfd p = {fd, events, 0};
        int r = poll(&p, 1, (int)(left > 1000000 ? 1000000 : left));
        if (r < 0 && errno == EINTR) continue;
        return r;
    }
}

static int tcp_connect(const archive_t *a, int64_t deadline, char *why, size_t whyn) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    int rc = getaddrinfo(a->host, a->port, &hints, &res);
    if (rc != 0) {
        snprintf(why, whyn, "resolve %s: %s", a->host, gai_strerror(rc));
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        if (errno == EINPROGRESS && wait_fd(fd, POLLOUT, deadline) > 0) {
            int soerr = 0;
            socklen_t len = sizeof soerr;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len);
            if (soerr == 0) break;
            errno = soerr;
        }
        snprintf(why, whyn, "connect: %s", strerror(errno));
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0 && !why[0]) snprintf(why, whyn, "connect failed");
    return fd;
}

static bool send_all(int fd, const char *p, size_t n, int64_t deadline) {
    while (n) {
        ssize_t w = send(fd, p, n, 0);
        if (w > 0) { p += w; n -= (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && wait_fd(fd, POLLOUT, deadline) > 0) continue;
        return false;
    }
    return true;
}

/* Reads into buf; 0 on EOF, -1 on error/timeout. */
static ssize_t recv_some(int fd, void *buf, size_t n, int64_t deadline) {
    for (;;) {
        ssize_t r = recv(fd, buf, n, 0);
        if (r >= 0) return r;
        if (errno == EINTR) continue;
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && wait_fd(fd, POLLIN, deadline) > 0) continue;
        return -1;
    }
}

typedef struct {
    int fd;
    int64_t deadline;
    char buf[16384];
    size_t pos, len;
    bool eof, error;
} rd_t;

static bool rd_fill(rd_t *r) {
    if (r->pos < r->len) return true;
    if (r->eof || r->error) return false;
    ssize_t n = recv_some(r->fd, r->buf, sizeof r->buf, r->deadline);
    if (n < 0) { r->error = true; return false; }
    if (n == 0) { r->eof = true; return false; }
    r->pos = 0;
    r->len = (size_t)n;
    return true;
}

/* A CRLF-terminated line (without CRLF) into out; false on EOF/error/overlong. */
static bool rd_line(rd_t *r, char *out, size_t outn) {
    size_t o = 0;
    for (;;) {
        if (!rd_fill(r)) return false;
        char ch = r->buf[r->pos++];
        if (ch == '\n') {
            if (o && out[o - 1] == '\r') o--;
            out[o] = 0;
            return true;
        }
        if (o + 1 >= outn) return false;
        out[o++] = ch;
    }
}

static bool rd_body(rd_t *r, sink_t *s, uint64_t n) {
    while (n) {
        if (!rd_fill(r)) return false;
        size_t take = r->len - r->pos;
        if (take > n) take = (size_t)n;
        sink_write(s, (const uint8_t *)r->buf + r->pos, take);
        if (s->over_cap) return true;
        r->pos += take;
        n -= take;
    }
    return true;
}

static void http_attempt(const archive_t *a, const char *path, uint64_t start, uint64_t end, sink_t *sink, attempt_t *at) {
    int64_t t0 = now_ms();
    int fd = tcp_connect(a, t0 + CONNECT_TIMEOUT_MS, at->why, sizeof at->why);
    if (fd < 0) { at->kind = AT_TRANSPORT; return; }
    rd_t *r = malloc(sizeof *r);
    if (!r) { close(fd); at->kind = AT_TRANSPORT; snprintf(at->why, sizeof at->why, "out of memory"); return; }
    r->fd = fd;
    r->deadline = t0 + ATTEMPT_TIMEOUT_MS;
    r->pos = r->len = 0;
    r->eof = r->error = false;
    char req[4096];
    int qn = snprintf(req, sizeof req,
                      "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%llu-%llu\r\nUser-Agent: " USER_AGENT
                      "\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
                      path, a->authority, (unsigned long long)start, (unsigned long long)end);
    char line[8192];
    bool chunked = false, has_length = false;
    uint64_t content_length = 0;
    at->kind = AT_TRANSPORT;
    if (qn <= 0 || (size_t)qn >= sizeof req) { at->kind = AT_FATAL; snprintf(at->why, sizeof at->why, "request too long"); goto done; }
    if (!send_all(fd, req, (size_t)qn, r->deadline)) { snprintf(at->why, sizeof at->why, "send failed"); goto done; }
    if (!rd_line(r, line, sizeof line)) { snprintf(at->why, sizeof at->why, "no status line"); goto done; }
    int status;
    if (sscanf(line, "HTTP/%*d.%*d %d", &status) != 1 || status < 100 || status > 999) {
        snprintf(at->why, sizeof at->why, "malformed status line");
        goto done;
    }
    for (;;) {
        if (!rd_line(r, line, sizeof line)) { snprintf(at->why, sizeof at->why, "truncated headers"); goto done; }
        if (!line[0]) break;
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = 0;
        char *v = colon + 1;
        while (*v == ' ' || *v == '\t') v++;
        if (strcasecmp(line, "content-length") == 0) {
            char *endp;
            errno = 0;
            unsigned long long cl = strtoull(v, &endp, 10);
            while (*endp == ' ' || *endp == '\t') endp++;
            if (errno || endp == v || *endp || *v == '-') { snprintf(at->why, sizeof at->why, "bad Content-Length"); goto done; }
            has_length = true;
            content_length = cl;
        } else if (strcasecmp(line, "transfer-encoding") == 0) {
            if (strcasestr(v, "chunked")) chunked = true;
        } else if (strcasecmp(line, "retry-after") == 0) {
            parse_retry_after(at, v, strlen(v));
        }
    }
    if (status >= 100 && status < 200) { snprintf(at->why, sizeof at->why, "unexpected interim response"); goto done; }
    at->status = status;
    if (status != 206) { at->kind = AT_STATUS; goto done; }
    if (!chunked && has_length && content_length > sink->cap) {
        at->kind = AT_FATAL;
        snprintf(at->why, sizeof at->why, "Content-Length %llu exceeds the range cap", (unsigned long long)content_length);
        goto done;
    }
    if (chunked) {
        for (;;) {
            if (!rd_line(r, line, sizeof line)) { snprintf(at->why, sizeof at->why, "truncated chunk header"); goto done; }
            char *endp;
            errno = 0;
            unsigned long long size = strtoull(line, &endp, 16);
            if (errno || endp == line || (*endp && *endp != ';' && *endp != ' ' && *endp != '\t')) {
                snprintf(at->why, sizeof at->why, "bad chunk size");
                goto done;
            }
            if (size == 0) {
                for (;;) {
                    if (!rd_line(r, line, sizeof line)) { snprintf(at->why, sizeof at->why, "truncated trailers"); goto done; }
                    if (!line[0]) break;
                }
                break;
            }
            if (!rd_body(r, sink, size)) { snprintf(at->why, sizeof at->why, "truncated chunk"); goto done; }
            if (sink->over_cap) break;
            if (!rd_line(r, line, sizeof line) || line[0]) { snprintf(at->why, sizeof at->why, "bad chunk terminator"); goto done; }
        }
    } else if (has_length) {
        if (!rd_body(r, sink, content_length)) { snprintf(at->why, sizeof at->why, "connection closed mid-body"); goto done; }
    } else {
        for (;;) {
            if (!rd_fill(r)) break;
            sink_write(sink, (const uint8_t *)r->buf + r->pos, r->len - r->pos);
            r->pos = r->len;
            if (sink->over_cap) break;
        }
        if (r->error) { snprintf(at->why, sizeof at->why, "read error"); goto done; }
    }
    if (sink->over_cap) {
        at->kind = AT_FATAL;
        snprintf(at->why, sizeof at->why, "range body exceeds its cap");
        goto done;
    }
    at->kind = AT_OK;
done:
    free(r);
    close(fd);
}

/* ---------------------------------------------------------------- HTTPS via the system libcurl */

typedef struct {
    sink_t *sink;
    attempt_t *at;
    CURL *curl;
    bool fatal;
} curl_ctx_t;

static size_t curl_header(char *p, size_t size, size_t nitems, void *ud) {
    curl_ctx_t *cc = ud;
    size_t n = size * nitems;
    if (n > 12 && strncasecmp(p, "retry-after:", 12) == 0) parse_retry_after(cc->at, p + 12, n - 12);
    if (n > 15 && strncasecmp(p, "content-length:", 15) == 0) {
        long code = 0;
        curl_easy_getinfo(cc->curl, CURLINFO_RESPONSE_CODE, &code);
        char tmp[32];
        size_t k = n - 15 < 31 ? n - 15 : 31;
        memcpy(tmp, p + 15, k);
        tmp[k] = 0;
        unsigned long long cl = strtoull(tmp, NULL, 10);
        if (code == 206 && cl > cc->sink->cap) {
            cc->fatal = true;
            return 0; /* abort the transfer */
        }
    }
    return n;
}

static size_t curl_write(char *p, size_t size, size_t nmemb, void *ud) {
    curl_ctx_t *cc = ud;
    size_t n = size * nmemb;
    long code = 0;
    curl_easy_getinfo(cc->curl, CURLINFO_RESPONSE_CODE, &code);
    if (code != 206) return n; /* status-only responses: discard the body */
    sink_write(cc->sink, (const uint8_t *)p, n);
    if (cc->sink->over_cap) {
        cc->fatal = true;
        return 0;
    }
    return n;
}

static void https_attempt(const archive_t *a, const char *path, uint64_t start, uint64_t end, sink_t *sink, attempt_t *at) {
    char url[4096], range[64];
    snprintf(url, sizeof url, "%s://%s%s", "https", a->authority, path);
    snprintf(range, sizeof range, "%llu-%llu", (unsigned long long)start, (unsigned long long)end);
    CURL *curl = curl_easy_init();
    if (!curl) { at->kind = AT_TRANSPORT; snprintf(at->why, sizeof at->why, "curl_easy_init failed"); return; }
    curl_ctx_t cc = {sink, at, curl, false};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_RANGE, range);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)CONNECT_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)ATTEMPT_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &cc);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &cc);
    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    if (cc.fatal) {
        at->kind = AT_FATAL;
        snprintf(at->why, sizeof at->why, "range body exceeds its cap");
        return;
    }
    if (rc != CURLE_OK) {
        if (code != 0 && code != 206) { at->kind = AT_STATUS; at->status = (int)code; return; }
        at->kind = AT_TRANSPORT;
        snprintf(at->why, sizeof at->why, "https: %s", curl_easy_strerror(rc));
        return;
    }
    at->status = (int)code;
    at->kind = code == 206 ? AT_OK : AT_STATUS;
}

/* ================================================================== retry loop (SPEC §4.2–4.3) */

static bytes_t read_range(ctx_t *c, archive_t *a, uint64_t slot, const char *suffix, uint64_t start, uint64_t length,
                          uint64_t cap) {
    if (length == 0 || start > UINT64_MAX - (length - 1)) DIE(c, "archive range end overflows u64");
    uint64_t end = start + length - 1;
    uint64_t epoch = slot / SLOTS_PER_EPOCH;
    char path[2048];
    snprintf(path, sizeof path, "%s/%llu/epoch-%llu%s", a->prefix, (unsigned long long)epoch, (unsigned long long)epoch,
             suffix);
    uint8_t *dst = amalloc(c, (size_t)length);
    for (int failures = 0;; failures++) {
        sink_t sink = {dst, length, cap, 0, false};
        attempt_t at;
        memset(&at, 0, sizeof at);
        sem_acquire(a);
        if (a->https) https_attempt(a, path, start, end, &sink, &at);
        else http_attempt(a, path, start, end, &sink, &at);
        sem_release(a);
        if (at.kind == AT_OK) {
            if (sink.received != length)
                DIE(c, "archive range body has %llu bytes, expected %llu", (unsigned long long)sink.received,
                    (unsigned long long)length);
            bytes_t b = {dst, (size_t)length};
            return b;
        }
        if (at.kind == AT_FATAL) DIE(c, "archive range read failed: %s", at.why);
        if (at.kind == AT_STATUS) {
            if (at.status == 404)
                fail(c, E_UNARCHIVED,
                     "Block not available for slot %llu: epoch %llu is not archived in Old Faithful (historical-only server)",
                     (unsigned long long)slot, (unsigned long long)epoch);
            if (at.status != 429 && (at.status < 500 || at.status > 599))
                DIE(c, "unexpected archive HTTP status %d", at.status);
        }
        if (failures == MAX_RETRIES) {
            if (at.kind == AT_STATUS) DIE(c, "archive retries exhausted (HTTP %d)", at.status);
            DIE(c, "archive retries exhausted: %s", at.why);
        }
        int64_t delay;
        if (at.has_retry_after) {
            delay = at.retry_after_ms < MAX_BACKOFF_MS ? at.retry_after_ms : MAX_BACKOFF_MS;
        } else {
            int64_t base = (int64_t)INITIAL_BACKOFF_MS << (failures < 30 ? failures : 30);
            if (base > MAX_BACKOFF_MS) base = MAX_BACKOFF_MS;
            delay = (int64_t)((double)base * jitter(a));
        }
        if (delay > 0) {
            struct timespec ts = {delay / 1000, (long)(delay % 1000) * 1000000L};
            while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
        }
    }
}

bytes_t archive_slot_slice(ctx_t *c, archive_t *a, uint64_t slot) {
    slot_range_t range;
    if (!lru_get(&a->ranges, slot, &range)) {
        uint64_t idx = slot % SLOTS_PER_EPOCH;
        bytes_t rec = read_range(c, a, slot, "-slot-ranges.raw", idx * 12, 12, 12);
        memset(&range, 0, sizeof range);
        range.offset = rd64le(rec.p);
        range.length = rd32le(rec.p + 8);
        range.skipped = range.length == 0;
        lru_put(&a->ranges, slot, &range);
    }
    if (range.skipped)
        fail(c, E_SKIPPED, "Slot %llu was skipped, or missing in long-term storage", (unsigned long long)slot);
    if (range.length > MAX_SLICE_BYTES) DIE(c, "slot slice of %u bytes exceeds the 128 MiB cap", range.length);
    return read_range(c, a, slot, ".car", range.offset, range.length, MAX_SLICE_BYTES);
}
