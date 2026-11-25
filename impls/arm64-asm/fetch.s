// fetch.s: the Old Faithful client. Plain-HTTP Range GETs over libSystem
// sockets (getaddrinfo, connect, read), https:// via the OS libcurl, the
// SPEC §4.3 retry policy, and the two bounded RAM-only LRU caches.

.include "defs.s"

// LRU cache: hashed by slot, doubly linked by recency, fixed capacity.
.equ LRU_BUCKETS, 131072
.equ L_BUCKETS, 0
.equ L_ENTRIES, 8
.equ L_COUNT, 16
.equ L_HEAD, 24
.equ L_TAIL, 32
.equ L_SIZE, 40
.equ E_KEY, 0
.equ E_PREV, 8
.equ E_NEXT, 12
.equ E_HNEXT, 16
.equ E_VAL, 24
.equ E_SIZE, 64

    .text

FN _fetch_init
    ENTER
    LA x0, _g_ranges
    bl lru_init
    LA x0, _g_hashes
    bl lru_init
    // Host header: host or [v6], plus :port unless it is the scheme default
    mov x0, #300
    bl _malloc
    mov x19, x0
    STG x19, g_hosthdr, x9
    LDG x20, _g_url_host
    LDG x21, _g_url_port
    mov x0, x20
    mov w1, #':'
    bl _strchr
    mov x22, x0                  // IPv6 literal?
    LDG x9, _g_url_https
    LA x10, Lport_80
    LA x11, Lport_443
    cmp x9, #0
    csel x0, x10, x11, eq
    mov x1, x21
    bl _strcmp
    mov x23, x0                  // 0 = default port
    LA x2, Lhost_plain
    LA x9, Lhost_v6
    cmp x22, #0
    csel x2, x2, x9, eq
    cbnz x23, 2f
    LA x2, Lhost_plain_np
    LA x9, Lhost_v6_np
    cmp x22, #0
    csel x2, x2, x9, eq
2:  sub sp, sp, #16
    stp x20, x21, [sp]
    mov x0, x19
    mov x1, #300
    bl _snprintf
    add sp, sp, #16
    LDG x9, _g_url_https
    cbz x9, 3f
    mov x0, #3                   // CURL_GLOBAL_DEFAULT
    bl _curl_global_init
3:  LEAVE

// ===================================================================== LRU

    .p2align 2
lru_init:
    ENTER
    mov x19, x0
    mov x0, #LRU_BUCKETS
    mov x1, #4
    bl _calloc
    str x0, [x19, #L_BUCKETS]
    MOV64 x0, LRU_CAP
    mov x1, #E_SIZE
    bl _calloc
    str x0, [x19, #L_ENTRIES]
    cbz x0, 9f
    ldr x9, [x19, #L_BUCKETS]
    cbz x9, 9f
    LEAVE
9:  bl _abort

    .p2align 2
lru_bucket:                      // x1 = key -> x9 = bucket index
    MOV64 x9, 0x9e3779b97f4a7c15
    mul x9, x1, x9
    lsr x9, x9, #47
    ret

// lru_find(x0 = lru, x1 = key) -> x0 = entry index (1-based) or 0, x2 = entry.
    .p2align 2
lru_find:
    mov x15, x30
    bl lru_bucket
    mov x30, x15
    ldr x10, [x0, #L_BUCKETS]
    ldr w11, [x10, x9, lsl #2]
    ldr x12, [x0, #L_ENTRIES]
1:  cbz w11, 2f
    sub w13, w11, #1
    add x2, x12, x13, lsl #6
    ldr x14, [x2, #E_KEY]
    cmp x14, x1
    b.eq 3f
    ldr w11, [x2, #E_HNEXT]
    b 1b
2:  mov x0, #0
    ret
3:  mov x0, x11
    ret

// lru_unlink(x0 = lru, x1 = index)
    .p2align 2
lru_unlink:
    ldr x12, [x0, #L_ENTRIES]
    sub x13, x1, #1
    add x13, x12, x13, lsl #6
    ldr w9, [x13, #E_PREV]
    ldr w10, [x13, #E_NEXT]
    cbz w9, 1f
    sub w11, w9, #1
    add x11, x12, x11, lsl #6
    str w10, [x11, #E_NEXT]
    b 2f
1:  str x10, [x0, #L_HEAD]
2:  cbz w10, 3f
    sub w11, w10, #1
    add x11, x12, x11, lsl #6
    str w9, [x11, #E_PREV]
    ret
3:  str x9, [x0, #L_TAIL]
    ret

// lru_front(x0 = lru, x1 = index)
    .p2align 2
lru_front:
    ldr x12, [x0, #L_ENTRIES]
    sub x13, x1, #1
    add x13, x12, x13, lsl #6
    ldr x9, [x0, #L_HEAD]
    str wzr, [x13, #E_PREV]
    str w9, [x13, #E_NEXT]
    cbz x9, 1f
    sub w11, w9, #1
    add x11, x12, x11, lsl #6
    str w1, [x11, #E_PREV]
    b 2f
1:  str x1, [x0, #L_TAIL]
2:  str x1, [x0, #L_HEAD]
    ret

// lru_get(x0 = lru, x1 = key) -> x0 = value (40 bytes) or 0.
FN _lru_get
    ENTER
    mov x19, x0
    mov x20, x1
    bl lru_find
    cbz x0, 9f
    mov x21, x0
    mov x22, x2
    mov x0, x19
    mov x1, x21
    bl lru_unlink
    mov x0, x19
    mov x1, x21
    bl lru_front
    add x0, x22, #E_VAL
9:  LEAVE

// lru_put(x0 = lru, x1 = key) -> x0 = value slot for key (most recent).
FN _lru_put
    ENTER
    mov x19, x0
    mov x20, x1
    bl lru_find
    cbz x0, 1f
    mov x21, x0
    mov x22, x2
    mov x0, x19
    mov x1, x21
    bl lru_unlink
    b 5f
1:  ldr x9, [x19, #L_COUNT]
    MOV64 x10, LRU_CAP
    cmp x9, x10
    b.hs 2f
    add x21, x9, #1
    str x21, [x19, #L_COUNT]
    b 4f
2:  // evict the least recently used entry
    ldr x21, [x19, #L_TAIL]
    mov x0, x19
    mov x1, x21
    bl lru_unlink
    ldr x12, [x19, #L_ENTRIES]
    sub x13, x21, #1
    add x22, x12, x13, lsl #6
    ldr x1, [x22, #E_KEY]
    bl lru_bucket
    ldr x10, [x19, #L_BUCKETS]
    add x10, x10, x9, lsl #2     // link to patch
3:  ldr w11, [x10]
    cmp w11, w21
    b.eq 31f
    sub w11, w11, #1
    add x10, x12, x11, lsl #6
    add x10, x10, #E_HNEXT
    b 3b
31: ldr w11, [x22, #E_HNEXT]
    str w11, [x10]
4:  ldr x12, [x19, #L_ENTRIES]
    sub x13, x21, #1
    add x22, x12, x13, lsl #6
    str x20, [x22, #E_KEY]
    mov x1, x20
    bl lru_bucket
    ldr x10, [x19, #L_BUCKETS]
    ldr w11, [x10, x9, lsl #2]
    str w11, [x22, #E_HNEXT]
    str w21, [x10, x9, lsl #2]
5:  mov x0, x19
    mov x1, x21
    bl lru_front
    add x0, x22, #E_VAL
    LEAVE

// =================================================================== slices

// load_slice(x0 = slot) -> x0 = CAR slice, x1 = length. Range read 1 is
// served from the slot-range cache when possible.
FN _load_slice
    ENTER 32
    mov x19, x0
    MOV64 x9, SLOTS_PER_EPOCH
    udiv x20, x19, x9            // epoch
    msub x21, x20, x9, x19       // slot index
    LA x0, _g_ranges
    mov x1, x19
    bl _lru_get
    cbnz x0, 2f
    mov x9, #12
    mul x3, x21, x9
    add x4, x3, #11
    mov x0, x19
    mov x1, x20
    LA x2, Lsfx_ranges
    mov x5, #12
    mov x6, #12
    bl range_get
    mov x22, x0
    LA x0, _g_ranges
    mov x1, x19
    bl _lru_put
    ldr x9, [x22]
    ldr w10, [x22, #8]
    str x9, [x0]
    str x10, [x0, #8]
2:  ldr x22, [x0]                // offset
    ldr x23, [x0, #8]            // length
    cbz x23, 90f
    mov x9, #MAX_SLICE
    cmp x23, x9
    b.hi 91f
    sub x9, x23, #1
    adds x4, x22, x9
    b.cs 92f
    mov x0, x19
    mov x1, x20
    LA x2, Lsfx_car
    mov x3, x22
    mov x5, x23
    mov x6, #MAX_SLICE
    bl range_get
    mov x1, x23
    LEAVE 32
90: mov x0, x19
    LA x1, Lmsg_skipped
    bl fmt_slot_msg
    mov x1, x0
    mov x0, #ERR_SKIPPED
    bl _ob_throw
91: FAIL "Archive slice exceeds 128 MiB"
92: FAIL "Archive range end overflows u64"

// fmt_slot_msg(x0 = slot, x1 = format with %llu [, %llu epoch]) -> arena text.
    .p2align 2
fmt_slot_msg:
    ENTER 16
    mov x19, x0
    mov x20, x1
    mov x0, #256
    bl _arena_alloc
    mov x21, x0
    MOV64 x9, SLOTS_PER_EPOCH
    udiv x9, x19, x9
    stp x19, x9, [sp]
    mov x0, x21
    mov x1, #256
    mov x2, x20
    bl _snprintf
    mov x0, x21
    LEAVE 16

// range_get(x0 = slot, x1 = epoch, x2 = suffix, x3 = first, x4 = last,
//           x5 = expected length, x6 = cap) -> x0 = body.
    .p2align 2
range_get:
    ENTER 64
    mov x19, x0
    stp x3, x4, [sp, #32]
    stp x5, x6, [sp, #48]
    mov x20, x1
    mov x21, x2
    mov x0, #512
    bl _arena_alloc
    mov x22, x0                  // path
    LDG x9, _g_url_path
    stp x9, x20, [sp]
    stp x20, x21, [sp, #16]
    mov x0, x22
    mov x1, #512
    LA x2, Lpath_fmt
    bl _snprintf
    mov x23, #0                  // attempt
1:  mov x0, x22
    ldp x1, x2, [sp, #32]
    ldr x3, [sp, #56]
    LDG x9, _g_url_https
    cbz x9, 2f
    bl curl_attempt
    b 3f
2:  bl http_attempt
3:  mov x24, x0                  // status
    cmp x24, #206
    b.ne 10f
    LDG x9, g_att_capx
    cbnz x9, 93f
    LDG x9, g_att_len
    ldr x10, [sp, #48]
    cmp x9, x10
    b.ne 94f
    LDG x0, g_att_body
    LEAVE 64
10: cmp x24, #404
    b.eq 90f
    cbz x24, 11f
    cmp x24, #429
    b.eq 11f
    sub x9, x24, #500
    cmp x9, #99
    b.hi 91f
11: cmp x23, #4
    b.hs 92f
    // delay before the retry
    LDG x9, g_att_retry
    tbnz x9, #63, 12f
    mov x10, #10
    cmp x9, x10
    csel x9, x10, x9, hi
    mov x10, #1000
    mul x9, x9, x10              // ms
    b 13f
12: mov x9, #200
    lsl x9, x9, x23
    mov x10, #10000
    cmp x9, x10
    csel x9, x10, x9, hi
    str x9, [sp, #24]
    mov w0, #1000
    bl _arc4random_uniform
    ldr x9, [sp, #24]
    lsr w0, w0, #1
    add x0, x0, #500
    mul x9, x9, x0
    mov x10, #1000
    udiv x9, x9, x10
13: cbz x9, 14f
    mov x10, #1000
    mul x0, x9, x10
    bl _usleep
14: add x23, x23, #1
    b 1b
90: mov x0, x19
    LA x1, Lmsg_unarchived
    bl fmt_slot_msg
    mov x1, x0
    mov x0, #ERR_UNAVAILABLE
    bl _ob_throw
91: FAIL "Unexpected archive HTTP status"
92: FAIL "Archive range retries exhausted"
93: FAIL "Archive body exceeds the range cap"
94: FAIL "Archive range body has the wrong length"

// ============================================================ plain HTTP

// http_attempt(x0 = path, x1 = first, x2 = last, x3 = cap) -> x0 = status
// (0 = transport failure). On 206 sets g_att_body/len/capx.
    .p2align 2
http_attempt:
    ENTER 128
    mov x19, x0
    stp x1, x2, [sp, #96]
    str x3, [sp, #112]
    STG xzr, g_att_capx, x9
    mov x9, #-1
    STG x9, g_att_retry, x10
    // hints at [sp, #0 .. 48)
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    stp xzr, xzr, [sp, #32]
    mov w9, #1
    str w9, [sp, #8]             // ai_socktype = SOCK_STREAM
    LDG x0, _g_url_host
    LDG x1, _g_url_port
    mov x2, sp
    add x3, sp, #48              // result
    bl _getaddrinfo
    cbnz w0, 80f
    ldr x20, [sp, #48]
    mov x21, x20
    mov w22, #-1
1:  cbz x21, 3f
    ldr w0, [x21, #4]
    ldr w1, [x21, #8]
    ldr w2, [x21, #12]
    bl _socket
    tbnz w0, #31, 2f
    mov w22, w0
    mov w0, w22
    ldr x1, [x21, #32]
    ldr w2, [x21, #16]
    bl _connect
    cbz w0, 3f
    mov w0, w22
    bl _close
    mov w22, #-1
2:  ldr x21, [x21, #40]
    b 1b
3:  mov x0, x20
    bl _freeaddrinfo
    tbnz w22, #31, 80f
    // 60 s per-attempt timeouts, no SIGPIPE
    mov x9, #60
    stp x9, xzr, [sp, #56]
    mov w0, w22
    mov w1, #0xffff
    mov w2, #0x1006
    add x3, sp, #56
    mov w4, #16
    bl _setsockopt
    mov w0, w22
    mov w1, #0xffff
    mov w2, #0x1005
    add x3, sp, #56
    mov w4, #16
    bl _setsockopt
    mov w9, #1
    str w9, [sp, #72]
    mov w0, w22
    mov w1, #0xffff
    mov w2, #0x1022
    add x3, sp, #72
    mov w4, #4
    bl _setsockopt
    // request
    mov x0, #1024
    bl _arena_alloc
    mov x23, x0
    LDG x9, g_hosthdr
    stp x19, x9, [sp]
    ldp x10, x11, [sp, #96]
    stp x10, x11, [sp, #16]
    mov x0, x23
    mov x1, #1024
    LA x2, Lreq_fmt
    bl _snprintf
    mov x2, x0
    mov w0, w22
    mov x1, x23
    bl _write_all
    cbz x0, 79f
    // response
    bl _buf_new
    mov x24, x0
    mov x25, #0                  // header length (0 = not parsed yet)
    mov x26, #-1                 // Content-Length
    mov x27, #0                  // chunked
    mov x28, #0                  // status
10: mov x0, x24
    mov x1, #65536
    bl _buf_reserve
    ldp x9, x10, [x24]
    ldr x11, [x24, #BUF_CAP]
    mov w0, w22
    add x1, x9, x10
    sub x2, x11, x10
    bl _read
    cmp x0, #0
    b.gt 11f
    b.eq 30f                     // EOF
    bl ___error
    ldr w9, [x0]
    cmp w9, #4
    b.eq 10b
    b 79f
11: ldr x10, [x24, #BUF_LEN]
    add x10, x10, x0
    str x10, [x24, #BUF_LEN]
    cbnz x25, 20f
    ldr x0, [x24, #BUF_PTR]
    mov x1, x10
    bl find_hdr_end
    cbz x0, 12f
    mov x25, x0
    bl parse_resp_headers
    mov x28, x0
    mov x26, x1
    mov x27, x2
    cmp x28, #206
    b.ne 70f
    cbnz x27, 20f
    cmn x26, #1
    b.eq 20f
    ldr x9, [sp, #112]
    cmp x26, x9
    b.hi 75f
    b 20f
12: ldr x10, [x24, #BUF_LEN]
    cmp x10, #16, lsl #12
    b.hi 79f
    b 10b
20: // body progress
    ldr x10, [x24, #BUF_LEN]
    sub x10, x10, x25            // body bytes so far
    cbnz x27, 22f
    cmn x26, #1
    b.eq 21f
    cmp x10, x26
    b.hs 40f
    b 10b
21: ldr x9, [sp, #112]
    cmp x10, x9
    b.hi 75f
    b 10b
22: ldr x9, [sp, #112]
    add x9, x9, #16, lsl #12
    cmp x10, x9, lsl #1
    b.hi 75f
    b 10b
30: // EOF
    cbz x25, 79f
    cbnz x27, 50f
    cmn x26, #1
    b.ne 79f                     // fewer than Content-Length bytes
    ldr x10, [x24, #BUF_LEN]
    sub x10, x10, x25
    ldr x9, [x24, #BUF_PTR]
    add x9, x9, x25
    b 41f
40: ldr x9, [x24, #BUF_PTR]
    add x9, x9, x25
    mov x10, x26
41: STG x9, g_att_body, x11
    STG x10, g_att_len, x11
    mov w0, w22
    bl _close
    mov x0, #206
    LEAVE 128
50: // chunked: decode what we have
    bl _buf_new
    mov x23, x0
    ldp x9, x10, [x24]
    add x1, x9, x25
    add x2, x9, x10
    mov x3, x23
    ldr x4, [sp, #112]
    bl _chunked_decode
    cmn x0, #2
    b.eq 75f
    cmp x0, #1
    b.ne 79f
    ldp x9, x10, [x23]
    b 41b
70: // non-206: close and report
    mov w0, w22
    bl _close
    mov x0, x28
    LEAVE 128
75: STG xzr, g_att_len, x9
    mov x9, #1
    STG x9, g_att_capx, x10
    mov w0, w22
    bl _close
    mov x0, #206
    LEAVE 128
79: mov w0, w22
    bl _close
80: mov x0, #0
    LEAVE 128

// find_hdr_end(x0 = buf, x1 = len) -> offset after CRLFCRLF, or 0.
    .p2align 2
find_hdr_end:
    mov x9, #0
    mov w12, #0x0a0d
    movk w12, #0x0a0d, lsl #16
1:  add x10, x9, #4
    cmp x10, x1
    b.hi 3f
    ldr w11, [x0, x9]
    cmp w11, w12
    b.eq 2f
    add x9, x9, #1
    b 1b
2:  add x0, x9, #4
    ret
3:  mov x0, #0
    ret

// parse_resp_headers(x24 = Buf, x25 = header length) -> x0 = status,
// x1 = Content-Length (-1 absent), x2 = chunked; sets g_att_retry.
    .p2align 2
parse_resp_headers:
    ENTER 80
    ldr x19, [x24, #BUF_PTR]
    add x20, x19, x25            // end of headers
    mov x21, #-1
    mov x22, #0
    mov x23, #0
    // status line "HTTP/1.x NNN"
    sub x9, x20, x19
    cmp x9, #12
    b.lo 90f
    mov x0, x19
    LA x1, Lhttp1
    mov x2, #7
    bl _strncmp
    cbnz w0, 90f
    mov x9, #0
    mov x10, #9
1:  ldrb w11, [x19, x10]
    sub w11, w11, #'0'
    cmp w11, #9
    b.hi 90f
    mov x12, #10
    madd x9, x9, x12, x11
    add x10, x10, #1
    cmp x10, #12
    b.lo 1b
    mov x23, x9
    mov x0, x19
    bl next_line_r
    mov x24, x0                  // cursor (x24 restored on LEAVE)
2:  cmp x24, x20
    b.hs 80f
    ldrb w9, [x24]
    cmp w9, #'\r'
    b.eq 80f
    mov x0, x24
    LA x1, Lh_cl
    mov x2, #15
    bl _strncasecmp
    cbnz w0, 4f
    add x9, x24, #15
    bl skip_spaces
    mov x21, #0
    mov x12, #0
3:  ldrb w10, [x9], #1
    sub w10, w10, #'0'
    cmp w10, #9
    b.hi 31f
    mov x11, #10
    umulh x13, x21, x11
    cbnz x13, 90f
    mul x21, x21, x11
    adds x21, x21, x10
    b.cs 90f
    add x12, x12, #1
    b 3b
31: cbz x12, 90f
    b 7f
4:  mov x0, x24
    LA x1, Lh_te
    mov x2, #18
    bl _strncasecmp
    cbnz w0, 5f
    add x0, x24, #18
    LA x1, Lchunked
    bl line_has_ci
    orr x22, x22, x0
    b 7f
5:  mov x0, x24
    LA x1, Lh_ra
    mov x2, #12
    bl _strncasecmp
    cbnz w0, 7f
    add x0, x24, #12
    bl parse_retry_after
    STG x0, g_att_retry, x9
7:  mov x0, x24
    bl next_line_r
    mov x24, x0
    b 2b
80: mov x0, x23
    mov x1, x21
    mov x2, x22
    LEAVE 80
90: mov x0, #0
    mov x1, #-1
    mov x2, #0
    LEAVE 80

    .p2align 2
next_line_r:
1:  ldrb w9, [x0], #1
    cmp w9, #'\n'
    b.ne 1b
    ret

    .p2align 2
skip_spaces:
1:  ldrb w10, [x9]
    cmp w10, #' '
    b.eq 2f
    cmp w10, #'\t'
    b.ne 3f
2:  add x9, x9, #1
    b 1b
3:  ret

// line_has_ci(x0 = text, x1 = lowercase word) -> 1 if found before CR.
    .p2align 2
line_has_ci:
    mov x9, x0
1:  ldrb w10, [x9]
    cmp w10, #'\r'
    b.eq 8f
    cbz w10, 8f
    mov x11, x9
    mov x12, x1
2:  ldrb w13, [x12], #1
    cbz w13, 9f
    ldrb w14, [x11], #1
    orr w14, w14, #0x20
    cmp w14, w13
    b.eq 2b
    add x9, x9, #1
    b 1b
8:  mov x0, #0
    ret
9:  mov x0, #1
    ret

// parse_retry_after(x0 = header value) -> seconds, or -1 when unparseable.
// Accepts delta-seconds or an IMF-fixdate (a past date gives 0).
    .p2align 2
parse_retry_after:
    ENTER 144
    mov x9, x0
    bl skip_spaces
    // copy up to CR into a C string at [sp, #64]
    add x10, sp, #64
    mov x11, #0
1:  ldrb w12, [x9, x11]
    cmp w12, #'\r'
    b.eq 2f
    cbz w12, 2f
    cmp x11, #70
    b.hs 9f
    strb w12, [x10, x11]
    add x11, x11, #1
    b 1b
2:  strb wzr, [x10, x11]
    cbz x11, 9f
    // all digits?
    mov x12, #0
    mov x13, #0
3:  cmp x12, x11
    b.hs 4f
    ldrb w14, [x10, x12]
    sub w14, w14, #'0'
    cmp w14, #9
    b.hi 5f
    mov x15, #10
    madd x13, x13, x15, x14
    lsr x15, x13, #40
    cbnz x15, 9f
    add x12, x12, #1
    b 3b
4:  mov x0, x13
    LEAVE 144
5:  // HTTP-date
    mov x0, sp
    mov x1, #0
    mov x2, #56
    bl _memset
    add x0, sp, #64
    LA x1, Ldate_fmt
    mov x2, sp
    bl _strptime
    cbz x0, 9f
    mov x0, sp
    bl _timegm
    mov x19, x0
    mov x0, #0
    bl _time
    subs x0, x19, x0
    csel x0, xzr, x0, lt
    LEAVE 144
9:  mov x0, #-1
    LEAVE 144

// ================================================================== HTTPS
// curl_attempt(x0 = path, x1 = first, x2 = last, x3 = cap) -> status.

    .p2align 2
curl_attempt:
    ENTER 96
    mov x19, x0
    stp x1, x2, [sp, #64]
    str x3, [sp, #80]
    STG xzr, g_att_capx, x9
    mov x9, #-1
    STG x9, g_att_retry, x10
    bl _buf_new
    mov x20, x0
    STG x20, g_curl_buf, x9
    ldr x9, [sp, #80]
    STG x9, g_curl_cap, x10
    // URL = scheme://host[:port] + path, rebuilt from g_url (no trailing /)
    mov x0, #2048
    bl _arena_alloc
    mov x21, x0
    LDG x9, _g_url
    LDG x10, _g_url_path
    stp x9, x10, [sp]
    mov x0, x9
    bl _strlen
    LDG x10, _g_url_path
    mov x22, x0
    mov x0, x10
    bl _strlen
    sub x9, x22, x0              // length of scheme://authority
    LDG x10, _g_url
    stp x9, x10, [sp]
    str x19, [sp, #16]
    mov x0, x21
    mov x1, #2048
    LA x2, Lurl_fmt
    bl _snprintf
    // range text
    mov x0, #64
    bl _arena_alloc
    mov x22, x0
    ldp x9, x10, [sp, #64]
    stp x9, x10, [sp]
    mov x0, x22
    mov x1, #64
    LA x2, Lrange_fmt
    bl _snprintf
    bl _curl_easy_init
    cbz x0, 80f
    mov x23, x0
    mov x1, #10002               // CURLOPT_URL
    mov x2, x21
    bl curl_set
    mov x1, #10007               // CURLOPT_RANGE
    mov x2, x22
    bl curl_set
    mov x1, #10018               // CURLOPT_USERAGENT
    LA x2, Lua
    bl curl_set
    mov x1, #20011               // CURLOPT_WRITEFUNCTION
    LA x2, curl_write_cb
    bl curl_set
    mov x1, #20079               // CURLOPT_HEADERFUNCTION
    LA x2, curl_header_cb
    bl curl_set
    mov x1, #78                  // CURLOPT_CONNECTTIMEOUT
    mov x2, #10
    bl curl_set
    mov x1, #13                  // CURLOPT_TIMEOUT
    mov x2, #60
    bl curl_set
    mov x1, #99                  // CURLOPT_NOSIGNAL
    mov x2, #1
    bl curl_set
    mov x1, #84                  // CURLOPT_HTTP_VERSION
    mov x2, #2                   // 1.1
    bl curl_set
    mov x0, x23
    bl _curl_easy_perform
    mov x24, x0
    str xzr, [sp, #88]
    add x9, sp, #88
    str x9, [sp]
    mov x0, x23
    MOV64 x1, 0x200002            // CURLINFO_RESPONSE_CODE
    bl _curl_easy_getinfo
    ldr x25, [sp, #88]
    mov x0, x23
    bl _curl_easy_cleanup
    LDG x9, g_att_capx
    cbnz x9, 70f
    cbnz x24, 80f                // transport failure
    cmp x25, #206
    b.ne 75f
    ldp x9, x10, [x20]
    STG x9, g_att_body, x11
    STG x10, g_att_len, x11
70: mov x0, #206
    LEAVE 96
75: mov x0, x25
    LEAVE 96
80: mov x0, #0
    LEAVE 96

// curl_set(x23 = handle, x1 = option, x2 = value): the value is variadic.
    .p2align 2
curl_set:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x2, [sp, #16]
    sub sp, sp, #16
    str x2, [sp]
    mov x0, x23
    bl _curl_easy_setopt
    add sp, sp, #16
    ldp x29, x30, [sp], #32
    ret

// size_t write(char *data, size_t size, size_t nmemb, void *userdata)
    .p2align 2
curl_write_cb:
    ENTER
    mul x19, x1, x2
    mov x20, x0
    LDG x21, g_curl_buf
    ldr x9, [x21, #BUF_LEN]
    add x9, x9, x19
    LDG x10, g_curl_cap
    cmp x9, x10
    b.hi 9f
    mov x0, x21
    mov x1, x20
    mov x2, x19
    bl _buf_append
    mov x0, x19
    LEAVE
9:  mov x9, #1
    STG x9, g_att_capx, x10
    mov x0, #0
    LEAVE

// header callback: picks up Retry-After.
    .p2align 2
curl_header_cb:
    ENTER
    mul x19, x1, x2
    mov x20, x0
    cmp x19, #13
    b.lo 9f
    mov x0, x20
    LA x1, Lh_ra
    mov x2, #12
    bl _strncasecmp
    cbnz w0, 9f
    add x0, x20, #12
    bl parse_retry_after
    STG x0, g_att_retry, x9
9:  mov x0, x19
    LEAVE

// ================================================================ helpers

// write_all(w0 = fd, x1 = ptr, x2 = len) -> x0 = 1 if everything was sent.
FN _write_all
    ENTER
    mov w19, w0
    mov x20, x1
    mov x21, x2
1:  cbz x21, 8f
    mov w0, w19
    mov x1, x20
    mov x2, x21
    bl _write
    cmp x0, #0
    b.gt 2f
    bl ___error
    ldr w9, [x0]
    cmp w9, #4
    b.eq 1b
    mov x0, #0
    LEAVE
2:  add x20, x20, x0
    sub x21, x21, x0
    b 1b
8:  mov x0, #1
    LEAVE

// chunked_decode(x1 = start, x2 = end, x3 = out Buf, x4 = cap)
// -> 1 complete, 0 need more, -1 malformed, -2 larger than cap.
FN _chunked_decode
    ENTER
    mov x19, x1
    mov x20, x2
    mov x21, x3
    mov x24, x4
    str xzr, [x21, #BUF_LEN]
1:  mov x22, #0
    mov x23, #0
2:  cmp x19, x20
    b.hs 80f
    ldrb w9, [x19]
    sub w10, w9, #'0'
    cmp w10, #9
    b.ls 3f
    orr w9, w9, #0x20
    sub w10, w9, #'a'
    cmp w10, #5
    b.hi 4f
    add w10, w10, #10
3:  lsl x22, x22, #4
    add x22, x22, x10
    add x23, x23, #1
    cmp x23, #15
    b.hi 82f
    add x19, x19, #1
    b 2b
4:  cbz x23, 81f
5:  cmp x19, x20
    b.hs 80f
    ldrb w9, [x19], #1
    cmp w9, #'\n'
    b.ne 5b
    cbz x22, 10f
    ldr x10, [x21, #BUF_LEN]
    add x10, x10, x22
    cmp x10, x24
    b.hi 82f
    sub x9, x20, x19
    cmp x9, x22
    b.lo 80f
    sub x9, x9, x22
    cmp x9, #2
    b.lo 80f
    mov x0, x21
    mov x1, x19
    mov x2, x22
    bl _buf_append
    add x19, x19, x22
    ldrb w9, [x19]
    cmp w9, #'\r'
    b.ne 81f
    ldrb w9, [x19, #1]
    cmp w9, #'\n'
    b.ne 81f
    add x19, x19, #2
    b 1b
10: cmp x19, x20
    b.hs 80f
    ldrb w9, [x19]
    cmp w9, #'\r'
    b.eq 12f
11: cmp x19, x20
    b.hs 80f
    ldrb w9, [x19], #1
    cmp w9, #'\n'
    b.ne 11b
    b 10b
12: add x9, x19, #2
    cmp x9, x20
    b.hi 80f
    mov x0, #1
    LEAVE
80: mov x0, #0
    LEAVE
81: mov x0, #-1
    LEAVE
82: mov x0, #-2
    LEAVE

    .section __TEXT,__cstring
Lsfx_ranges:  .asciz "-slot-ranges.raw"
Lsfx_car:     .asciz ".car"
Lpath_fmt:    .asciz "%s/%llu/epoch-%llu%s"
Lreq_fmt:     .asciz "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%llu-%llu\r\nUser-Agent: onlyblocks/arm64-asm\r\nAccept: */*\r\nConnection: close\r\n\r\n"
Lmsg_skipped: .asciz "Slot %llu was skipped, or missing in long-term storage"
Lmsg_unarchived: .asciz "Block not available for slot %llu: epoch %llu is not archived in Old Faithful (historical-only server)"
Lhost_plain:  .asciz "%s:%s"
Lhost_v6:     .asciz "[%s]:%s"
Lhost_plain_np: .asciz "%s"
Lhost_v6_np:  .asciz "[%s]"
Lport_80:     .asciz "80"
Lport_443:    .asciz "443"
Lhttp1:       .asciz "HTTP/1."
Lh_cl:        .asciz "content-length:"
Lh_te:        .asciz "transfer-encoding:"
Lh_ra:        .asciz "retry-after:"
Lchunked:     .asciz "chunked"
Ldate_fmt:    .asciz "%a, %d %b %Y %H:%M:%S"
Lurl_fmt:     .asciz "%.*s%s"
Lrange_fmt:   .asciz "%llu-%llu"
Lua:          .asciz "onlyblocks/arm64-asm"

    .data
    .p2align 3
    .globl _g_ranges, _g_hashes
_g_ranges:    .space L_SIZE
_g_hashes:    .space L_SIZE
g_hosthdr:    .quad 0
g_att_body:   .quad 0
g_att_len:    .quad 0
g_att_capx:   .quad 0
g_att_retry:  .quad -1
g_curl_buf:   .quad 0
g_curl_cap:   .quad 0
