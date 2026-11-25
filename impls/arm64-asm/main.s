// main.s: start-up (flags, environment, base URL), the listening socket and
// the inbound HTTP/1.1 server (Content-Length and chunked bodies, 1 MiB cap).
// Connections are served one at a time, each closed after its response.

.include "defs.s"

    .text

FN _main
    ENTER 64
    mov x19, x0
    mov x20, x1
    LA x0, Lenv_bind
    bl _getenv
    cbnz x0, 1f
    LA x0, Ldef_bind
1:  mov x21, x0                  // bind text
    LA x0, Lenv_base
    bl _getenv
    cbnz x0, 2f
    LA x0, Ldef_base
2:  mov x22, x0                  // base URL text
    mov x23, #1
3:  cmp x23, x19
    b.hs 10f
    ldr x24, [x20, x23, lsl #3]
    add x23, x23, #1
    mov x0, x24
    LA x1, Lopt_bind_eq
    mov x2, #7
    bl _strncmp
    cbnz w0, 4f
    add x21, x24, #7
    b 3b
4:  mov x0, x24
    LA x1, Lopt_base_eq
    mov x2, #11
    bl _strncmp
    cbnz w0, 5f
    add x22, x24, #11
    b 3b
5:  mov x0, x24
    LA x1, Lopt_bind
    bl _strcmp
    cbnz w0, 6f
    cmp x23, x19
    b.hs 90f
    ldr x21, [x20, x23, lsl #3]
    add x23, x23, #1
    b 3b
6:  mov x0, x24
    LA x1, Lopt_base
    bl _strcmp
    cbnz w0, 90f
    cmp x23, x19
    b.hs 90f
    ldr x22, [x20, x23, lsl #3]
    add x23, x23, #1
    b 3b

10: mov x0, x22
    bl parse_base_url
    cbz x0, 91f
    mov x0, x21
    add x1, sp, #16              // sockaddr_in
    bl parse_bind
    cbz x0, 92f

    mov x0, #13                  // SIGPIPE
    mov x1, #1                   // SIG_IGN
    bl _signal
    mov x0, #15                  // SIGTERM
    LA x1, on_term
    bl _signal
    mov x0, #2                   // SIGINT
    LA x1, on_term
    bl _signal

    bl _fetch_init
    bl _tx_init

    mov x0, #2
    mov x1, #1
    mov x2, #0
    bl _socket
    tbnz w0, #31, 93f
    mov w24, w0
    mov w9, #1
    str w9, [sp, #8]
    mov w0, w24
    mov w1, #0xffff
    mov w2, #4                   // SO_REUSEADDR
    add x3, sp, #8
    mov w4, #4
    bl _setsockopt
    mov w0, w24
    add x1, sp, #16
    mov w2, #16
    bl _bind
    tbnz w0, #31, 93f
    mov w0, w24
    mov w1, #128
    bl _listen
    tbnz w0, #31, 93f

20: mov w0, w24
    mov x1, #0
    mov x2, #0
    bl _accept
    tbnz w0, #31, 20b
    mov w25, w0
    mov w0, w25
    bl serve_conn
    mov w0, w25
    bl _close
    b 20b

90: LA x0, Lusage
    b 99f
91: LA x0, Lbad_base
    b 99f
92: LA x0, Lbad_bind
    b 99f
93: LA x0, Llisten_fail
99: mov x19, x0
    adrp x1, ___stderrp@GOTPAGE
    ldr x1, [x1, ___stderrp@GOTPAGEOFF]
    ldr x1, [x1]
    mov x0, x19
    bl _fputs
    mov w0, #1
    bl _exit

    .p2align 2
on_term:
    mov w0, #0
    bl __exit

// parse_bind(x0 = "HOST:PORT", x1 = sockaddr_in out) -> 1 on success.
    .p2align 2
parse_bind:
    ENTER 48
    mov x19, x0
    mov x20, x1
    mov x0, x20
    mov x1, #0
    mov x2, #16
    bl _memset
    mov w9, #16
    strb w9, [x20]
    mov w9, #2
    strb w9, [x20, #1]
    mov x0, x19
    mov w1, #':'
    bl _strrchr
    cbz x0, 9f
    mov x21, x0                  // ':'
    sub x22, x21, x19            // host length
    cbz x22, 9f
    cmp x22, #40
    b.hs 9f
    mov x0, sp
    mov x1, x19
    mov x2, x22
    bl _memcpy
    strb wzr, [sp, x22]
    // port: 1..5 digits <= 65535
    add x9, x21, #1
    mov x10, #0
    mov x11, #0
1:  ldrb w12, [x9], #1
    cbz w12, 2f
    sub w12, w12, #'0'
    cmp w12, #9
    b.hi 9f
    mov x13, #10
    madd x10, x10, x13, x12
    add x11, x11, #1
    cmp x11, #5
    b.hi 9f
    b 1b
2:  cbz x11, 9f
    mov x13, #65535
    cmp x10, x13
    b.hi 9f
    rev16 w10, w10
    strh w10, [x20, #2]
    mov x0, sp
    LA x1, Llocalhost
    bl _strcmp
    cbnz w0, 3f
    mov w9, #0x007f
    movk w9, #0x0100, lsl #16    // 127.0.0.1 in network order
    str w9, [x20, #4]
    b 8f
3:  mov w0, #2
    mov x1, sp
    add x2, x20, #4
    bl _inet_pton
    cmp w0, #1
    b.ne 9f
8:  mov x0, #1
    LEAVE 48
9:  mov x0, #0
    LEAVE 48

// parse_base_url(x0 = text) -> 1 on success. Fills the _g_url* globals.
    .p2align 2
parse_base_url:
    ENTER
    bl _strdup
    cbz x0, 9f
    mov x19, x0
    // trim leading whitespace
1:  ldrb w9, [x19]
    cbz w9, 2f
    mov w0, w9
    bl is_space
    cbz x0, 2f
    add x19, x19, #1
    b 1b
2:  mov x0, x19
    bl _strlen
    add x20, x19, x0             // end
3:  cmp x20, x19
    b.ls 4f
    ldrb w0, [x20, #-1]
    bl is_space
    cbnz x0, 31f
    ldrb w9, [x20, #-1]
    cmp w9, #'/'
    b.ne 4f
31: sub x20, x20, #1
    b 3b
4:  strb wzr, [x20]
    STG x19, _g_url, x9
    mov x0, x19
    LA x1, Lhttp_pfx
    mov x2, #7
    bl _strncmp
    mov x21, #0
    mov x22, #7
    cbz w0, 5f
    mov x0, x19
    LA x1, Lhttps_pfx
    mov x2, #8
    bl _strncmp
    cbnz w0, 9f
    mov x21, #1
    mov x22, #8
5:  STG x21, _g_url_https, x9
    add x23, x19, x22            // host start
    ldrb w9, [x23]
    cbz w9, 9f
    cmp w9, #'/'
    b.eq 9f
    // host[:port] up to '/' or end
    mov x24, x23
6:  ldrb w9, [x24]
    cbz w9, 7f
    cmp w9, #'/'
    b.eq 7f
    add x24, x24, #1
    b 6b
7:  // path prefix = [x24, end)
    mov x0, x24
    bl _strdup
    STG x0, _g_url_path, x9
    sub x25, x24, x23            // host:port length
    add x0, x25, #1
    bl _malloc
    mov x26, x0
    mov x1, x23
    mov x2, x25
    bl _memcpy
    strb wzr, [x26, x25]
    // strip userinfo
    mov x0, x26
    mov w1, #'@'
    bl _strrchr
    cbz x0, 71f
    add x26, x0, #1
71: ldrb w9, [x26]
    cmp w9, #'['
    b.ne 75f
    add x26, x26, #1
    mov x0, x26
    mov w1, #']'
    bl _strchr
    cbz x0, 9f
    strb wzr, [x0]
    add x27, x0, #1
    ldrb w9, [x27]
    cbz w9, 78f
    cmp w9, #':'
    b.ne 9f
    add x27, x27, #1
    b 79f
75: mov x0, x26
    mov w1, #':'
    bl _strchr
    cbz x0, 78f
    strb wzr, [x0]
    add x27, x0, #1
    b 79f
78: LA x27, Lport80
    cbz x21, 79f
    LA x27, Lport443
79: STG x26, _g_url_host, x9
    STG x27, _g_url_port, x9
    ldrb w9, [x26]
    cbz w9, 9f
    mov x0, #1
    LEAVE
9:  mov x0, #0
    LEAVE

    .p2align 2
is_space:
    cmp w0, #' '
    b.eq 1f
    sub w9, w0, #9               // \t \n \v \f \r
    cmp w9, #4
    b.ls 1f
    mov x0, #0
    ret
1:  mov x0, #1
    ret

// =============================================================== HTTP in
// serve_conn(w0 = connected socket).
    .p2align 2
serve_conn:
    ENTER 64
    mov w19, w0
    // 10 s receive timeout, no SIGPIPE
    mov x9, #10
    stp x9, xzr, [sp, #16]
    mov w0, w19
    mov w1, #0xffff
    mov w2, #0x1006
    add x3, sp, #16
    mov w4, #16
    bl _setsockopt
    mov w9, #1
    str w9, [sp, #8]
    mov w0, w19
    mov w1, #0xffff
    mov w2, #0x1022
    add x3, sp, #8
    mov w4, #4
    bl _setsockopt
    LA x20, g_req
    str xzr, [x20, #BUF_LEN]
    // read until CRLF CRLF
1:  mov x0, x20
    mov x1, #4096
    bl _buf_reserve
    ldp x9, x10, [x20]
    ldr x11, [x20, #BUF_CAP]
    mov w0, w19
    add x1, x9, x10
    sub x2, x11, x10
    bl _read
    cmp x0, #0
    b.gt 2f
    b.eq 98f
    bl ___error
    ldr w9, [x0]
    cmp w9, #4
    b.eq 1b
    b 98f
2:  ldr x10, [x20, #BUF_LEN]
    add x10, x10, x0
    str x10, [x20, #BUF_LEN]
    ldr x0, [x20, #BUF_PTR]
    mov x1, x10
    bl find_crlfcrlf
    cbnz x0, 3f
    ldr x10, [x20, #BUF_LEN]
    cmp x10, #16, lsl #12        // 64 KiB of headers
    b.hi 97f
    b 1b
3:  mov x21, x0                  // offset of the body
    ldr x22, [x20, #BUF_PTR]
    // request line: METHOD SP TARGET SP VERSION
    mov x23, x22
4:  ldrb w9, [x23]
    cmp w9, #' '
    b.eq 5f
    cmp w9, #'\r'
    b.eq 96f
    add x23, x23, #1
    b 4b
5:  sub x9, x23, x22             // method length
    stp x22, x9, [sp, #32]
    add x23, x23, #1
    mov x24, x23
6:  ldrb w9, [x24]
    cmp w9, #' '
    b.eq 7f
    cmp w9, #'\r'
    b.eq 7f
    add x24, x24, #1
    b 6b
7:  sub x25, x24, x23            // target length
    // headers
    mov x26, #-1                 // Content-Length (-1 = absent)
    mov x27, #0                  // chunked
    mov x0, x22
    bl next_line
    mov x28, x0
8:  ldrb w9, [x28]
    cmp w9, #'\r'
    b.eq 20f
    mov x0, x28
    LA x1, Lh_cl
    mov x2, #15
    bl _strncasecmp
    cbnz w0, 10f
    add x9, x28, #15
    bl skip_sp
    // digits
    mov x26, #0
    mov x11, #0
9:  ldrb w10, [x9], #1
    sub w10, w10, #'0'
    cmp w10, #9
    b.hi 91f
    mov x12, #10
    madd x26, x26, x12, x10
    add x11, x11, #1
    cmp x11, #12
    b.hi 95f
    b 9b
91: cbz x11, 96f
    b 12f
10: mov x0, x28
    LA x1, Lh_te
    mov x2, #18
    bl _strncasecmp
    cbnz w0, 12f
    add x0, x28, #18
    LA x1, Lchunked
    bl line_contains_ci
    orr x27, x27, x0
12: mov x0, x28
    bl next_line
    mov x28, x0
    b 8b

20: // routing
    cmp x25, #1
    b.ne 94f
    ldrb w9, [x23]
    cmp w9, #'/'
    b.ne 94f
    ldp x0, x9, [sp, #32]
    cmp x9, #4
    b.ne 93f
    LA x1, Lpost
    mov x2, #4
    bl _strncmp
    cbnz w0, 93f
    cbnz x27, 30f
    cmn x26, #1
    b.eq 25f
    mov x9, #MAX_BODY
    cmp x26, x9
    b.hi 95f
    // read the rest of the body
21: ldr x10, [x20, #BUF_LEN]
    sub x11, x10, x21
    cmp x11, x26
    b.hs 24f
    mov x0, x20
    sub x1, x26, x11
    bl _buf_reserve
    ldp x9, x10, [x20]
    mov w0, w19
    add x1, x9, x10
    add x2, x21, x26
    sub x2, x2, x10
    bl _read
    cmp x0, #0
    b.gt 22f
    b.eq 98f
    bl ___error
    ldr w9, [x0]
    cmp w9, #4
    b.eq 21b
    b 98f
22: ldr x10, [x20, #BUF_LEN]
    add x10, x10, x0
    str x10, [x20, #BUF_LEN]
    b 21b
24: ldr x0, [x20, #BUF_PTR]
    add x0, x0, x21
    mov x1, x26
    b 40f
25: ldr x0, [x20, #BUF_PTR]
    add x0, x0, x21
    mov x1, #0
    b 40f

30: // chunked: read until the decoder sees the whole body
    LA x0, g_chunk
    str xzr, [x0, #BUF_LEN]
    ldr x0, [x20, #BUF_PTR]
    add x1, x0, x21
    ldr x2, [x20, #BUF_LEN]
    add x2, x0, x2
    LA x3, g_chunk
    bl chunked_decode
    cmp x0, #1
    b.eq 35f
    cmn x0, #2
    b.eq 95f
    cmn x0, #1
    b.eq 96f
    ldr x10, [x20, #BUF_LEN]
    sub x10, x10, x21
    mov x11, #MAX_BODY
    add x11, x11, #16, lsl #12
    cmp x10, x11, lsl #1
    b.hi 95f
    mov x0, x20
    mov x1, #4096
    bl _buf_reserve
    ldp x9, x10, [x20]
    ldr x11, [x20, #BUF_CAP]
    mov w0, w19
    add x1, x9, x10
    sub x2, x11, x10
    bl _read
    cmp x0, #0
    b.gt 31f
    b.eq 98f
    bl ___error
    ldr w9, [x0]
    cmp w9, #4
    b.eq 30b
    b 98f
31: ldr x10, [x20, #BUF_LEN]
    add x10, x10, x0
    str x10, [x20, #BUF_LEN]
    b 30b
35: LA x9, g_chunk
    ldp x0, x1, [x9]

40: bl _rpc_handle
    LA x9, _g_out
    ldr x3, [x9, #BUF_LEN]
    str x3, [sp]
    LA x0, g_hdrbuf
    mov x1, #256
    LA x2, Lresp_fmt
    bl _snprintf
    mov x22, x0
    mov w0, w19
    LA x1, g_hdrbuf
    mov x2, x22
    bl write_all
    LA x9, _g_out
    ldp x1, x2, [x9]
    mov w0, w19
    bl write_all
    LEAVE 64

93: LA x1, Lr405
    b 99f
94: LA x1, Lr404
    b 99f
95: LA x1, Lr413
    b 99f
96: LA x1, Lr400
    b 99f
97: LA x1, Lr431
99: mov x22, x1
    mov x0, x1
    bl _strlen
    mov x2, x0
    mov x1, x22
    mov w0, w19
    bl write_all
98: LEAVE 64

// header line helpers ----------------------------------------------------

// find_crlfcrlf(x0 = buf, x1 = len) -> offset after CRLFCRLF, or 0.
    .p2align 2
find_crlfcrlf:
    mov x9, #0
1:  add x10, x9, #4
    cmp x10, x1
    b.hi 3f
    ldr w11, [x0, x9]
    mov w12, #0x0a0d
    movk w12, #0x0a0d, lsl #16
    cmp w11, w12
    b.eq 2f
    add x9, x9, #1
    b 1b
2:  add x0, x9, #4
    ret
3:  mov x0, #0
    ret

// next_line(x0) -> start of the line after the next CRLF.
    .p2align 2
next_line:
1:  ldrb w9, [x0], #1
    cmp w9, #'\n'
    b.ne 1b
    ret

// skip_sp(x9) -> x9 past spaces and tabs.
    .p2align 2
skip_sp:
1:  ldrb w10, [x9]
    cmp w10, #' '
    b.eq 2f
    cmp w10, #'\t'
    b.ne 3f
2:  add x9, x9, #1
    b 1b
3:  ret

// line_contains_ci(x0 = line, x1 = lowercase word) -> 1 if found before CR.
    .p2align 2
line_contains_ci:
    mov x9, x0
1:  ldrb w10, [x9]
    cmp w10, #'\r'
    b.eq 8f
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

// chunked_decode(x0 = unused, x1 = start, x2 = end, x3 = out Buf)
// -> 1 complete, 0 need more, -1 malformed, -2 too large.
    .p2align 2
chunked_decode:
    ENTER
    mov x19, x1
    mov x20, x2
    mov x21, x3
    str xzr, [x21, #BUF_LEN]
1:  mov x22, #0                  // chunk size
    mov x23, #0                  // digits
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
    cmp x23, #8
    b.hi 82f
    add x19, x19, #1
    b 2b
4:  cbz x23, 81f
    // skip to LF (extensions)
5:  cmp x19, x20
    b.hs 80f
    ldrb w9, [x19], #1
    cmp w9, #'\n'
    b.ne 5b
    cbz x22, 10f
    add x9, x19, x22
    add x9, x9, #2
    cmp x9, x20
    b.hi 80f
    ldr x10, [x21, #BUF_LEN]
    add x10, x10, x22
    mov x11, #MAX_BODY
    cmp x10, x11
    b.hi 82f
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
10: // trailers until an empty line
    cmp x19, x20
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

// write_all(w0 = fd, x1 = ptr, x2 = len).
    .p2align 2
write_all:
    ENTER
    mov w19, w0
    mov x20, x1
    mov x21, x2
1:  cbz x21, 9f
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
    b 9f
2:  add x20, x20, x0
    sub x21, x21, x0
    b 1b
9:  LEAVE

    .section __TEXT,__cstring
Lenv_bind:    .asciz "ONLYBLOCKS_BIND"
Lenv_base:    .asciz "OLD_FAITHFUL_BASE_URL"
Ldef_bind:    .asciz "127.0.0.1:8899"
Ldef_base:    .asciz "https://files.old-faithful.net"
Lopt_bind_eq: .asciz "--bind="
Lopt_base_eq: .asciz "--base-url="
Lopt_bind:    .asciz "--bind"
Lopt_base:    .asciz "--base-url"
Lusage:       .asciz "usage: onlyblocks [--bind HOST:PORT] [--base-url URL]\n"
Lbad_base:    .asciz "onlyblocks: --base-url must be an http:// or https:// URL\n"
Lbad_bind:    .asciz "onlyblocks: --bind must be IPV4:PORT\n"
Llisten_fail: .asciz "onlyblocks: cannot listen on the bind address\n"
Llocalhost:   .asciz "localhost"
Lhttp_pfx:    .asciz "http://"
Lhttps_pfx:   .asciz "https://"
Lport80:      .asciz "80"
Lport443:     .asciz "443"
Lh_cl:        .asciz "content-length:"
Lh_te:        .asciz "transfer-encoding:"
Lchunked:     .asciz "chunked"
Lpost:        .asciz "POST"
Lresp_fmt:    .asciz "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %llu\r\nConnection: close\r\n\r\n"
Lr400:        .asciz "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
Lr404:        .asciz "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
Lr405:        .asciz "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
Lr413:        .asciz "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
Lr431:        .asciz "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

    .data
    .p2align 3
    .globl _g_url, _g_url_https, _g_url_host, _g_url_port, _g_url_path
_g_url:       .quad 0
_g_url_https: .quad 0
_g_url_host:  .quad 0
_g_url_port:  .quad 0
_g_url_path:  .quad 0
g_req:        .quad 0, 0, 0, 0
g_chunk:      .quad 0, 0, 0, 0
g_hdrbuf:     .space 256
