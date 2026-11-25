// json.s: RFC 8259 request parser. Builds JN_* nodes in the arena; any
// syntax error (or nesting deeper than 128) throws -32700. Strings keep
// their raw source text (for echoing ids) and a decoded copy (for compares).

.include "defs.s"

    .text

// json_parse(x0 = text, x1 = len) -> x0 = root node.
FN _json_parse
    ENTER
    STG x0, g_jpos, x9
    add x1, x0, x1
    STG x1, g_jend, x9
    mov x0, #1
    bl json_value
    mov x19, x0
    bl json_ws
    LDG x9, g_jpos
    LDG x10, g_jend
    cmp x9, x10
    b.ne json_bad
    mov x0, x19
    LEAVE

json_bad:
    LA x1, Lparse_msg
    mov x0, #ERR_PARSE
    bl _ob_throw

// json_ws: skip whitespace; returns x0 = next byte or -1 at end.
    .p2align 2
json_ws:
    LDG x9, g_jpos
    LDG x10, g_jend
1:  cmp x9, x10
    b.hs 3f
    ldrb w0, [x9]
    cmp w0, #' '
    b.eq 2f
    cmp w0, #'\t'
    b.eq 2f
    cmp w0, #'\n'
    b.eq 2f
    cmp w0, #'\r'
    b.ne 4f
2:  add x9, x9, #1
    b 1b
3:  mov x0, #-1
4:  STG x9, g_jpos, x11
    ret

// new node of type x0 -> x0
    .p2align 2
json_node:
    ENTER
    mov x19, x0
    mov x0, #JN_SIZE
    bl _arena_alloc
    strb w19, [x0, #JN_TYPE]
    LEAVE

// json_value(x0 = depth) -> x0 = node
    .p2align 2
json_value:
    ENTER
    mov x19, x0
    cmp x19, #128
    b.hi json_bad
    bl json_ws
    cmp x0, #'{'
    b.eq 10f
    cmp x0, #'['
    b.eq 20f
    cmp x0, #34
    b.eq 30f
    cmp x0, #'t'
    b.eq 40f
    cmp x0, #'f'
    b.eq 41f
    cmp x0, #'n'
    b.eq 42f
    cmp x0, #'-'
    b.eq 50f
    sub x9, x0, #'0'
    cmp x9, #9
    b.ls 50f
    b json_bad

10: // object
    mov x0, #JT_OBJECT
    bl json_node
    mov x20, x0
    mov x21, #0                  // tail
    LDG x9, g_jpos
    add x9, x9, #1
    STG x9, g_jpos, x10
    bl json_ws
    cmp x0, #'}'
    b.eq 19f
11: bl json_ws
    cmp x0, #34
    b.ne json_bad
    bl json_string
    mov x22, x0                  // key node
    bl json_ws
    cmp x0, #':'
    b.ne json_bad
    LDG x9, g_jpos
    add x9, x9, #1
    STG x9, g_jpos, x10
    add x0, x19, #1
    bl json_value
    ldp x9, x10, [x22, #JN_STR]
    stp x9, x10, [x0, #JN_KEY]
    cbz x21, 12f
    str x0, [x21, #JN_NEXT]
    b 13f
12: str x0, [x20, #JN_FIRST]
13: mov x21, x0
    ldr w9, [x20, #JN_COUNT]
    add w9, w9, #1
    str w9, [x20, #JN_COUNT]
    bl json_ws
    LDG x9, g_jpos
    add x9, x9, #1
    STG x9, g_jpos, x10
    cmp x0, #','
    b.eq 11b
    cmp x0, #'}'
    b.ne json_bad
    mov x0, x20
    LEAVE
19: LDG x9, g_jpos
    add x9, x9, #1
    STG x9, g_jpos, x10
    mov x0, x20
    LEAVE

20: // array
    mov x0, #JT_ARRAY
    bl json_node
    mov x20, x0
    mov x21, #0
    LDG x9, g_jpos
    add x9, x9, #1
    STG x9, g_jpos, x10
    bl json_ws
    cmp x0, #']'
    b.eq 19b
21: add x0, x19, #1
    bl json_value
    cbz x21, 22f
    str x0, [x21, #JN_NEXT]
    b 23f
22: str x0, [x20, #JN_FIRST]
23: mov x21, x0
    ldr w9, [x20, #JN_COUNT]
    add w9, w9, #1
    str w9, [x20, #JN_COUNT]
    bl json_ws
    LDG x9, g_jpos
    add x9, x9, #1
    STG x9, g_jpos, x10
    cmp x0, #','
    b.eq 21b
    cmp x0, #']'
    b.ne json_bad
    mov x0, x20
    LEAVE

30: bl json_string
    LEAVE

40: LA x20, Ltrue_lit
    mov x21, #JT_TRUE
    b 43f
41: LA x20, Lfalse_lit
    mov x21, #JT_FALSE
    b 43f
42: LA x20, Lnull_lit
    mov x21, #JT_NULL
43: LDG x9, g_jpos
    LDG x10, g_jend
44: ldrb w11, [x20], #1
    cbz w11, 45f
    cmp x9, x10
    b.hs json_bad
    ldrb w12, [x9], #1
    cmp w11, w12
    b.ne json_bad
    b 44b
45: STG x9, g_jpos, x11
    mov x0, x21
    bl json_node
    LEAVE

50: // number: -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?
    LDG x20, g_jpos
    mov x21, x20
    LDG x22, g_jend
    ldrb w9, [x21]
    cmp w9, #'-'
    b.ne 51f
    add x21, x21, #1
51: cmp x21, x22
    b.hs json_bad
    ldrb w9, [x21]
    cmp w9, #'0'
    b.ne 52f
    add x21, x21, #1
    b 54f
52: sub w9, w9, #'1'
    cmp w9, #8
    b.hi json_bad
53: add x21, x21, #1
    cmp x21, x22
    b.hs 54f
    ldrb w9, [x21]
    sub w9, w9, #'0'
    cmp w9, #9
    b.ls 53b
54: cmp x21, x22
    b.hs 59f
    ldrb w9, [x21]
    cmp w9, #'.'
    b.ne 56f
    add x21, x21, #1
    bl 60f
55: cmp x21, x22
    b.hs 59f
    ldrb w9, [x21]
56: cmp w9, #'e'
    b.eq 57f
    cmp w9, #'E'
    b.ne 59f
57: add x21, x21, #1
    cmp x21, x22
    b.hs json_bad
    ldrb w9, [x21]
    cmp w9, #'+'
    b.eq 58f
    cmp w9, #'-'
    b.ne 581f
58: add x21, x21, #1
581: bl 60f
59: STG x21, g_jpos, x9
    mov x0, #JT_NUMBER
    bl json_node
    str x20, [x0, #JN_RAW]
    sub x9, x21, x20
    str x9, [x0, #JN_RAWLEN]
    LEAVE
60: // one or more digits at x21 (local subroutine; x22 = end)
    cmp x21, x22
    b.hs json_bad
    ldrb w9, [x21]
    sub w9, w9, #'0'
    cmp w9, #9
    b.hi json_bad
61: add x21, x21, #1
    cmp x21, x22
    b.hs 62f
    ldrb w9, [x21]
    sub w9, w9, #'0'
    cmp w9, #9
    b.ls 61b
62: ret

// json_string: parse the string at g_jpos -> x0 = string node.
    .p2align 2
json_string:
    ENTER
    LDG x19, g_jpos              // opening quote
    LDG x20, g_jend
    add x21, x19, #1
    // find the closing quote, rejecting raw control characters
1:  cmp x21, x20
    b.hs json_bad
    ldrb w9, [x21]
    cmp w9, #0x20
    b.lo json_bad
    cmp w9, #34
    b.eq 3f
    cmp w9, #92
    b.ne 2f
    add x21, x21, #1
    cmp x21, x20
    b.hs json_bad
    ldrb w9, [x21]
    cmp w9, #0x20
    b.lo json_bad
2:  add x21, x21, #1
    b 1b
3:  add x21, x21, #1             // past the closing quote
    STG x21, g_jpos, x9
    mov x0, #JT_STRING
    bl json_node
    mov x22, x0
    str x19, [x22, #JN_RAW]
    sub x9, x21, x19
    str x9, [x22, #JN_RAWLEN]
    sub x0, x9, #1
    bl _arena_alloc
    mov x23, x0                  // decoded output
    mov x24, x0
    add x19, x19, #1
    sub x20, x21, #1             // closing quote
4:  cmp x19, x20
    b.hs 9f
    ldrb w9, [x19], #1
    cmp w9, #92
    b.eq 5f
    strb w9, [x24], #1
    b 4b
5:  ldrb w9, [x19], #1
    LA x10, Lesc_from
    LA x11, Lesc_to
    mov x12, #0
6:  ldrb w13, [x10, x12]
    cbz w13, 7f
    cmp w13, w9
    b.eq 61f
    add x12, x12, #1
    b 6b
61: ldrb w13, [x11, x12]
    strb w13, [x24], #1
    b 4b
7:  cmp w9, #'u'
    b.ne json_bad
    bl json_hex4
    mov x25, x0
    // high surrogate followed by \uDC00..DFFF combines
    lsr x9, x25, #10
    cmp x9, #0x36
    b.ne 8f
    add x9, x19, #6
    cmp x9, x20
    b.hi 8f
    ldrb w9, [x19]
    cmp w9, #92
    b.ne 8f
    ldrb w9, [x19, #1]
    cmp w9, #'u'
    b.ne 8f
    mov x26, x19
    add x19, x19, #2
    bl json_hex4
    lsr x9, x0, #10
    cmp x9, #0x37
    b.ne 71f
    and x25, x25, #0x3ff
    and x0, x0, #0x3ff
    add x25, x0, x25, lsl #10
    add x25, x25, #0x10, lsl #12
    b 8f
71: mov x19, x26
8:  mov x0, x25
    bl json_utf8_put
    b 4b
9:  str x23, [x22, #JN_STR]
    sub x9, x24, x23
    str x9, [x22, #JN_STRLEN]
    mov x0, x22
    LEAVE

// json_hex4: 4 hex digits at x19 (bounded by x20) -> x0; advances x19.
    .p2align 2
json_hex4:
    mov x0, #0
    mov x12, #4
1:  cmp x19, x20
    b.hs json_bad
    ldrb w9, [x19], #1
    sub w10, w9, #'0'
    cmp w10, #9
    b.ls 2f
    orr w9, w9, #0x20
    sub w10, w9, #'a'
    cmp w10, #5
    b.hi json_bad
    add w10, w10, #10
2:  add x0, x10, x0, lsl #4
    subs x12, x12, #1
    b.ne 1b
    ret

// json_utf8_put: code point x0 -> UTF-8 at x24 (advances x24). U+0000 is
// stored as 0x01 (decoded strings are only ever compared).
    .p2align 2
json_utf8_put:
    cbnz x0, 1f
    mov x0, #1
1:  cmp x0, #0x80
    b.hs 2f
    strb w0, [x24], #1
    ret
2:  cmp x0, #0x800
    b.hs 3f
    lsr x9, x0, #6
    orr w9, w9, #0xc0
    strb w9, [x24], #1
    b 9f
3:  cmp x0, #0x10000
    b.hs 4f
    lsr x9, x0, #12
    orr w9, w9, #0xe0
    strb w9, [x24], #1
    b 8f
4:  lsr x9, x0, #18
    orr w9, w9, #0xf0
    strb w9, [x24], #1
    ubfx x9, x0, #12, #6
    orr w9, w9, #0x80
    strb w9, [x24], #1
8:  ubfx x9, x0, #6, #6
    orr w9, w9, #0x80
    strb w9, [x24], #1
9:  and x9, x0, #0x3f
    orr w9, w9, #0x80
    strb w9, [x24], #1
    ret

// json_get(x0 = object, x1 = C string key) -> x0 = last matching child or 0.
FN _json_get
    ENTER
    mov x19, x0
    mov x20, x1
    mov x21, #0
    cbz x19, 9f
    ldrb w9, [x19, #JN_TYPE]
    cmp w9, #JT_OBJECT
    b.ne 9f
    mov x0, x20
    bl _strlen
    mov x22, x0
    ldr x23, [x19, #JN_FIRST]
1:  cbz x23, 9f
    ldr x9, [x23, #JN_KEYLEN]
    cmp x9, x22
    b.ne 2f
    ldr x0, [x23, #JN_KEY]
    mov x1, x20
    mov x2, x22
    bl _memcmp
    cbnz w0, 2f
    mov x21, x23
2:  ldr x23, [x23, #JN_NEXT]
    b 1b
9:  mov x0, x21
    LEAVE

// json_val(x0 = object, x1 = key): like json_get, but null counts as absent.
FN _json_val
    ENTER
    bl _json_get
    cbz x0, 1f
    ldrb w9, [x0, #JN_TYPE]
    cmp w9, #JT_NULL
    csel x0, xzr, x0, eq
1:  LEAVE

// json_str_is(x0 = node, x1 = C string) -> 1 when node is that string.
FN _json_str_is
    ENTER
    mov x19, x0
    mov x20, x1
    mov x21, #0
    cbz x19, 9f
    ldrb w9, [x19, #JN_TYPE]
    cmp w9, #JT_STRING
    b.ne 9f
    mov x0, x20
    bl _strlen
    ldr x9, [x19, #JN_STRLEN]
    cmp x0, x9
    b.ne 9f
    mov x2, x0
    ldr x0, [x19, #JN_STR]
    mov x1, x20
    bl _memcmp
    cmp w0, #0
    cset x21, eq
9:  mov x0, x21
    LEAVE

// json_uint(x0 = node, x1 = max) -> x0 = value, x1 = 1 if node is an integer
// literal (0|[1-9][0-9]*) whose value fits in 0..max.
FN _json_uint
    mov x10, #0
    cbz x0, 9f
    ldrb w9, [x0, #JN_TYPE]
    cmp w9, #JT_NUMBER
    b.ne 9f
    ldr x11, [x0, #JN_RAW]
    ldr x12, [x0, #JN_RAWLEN]
    add x12, x11, x12
    ldrb w9, [x11]
    cmp w9, #'0'
    b.ne 1f
    add x13, x11, #1
    cmp x13, x12
    b.ne 9f
1:  mov x13, #10
2:  cmp x11, x12
    b.hs 3f
    ldrb w9, [x11], #1
    sub w9, w9, #'0'
    cmp w9, #9
    b.hi 9f
    umulh x14, x10, x13
    cbnz x14, 9f
    mul x10, x10, x13
    adds x10, x10, x9
    b.cs 9f
    b 2b
3:  cmp x10, x1
    b.hi 9f
    mov x0, x10
    mov x1, #1
    ret
9:  mov x0, #0
    mov x1, #0
    ret

    .section __TEXT,__cstring
Lparse_msg: .asciz "Parse error"
Ltrue_lit:  .asciz "true"
Lfalse_lit: .asciz "false"
Lnull_lit:  .asciz "null"
Lesc_from:  .asciz "\"\\/bfnrt"
Lesc_to:    .byte 34, 92, 47, 8, 12, 10, 13, 9, 0

    .data
    .p2align 3
g_jpos: .quad 0
g_jend: .quad 0
