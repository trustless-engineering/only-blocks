// util.s: try/throw unwinding, the request arena, growable buffers, the
// response output buffer and its formatters (decimal, Base58, Base64, JSON
// strings, doubles), Base58 decoding and UTF-8 validation.

.include "defs.s"

    .text

// ===================================================================== try
// _ob_try(x0 = jump buffer) returns 0, then returns again with the thrown
// (non-zero) code when _ob_throw unwinds to it. Like setjmp: the function
// that called _ob_try must still be active when the throw happens.

FN _ob_try
    stp x19, x20, [x0]
    stp x21, x22, [x0, #16]
    stp x23, x24, [x0, #32]
    stp x25, x26, [x0, #48]
    stp x27, x28, [x0, #64]
    stp x29, x30, [x0, #80]
    mov x9, sp
    adrp x10, _g_trytop@PAGE
    ldr x11, [x10, _g_trytop@PAGEOFF]
    stp x9, x11, [x0, #96]
    str x0, [x10, _g_trytop@PAGEOFF]
    mov x0, #0
    ret

// _ob_untry(x0 = jump buffer): leave a try block normally.
FN _ob_untry
    ldr x11, [x0, #104]
    adrp x10, _g_trytop@PAGE
    str x11, [x10, _g_trytop@PAGEOFF]
    ret

// _ob_throw(x0 = code, x1 = message): unwind to the innermost try.
FN _ob_throw
    cbnz x0, 1f
    movn x0, #32602
1:  adrp x10, _g_err_code@PAGE
    str x0, [x10, _g_err_code@PAGEOFF]
    adrp x10, _g_err_msg@PAGE
    str x1, [x10, _g_err_msg@PAGEOFF]
    mov x2, x0
    adrp x10, _g_trytop@PAGE
    ldr x9, [x10, _g_trytop@PAGEOFF]
    cbz x9, 2f
    ldp x12, x11, [x9, #96]
    str x11, [x10, _g_trytop@PAGEOFF]
    ldp x19, x20, [x9]
    ldp x21, x22, [x9, #16]
    ldp x23, x24, [x9, #32]
    ldp x25, x26, [x9, #48]
    ldp x27, x28, [x9, #64]
    ldp x29, x30, [x9, #80]
    mov sp, x12
    mov x0, x2
    ret
2:  bl _abort

// =================================================================== arena
// Request-scoped, zero-filled, 16-byte aligned allocations. Chunk header:
// next, used, cap, pad; data starts at +32. arena_reset frees everything,
// including the storage of every Buf created with buf_new.

.equ ARENA_CHUNK, 0x100000

FN _arena_alloc
    ENTER
    add x19, x0, #15
    and x19, x19, #~15
    LDG x20, _g_arena
    cbz x20, 3f
    ldp x21, x22, [x20, #8]
    add x23, x21, x19
    cmp x23, x22
    b.hi 3f
    str x23, [x20, #8]
    add x0, x20, #32
    add x0, x0, x21
    LEAVE
3:  cmp x19, #64, lsl #12
    b.hi 4f
    mov x0, #1
    mov x1, #ARENA_CHUNK
    add x1, x1, #32
    bl _calloc
    cbz x0, 5f
    str x20, [x0]
    str x19, [x0, #8]
    mov x1, #ARENA_CHUNK
    str x1, [x0, #16]
    STG x0, _g_arena, x9
    add x0, x0, #32
    LEAVE
4:  mov x0, #1
    add x1, x19, #32
    bl _calloc
    cbz x0, 5f
    LDG x1, _g_arena_big
    str x1, [x0]
    STG x0, _g_arena_big, x9
    add x0, x0, #32
    LEAVE
5:  FAIL "Out of memory"

FN _arena_reset
    ENTER
    LDG x19, _g_bufs
1:  cbz x19, 2f
    ldr x0, [x19, #BUF_PTR]
    ldr x19, [x19, #BUF_NEXT]
    bl _free
    b 1b
2:  STG xzr, _g_bufs, x9
    LDG x19, _g_arena
3:  cbz x19, 4f
    mov x0, x19
    ldr x19, [x19]
    bl _free
    b 3b
4:  STG xzr, _g_arena, x9
    LDG x19, _g_arena_big
5:  cbz x19, 6f
    mov x0, x19
    ldr x19, [x19]
    bl _free
    b 5b
6:  STG xzr, _g_arena_big, x9
    LEAVE

// ===================================================================== Buf

// buf_new() -> x0 = empty Buf (arena header, storage freed by arena_reset).
FN _buf_new
    ENTER
    mov x0, #BUF_SIZE
    bl _arena_alloc
    LDG x1, _g_bufs
    str x1, [x0, #BUF_NEXT]
    STG x0, _g_bufs, x9
    LEAVE

// buf_reserve(x0 = Buf, x1 = extra) -> x0 = Buf.
FN _buf_reserve
    ENTER
    mov x19, x0
    ldp x20, x21, [x19, #BUF_LEN]
    adds x22, x20, x1
    b.cs 2f
    cmp x22, x21
    b.ls 1f
    lsl x23, x21, #1
    cmp x23, x22
    csel x23, x22, x23, lo
    mov x9, #4096
    cmp x23, x9
    csel x23, x9, x23, lo
    ldr x0, [x19, #BUF_PTR]
    mov x1, x23
    bl _realloc
    cbz x0, 2f
    str x0, [x19, #BUF_PTR]
    str x23, [x19, #BUF_CAP]
1:  mov x0, x19
    LEAVE
2:  FAIL "Out of memory"

// buf_append(x0 = Buf, x1 = ptr, x2 = len).
FN _buf_append
    ENTER
    mov x19, x0
    mov x20, x1
    mov x21, x2
    cbz x21, 1f
    mov x1, x2
    bl _buf_reserve
    ldp x0, x9, [x19]
    add x0, x0, x9
    mov x1, x20
    mov x2, x21
    bl _memcpy
    ldr x9, [x19, #BUF_LEN]
    add x9, x9, x21
    str x9, [x19, #BUF_LEN]
1:  LEAVE

// buf_byte(x0 = Buf, w1 = byte).
FN _buf_byte
    ENTER
    mov x19, x0
    mov x20, x1
    mov x1, #1
    bl _buf_reserve
    ldp x9, x10, [x19]
    strb w20, [x9, x10]
    add x10, x10, #1
    str x10, [x19, #BUF_LEN]
    LEAVE

// ================================================================= vectors
// vec_push(x0 = vec header, x1 = element size) -> x0 = new zeroed element.

FN _vec_push
    ENTER
    mov x19, x0
    mov x20, x1
    ldp x21, x22, [x19, #VEC_N]
    cmp x21, x22
    b.lo 1f
    lsl x23, x22, #1
    cmp x23, #4
    mov x9, #4
    csel x23, x9, x23, lo
    mul x0, x23, x20
    bl _arena_alloc
    mov x24, x0
    ldr x1, [x19, #VEC_PTR]
    mul x2, x21, x20
    cbz x2, 2f
    bl _memcpy
2:  str x24, [x19, #VEC_PTR]
    str x23, [x19, #VEC_CAP]
1:  ldr x9, [x19, #VEC_PTR]
    madd x0, x21, x20, x9
    add x21, x21, #1
    str x21, [x19, #VEC_N]
    LEAVE

// ================================================================== output
// All JSON is written to the global Buf _g_out.

FN _out_reserve
    mov x1, x0
    LA x0, _g_out
    b _buf_reserve

FN _out_byte
    mov x1, x0
    LA x0, _g_out
    b _buf_byte

FN _out_mem
    mov x2, x1
    mov x1, x0
    LA x0, _g_out
    b _buf_append

FN _out_cstr
    ENTER
    mov x19, x0
    bl _strlen
    mov x1, x0
    mov x0, x19
    bl _out_mem
    LEAVE

FN _out_u64
    ENTER 32
    mov x19, x0
    add x20, sp, #32
    mov x21, x20
    mov x9, #10
1:  udiv x10, x19, x9
    msub x11, x10, x9, x19
    add w11, w11, #'0'
    strb w11, [x21, #-1]!
    mov x19, x10
    cbnz x19, 1b
    mov x0, x21
    sub x1, x20, x21
    bl _out_mem
    LEAVE 32

FN _out_i64
    ENTER
    mov x19, x0
    tbz x19, #63, 1f
    mov x0, #'-'
    bl _out_byte
    neg x19, x19
1:  mov x0, x19
    bl _out_u64
    LEAVE

// out_bool(x0): true / false.
FN _out_bool
    LA x9, Ltrue
    LA x10, Lfalse
    cmp x0, #0
    csel x0, x10, x9, eq
    b _out_cstr

// out_jstr(x0 = ptr, x1 = len): a quoted JSON string (raw UTF-8 kept).
FN _out_jstr
    ENTER
    mov x19, x0
    mov x20, x1
    mov x0, #34
    bl _out_byte
    mov x0, x19
    mov x1, x20
    bl _out_jesc
    mov x0, #34
    bl _out_byte
    LEAVE

// out_jesc(x0 = ptr, x1 = len): JSON string escaping without the quotes.
FN _out_jesc
    ENTER 16
    mov x19, x0
    add x20, x0, x1
1:  mov x21, x19
2:  cmp x19, x20
    b.hs 3f
    ldrb w22, [x19]
    cmp w22, #34
    b.eq 3f
    cmp w22, #92
    b.eq 3f
    cmp w22, #0x20
    b.lo 3f
    add x19, x19, #1
    b 2b
3:  sub x1, x19, x21
    cbz x1, 4f
    mov x0, x21
    bl _out_mem
4:  cmp x19, x20
    b.hs 9f
    ldrb w22, [x19], #1
    mov x0, #92
    bl _out_byte
    cmp w22, #0x20
    b.hs 6f
    LA x9, Lshortesc
    ldrb w0, [x9, x22]
    cbz w0, 5f
    bl _out_byte
    b 1b
5:  mov w9, #'u'
    strb w9, [sp]
    mov w9, #'0'
    strb w9, [sp, #1]
    strb w9, [sp, #2]
    LA x9, Lhexdigits
    lsr w10, w22, #4
    ldrb w10, [x9, x10]
    strb w10, [sp, #3]
    and w10, w22, #15
    ldrb w10, [x9, x10]
    strb w10, [sp, #4]
    mov x0, sp
    mov x1, #5
    bl _out_mem
    b 1b
6:  mov x0, x22
    bl _out_byte
    b 1b
9:  LEAVE 16

// out_b58(x0 = ptr, x1 = len): Bitcoin-alphabet Base58 (no quotes). Works on
// base-58^9 limbs so each step is one 64-bit multiply-add and divide.
.equ B58_LIMB, 7427658739644928      // 58^9

FN _out_b58
    ENTER 48
    mov x19, x0
    mov x20, x1
    mov x21, #0                  // leading zero bytes
1:  cmp x21, x20
    b.hs 2f
    ldrb w9, [x19, x21]
    cbnz w9, 2f
    add x21, x21, #1
    b 1b
2:  // limbs: at most len * 138 / 100 / 9 + 2
    sub x9, x20, x21
    mov x10, #138
    mul x9, x9, x10
    mov x10, #900
    udiv x9, x9, x10
    add x9, x9, #2
    lsl x0, x9, #3
    bl _arena_alloc
    mov x22, x0                  // limbs
    mov x23, #0                  // limb count
    MOV64 x24, B58_LIMB
    mov x25, x21
3:  cmp x25, x20
    b.hs 6f
    ldrb w26, [x19, x25]         // carry
    add x25, x25, #1
    mov x27, #0
4:  cmp x27, x23
    b.hs 5f
    ldr x9, [x22, x27, lsl #3]
    lsl x9, x9, #8
    add x9, x9, x26
    udiv x26, x9, x24
    msub x9, x26, x24, x9
    str x9, [x22, x27, lsl #3]
    add x27, x27, #1
    b 4b
5:  cbz x26, 3b
    udiv x9, x26, x24
    msub x10, x9, x24, x26
    str x10, [x22, x23, lsl #3]
    add x23, x23, #1
    mov x26, x9
    b 5b
6:  // leading '1's
    cbz x21, 7f
    mov x0, #'1'
    bl _out_byte
    sub x21, x21, #1
    b 6b
7:  cbz x23, 9f
    sub x23, x23, #1
    ldr x0, [x22, x23, lsl #3]
    mov x1, #0                   // top limb: no leading zero digits
    bl b58_limb
8:  cbz x23, 9f
    sub x23, x23, #1
    ldr x0, [x22, x23, lsl #3]
    mov x1, #1
    bl b58_limb
    b 8b
9:  LEAVE 48

// b58_limb(x0 = limb, x1 = pad to 9 digits?)
    .p2align 2
b58_limb:
    ENTER 16
    mov x19, x1
    add x20, sp, #16
    mov x21, x20
    mov x9, #58
    LA x12, Lb58alpha
    mov x13, #9
1:  udiv x10, x0, x9
    msub x11, x10, x9, x0
    ldrb w11, [x12, x11]
    strb w11, [x21, #-1]!
    mov x0, x10
    sub x13, x13, #1
    cbnz x19, 2f
    cbz x0, 3f
2:  cbnz x13, 1b
3:  mov x0, x21
    sub x1, x20, x21
    bl _out_mem
    LEAVE 16

// out_b64(x0 = ptr, x1 = len): RFC 4648 Base64 with padding (no quotes).
FN _out_b64
    ENTER 16
    mov x19, x0
    mov x20, x1
    LA x21, Lb64alpha
1:  cmp x20, #3
    b.lo 2f
    ldrb w9, [x19]
    ldrb w10, [x19, #1]
    ldrb w11, [x19, #2]
    add x19, x19, #3
    sub x20, x20, #3
    orr w9, w11, w9, lsl #16
    orr w9, w9, w10, lsl #8
    bl b64_quad
    b 1b
2:  cbz x20, 9f
    ldrb w9, [x19]
    lsl w9, w9, #16
    cmp x20, #2
    b.ne 3f
    ldrb w10, [x19, #1]
    orr w9, w9, w10, lsl #8
3:  bl b64_quad
    // overwrite the tail with '='
    LA x9, _g_out
    ldr x10, [x9, #BUF_PTR]
    ldr x11, [x9, #BUF_LEN]
    add x10, x10, x11
    mov w12, #'='
    strb w12, [x10, #-1]
    cmp x20, #1
    b.ne 9f
    strb w12, [x10, #-2]
9:  LEAVE 16

// b64_quad: w9 = 24-bit group, x21 = alphabet -> 4 characters.
    .p2align 2
b64_quad:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    lsr w10, w9, #18
    ldrb w10, [x21, x10]
    strb w10, [sp, #16]
    ubfx w10, w9, #12, #6
    ldrb w10, [x21, x10]
    strb w10, [sp, #17]
    ubfx w10, w9, #6, #6
    ldrb w10, [x21, x10]
    strb w10, [sp, #18]
    and w10, w9, #63
    ldrb w10, [x21, x10]
    strb w10, [sp, #19]
    add x0, sp, #16
    mov x1, #4
    bl _out_mem
    ldp x29, x30, [sp], #32
    ret

// out_f64(d0): shortest-enough round-trip text via %.17g; NaN/Inf -> null.
FN _out_f64
    ENTER 64
    fabs d1, d0
    fcmp d1, d1
    b.vs 1f
    mov x9, #0x7ff0000000000000
    fmov d2, x9
    fcmp d1, d2
    b.eq 1f
    str d0, [sp]
    add x0, sp, #16
    mov x1, #40
    LA x2, Lfmt17g
    bl _snprintf
    add x0, sp, #16
    bl _out_cstr
    LEAVE 64
1:  LA x0, Lnull
    bl _out_cstr
    LEAVE 64

// out_fmt(x0 = format, x1..x7 = arguments). Directives:
//   %u u64  %d i64  %s C string  %c byte  %b bool  %% percent
//   %S JSON string (ptr, len)   %B quoted Base58 (ptr, len)
//   %K quoted Base58 of a 32-byte key (ptr)   %G of a 64-byte signature (ptr)
//   %Y quoted Base64 (ptr, len)
FN _out_fmt
    ENTER 64
    stp x1, x2, [sp]
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    str x7, [sp, #48]
    mov x19, x0
    mov x20, sp
1:  mov x21, x19
2:  ldrb w9, [x19]
    cbz w9, 3f
    cmp w9, #'%'
    b.eq 3f
    add x19, x19, #1
    b 2b
3:  sub x1, x19, x21
    cbz x1, 4f
    mov x0, x21
    bl _out_mem
4:  ldrb w9, [x19]
    cbz w9, 99f
    ldrb w22, [x19, #1]
    add x19, x19, #2
    cmp w22, #'u'
    b.ne 5f
    ldr x0, [x20], #8
    bl _out_u64
    b 1b
5:  cmp w22, #'d'
    b.ne 6f
    ldr x0, [x20], #8
    bl _out_i64
    b 1b
6:  cmp w22, #'s'
    b.ne 7f
    ldr x0, [x20], #8
    bl _out_cstr
    b 1b
7:  cmp w22, #'c'
    b.ne 8f
    ldr x0, [x20], #8
    bl _out_byte
    b 1b
8:  cmp w22, #'b'
    b.ne 10f
    ldr x0, [x20], #8
    bl _out_bool
    b 1b
10: cmp w22, #'S'
    b.ne 11f
    ldp x0, x1, [x20], #16
    bl _out_jstr
    b 1b
11: cmp w22, #'B'
    b.ne 12f
    ldp x23, x24, [x20], #16
    b 20f
12: cmp w22, #'K'
    b.ne 13f
    ldr x23, [x20], #8
    mov x24, #32
    b 20f
13: cmp w22, #'G'
    b.ne 14f
    ldr x23, [x20], #8
    mov x24, #64
    b 20f
14: cmp w22, #'Y'
    b.ne 15f
    ldp x23, x24, [x20], #16
    mov x0, #34
    bl _out_byte
    mov x0, x23
    mov x1, x24
    bl _out_b64
    mov x0, #34
    bl _out_byte
    b 1b
15: mov x0, x22
    bl _out_byte
    b 1b
20: mov x0, #34
    bl _out_byte
    mov x0, x23
    mov x1, x24
    bl _out_b58
    mov x0, #34
    bl _out_byte
    b 1b
99: LEAVE 64

// ================================================================== Base58
// b58_decode32(x0 = C string, x1 = 32-byte output): 0 on failure.
FN _b58_decode32
    ENTER
    mov x19, x0
    mov x20, x1
    mov x0, x20
    mov x1, #0
    mov x2, #32
    bl _memset
    LA x21, Lb58alpha
1:  ldrb w22, [x19], #1
    cbz w22, 8f
    mov x23, #0
2:  cmp x23, #58
    b.hs 9f
    ldrb w9, [x21, x23]
    cmp w9, w22
    b.eq 3f
    add x23, x23, #1
    b 2b
3:  mov x10, #31                 // carry = digit; out = out * 58 + carry
4:  ldrb w9, [x20, x10]
    mov x11, #58
    madd x23, x9, x11, x23
    strb w23, [x20, x10]
    lsr x23, x23, #8
    subs x10, x10, #1
    b.pl 4b
    cbnz x23, 9f
    b 1b
8:  mov x0, #1
    LEAVE
9:  mov x0, #0
    LEAVE

// ================================================================== UTF-8
// utf8_valid(x0 = ptr, x1 = len) -> 1 if strict UTF-8 (Rust from_utf8).
FN _utf8_valid
    add x1, x0, x1
1:  cmp x0, x1
    b.hs 8f
    ldrb w9, [x0], #1
    cmp w9, #0x80
    b.lo 1b
    mov w10, #0x80               // lo bound of the 2nd byte
    mov w11, #0xbf               // hi bound of the 2nd byte
    cmp w9, #0xc2
    b.lo 9f
    cmp w9, #0xdf
    b.hi 2f
    mov x12, #1
    b 5f
2:  cmp w9, #0xef
    b.hi 3f
    mov x12, #2
    cmp w9, #0xe0
    b.ne 21f
    mov w10, #0xa0
21: cmp w9, #0xed
    b.ne 5f
    mov w11, #0x9f
    b 5f
3:  cmp w9, #0xf4
    b.hi 9f
    mov x12, #3
    cmp w9, #0xf0
    b.ne 31f
    mov w10, #0x90
31: cmp w9, #0xf4
    b.ne 5f
    mov w11, #0x8f
5:  sub x13, x1, x0
    cmp x13, x12
    b.lo 9f
    ldrb w9, [x0], #1
    cmp w9, w10
    b.lo 9f
    cmp w9, w11
    b.hi 9f
6:  subs x12, x12, #1
    b.eq 1b
    ldrb w9, [x0], #1
    and w13, w9, #0xc0
    cmp w13, #0x80
    b.ne 9f
    b 6b
8:  mov x0, #1
    ret
9:  mov x0, #0
    ret

// =================================================================== data

    .section __TEXT,__cstring
Ltrue:  .asciz "true"
Lfalse: .asciz "false"
Lnull:  .asciz "null"
Lfmt17g: .asciz "%.17g"
    .globl _Lb58alpha_pub
Lb58alpha:
_Lb58alpha_pub:
    .asciz "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
Lb64alpha: .asciz "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
Lhexdigits: .asciz "0123456789abcdef"

    .section __TEXT,__const
// Short escapes for control bytes (0 = use \u00XX).
Lshortesc:
    .byte 0,0,0,0,0,0,0,0, 'b','t','n',0,'f','r',0,0
    .byte 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0

    .data
    .p2align 3
    .globl _g_trytop, _g_err_code, _g_err_msg, _g_arena, _g_arena_big, _g_bufs, _g_out
_g_trytop:    .quad 0
_g_err_code:  .quad 0
_g_err_msg:   .quad 0
_g_arena:     .quad 0
_g_arena_big: .quad 0
_g_bufs:      .quad 0
_g_out:       .quad 0, 0, 0, 0
