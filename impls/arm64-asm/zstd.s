// zstd.s: an RFC 8878 Zstandard decoder (docs/ZSTD_MINI_SPEC.md): frames,
// skippable frames, raw/RLE/compressed blocks, raw/RLE/Huffman/treeless
// literals with 1 or 4 streams, FSE tables in all four modes, repeat
// offsets, the 512 MiB output limit and the XXH64 content checksum.
// Any violation throws -32603 (the caller falls back per WIRE_FORMATS §9.1).

.include "defs.s"

.equ BLOCK_MAX, 131072

    .text

zbad:
    FAIL "Corrupt zstd data"

// zstd_decompress(x0 = src, x1 = len) -> x0 = output, x1 = length.
FN _zstd_decompress
    ENTER
    mov x19, x0
    add x20, x0, x1
    STG x20, z_end, x9
    bl _buf_new
    STG x0, z_out, x9
1:  cmp x19, x20
    b.hs 9f
    sub x9, x20, x19
    cmp x9, #4
    b.lo zbad
    ldr w10, [x19]
    and w11, w10, #0xfffffff0
    MOV64 x12, 0x184d2a50
    cmp w11, w12
    b.ne 2f
    cmp x9, #8
    b.lo zbad
    ldr w11, [x19, #4]
    add x19, x19, #8
    sub x9, x20, x19
    cmp x11, x9
    b.hi zbad
    add x19, x19, x11
    b 1b
2:  MOV64 x12, 0xfd2fb528
    cmp w10, w12
    b.ne zbad
    add x0, x19, #4
    bl decode_frame
    mov x19, x0
    b 1b
9:  LDG x9, z_out
    ldp x0, x1, [x9]
    LEAVE

// le_n(x0 = p, x1 = n) -> little-endian value (bounds checked against z_end).
    .p2align 2
le_n:
    LDG x9, z_end
    add x10, x0, x1
    cmp x10, x9
    b.hi zbad
    mov x9, #0
    mov x11, #0
1:  cmp x11, x1
    b.hs 2f
    ldrb w12, [x0, x11]
    lsl x13, x11, #3
    lsl x12, x12, x13
    orr x9, x9, x12
    add x11, x11, #1
    b 1b
2:  mov x0, x9
    ret

// decode_frame(x0 = position after the magic) -> position after the frame.
    .p2align 2
decode_frame:
    ENTER 32
    mov x19, x0
    mov x1, #1
    bl le_n
    mov x20, x0                  // descriptor
    add x19, x19, #1
    tbnz x20, #3, zbad
    ubfx x21, x20, #5, #1        // single segment
    cbnz x21, 1f
    mov x0, x19
    mov x1, #1
    bl le_n
    add x19, x19, #1
1:  and x9, x20, #3
    LA x10, Ldid_sizes
    ldrb w22, [x10, x9]
    cbz x22, 2f
    mov x0, x19
    mov x1, x22
    bl le_n
    cbnz x0, zbad
    add x19, x19, x22
2:  lsr x9, x20, #6
    LA x10, Lfcs_sizes
    ldrb w22, [x10, x9]
    cbnz x9, 3f
    mov x22, x21                 // FCS flag 0: 1 byte iff single segment
3:  mov x23, #-1                 // content size
    cbz x22, 4f
    mov x0, x19
    mov x1, x22
    bl le_n
    mov x23, x0
    cmp x22, #2
    b.ne 31f
    add x23, x23, #256
31: add x19, x19, x22
4:  // frame state
    LDG x9, z_out
    ldr x24, [x9, #BUF_LEN]      // frame start
    STG x24, z_frame_start, x9
    mov x9, #1
    mov x10, #4
    mov x11, #8
    LA x12, z_rep
    stp x9, x10, [x12]
    str x11, [x12, #16]
    STG xzr, z_huf_valid, x9
    LA x9, z_tab_valid
    stp xzr, xzr, [x9]
    str xzr, [x9, #16]
10: // blocks
    mov x0, x19
    mov x1, #3
    bl le_n
    add x19, x19, #3
    and x25, x0, #1              // last
    ubfx x26, x0, #1, #2         // type
    lsr x27, x0, #3              // size
    mov x9, #BLOCK_MAX
    cmp x27, x9
    b.hi zbad
    cmp x26, #3
    b.eq zbad
    cmp x26, #0
    b.ne 11f
    LDG x9, z_end
    add x10, x19, x27
    cmp x10, x9
    b.hi zbad
    mov x0, x27
    bl out_reserve
    LDG x0, z_out
    mov x1, x19
    mov x2, x27
    bl _buf_append
    add x19, x19, x27
    b 15f
11: cmp x26, #1
    b.ne 12f
    mov x0, x19
    mov x1, #1
    bl le_n
    mov x28, x0
    add x19, x19, #1
    mov x0, x27
    bl out_reserve
    LDG x9, z_out
    ldp x10, x11, [x9]
    add x0, x10, x11
    mov x1, x28
    mov x2, x27
    bl _memset
    LDG x9, z_out
    ldr x11, [x9, #BUF_LEN]
    add x11, x11, x27
    str x11, [x9, #BUF_LEN]
    b 15f
12: LDG x9, z_end
    add x28, x19, x27            // block end
    cmp x28, x9
    b.hi zbad
    mov x0, x19
    mov x1, x28
    bl decode_literals
    mov x1, x28
    bl decode_sequences
    mov x19, x28
15: LDG x9, z_out
    ldr x10, [x9, #BUF_LEN]
    MOV64 x11, MAX_ZSTD_OUT
    cmp x10, x11
    b.hi zbad
    cbz x25, 10b
    // content size and checksum
    LDG x9, z_out
    ldr x10, [x9, #BUF_LEN]
    sub x10, x10, x24
    cmn x23, #1
    b.eq 16f
    cmp x10, x23
    b.ne zbad
16: tbz x20, #2, 17f
    mov x0, x19
    mov x1, #4
    bl le_n
    mov x25, x0
    add x19, x19, #4
    LDG x9, z_out
    ldr x0, [x9, #BUF_PTR]
    add x0, x0, x24
    ldr x1, [x9, #BUF_LEN]
    sub x1, x1, x24
    bl xxh64
    mov w9, w0
    cmp x9, x25
    b.ne zbad
17: mov x0, x19
    LEAVE 32

// out_reserve(x0 = extra): the 512 MiB limit is enforced before growing.
    .p2align 2
out_reserve:
    LDG x9, z_out
    ldr x10, [x9, #BUF_LEN]
    add x10, x10, x0
    MOV64 x11, MAX_ZSTD_OUT
    cmp x10, x11
    b.hi zbad
    mov x1, x0
    mov x0, x9
    b _buf_reserve

// ================================================================ literals

// decode_literals(x0 = p, x1 = block end) -> x0 = position after literals.
// Sets z_lit_ptr / z_lit_len.
    .p2align 2
decode_literals:
    ENTER 32
    mov x19, x0
    mov x20, x1
    cmp x19, x20
    b.hs zbad
    ldrb w21, [x19]
    and x22, x21, #3             // type
    ubfx x23, x21, #2, #2        // size format
    cmp x22, #1
    b.hi 20f
    // raw / RLE
    cmp x23, #1
    b.eq 2f
    cmp x23, #3
    b.eq 3f
    lsr x24, x21, #3
    add x19, x19, #1
    b 4f
2:  mov x0, x19
    mov x1, #2
    bl le_n
    lsr x24, x0, #4
    add x19, x19, #2
    b 4f
3:  mov x0, x19
    mov x1, #3
    bl le_n
    lsr x24, x0, #4
    add x19, x19, #3
4:  mov x9, #BLOCK_MAX
    cmp x24, x9
    b.hi zbad
    cbnz x22, 5f
    add x9, x19, x24
    cmp x9, x20
    b.hi zbad
    STG x19, z_lit_ptr, x10
    STG x24, z_lit_len, x10
    mov x0, x9
    LEAVE 32
5:  cmp x19, x20
    b.hs zbad
    ldrb w1, [x19]
    LA x0, z_lit_buf
    mov x2, x24
    bl _memset
    LA x9, z_lit_buf
    STG x9, z_lit_ptr, x10
    STG x24, z_lit_len, x10
    add x0, x19, #1
    LEAVE 32
20: // compressed (2) / treeless (3)
    LA x9, Llit_hdr
    ldrb w25, [x9, x23]          // header bytes
    LA x9, Llit_width
    ldrb w26, [x9, x23]          // field width
    mov x0, x19
    mov x1, x25
    bl le_n
    mov x9, #1
    lsl x9, x9, x26
    sub x9, x9, #1
    lsr x10, x0, #4
    and x24, x10, x9             // regenerated
    add x11, x26, #4
    lsr x10, x0, x11
    and x27, x10, x9             // compressed
    add x19, x19, x25
    add x28, x19, x27            // literals end
    cmp x28, x20
    b.hi zbad
    mov x9, #BLOCK_MAX
    cmp x24, x9
    b.hi zbad
    cmp x22, #2
    b.ne 21f
    mov x0, x19
    mov x1, x28
    bl huf_read_description
    mov x19, x0
    b 22f
21: LDG x9, z_huf_valid
    cbz x9, zbad
22: LA x9, z_lit_buf
    STG x9, z_lit_ptr, x10
    STG x24, z_lit_len, x10
    cbnz x23, 30f
    // one stream
    mov x0, x19
    mov x1, x28
    mov x2, x24
    LA x3, z_lit_buf
    bl huf_stream
    mov x0, x28
    LEAVE 32
30: // four streams with a 6-byte jump table
    add x9, x19, #6
    cmp x9, x28
    b.hi zbad
    ldrh w10, [x19]
    ldrh w11, [x19, #2]
    ldrh w12, [x19, #4]
    stp x10, x11, [sp]
    str x12, [sp, #16]
    add x19, x19, #6
    add x13, x10, x11
    add x13, x13, x12
    sub x14, x28, x19
    cmp x13, x14
    b.hs zbad                    // stream 4 needs at least one byte
    add x25, x24, #3
    lsr x25, x25, #2             // quarter
    mov x9, #3
    msub x26, x25, x9, x24       // stream 4 count
    tbnz x26, #63, zbad
    LA x27, z_lit_buf
    mov x21, #0
31: cmp x21, #4
    b.hs 39f
    cmp x21, #3
    b.eq 32f
    ldr x9, [sp, x21, lsl #3]
    add x1, x19, x9
    mov x2, x25
    b 33f
32: mov x1, x28
    mov x2, x26
33: mov x0, x19
    mov x22, x1
    mov x3, x27
    add x27, x27, x2
    bl huf_stream
    mov x19, x22
    add x21, x21, #1
    b 31b
39: mov x0, x28
    LEAVE 32

// ================================================================ Huffman

// huf_read_description(x0 = p, x1 = literals end) -> position after it.
    .p2align 2
huf_read_description:
    ENTER 32
    mov x19, x0
    mov x20, x1
    cmp x19, x20
    b.hs zbad
    ldrb w21, [x19], #1
    mov x22, #0                  // weight count
    LA x23, z_weights
    cmp x21, #128
    b.hs 20f
    // FSE-compressed weights
    add x24, x19, x21            // end
    cmp x24, x20
    b.hi zbad
    mov x0, x19
    mov x1, x24
    mov x2, #255
    mov x3, #6
    bl fse_read
    mov x25, x0                  // accuracy log
    mov x26, x1                  // stream start
    mov x0, x2                   // symbols
    mov x1, x25
    LA x2, z_wt_table
    bl fse_build
    mov x0, x26
    mov x1, x24
    bl br_init
    mov x0, x25
    bl br_read
    mov x26, x0                  // state 1
    mov x0, x25
    bl br_read
    mov x27, x0                  // state 2
    LA x28, z_wt_table
10: cmp x22, #255
    b.hi zbad
    ldr w9, [x28, x26, lsl #2]
    strb w9, [x23, x22]
    add x22, x22, #1
    ubfx x0, x9, #8, #8
    lsr x26, x9, #16
    bl br_read
    add x26, x26, x0
    LDG x9, z_br_bits
    tbz x9, #63, 11f
    ldr w9, [x28, x27, lsl #2]
    strb w9, [x23, x22]
    add x22, x22, #1
    b 30f
11: cmp x22, #255
    b.hi zbad
    ldr w9, [x28, x27, lsl #2]
    strb w9, [x23, x22]
    add x22, x22, #1
    ubfx x0, x9, #8, #8
    lsr x27, x9, #16
    bl br_read
    add x27, x27, x0
    LDG x9, z_br_bits
    tbz x9, #63, 10b
    ldr w9, [x28, x26, lsl #2]
    strb w9, [x23, x22]
    add x22, x22, #1
    b 30f
20: // direct 4-bit weights
    sub x21, x21, #127           // n
    add x24, x21, #1
    lsr x24, x24, #1
    add x24, x19, x24            // end
    cmp x24, x20
    b.hi zbad
21: cmp x22, x21
    b.hs 30f
    lsr x9, x22, #1
    ldrb w10, [x19, x9]
    tst x22, #1
    lsr w11, w10, #4
    and w12, w10, #15
    csel w10, w11, w12, eq
    strb w10, [x23, x22]
    add x22, x22, #1
    b 21b
30: mov x19, x24
    mov x0, x22
    bl huf_build
    mov x0, x19
    LEAVE 32

// huf_build(x0 = number of listed weights in z_weights)
    .p2align 2
huf_build:
    ENTER 128
    mov x19, x0
    cmp x19, #255
    b.hi zbad
    LA x20, z_weights
    mov x21, #0                  // total
    mov x9, #0
1:  cmp x9, x19
    b.hs 2f
    ldrb w10, [x20, x9]
    cmp w10, #11
    b.hi zbad
    cbz w10, 11f
    sub w10, w10, #1
    mov x11, #1
    lsl x11, x11, x10
    add x21, x21, x11
11: add x9, x9, #1
    b 1b
2:  cbz x21, zbad
    clz x9, x21
    mov x10, #64
    sub x22, x10, x9             // max_bits = highbit(total) + 1
    cmp x22, #11
    b.hi zbad
    mov x9, #1
    lsl x9, x9, x22
    sub x23, x9, x21             // rest
    sub x10, x23, #1
    tst x23, x10
    b.ne zbad
    clz x9, x23
    mov x10, #64
    sub x9, x10, x9              // highbit(rest) + 1
    strb w9, [x20, x19]
    add x19, x19, #1             // symbols including the implied last
    // next_cell[w] for w = 1..max_bits, at [sp]
    mov x24, #0                  // start
    mov x25, #1
3:  cmp x25, x22
    b.hi 5f
    str x24, [sp, x25, lsl #3]
    mov x9, #0
    mov x10, #0                  // count of weight w
4:  cmp x9, x19
    b.hs 41f
    ldrb w11, [x20, x9]
    cmp x11, x25
    cinc x10, x10, eq
    add x9, x9, #1
    b 4b
41: sub x11, x25, #1
    lsl x10, x10, x11
    add x24, x24, x10
    add x25, x25, #1
    b 3b
5:  LA x26, z_huf_table
    mov x9, #0                   // symbol
6:  cmp x9, x19
    b.hs 8f
    ldrb w10, [x20, x9]
    cbz w10, 7f
    ldr x11, [sp, x10, lsl #3]   // first cell
    sub x12, x10, #1
    mov x13, #1
    lsl x13, x13, x12            // cells
    add x14, x11, x13
    str x14, [sp, x10, lsl #3]
    add x15, x22, #1
    sub x15, x15, x10            // code length
    orr x15, x9, x15, lsl #8
61: cmp x11, x14
    b.hs 7f
    strh w15, [x26, x11, lsl #1]
    add x11, x11, #1
    b 61b
7:  add x9, x9, #1
    b 6b
8:  STG x22, z_huf_maxbits, x9
    mov x9, #1
    STG x9, z_huf_valid, x10
    LEAVE 128

// huf_stream(x0 = start, x1 = end, x2 = count, x3 = output)
    .p2align 2
huf_stream:
    ENTER
    mov x19, x2
    mov x20, x3
    bl br_init
    LDG x21, z_huf_maxbits
    LA x22, z_huf_table
1:  cbz x19, 2f
    mov x0, x21
    bl br_peek
    ldrh w9, [x22, x0, lsl #1]
    strb w9, [x20], #1
    lsr w10, w9, #8
    LDG x11, z_br_bits
    sub x11, x11, x10
    STG x11, z_br_bits, x12
    sub x19, x19, #1
    b 1b
2:  LDG x9, z_br_bits
    cbnz x9, zbad
    LEAVE

// ============================================================ bitstreams

// br_init(x0 = start, x1 = end): backward bit reader.
    .p2align 2
br_init:
    cmp x1, x0
    b.ls zbad
    ldrb w9, [x1, #-1]
    cbz w9, zbad
    STG x0, z_br_ptr, x10
    sub x10, x1, x0
    sub x10, x10, #1
    lsl x10, x10, #3
    clz w11, w9
    mov w12, #31
    sub w11, w12, w11            // highbit
    add x10, x10, x11
    STG x10, z_br_bits, x11
    ret

// br_peek(x0 = n <= 32) -> bits [bits - n, bits) of the stream (zero padded).
    .p2align 2
br_peek:
    LDG x9, z_br_bits            // hi
    cbz x0, 9f
    cmp x9, #0
    b.le 9f
    sub x10, x9, x0              // lo
    mov x14, #0                  // left shift for missing low bits
    tbz x10, #63, 1f
    neg x14, x10
    mov x10, #0
1:  // window(lo = x10, hi = x9)
    LDG x11, z_br_ptr
    lsr x12, x10, #3             // first byte
    sub x13, x9, #1
    lsr x13, x13, #3             // last byte
    mov x15, #0
    mov x16, #0                  // shift
2:  cmp x12, x13
    b.hi 3f
    ldrb w17, [x11, x12]
    lsl x17, x17, x16
    orr x15, x15, x17
    add x12, x12, #1
    add x16, x16, #8
    b 2b
3:  and x12, x10, #7
    lsr x15, x15, x12
    sub x13, x9, x10             // width
    mov x12, #1
    lsl x12, x12, x13
    sub x12, x12, #1
    and x15, x15, x12
    lsl x0, x15, x14
    ret
9:  mov x0, #0
    ret

// br_read(x0 = n) -> value; bits -= n.
    .p2align 2
br_read:
    mov x8, x30
    mov x7, x0
    bl br_peek
    LDG x9, z_br_bits
    sub x9, x9, x7
    STG x9, z_br_bits, x10
    mov x30, x8
    ret

// ===================================================================== FSE

// fse_read(x0 = p, x1 = limit, x2 = max symbol, x3 = max log) -> x0 =
// accuracy log, x1 = position after the description, x2 = symbol count.
// Probabilities go to z_probs (i16, -1 = "less than 1").
    .p2align 2
fse_read:
    ENTER 32
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    STG x19, z_fw_base, x9
    STG x20, z_fw_limit, x9
    mov x23, #0                  // bit position
    mov x0, x23
    mov x1, #4
    bl fw_peek
    add x23, x23, #4
    add x24, x0, #5              // accuracy log
    cmp x24, x22
    b.hi zbad
    mov x9, #1
    lsl x25, x9, x24             // threshold
    add x26, x25, #1             // remaining
    add x27, x24, #1             // nbits
    mov x28, #0                  // symbols
    LA x9, z_probs
    str x9, [sp]
1:  cmp x26, #1
    b.le 9f
    cmp x28, x21
    b.hi zbad
    lsl x9, x25, #1
    sub x9, x9, #1
    sub x9, x9, x26              // biggest
    str x9, [sp, #8]
    mov x0, x23
    sub x1, x27, #1
    bl fw_peek
    ldr x9, [sp, #8]
    cmp x0, x9
    b.hs 2f
    sub x10, x27, #1
    add x23, x23, x10
    b 3f
2:  mov x0, x23
    mov x1, x27
    bl fw_peek
    add x23, x23, x27
    cmp x0, x25
    b.lo 3f
    ldr x9, [sp, #8]
    sub x0, x0, x9
3:  sub x10, x0, #1              // prob
    ldr x9, [sp]
    strh w10, [x9, x28, lsl #1]
    add x28, x28, #1
    cmp x10, #0
    cneg x11, x10, lt
    sub x26, x26, x11
    cbnz x10, 6f
    // zero probability: 2-bit repeat flags
4:  mov x0, x23
    mov x1, #2
    bl fw_peek
    add x23, x23, #2
    mov x12, x0
5:  cbz x12, 51f
    cmp x28, #256
    b.hs zbad
    ldr x9, [sp]
    strh wzr, [x9, x28, lsl #1]
    add x28, x28, #1
    sub x12, x12, #1
    b 5b
51: cmp x0, #3
    b.eq 4b
6:  cmp x26, x25
    b.ge 1b
    sub x27, x27, #1
    lsr x25, x25, #1
    b 6b
9:  cmp x26, #1
    b.ne zbad
    add x9, x21, #1
    cmp x28, x9
    b.hi zbad
    add x9, x23, #7
    lsr x9, x9, #3
    add x1, x19, x9
    cmp x1, x20
    b.hi zbad
    mov x0, x24
    mov x2, x28
    LEAVE 32

// fw_peek(x0 = bit position, x1 = n <= 16) -> forward bits (zero past limit).
    .p2align 2
fw_peek:
    LDG x9, z_fw_base
    LDG x10, z_fw_limit
    lsr x11, x0, #3
    add x11, x9, x11
    mov x12, #0
    mov x13, #0
1:  cmp x13, #32
    b.hs 3f
    cmp x11, x10
    b.hs 3f
    ldrb w14, [x11], #1
    lsl x14, x14, x13
    orr x12, x12, x14
    add x13, x13, #8
    b 1b
3:  and x14, x0, #7
    lsr x12, x12, x14
    mov x14, #1
    lsl x14, x14, x1
    sub x14, x14, #1
    and x0, x12, x14
    ret

// fse_build(x0 = symbol count, x1 = accuracy log, x2 = table): cells of
// symbol | nb_bits << 8 | baseline << 16 from z_probs.
    .p2align 2
fse_build:
    ENTER 1056
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x9, #1
    lsl x22, x9, x20             // size
    sub x23, x22, #1             // high
    LA x24, z_probs
    add x25, sp, #512            // counters (u16 x 256)
    // cell symbols at [sp, 0..512)
    mov x9, #0
1:  cmp x9, x19
    b.hs 3f
    ldrsh x10, [x24, x9, lsl #1]
    cmn x10, #1
    b.ne 2f
    strb w9, [sp, x23]
    sub x23, x23, #1
    mov w11, #1
    strh w11, [x25, x9, lsl #1]
    b 21f
2:  strh w10, [x25, x9, lsl #1]
21: add x9, x9, #1
    b 1b
3:  lsr x26, x22, #1
    add x26, x26, x22, lsr #3
    add x26, x26, #3             // step
    sub x27, x22, #1             // mask
    mov x28, #0                  // position
    mov x9, #0
4:  cmp x9, x19
    b.hs 7f
    ldrsh x10, [x24, x9, lsl #1]
5:  cmp x10, #0
    b.le 6f
    strb w9, [sp, x28]
51: add x28, x28, x26
    and x28, x28, x27
    cmp x28, x23
    b.hi 51b
    sub x10, x10, #1
    b 5b
6:  add x9, x9, #1
    b 4b
7:  cbnz x28, zbad
    mov x9, #0                   // cell
8:  cmp x9, x22
    b.hs 9f
    ldrb w10, [sp, x9]           // symbol
    ldrh w11, [x25, x10, lsl #1] // x
    add w12, w11, #1
    strh w12, [x25, x10, lsl #1]
    cbz w11, zbad
    clz w12, w11
    mov w13, #31
    sub w12, w13, w12            // highbit(x)
    sub x13, x20, x12            // nb
    lsl x14, x11, x13
    sub x14, x14, x22            // baseline
    orr x15, x10, x13, lsl #8
    orr x15, x15, x14, lsl #16
    str w15, [x21, x9, lsl #2]
    add x9, x9, #1
    b 8b
9:  LEAVE 1056

// ============================================================== sequences

// seq_table(x0 = p, x1 = end, x2 = mode, x3 = kind 0 ll / 1 of / 2 ml)
// -> x0 = position after its description; sets the current table.
    .p2align 2
seq_table:
    ENTER 16
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    LA x23, z_tabs
    lsl x9, x22, #11             // 512 cells x 4 bytes
    add x23, x23, x9             // table of this kind
    LA x24, Lseq_maxsym
    ldrb w24, [x24, x22]
    cmp x21, #0
    b.ne 10f
    // predefined distribution
    LA x9, Lseq_default
    ldr x9, [x9, x22, lsl #3]
    LA x10, Lseq_default_n
    ldrb w25, [x10, x22]
    LA x10, Lseq_default_log
    ldrb w26, [x10, x22]
    LA x11, z_probs
    mov x12, #0
1:  cmp x12, x25
    b.hs 2f
    ldrsb x13, [x9, x12]
    strh w13, [x11, x12, lsl #1]
    add x12, x12, #1
    b 1b
2:  mov x0, x25
    mov x1, x26
    mov x2, x23
    bl fse_build
    b 40f
10: cmp x21, #1
    b.ne 20f
    cmp x19, x20
    b.hs zbad
    ldrb w9, [x19], #1
    cmp x9, x24
    b.hi zbad
    str w9, [x23]                // symbol, 0 bits, baseline 0
    mov x26, #0
    b 40f
20: cmp x21, #2
    b.ne 30f
    LA x9, Lseq_maxlog
    ldrb w3, [x9, x22]
    mov x0, x19
    mov x1, x20
    mov x2, x24
    bl fse_read
    mov x26, x0
    mov x19, x1
    mov x0, x2
    mov x1, x26
    mov x2, x23
    bl fse_build
    b 40f
30: // repeat: the previous table of this kind
    LA x9, z_tab_valid
    ldr x10, [x9, x22, lsl #3]
    cbz x10, zbad
    mov x0, x19
    LEAVE 16
40: LA x9, z_tab_valid
    mov x10, #1
    str x10, [x9, x22, lsl #3]
    LA x9, z_tab_log
    str x26, [x9, x22, lsl #3]
    mov x0, x19
    LEAVE 16

// decode_sequences(x0 = p, x1 = block end): decodes and executes.
    .p2align 2
decode_sequences:
    ENTER 64
    mov x19, x0
    mov x20, x1
    STG xzr, z_lit_used, x9
    cmp x19, x20
    b.hs zbad
    ldrb w9, [x19]
    cbnz w9, 1f
    add x9, x19, #1
    cmp x9, x20
    b.ne zbad
    mov x21, #0
    b 80f                        // no sequences: all literals
1:  cmp w9, #128
    b.hs 2f
    mov x21, x9
    add x19, x19, #1
    b 4f
2:  cmp w9, #255
    b.eq 3f
    add x0, x19, #1
    mov x1, #1
    bl le_n
    ldrb w9, [x19]
    sub x9, x9, #128
    add x21, x0, x9, lsl #8
    add x19, x19, #2
    b 4f
3:  add x0, x19, #1
    mov x1, #2
    bl le_n
    mov x9, #0x7f00
    add x21, x0, x9
    add x19, x19, #3
4:  cmp x19, x20
    b.hs zbad
    ldrb w22, [x19], #1          // modes
    tst x22, #3
    b.ne zbad
    mov x0, x19
    mov x1, x20
    ubfx x2, x22, #6, #2
    mov x3, #0
    bl seq_table
    mov x1, x20
    ubfx x2, x22, #4, #2
    mov x3, #1
    bl seq_table
    mov x1, x20
    ubfx x2, x22, #2, #2
    mov x3, #2
    bl seq_table
    mov x1, x20
    bl br_init
    LA x9, z_tab_log
    ldr x0, [x9]
    bl br_read
    mov x23, x0                  // ll state
    LA x9, z_tab_log
    ldr x0, [x9, #8]
    bl br_read
    mov x24, x0                  // of state
    LA x9, z_tab_log
    ldr x0, [x9, #16]
    bl br_read
    mov x25, x0                  // ml state
    LDG x26, z_lit_ptr           // literal cursor
    LDG x9, z_lit_len
    add x27, x26, x9             // literal end
    LA x28, z_tabs
10: cbz x21, 70f
    // current symbols: LL table at +0, OF at +2048, ML at +4096
    add x9, x28, #2048
    ldr w9, [x9, x24, lsl #2]
    and x9, x9, #0xff
    str x9, [sp]                 // of code
    add x10, x28, #1, lsl #12
    ldr w10, [x10, x25, lsl #2]
    and x10, x10, #0xff
    str x10, [sp, #8]            // ml code
    ldr w11, [x28, x23, lsl #2]
    and x11, x11, #0xff
    str x11, [sp, #16]           // ll code
    cmp x9, #31
    b.hi zbad
    // offset_value = (1 << of_code) + read(of_code)
    mov x0, x9
    bl br_read
    ldr x9, [sp]
    mov x10, #1
    lsl x10, x10, x9
    add x0, x0, x10
    str x0, [sp, #24]            // offset value
    ldr x9, [sp, #8]
    cmp x9, #52
    b.hi zbad
    LA x10, Lml_bits
    ldrb w0, [x10, x9]
    bl br_read
    ldr x9, [sp, #8]
    LA x10, Lml_base
    ldr w10, [x10, x9, lsl #2]
    add x0, x0, x10
    str x0, [sp, #32]            // match length
    ldr x9, [sp, #16]
    cmp x9, #35
    b.hi zbad
    LA x10, Lll_bits
    ldrb w0, [x10, x9]
    bl br_read
    ldr x9, [sp, #16]
    LA x10, Lll_base
    ldr w10, [x10, x9, lsl #2]
    add x0, x0, x10
    str x0, [sp, #40]            // literal length
    sub x21, x21, #1
    cbz x21, 20f
    // advance states: LL, ML, OF
    ldr w9, [x28, x23, lsl #2]
    ubfx x0, x9, #8, #8
    lsr x23, x9, #16
    bl br_read
    add x23, x23, x0
    add x10, x28, #1, lsl #12
    ldr w9, [x10, x25, lsl #2]
    ubfx x0, x9, #8, #8
    lsr x25, x9, #16
    bl br_read
    add x25, x25, x0
    add x10, x28, #2048
    ldr w9, [x10, x24, lsl #2]
    ubfx x0, x9, #8, #8
    lsr x24, x9, #16
    bl br_read
    add x24, x24, x0
20: // execute (ll, offset_value, ml)
    ldr x0, [sp, #40]
    ldr x1, [sp, #24]
    ldr x2, [sp, #32]
    bl exec_seq
    b 10b
70: LDG x9, z_br_bits
    cbnz x9, zbad
    LDG x26, z_lit_ptr
    LDG x9, z_lit_len
    add x27, x26, x9
    LDG x9, z_lit_used
    add x26, x26, x9
    b 81f
80: LDG x26, z_lit_ptr
    LDG x9, z_lit_len
    add x27, x26, x9
81: // remaining literals
    sub x2, x27, x26
    mov x0, x2
    bl out_reserve
    LDG x0, z_out
    mov x1, x26
    sub x2, x27, x26
    bl _buf_append
    STG xzr, z_lit_used, x9
    LEAVE 64

// exec_seq(x0 = literal length, x1 = offset value, x2 = match length)
    .p2align 2
exec_seq:
    ENTER
    mov x19, x0
    mov x20, x1
    mov x21, x2
    LDG x9, z_lit_used
    LDG x10, z_lit_len
    add x11, x9, x19
    cmp x11, x10
    b.hi zbad
    // literals
    add x0, x19, x21
    bl out_reserve
    LDG x9, z_lit_ptr
    LDG x10, z_lit_used
    add x1, x9, x10
    add x10, x10, x19
    STG x10, z_lit_used, x11
    LDG x0, z_out
    mov x2, x19
    bl _buf_append
    // offset
    LA x9, z_rep
    ldp x10, x11, [x9]
    ldr x12, [x9, #16]
    cmp x20, #3
    b.ls 1f
    sub x22, x20, #3
    stp x22, x10, [x9]
    str x11, [x9, #16]
    b 5f
1:  sub x13, x20, #1
    cmp x19, #0
    cinc x13, x13, eq
    cbnz x13, 2f
    mov x22, x10
    b 5f
2:  cmp x13, #1
    b.ne 3f
    mov x22, x11
    stp x11, x10, [x9]
    b 5f
3:  cmp x13, #2
    b.ne 4f
    mov x22, x12
    stp x12, x10, [x9]
    str x11, [x9, #16]
    b 5f
4:  sub x22, x10, #1
    stp x22, x10, [x9]
    str x11, [x9, #16]
5:  // copy ml bytes from offset back, byte by byte
    LDG x9, z_out
    ldp x10, x11, [x9]           // ptr, len
    LDG x12, z_frame_start
    sub x13, x11, x12
    cbz x22, zbad
    cmp x22, x13
    b.hi zbad
    add x14, x10, x11            // dst
    sub x15, x14, x22            // src
    mov x16, x21
6:  cbz x16, 7f
    ldrb w17, [x15], #1
    strb w17, [x14], #1
    sub x16, x16, #1
    b 6b
7:  add x11, x11, x21
    str x11, [x9, #BUF_LEN]
    LEAVE

// =================================================================== XXH64

.equ P1, 0x9e3779b185ebca87
.equ P2, 0xc2b2ae3d27d4eb4f
.equ P3, 0x165667b19e3779f9
.equ P4, 0x85ebca77c2b2ae63
.equ P5, 0x27d4eb2f165667c5

// xxh64(x0 = ptr, x1 = len) -> seed-0 XXH64.
    .p2align 2
xxh64:
    MOV64 x2, P1
    MOV64 x3, P2
    MOV64 x4, P3
    MOV64 x5, P4
    MOV64 x6, P5
    mov x7, x1                   // total length
    add x8, x0, x1               // end
    cmp x1, #32
    b.lo 5f
    add x9, x2, x3               // v1 = P1 + P2
    mov x10, x3                  // v2 = P2
    mov x11, #0                  // v3 = 0
    neg x12, x2                  // v4 = -P1
1:  sub x13, x8, x0
    cmp x13, #32
    b.lo 2f
    ldr x13, [x0], #8
    madd x9, x13, x3, x9
    ror x9, x9, #33
    mul x9, x9, x2
    ldr x13, [x0], #8
    madd x10, x13, x3, x10
    ror x10, x10, #33
    mul x10, x10, x2
    ldr x13, [x0], #8
    madd x11, x13, x3, x11
    ror x11, x11, #33
    mul x11, x11, x2
    ldr x13, [x0], #8
    madd x12, x13, x3, x12
    ror x12, x12, #33
    mul x12, x12, x2
    b 1b
2:  ror x14, x9, #63
    ror x13, x10, #57
    add x14, x14, x13
    ror x13, x11, #52
    add x14, x14, x13
    ror x13, x12, #46
    add x14, x14, x13
    // merge rounds
    mul x13, x9, x3
    ror x13, x13, #33
    mul x13, x13, x2
    eor x14, x14, x13
    madd x14, x14, x2, x5
    mul x13, x10, x3
    ror x13, x13, #33
    mul x13, x13, x2
    eor x14, x14, x13
    madd x14, x14, x2, x5
    mul x13, x11, x3
    ror x13, x13, #33
    mul x13, x13, x2
    eor x14, x14, x13
    madd x14, x14, x2, x5
    mul x13, x12, x3
    ror x13, x13, #33
    mul x13, x13, x2
    eor x14, x14, x13
    madd x14, x14, x2, x5
    b 6f
5:  mov x14, x6                  // seed + P5
6:  add x14, x14, x7
7:  sub x13, x8, x0
    cmp x13, #8
    b.lo 8f
    ldr x13, [x0], #8
    mul x13, x13, x3
    ror x13, x13, #33
    mul x13, x13, x2
    eor x14, x14, x13
    ror x14, x14, #37            // rotl 27
    madd x14, x14, x2, x5
    b 7b
8:  sub x13, x8, x0
    cmp x13, #4
    b.lo 9f
    ldr w13, [x0], #4
    mul x13, x13, x2
    eor x14, x14, x13
    ror x14, x14, #41            // rotl 23
    madd x14, x14, x3, x4
9:  cmp x0, x8
    b.hs 10f
    ldrb w13, [x0], #1
    mul x13, x13, x6
    eor x14, x14, x13
    ror x14, x14, #53            // rotl 11
    mul x14, x14, x2
    b 9b
10: eor x14, x14, x14, lsr #33
    mul x14, x14, x3
    eor x14, x14, x14, lsr #29
    mul x14, x14, x4
    eor x0, x14, x14, lsr #32
    ret

// ================================================================== tables

    .section __TEXT,__const
Ldid_sizes:  .byte 0, 1, 2, 4
Lfcs_sizes:  .byte 0, 2, 4, 8
Llit_hdr:    .byte 3, 3, 4, 5
Llit_width:  .byte 10, 10, 14, 18
Lseq_maxsym: .byte 35, 31, 52
Lseq_maxlog: .byte 9, 8, 9
Lseq_default_n:   .byte 36, 29, 53
Lseq_default_log: .byte 6, 5, 6
Lll_default:
    .byte 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1
    .byte 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1
    .byte -1, -1, -1, -1
Lof_default:
    .byte 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1
    .byte 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1
Lml_default:
    .byte 1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1
    .byte 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
    .byte 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1
    .byte -1, -1, -1, -1, -1
Lll_bits:
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    .byte 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12
    .byte 13, 14, 15, 16
Lml_bits:
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    .byte 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11
    .byte 12, 13, 14, 15, 16
    .p2align 2
Lll_base:
    .long 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    .long 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096
    .long 8192, 16384, 32768, 65536
Lml_base:
    .long 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18
    .long 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34
    .long 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051
    .long 4099, 8195, 16387, 32771, 65539

    .section __DATA,__const
    .p2align 3
Lseq_default: .quad Lll_default, Lof_default, Lml_default

    .data
    .p2align 3
z_end:         .quad 0
z_out:         .quad 0
z_frame_start: .quad 0
z_rep:         .quad 0, 0, 0
z_huf_valid:   .quad 0
z_huf_maxbits: .quad 0
z_tab_valid:   .quad 0, 0, 0
z_tab_log:     .quad 0, 0, 0
z_lit_ptr:     .quad 0
z_lit_len:     .quad 0
z_lit_used:    .quad 0
z_br_ptr:      .quad 0
z_br_bits:     .quad 0
z_fw_base:     .quad 0
z_fw_limit:    .quad 0

    .zerofill __DATA,__bss,z_huf_table,4096,4
    .zerofill __DATA,__bss,z_tabs,6144,4
    .zerofill __DATA,__bss,z_wt_table,256,4
    .zerofill __DATA,__bss,z_probs,512,4
    .zerofill __DATA,__bss,z_weights,256,4
    .zerofill __DATA,__bss,z_lit_buf,131136,4
