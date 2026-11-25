// car.s: LEB128 varints, CIDs, a validating DAG-CBOR cursor, the CARv1
// section index (hashed by raw CID bytes), node views, DataFrame
// reassembly and the CRC-64/GO-ISO + FNV-1a checks. Every malformed input
// throws -32603.

.include "defs.s"


    .text

// uvarint(x0 = p, x1 = end) -> x0 = value, x1 = position after it.
FN _uvarint
    b uvar

// cid_parse(x0 = p, x1 = end) -> x0 = CID length, x1 = 1 if it is the empty
// identity CID (absent).
FN _cid_parse
    ENTER
    mov x19, x0
    mov x20, x1
    bl uvar
    mov x21, x0                  // a
    mov x0, x1
    mov x1, x20
    bl uvar
    mov x22, x0                  // b
    cmp x21, #0x12
    b.ne 1f
    cmp x22, #0x20
    b.ne 1f
    add x9, x1, #32
    cmp x9, x20
    b.hi 8f
    sub x0, x9, x19
    mov x1, #0
    LEAVE
1:  cmp x21, #1
    b.ne 8f
    mov x0, x1
    mov x1, x20
    bl uvar
    mov x23, x0                  // hash code
    mov x0, x1
    mov x1, x20
    bl uvar
    cmp x0, #64
    b.hi 8f
    add x9, x1, x0
    cmp x9, x20
    b.hi 8f
    orr x10, x23, x0
    cmp x10, #0
    cset x1, eq
    sub x0, x9, x19
    LEAVE
8:  FAIL "Malformed CID"

// uvar: internal uvarint returning x0 = value, x1 = next position.
    .p2align 2
uvar:
    mov x9, #0
    mov x10, #0
    mov x11, #0
1:  cmp x0, x1
    b.hs 9f
    ldrb w12, [x0], #1
    and x13, x12, #0x7f
    lsl x13, x13, x10
    orr x9, x9, x13
    tbz w12, #7, 2f
    add x10, x10, #7
    add x11, x11, #1
    cmp x11, #10
    b.lo 1b
    b 9f
2:  cmp x11, #9
    b.ne 3f
    cmp w12, #1
    b.hi 9f
3:  mov x1, x0
    mov x0, x9
    ret
9:  stp x29, x30, [sp, #-16]!
    FAIL "Malformed varint"

// ==================================================================== CBOR

// cbor_head(x0 = p, x1 = end) -> x0 = major, x1 = argument (-1 = indefinite),
// x2 = position after the head, x3 = additional info.
FN _cbor_head
    cmp x0, x1
    b.hs 9f
    ldrb w9, [x0], #1
    lsr x10, x9, #5
    and x3, x9, #31
    cmp x3, #24
    b.hs 1f
    mov x2, x0
    mov x0, x10
    mov x1, x3
    ret
1:  cmp x3, #31
    b.ne 2f
    mov x2, x0
    mov x0, x10
    mov x1, #-1
    ret
2:  cmp x3, #27
    b.hi 9f
    sub x11, x3, #24
    mov x12, #1
    lsl x12, x12, x11            // 1, 2, 4, 8 bytes
    add x13, x0, x12
    cmp x13, x1
    b.hi 9f
    mov x1, #0
3:  ldrb w14, [x0], #1
    orr x1, x14, x1, lsl #8
    subs x12, x12, #1
    b.ne 3b
    mov x2, x0
    mov x0, x10
    ret
9:  stp x29, x30, [sp, #-16]!
    FAIL "Truncated CBOR"

// cbor_skip(x0 = p, x1 = end, x2 = depth) -> x0 = position after the item.
// Validates structure, definite counts, string chunks and UTF-8.
FN _cbor_skip
    ENTER
    mov x19, x1
    mov x20, x2
    cmp x20, #128
    b.hi 90f
    bl _cbor_head
    mov x21, x0                  // major
    mov x22, x1                  // argument
    mov x23, x2                  // position
    cmp x21, #7
    b.ne 10f
    // simple values and floats
    cmp x3, #20
    b.lo 90f
    cmp x3, #23
    b.ls 99f
    cmp x3, #25
    b.lo 90f
    cmp x3, #27
    b.hi 90f
    b 99f                        // the float bytes were consumed as the argument
10: cmp x21, #1
    b.ls 11f
    cmp x21, #6
    b.ne 12f
    cmn x22, #1
    b.eq 90f
    mov x0, x23
    mov x1, x19
    add x2, x20, #1
    bl _cbor_skip
    LEAVE
11: cmn x22, #1
    b.eq 90f
    b 99f
12: cmp x21, #3
    b.hi 20f
    // byte / text string
    cmn x22, #1
    b.eq 15f
    sub x9, x19, x23
    cmp x22, x9
    b.hi 90f
    cmp x21, #3
    b.ne 13f
    mov x0, x23
    mov x1, x22
    bl _utf8_valid
    cbz x0, 90f
13: add x23, x23, x22
    b 99f
15: // indefinite: definite chunks of the same major until 0xff
    cmp x23, x19
    b.hs 90f
    ldrb w9, [x23]
    cmp w9, #0xff
    b.eq 16f
    mov x0, x23
    mov x1, x19
    bl _cbor_head
    cmp x0, x21
    b.ne 90f
    cmn x1, #1
    b.eq 90f
    sub x9, x19, x2
    cmp x1, x9
    b.hi 90f
    mov x23, x2
    mov x24, x1
    cmp x21, #3
    b.ne 151f
    mov x0, x23
    mov x1, x24
    bl _utf8_valid
    cbz x0, 90f
151: add x23, x23, x24
    b 15b
16: add x23, x23, #1
    b 99f
20: // array (4) or map (5)
    cmn x22, #1
    b.eq 25f
    lsl x24, x22, #1
    cmp x21, #4
    csel x24, x22, x24, eq       // item count
    sub x9, x19, x23
    cmp x22, x9
    b.hi 90f
    cmp x24, x9
    b.hi 90f
21: cbz x24, 99f
    mov x0, x23
    mov x1, x19
    add x2, x20, #1
    bl _cbor_skip
    mov x23, x0
    sub x24, x24, #1
    b 21b
25: cmp x23, x19
    b.hs 90f
    ldrb w9, [x23]
    cmp w9, #0xff
    b.eq 16b
    mov x0, x23
    mov x1, x19
    add x2, x20, #1
    bl _cbor_skip
    mov x23, x0
    cmp x21, #5
    b.ne 25b
    mov x1, x19
    add x2, x20, #1
    bl _cbor_skip
    mov x23, x0
    b 25b
90: FAIL "Malformed DAG-CBOR"
99: mov x0, x23
    LEAVE

// cbor_untag(x0 = p, x1 = end) -> x0 = p after any tag heads.
FN _cbor_untag
    ENTER
    mov x19, x0
    mov x20, x1
1:  cmp x19, x20
    b.hs 2f
    ldrb w9, [x19]
    lsr w9, w9, #5
    cmp w9, #6
    b.ne 2f
    mov x0, x19
    mov x1, x20
    bl _cbor_head
    mov x19, x2
    b 1b
2:  mov x0, x19
    LEAVE

// cbor_uint(x0 = p, x1 = end) -> x0 = value, x1 = 1 if an unsigned int.
FN _cbor_uint
    ENTER
    cbz x0, 9f
    mov x19, x1
    bl _cbor_untag
    mov x1, x19
    bl _cbor_head
    cbnz x0, 9f
    cmn x1, #1
    b.eq 9f
    mov x0, x1
    mov x1, #1
    LEAVE
9:  mov x0, #0
    mov x1, #0
    LEAVE

// cbor_i64(x0 = p, x1 = end) -> x0 = value, x1 = 1 if it fits an i64.
FN _cbor_i64
    ENTER
    cbz x0, 9f
    mov x19, x1
    bl _cbor_untag
    mov x1, x19
    bl _cbor_head
    cmn x1, #1
    b.eq 9f
    tbnz x1, #63, 9f
    cmp x0, #1
    b.hi 9f
    b.ne 1f
    mvn x1, x1                   // -1 - n
1:  mov x0, x1
    mov x1, #1
    LEAVE
9:  mov x0, #0
    mov x1, #0
    LEAVE

// cbor_bytes(x0 = p, x1 = end) -> x0 = ptr, x1 = len, x2 = 1 if a byte string.
// Indefinite byte strings are concatenated into the arena.
FN _cbor_bytes
    ENTER
    cbz x0, 9f
    mov x19, x1
    bl _cbor_untag
    mov x1, x19
    bl _cbor_head
    cmp x0, #2
    b.ne 9f
    cmn x1, #1
    b.eq 2f
    mov x0, x2
    mov x2, #1
    LEAVE
2:  mov x20, x2                  // chunk cursor
    bl _buf_new
    mov x21, x0
3:  ldrb w9, [x20]
    cmp w9, #0xff
    b.eq 4f
    mov x0, x20
    mov x1, x19
    bl _cbor_head
    mov x22, x2
    mov x23, x1
    mov x0, x21
    mov x1, x22
    mov x2, x23
    bl _buf_append
    add x20, x22, x23
    b 3b
4:  ldp x0, x1, [x21]
    mov x2, #1
    LEAVE
9:  mov x0, #0
    mov x1, #0
    mov x2, #0
    LEAVE

// cbor_kind(x0 = p, x1 = end) -> x0 = major type after tags, -1 if none.
FN _cbor_major
    ENTER
    cbz x0, 9f
    mov x19, x1
    bl _cbor_untag
    cmp x0, x19
    b.hs 9f
    ldrb w9, [x0]
    lsr x0, x9, #5
    LEAVE
9:  mov x0, #-1
    LEAVE

// node_view(x0 = p, x1 = end of the item, x2 = expected kind or -1)
// -> x0 = NV with the positions of the first 8 elements. The item must be a
// single valid CBOR array (tags discarded) spanning exactly [p, end).
FN _node_view
    ENTER
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x0, x19
    mov x1, x20
    mov x2, #0
    bl _cbor_skip
    cmp x0, x20
    b.ne 90f
    mov x0, #NV_SIZE
    bl _arena_alloc
    mov x22, x0
    str x20, [x22, #NV_END]
    mov x0, x19
    mov x1, x20
    bl _cbor_untag
    mov x1, x20
    bl _cbor_head
    cmp x0, #4
    b.ne 90f
    mov x23, x1                  // count or -1
    mov x24, x2                  // element cursor
    mov x25, #0
1:  cmn x23, #1
    b.ne 2f
    ldrb w9, [x24]
    cmp w9, #0xff
    b.eq 3f
    b 21f
2:  cmp x25, x23
    b.hs 3f
21: cmp x25, #8
    b.hs 22f
    add x9, x22, #NV_POS
    str x24, [x9, x25, lsl #3]
22: mov x0, x24
    mov x1, x20
    mov x2, #1
    bl _cbor_skip
    mov x24, x0
    add x25, x25, #1
    b 1b
3:  str x25, [x22, #NV_COUNT]
    cmn x21, #1
    b.eq 8f
    cbz x25, 91f
    ldr x0, [x22, #NV_POS]
    mov x1, x20
    bl _cbor_uint
    cbz x1, 91f
    cmp x0, x21
    b.ne 91f
8:  mov x0, x22
    LEAVE
90: FAIL "Invalid DAG-CBOR node"
91: FAIL "Unexpected IPLD node kind"

// nv_elem(x0 = NV, x1 = index) -> x0 = element position or 0.
FN _nv_elem
    ldr x9, [x0, #NV_COUNT]
    cmp x1, x9
    b.hs 1f
    cmp x1, #8
    b.hs 1f
    add x9, x0, #NV_POS
    ldr x0, [x9, x1, lsl #3]
    ret
1:  mov x0, #0
    ret

// item_end(x0 = p, x1 = end) -> x0 = end of the item at p.
FN _item_end
    mov x2, #1
    b _cbor_skip

// cbor_link(x0 = p, x1 = end) -> x0 = CID ptr, x1 = CID len, x2 = absent.
// The value must be a byte string 00 <CID ...>.
FN _cbor_link
    ENTER
    bl _cbor_bytes
    cbz x2, 9f
    cbz x1, 9f
    ldrb w9, [x0]
    cbnz w9, 9f
    add x19, x0, #1
    add x1, x0, x1
    mov x0, x19
    bl _cid_parse
    mov x2, x1
    mov x1, x0
    mov x0, x19
    LEAVE
9:  FAIL "Invalid CID link"

// cbor_links(x0 = p or 0, x1 = end) -> x0 = vec of {cid, len} (0 entries when
// p is not an array). Every element must be a valid link.
FN _cbor_links
    ENTER
    mov x19, x0
    mov x20, x1
    mov x0, #VEC_SIZE
    bl _arena_alloc
    mov x21, x0
    cbz x19, 8f
    mov x0, x19
    mov x1, x20
    bl _cbor_untag
    mov x19, x0
    mov x1, x20
    bl _cbor_head
    cmp x0, #4
    b.ne 8f
    mov x22, x1
    mov x23, x2
    mov x24, #0
1:  cmn x22, #1
    b.ne 2f
    ldrb w9, [x23]
    cmp w9, #0xff
    b.eq 8f
    b 3f
2:  cmp x24, x22
    b.hs 8f
3:  mov x0, x23
    mov x1, x20
    bl _item_end
    mov x25, x0
    mov x0, x23
    mov x1, x25
    bl _cbor_link
    stp x0, x1, [sp, #-16]!
    mov x0, x21
    mov x1, #16
    bl _vec_push
    ldp x9, x10, [sp], #16
    stp x9, x10, [x0]
    mov x23, x25
    add x24, x24, #1
    b 1b
8:  mov x0, x21
    LEAVE

// ===================================================================== CAR

// car_index(x0 = slice, x1 = len) -> x0 = CX.
FN _car_index
    ENTER 16
    mov x19, x0
    add x20, x0, x1              // end
    mov x0, #CX_SIZE
    bl _arena_alloc
    mov x21, x0
    mov x22, #1                  // first non-empty section
1:  cmp x19, x20
    b.hs 40f
    mov x0, x19
    mov x1, x20
    bl uvar
    mov x19, x1
    cbz x0, 1b
    mov x9, #0x2000000           // 32 MiB
    cmp x0, x9
    b.hi 91f
    sub x9, x20, x19
    cmp x0, x9
    b.hi 92f
    add x23, x19, x0             // section end
    cbz x22, 10f
    mov x22, #0
    ldrb w9, [x19]
    lsr w9, w9, #5
    cmp w9, #5
    b.ne 10f
    mov x0, x19
    mov x1, x23
    bl car_is_header
    cbz x0, 10f
    mov x19, x23
    b 1b
10: mov x0, x19
    mov x1, x23
    bl _cid_parse
    mov x24, x0                  // CID length
    mov x0, x21
    mov x1, #32
    bl _vec_push
    add x9, x19, x24
    sub x10, x23, x9
    stp x19, x24, [x0]
    stp x9, x10, [x0, #16]
    // Block detection: array head followed by the uint 2
    cbz x10, 12f
    ldrb w11, [x9]
    lsr w12, w11, #5
    cmp w12, #4
    b.ne 12f
    and w11, w11, #31
    mov x13, #1
    cmp w11, #24
    b.lo 11f
    cmp w11, #31
    b.eq 11f
    mov x13, #2
    cmp w11, #24
    b.eq 11f
    mov x13, #3
    cmp w11, #25
    b.eq 11f
    mov x13, #5
    cmp w11, #26
    b.eq 11f
    mov x13, #9
    cmp w11, #27
    b.ne 12f
11: cmp x13, x10
    b.hs 12f
    ldrb w11, [x9, x13]
    cmp w11, #2
    b.ne 12f
    stp x9, x10, [x21, #CX_BLOCK]
12: mov x19, x23
    b 1b
40: ldr x9, [x21, #CX_BLOCK]
    cbz x9, 93f
    // hash table: power of two >= 2 * entries
    ldr x22, [x21, #VEC_N]
    lsl x9, x22, #1
    mov x23, #16
41: cmp x23, x9
    b.hs 42f
    lsl x23, x23, #1
    b 41b
42: sub x9, x23, #1
    str x9, [x21, #CX_MASK]
    lsl x0, x23, #2
    bl _arena_alloc
    str x0, [x21, #CX_TAB]
    mov x24, #0
43: cmp x24, x22
    b.hs 49f
    ldr x9, [x21, #VEC_PTR]
    add x25, x9, x24, lsl #5
    ldp x0, x1, [x25]
    bl cid_hash
    ldr x9, [x21, #CX_MASK]
    ldr x10, [x21, #CX_TAB]
44: and x0, x0, x9
    ldr w11, [x10, x0, lsl #2]
    cbz w11, 46f
    // same CID already present: a later duplicate overwrites
    sub w12, w11, #1
    ldr x13, [x21, #VEC_PTR]
    add x13, x13, x12, lsl #5
    ldr x14, [x13, #8]
    ldr x15, [x25, #8]
    cmp x14, x15
    b.ne 45f
    stp x0, x9, [sp]
    ldr x0, [x13]
    ldr x1, [x25]
    mov x2, x15
    bl _memcmp
    mov w12, w0
    ldp x0, x9, [sp]
    ldr x10, [x21, #CX_TAB]
    cbnz w12, 45f
    add w11, w24, #1
    str w11, [x10, x0, lsl #2]
    b 47f
45: add x0, x0, #1
    b 44b
46: add w11, w24, #1
    str w11, [x10, x0, lsl #2]
47: add x24, x24, #1
    b 43b
49: mov x0, x21
    LEAVE 16
91: FAIL "Oversize CAR section"
92: FAIL "Truncated CAR section"
93: FAIL "CAR slice is missing its Block node"

// car_is_header(x0 = section, x1 = end) -> 1 if it is one CBOR map with a
// text key "version" (an optional CARv1 header).
    .p2align 2
car_is_header:
    ENTER TRY_SIZE
    mov x19, x0
    mov x20, x1
    mov x21, #0
    mov x0, sp
    bl _ob_try
    cbnz x0, 9f
    mov x0, x19
    mov x1, x20
    mov x2, #0
    bl _cbor_skip
    cmp x0, x20
    b.ne 8f
    mov x0, x19
    mov x1, x20
    bl _cbor_untag
    mov x1, x20
    bl _cbor_head
    cmp x0, #5
    b.ne 8f
    mov x22, x1                  // pairs (-1 = indefinite)
    mov x23, x2
    mov x24, #0
1:  cmn x22, #1
    b.ne 2f
    ldrb w9, [x23]
    cmp w9, #0xff
    b.eq 8f
    b 3f
2:  cmp x24, x22
    b.hs 8f
3:  mov x0, x23
    mov x1, x20
    bl _cbor_untag
    mov x25, x0
    mov x1, x20
    bl _cbor_head
    cmp x0, #3
    b.ne 4f
    cmp x1, #7
    b.ne 4f
    mov x0, x2
    LA x1, Lversion
    mov x2, #7
    bl _memcmp
    cbnz w0, 4f
    mov x21, #1
4:  mov x0, x23
    mov x1, x20
    bl _item_end
    mov x1, x20
    bl _item_end
    mov x23, x0
    add x24, x24, #1
    b 1b
8:  mov x0, sp
    bl _ob_untry
9:  mov x0, x21
    LEAVE TRY_SIZE

// cid_hash(x0 = ptr, x1 = len) -> x0 = FNV-1a 64.
    .p2align 2
cid_hash:
    MOV64 x9, 0xcbf29ce484222325
    MOV64 x10, 0x100000001b3
1:  cbz x1, 2f
    ldrb w11, [x0], #1
    eor x9, x9, x11
    mul x9, x9, x10
    sub x1, x1, #1
    b 1b
2:  mov x0, x9
    ret

// car_find(x0 = CX, x1 = CID ptr, x2 = CID len) -> x0 = node, x1 = len, or
// x0 = 0 when the CID is not in the slice.
FN _car_find
    ENTER
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x0, x20
    mov x1, x21
    bl cid_hash
    mov x22, x0
1:  ldr x9, [x19, #CX_MASK]
    and x22, x22, x9
    ldr x10, [x19, #CX_TAB]
    ldr w11, [x10, x22, lsl #2]
    cbz w11, 8f
    sub w11, w11, #1
    ldr x12, [x19, #VEC_PTR]
    add x23, x12, x11, lsl #5
    ldr x9, [x23, #8]
    cmp x9, x21
    b.ne 2f
    ldr x0, [x23]
    mov x1, x20
    mov x2, x21
    bl _memcmp
    cbnz w0, 2f
    ldp x0, x1, [x23, #16]
    LEAVE
2:  add x22, x22, #1
    b 1b
8:  mov x0, #0
    mov x1, #0
    LEAVE

// car_node(x0 = CX, x1 = CID ptr, x2 = len, x3 = kind) -> x0 = NV.
FN _car_node
    ENTER
    mov x19, x3
    bl _car_find
    cbz x0, 9f
    add x1, x0, x1
    mov x2, x19
    bl _node_view
    LEAVE
9:  FAIL "CID missing from CAR slice"

// ============================================================= DataFrames

// df_payload(x0 = CX, x1 = DataFrame item position, x2 = enclosing end)
// -> x0 = payload ptr, x1 = len.
FN _df_payload
    ENTER 32
    cbz x1, 93f
    mov x19, x0
    mov x0, x1
    mov x1, x2
    mov x20, x0
    bl _item_end
    mov x1, x0
    mov x0, x20
    mov x2, #6
    bl _node_view
    mov x20, x0                  // NV of the first frame
    // hash
    mov x1, #1
    bl _nv_elem
    ldr x1, [x20, #NV_END]
    bl _cbor_uint
    stp x0, x1, [sp, #16]        // expected hash, has hash
    mov x0, x20
    bl df_data
    mov x21, x0
    mov x22, x1
    mov x0, x20
    bl df_next
    mov x23, x0                  // vec of links
    ldr x9, [x23, #VEC_N]
    cbz x9, 50f
    bl _buf_new
    mov x24, x0
    mov x1, x21
    mov x2, x22
    bl _buf_append
    // stack (vec of {cid, len}) and visited (vec of {cid, len})
    mov x0, #VEC_SIZE
    bl _arena_alloc
    mov x25, x0
    mov x0, #VEC_SIZE
    bl _arena_alloc
    mov x26, x0
    mov x0, x25
    mov x1, x23
    bl push_reversed
10: ldr x9, [x25, #VEC_N]
    cbz x9, 40f
    sub x9, x9, #1
    str x9, [x25, #VEC_N]
    ldr x10, [x25, #VEC_PTR]
    add x10, x10, x9, lsl #4
    ldp x27, x28, [x10]          // cid, len
    // visited?
    ldr x11, [x26, #VEC_N]
    mov x12, #0
11: cmp x12, x11
    b.hs 13f
    ldr x13, [x26, #VEC_PTR]
    add x13, x13, x12, lsl #4
    ldr x14, [x13, #8]
    cmp x14, x28
    b.ne 12f
    stp x11, x12, [sp]
    ldr x0, [x13]
    mov x1, x27
    mov x2, x28
    bl _memcmp
    ldp x11, x12, [sp]
    cbz w0, 91f
12: add x12, x12, #1
    b 11b
13: mov x0, x26
    mov x1, #16
    bl _vec_push
    stp x27, x28, [x0]
    mov x0, x19
    mov x1, x27
    mov x2, x28
    mov x3, #6
    bl _car_node
    mov x20, x0
    bl df_data
    mov x2, x1
    mov x1, x0
    mov x0, x24
    bl _buf_append
    mov x0, x20
    bl df_next
    mov x1, x0
    mov x0, x25
    bl push_reversed
    b 10b
40: ldp x21, x22, [x24]
50: ldr x9, [sp, #24]
    cbz x9, 60f
    mov x0, x21
    mov x1, x22
    bl _crc64
    ldr x9, [sp, #16]
    cmp x0, x9
    b.eq 60f
    mov x0, x21
    mov x1, x22
    bl _fnv1a
    ldr x9, [sp, #16]
    cmp x0, x9
    b.ne 92f
60: mov x0, x21
    mov x1, x22
    LEAVE 32
91: FAIL "Repeated DataFrame CID"
92: FAIL "DataFrame hash mismatch"
93: FAIL "Expected a DataFrame"

// df_data(x0 = NV) -> x0/x1 = element 4 if it is a byte string, else empty.
    .p2align 2
df_data:
    ENTER
    mov x19, x0
    mov x1, #4
    bl _nv_elem
    ldr x1, [x19, #NV_END]
    bl _cbor_bytes
    cbnz x2, 1f
    mov x0, #0
    mov x1, #0
1:  LEAVE

// df_next(x0 = NV) -> vec of next links (empty unless a non-empty array).
    .p2align 2
df_next:
    ENTER
    mov x19, x0
    mov x1, #5
    bl _nv_elem
    ldr x1, [x19, #NV_END]
    bl _cbor_links
    LEAVE

// push_reversed(x0 = stack vec, x1 = links vec): push so pop yields links[0].
    .p2align 2
push_reversed:
    ENTER
    mov x19, x0
    mov x20, x1
    ldr x21, [x20, #VEC_N]
1:  cbz x21, 2f
    sub x21, x21, #1
    ldr x9, [x20, #VEC_PTR]
    add x9, x9, x21, lsl #4
    ldp x22, x23, [x9]
    mov x0, x19
    mov x1, #16
    bl _vec_push
    stp x22, x23, [x0]
    b 1b
2:  LEAVE

// ================================================================== hashes

// crc64(x0 = ptr, x1 = len) -> CRC-64/GO-ISO (reflected poly 0xD8..., init
// and xorout all ones).
FN _crc64
    LA x9, g_crc_table
    ldr x10, [x9, #8]            // built?
    cbnz x10, 1f
    // build the table
    MOV64 x13, 0xd800000000000000
    mov x10, #0
3:  mov x11, x10
    mov x12, #8
4:  tst x11, #1
    lsr x11, x11, #1
    b.eq 5f
    eor x11, x11, x13
5:  subs x12, x12, #1
    b.ne 4b
    str x11, [x9, x10, lsl #3]
    add x10, x10, #1
    cmp x10, #256
    b.lo 3b
1:  mov x10, #-1
2:  cbz x1, 6f
    ldrb w11, [x0], #1
    eor x12, x10, x11
    and x12, x12, #0xff
    ldr x12, [x9, x12, lsl #3]
    eor x10, x12, x10, lsr #8
    sub x1, x1, #1
    b 2b
6:  mvn x0, x10
    ret

// fnv1a(x0 = ptr, x1 = len) -> FNV-1a 64.
FN _fnv1a
    b cid_hash

    .section __TEXT,__cstring
Lversion: .asciz "version"

    .zerofill __DATA,__bss,g_crc_table,2048,3
