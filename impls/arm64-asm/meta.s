// meta.s: transaction metadata and block rewards (WIRE_FORMATS §9-§12):
// zstd frame unwrapping with raw fallback, the epoch-157 protobuf/bincode
// split, protobuf TransactionStatusMeta and Rewards, the five bincode
// metadata layouts, bincode rewards and TransactionError JSON.

.include "defs.s"

    .text

// ================================================================ entry

// meta_decode(x0 = frame, x1 = len) -> x0 = model, or 0 for an empty frame.
FN _meta_decode
    mov x2, #0
    b unwrap

// meta_default -> a model with every optional field absent.
FN _meta_default
    mov x0, #MT_SIZE
    b _arena_alloc

// block_rewards(x0 = CX, x1 = Block NV): ,"rewards":[...][,"numRewardPartitions":n]
FN _block_rewards
    ENTER 16
    mov x19, x0
    mov x20, x1
    STG xzr, g_rw_vec, x9
    STG xzr, g_parts_has, x9
    mov x0, x20
    mov x1, #5
    bl _nv_elem
    cbz x0, 8f
    mov x21, x0
    ldr x1, [x20, #NV_END]
    bl _cbor_major
    cmp x0, #2
    b.ne 8f
    mov x0, x21
    ldr x1, [x20, #NV_END]
    bl _cbor_link
    cbnz x2, 8f                  // empty identity CID: no rewards
    mov x2, x1
    mov x1, x0
    mov x0, x19
    bl _car_find
    cbz x0, 8f                   // not in the slice: no rewards
    add x1, x0, x1
    mov x2, #5
    bl _node_view
    mov x21, x0
    ldr x9, [x21, #NV_COUNT]
    cmp x9, #2
    b.ls 8f
    mov x1, #2
    bl _nv_elem
    mov x1, x0
    ldr x2, [x21, #NV_END]
    mov x0, x19
    bl _df_payload
    cbz x1, 8f
    mov x2, #1
    bl unwrap
8:  PUTS ",\"rewards\":"
    LDG x0, g_rw_vec
    cbnz x0, 9f
    mov x0, #VEC_SIZE
    bl _arena_alloc
9:  bl _rewards_json
    LDG x9, g_parts_has
    cbz x9, 10f
    LDG x1, g_parts
    FMT ",\"numRewardPartitions\":%u"
10: LEAVE 16

// unwrap(x0 = frame, x1 = len, x2 = kind: 0 metadata, 1 rewards) -> model
// (metadata) — WIRE_FORMATS §9.1.
    .p2align 2
unwrap:
    ENTER TRY_SIZE + 32
    mov x19, x0
    mov x20, x1
    mov x21, x2
    cbz x20, 90f
    cmp x20, #4
    b.lo 20f
    ldr w9, [x19]
    MOV64 x10, 0xfd2fb528
    cmp w9, w10
    b.ne 20f
    // zstd magic: decompress; on failure decode the raw bytes
    mov x0, sp
    bl _ob_try
    cbnz x0, 15f
    mov x0, x19
    mov x1, x20
    bl _zstd_decompress
    stp x0, x1, [sp, #TRY_SIZE]
    mov x0, sp
    bl _ob_untry
    ldp x0, x1, [sp, #TRY_SIZE]
    mov x2, x21
    bl payload
    LEAVE TRY_SIZE + 32
15: mov x0, x19
    mov x1, x20
    mov x2, x21
    bl payload
    LEAVE TRY_SIZE + 32
20: // no magic: raw first, zstd as the fallback
    mov x0, sp
    bl _ob_try
    cbnz x0, 25f
    mov x0, x19
    mov x1, x20
    mov x2, x21
    bl payload
    str x0, [sp, #TRY_SIZE]
    mov x0, sp
    bl _ob_untry
    ldr x0, [sp, #TRY_SIZE]
    LEAVE TRY_SIZE + 32
25: LDG x9, _g_err_code
    LDG x10, _g_err_msg
    stp x9, x10, [sp, #TRY_SIZE + 16]
    mov x0, sp
    bl _ob_try
    cbnz x0, 28f
    mov x0, x19
    mov x1, x20
    bl _zstd_decompress
    stp x0, x1, [sp, #TRY_SIZE]
    mov x0, sp
    bl _ob_untry
    ldp x0, x1, [sp, #TRY_SIZE]
    mov x2, x21
    bl payload
    LEAVE TRY_SIZE + 32
28: ldp x0, x1, [sp, #TRY_SIZE + 16]
    bl _ob_throw
90: mov x0, #0
    LEAVE TRY_SIZE + 32

// payload(x0 = bytes, x1 = len, x2 = kind) -> model (metadata) — §9.2.
    .p2align 2
payload:
    ENTER TRY_SIZE + 16
    mov x19, x0
    mov x20, x1
    mov x21, x2
    LDG x9, _gb_slot
    MOV64 x10, BINCODE_CUTOFF
    cmp x9, x10
    b.hs 20f
    // pre-157: bincode first, protobuf as the fallback
    mov x0, sp
    bl _ob_try
    cbnz x0, 10f
    mov x0, x19
    mov x1, x20
    cbnz x21, 5f
    bl bc_meta
    b 6f
5:  bl bc_rewards
6:  str x0, [sp, #TRY_SIZE]
    mov x0, sp
    bl _ob_untry
    ldr x0, [sp, #TRY_SIZE]
    LEAVE TRY_SIZE + 16
10: mov x0, x19
    mov x1, x20
    cbnz x21, 11f
    bl pb_meta
    bl pb_meta_convert
    LEAVE TRY_SIZE + 16
11: bl pb_rewards
    LEAVE TRY_SIZE + 16
20: // modern: protobuf first; only a parse failure falls back to bincode
    mov x0, sp
    bl _ob_try
    cbnz x0, 30f
    mov x0, x19
    mov x1, x20
    cbnz x21, 21f
    bl pb_meta
    b 22f
21: bl pb_rewards
22: str x0, [sp, #TRY_SIZE]
    mov x0, sp
    bl _ob_untry
    ldr x0, [sp, #TRY_SIZE]
    cbnz x21, 23f
    bl pb_meta_convert
23: LEAVE TRY_SIZE + 16
30: mov x0, x19
    mov x1, x20
    cbnz x21, 31f
    bl bc_meta
    LEAVE TRY_SIZE + 16
31: bl bc_rewards
    LEAVE TRY_SIZE + 16

// ============================================================= protobuf

// pb_field(x0 = p, x1 = end) -> x0 = field, x1 = wire type, x2 = varint
// value or payload ptr, x3 = payload length, x4 = next position.
    .p2align 2
pb_field:
    ENTER
    mov x19, x1
    mov x1, x19
    bl _uvarint
    lsr x9, x0, #32
    cbnz x9, 90f
    cmp x0, #8
    b.lo 90f
    lsr x20, x0, #3              // field
    and x21, x0, #7              // wire
    mov x22, x1                  // position
    cmp x21, #0
    b.ne 1f
    mov x0, x22
    mov x1, x19
    bl _uvarint
    mov x2, x0
    mov x4, x1
    b 8f
1:  cmp x21, #1
    b.ne 2f
    add x4, x22, #8
    cmp x4, x19
    b.hi 90f
    mov x2, x22
    b 8f
2:  cmp x21, #2
    b.ne 3f
    mov x0, x22
    mov x1, x19
    bl _uvarint
    sub x9, x19, x1
    cmp x0, x9
    b.hi 90f
    mov x2, x1
    mov x3, x0
    add x4, x1, x0
    b 8f
3:  cmp x21, #5
    b.ne 4f
    add x4, x22, #4
    cmp x4, x19
    b.hi 90f
    mov x2, x22
    b 8f
4:  cmp x21, #3
    b.ne 90f
    mov x0, x22
    mov x1, x19
    mov x2, x20
    mov x3, #0
    bl pb_group
    mov x4, x0
8:  mov x0, x20
    mov x1, x21
    LEAVE
90: FAIL "Malformed protobuf"

// pb_group(x0 = p, x1 = end, x2 = field, x3 = depth) -> position after the
// matching end-group key.
    .p2align 2
pb_group:
    ENTER
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    cmp x22, #100
    b.hs 90f
1:  mov x0, x19
    mov x1, x20
    bl _uvarint
    lsr x9, x0, #32
    cbnz x9, 90f
    cmp x0, #8
    b.lo 90f
    lsr x23, x0, #3
    and x24, x0, #7
    mov x19, x1
    cmp x24, #4
    b.ne 2f
    cmp x23, x21
    b.ne 90f
    mov x0, x19
    LEAVE
2:  cmp x24, #0
    b.ne 3f
    mov x0, x19
    mov x1, x20
    bl _uvarint
    mov x19, x1
    b 1b
3:  cmp x24, #1
    b.ne 4f
    add x19, x19, #8
    b 7f
4:  cmp x24, #5
    b.ne 5f
    add x19, x19, #4
    b 7f
5:  cmp x24, #2
    b.ne 6f
    mov x0, x19
    mov x1, x20
    bl _uvarint
    sub x9, x20, x1
    cmp x0, x9
    b.hi 90f
    add x19, x1, x0
    b 1b
6:  cmp x24, #3
    b.ne 90f
    mov x0, x19
    mov x1, x20
    mov x2, x23
    add x3, x22, #1
    bl pb_group
    mov x19, x0
    b 1b
7:  cmp x19, x20
    b.hi 90f
    b 1b
90: FAIL "Malformed protobuf group"

// Field loop helper: x25 = cursor, x26 = end. Loads the next field into
// x20 (field), x21 (wire), x22 (value/ptr), x23 (len). Returns x0 = 0 at end.
.macro PB_NEXT done
    cmp x25, x26
    b.hs \done
    mov x0, x25
    mov x1, x26
    bl pb_field
    mov x20, x0
    mov x21, x1
    mov x22, x2
    mov x23, x3
    mov x25, x4
.endm

.macro WIRE w
    cmp x21, #\w
    b.ne pb_bad
.endm

pb_bad:
    FAIL "Protobuf field has the wrong wire type"

// pb_utf8(x22 = ptr, x23 = len): throws unless valid UTF-8.
    .p2align 2
pb_utf8:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x0, x22
    mov x1, x23
    bl _utf8_valid
    cbz x0, 1f
    ldp x29, x30, [sp], #16
    ret
1:  FAIL "Protobuf string is not UTF-8"

// pb_meta(x0 = bytes, x1 = len) -> model (TransactionStatusMeta, unconverted).
    .p2align 2
pb_meta:
    ENTER
    mov x25, x0
    add x26, x0, x1
    mov x0, #MT_SIZE
    bl _arena_alloc
    mov x19, x0
    mov x9, #1
    str x9, [x19, #MT_TBHAS]
    str x9, [x19, #MT_TBHAS + 8]
    str x9, [x19, #MT_RWHAS]
1:  PB_NEXT 99f
    cmp x20, #1
    b.ne 2f
    WIRE 2
    mov x9, #1
    str x9, [x19, #MT_HASERR]
    // merge TransactionError { bytes err = 1 }
    stp x25, x26, [sp, #-16]!
    mov x25, x22
    add x26, x22, x23
11: PB_NEXT 12f
    cmp x20, #1
    b.ne 11b
    WIRE 2
    stp x22, x23, [x19, #MT_ERR]
    b 11b
12: ldp x25, x26, [sp], #16
    b 1b
2:  cmp x20, #2
    b.ne 3f
    WIRE 0
    str x22, [x19, #MT_FEE]
    b 1b
3:  cmp x20, #3
    b.ne 4f
    add x0, x19, #MT_PRE
    bl pb_u64s
    b 1b
4:  cmp x20, #4
    b.ne 5f
    add x0, x19, #MT_POST
    bl pb_u64s
    b 1b
5:  cmp x20, #5
    b.ne 6f
    WIRE 2
    mov x0, x19
    bl pb_inner
    b 1b
6:  cmp x20, #6
    b.ne 7f
    WIRE 2
    bl pb_utf8
    add x0, x19, #MT_LOG
    mov x1, #16
    bl _vec_push
    stp x22, x23, [x0]
    b 1b
7:  cmp x20, #7
    b.lo 9f
    cmp x20, #8
    b.hi 9f
    WIRE 2
    sub x9, x20, #7
    mov x10, #VEC_SIZE
    madd x0, x9, x10, x19
    add x0, x0, #MT_TB
    bl pb_token
    b 1b
9:  cmp x20, #9
    b.ne 10f
    WIRE 2
    add x0, x19, #MT_RW
    bl pb_reward
    b 1b
10: cmp x20, #10
    b.ne 13f
    WIRE 0
    cmp x22, #0
    cset x9, ne
    str x9, [x19, #MT_INNNONE]
    b 1b
13: cmp x20, #11
    b.ne 14f
    WIRE 0
    cmp x22, #0
    cset x9, ne
    str x9, [x19, #MT_LOGNONE]
    b 1b
14: cmp x20, #12
    b.lo 16f
    cmp x20, #13
    b.hi 16f
    WIRE 2
    add x0, x19, #MT_LW
    cmp x20, #13
    b.ne 15f
    add x0, x19, #MT_LR
15: mov x1, #16
    bl _vec_push
    stp x22, x23, [x0]
    b 1b
16: cmp x20, #14
    b.ne 18f
    WIRE 2
    mov x9, #1
    str x9, [x19, #MT_RDHAS]
    stp x25, x26, [sp, #-16]!
    mov x25, x22
    add x26, x22, x23
17: PB_NEXT 171f
    cmp x20, #1
    b.ne 172f
    WIRE 2
    stp x22, x23, [x19, #MT_RDPID]
    b 17b
172: cmp x20, #2
    b.ne 17b
    WIRE 2
    stp x22, x23, [x19, #MT_RDDATA]
    b 17b
171: ldp x25, x26, [sp], #16
    b 1b
18: cmp x20, #15
    b.ne 19f
    WIRE 0
    cmp x22, #0
    cset x9, ne
    str x9, [x19, #MT_RDNONE]
    b 1b
19: cmp x20, #16
    b.ne 20f
    WIRE 0
    mov x9, #1
    stp x9, x22, [x19, #MT_CUHAS]
    b 1b
20: cmp x20, #17
    b.ne 1b
    WIRE 0
    mov x9, #1
    stp x9, x22, [x19, #MT_COSTHAS]
    b 1b
99: mov x0, x19
    LEAVE

// pb_u64s(x0 = vec): a repeated uint64 field, packed or not (x21 = wire).
    .p2align 2
pb_u64s:
    ENTER
    mov x19, x0
    cmp x21, #0
    b.ne 1f
    mov x1, #8
    bl _vec_push
    str x22, [x0]
    LEAVE
1:  cmp x21, #2
    b.ne pb_bad
    mov x20, x22
    add x21, x22, x23
2:  cmp x20, x21
    b.hs 3f
    mov x0, x20
    mov x1, x21
    bl _uvarint
    mov x20, x1
    mov x22, x0
    mov x0, x19
    mov x1, #8
    bl _vec_push
    str x22, [x0]
    b 2b
3:  LEAVE

// pb_inner(x0 = model): InnerInstructions at x22/x23.
    .p2align 2
pb_inner:
    ENTER
    mov x19, x0
    add x0, x19, #MT_INN
    mov x1, #GR_SIZE
    bl _vec_push
    mov x24, x0                  // group
    mov x25, x22
    add x26, x22, x23
1:  PB_NEXT 9f
    cmp x20, #1
    b.ne 2f
    WIRE 0
    and x9, x22, #0xff
    str x9, [x24, #GR_INDEX]
    b 1b
2:  cmp x20, #2
    b.ne 1b
    WIRE 2
    add x0, x24, #GR_IXS
    mov x1, #IX_SIZE
    bl _vec_push
    mov x27, x0
    mov x9, #-1
    str x9, [x27, #IX_STACK]
    stp x25, x26, [sp, #-16]!
    mov x25, x22
    add x26, x22, x23
3:  PB_NEXT 8f
    cmp x20, #1
    b.ne 4f
    WIRE 0
    and x9, x22, #0xff
    str x9, [x27, #IX_PID]
    b 3b
4:  cmp x20, #2
    b.ne 5f
    WIRE 2
    stp x22, x23, [x27, #IX_ACC]
    b 3b
5:  cmp x20, #3
    b.ne 6f
    WIRE 2
    stp x22, x23, [x27, #IX_DATA]
    b 3b
6:  cmp x20, #4
    b.ne 3b
    WIRE 0
    mov w9, w22
    str x9, [x27, #IX_STACK]
    b 3b
8:  ldp x25, x26, [sp], #16
    b 1b
9:  LEAVE

// pb_token(x0 = vec): TokenBalance at x22/x23.
    .p2align 2
pb_token:
    ENTER
    mov x1, #TB_SIZE
    bl _vec_push
    mov x24, x0
    mov x25, x22
    add x26, x22, x23
1:  PB_NEXT 9f
    cmp x20, #1
    b.ne 2f
    WIRE 0
    and x9, x22, #0xff
    str x9, [x24, #TB_AI]
    b 1b
2:  cmp x20, #2
    b.ne 3f
    WIRE 2
    bl pb_utf8
    stp x22, x23, [x24, #TB_MINT]
    b 1b
3:  cmp x20, #3
    b.ne 6f
    WIRE 2
    stp x25, x26, [sp, #-16]!
    mov x25, x22
    add x26, x22, x23
31: PB_NEXT 39f
    cmp x20, #1
    b.ne 32f
    WIRE 1
    ldr d0, [x22]
    str d0, [x24, #TB_UI]
    fabs d1, d0
    MOV64 x9, 0x3cb0000000000000 // f64 epsilon 2^-52
    fmov d2, x9
    fcmp d1, d2
    cset x9, gt
    str x9, [x24, #TB_UIHAS]
    b 31b
32: cmp x20, #2
    b.ne 33f
    WIRE 0
    and x9, x22, #0xff
    str x9, [x24, #TB_DEC]
    b 31b
33: cmp x20, #3
    b.ne 34f
    WIRE 2
    bl pb_utf8
    stp x22, x23, [x24, #TB_AMT]
    b 31b
34: cmp x20, #4
    b.ne 31b
    WIRE 2
    bl pb_utf8
    stp x22, x23, [x24, #TB_UAS]
    b 31b
39: ldp x25, x26, [sp], #16
    b 1b
6:  cmp x20, #4
    b.ne 7f
    WIRE 2
    bl pb_utf8
    stp x22, x23, [x24, #TB_OWNER]
    b 1b
7:  cmp x20, #5
    b.ne 1b
    WIRE 2
    bl pb_utf8
    stp x22, x23, [x24, #TB_PROG]
    b 1b
9:  LEAVE

// pb_reward(x0 = vec): Reward at x22/x23 (WIRE_FORMATS §10.3).
    .p2align 2
pb_reward:
    ENTER 32
    mov x1, #RW_SIZE
    bl _vec_push
    mov x24, x0
    stp xzr, xzr, [sp]           // commission text
    stp xzr, xzr, [sp, #16]      // commission_bps text
    mov x27, #0                  // reward_type
    mov x25, x22
    add x26, x22, x23
1:  PB_NEXT 9f
    cmp x20, #1
    b.ne 2f
    WIRE 2
    bl pb_utf8
    stp x22, x23, [x24, #RW_PK]
    b 1b
2:  cmp x20, #2
    b.ne 3f
    WIRE 0
    str x22, [x24, #RW_LAM]
    b 1b
3:  cmp x20, #3
    b.ne 4f
    WIRE 0
    str x22, [x24, #RW_PB]
    b 1b
4:  cmp x20, #4
    b.ne 5f
    WIRE 0
    mov w27, w22
    b 1b
5:  cmp x20, #5
    b.ne 6f
    WIRE 2
    bl pb_utf8
    stp x22, x23, [sp]
    b 1b
6:  cmp x20, #6
    b.ne 1b
    WIRE 2
    bl pb_utf8
    stp x22, x23, [sp, #16]
    b 1b
9:  sub x10, x27, #1            // reward_type 1..4 kept, anything else -> none
    cmp x10, #3
    csel x9, x27, xzr, ls
    str x9, [x24, #RW_TYPE]
    mov x9, #-1
    str x9, [x24, #RW_COMM]
    ldp x0, x1, [sp]
    cbz x0, 10f
    bl _parse_u64_text
    cbz x1, 10f
    cmp x0, #255
    b.hi 10f
    str x0, [x24, #RW_COMM]
    LEAVE 32
10: ldp x0, x1, [sp, #16]
    cbz x0, 11f
    bl _parse_u64_text
    cbz x1, 11f
    mov x9, #65535
    cmp x0, x9
    b.hi 11f
    mov x9, #100
    udiv x0, x0, x9
    cmp x0, #255
    b.hi 11f
    str x0, [x24, #RW_COMM]
11: LEAVE 32

// pb_rewards(x0 = bytes, x1 = len): Rewards message into g_rw_vec/g_parts.
    .p2align 2
pb_rewards:
    ENTER
    mov x25, x0
    add x26, x0, x1
    mov x0, #VEC_SIZE
    bl _arena_alloc
    mov x19, x0
    STG x19, g_rw_vec, x9
    STG xzr, g_parts_has, x9
    STG xzr, g_parts, x9
1:  PB_NEXT 9f
    cmp x20, #1
    b.ne 2f
    WIRE 2
    mov x0, x19
    bl pb_reward
    b 1b
2:  cmp x20, #2
    b.ne 1b
    WIRE 2
    mov x9, #1
    STG x9, g_parts_has, x10
    stp x25, x26, [sp, #-16]!
    mov x25, x22
    add x26, x22, x23
3:  PB_NEXT 4f
    cmp x20, #1
    b.ne 3b
    WIRE 0
    STG x22, g_parts, x9
    b 3b
4:  ldp x25, x26, [sp], #16
    b 1b
9:  mov x0, #0
    LEAVE

// pb_meta_convert(x0 = model) -> model; §10.3 checks are final.
    .p2align 2
pb_meta_convert:
    ENTER
    mov x19, x0
    ldr x9, [x19, #MT_HASERR]
    cbz x9, 1f
    ldp x0, x1, [x19, #MT_ERR]
    add x1, x0, x1
    mov x2, #0
    bl _txerr
1:  ldr x9, [x19, #MT_INNNONE]
    eor x9, x9, #1
    str x9, [x19, #MT_INNHAS]
    ldr x9, [x19, #MT_LOGNONE]
    eor x9, x9, #1
    str x9, [x19, #MT_LOGHAS]
    add x0, x19, #MT_LW
    bl keys32
    add x0, x19, #MT_LR
    bl keys32
    ldr x9, [x19, #MT_RDNONE]
    cbz x9, 2f
    str xzr, [x19, #MT_RDHAS]
    b 3f
2:  ldr x9, [x19, #MT_RDHAS]
    cbz x9, 3f
    ldr x9, [x19, #MT_RDPIDLEN]
    cmp x9, #32
    b.ne 91f
3:  mov x0, x19
    LEAVE
91: FAIL "Return data program id is not 32 bytes"

// keys32(x0 = vec of {ptr, len}): every entry must be 32 bytes.
    .p2align 2
keys32:
    ldr x9, [x0, #VEC_N]
    ldr x10, [x0, #VEC_PTR]
1:  cbz x9, 2f
    ldr x11, [x10, #8]
    cmp x11, #32
    b.ne 3f
    add x10, x10, #16
    sub x9, x9, #1
    b 1b
2:  ret
3:  stp x29, x30, [sp, #-16]!
    FAIL "Loaded address is not 32 bytes"

// ================================================================ bincode
// Cursor in g_bp / g_be. Every short read throws.

    .p2align 2
bc_need:                         // x0 = bytes -> x9 = cursor (unchanged)
    LDG x9, g_bp
    LDG x10, g_be
    sub x10, x10, x9
    cmp x0, x10
    b.hi bc_bad
    ret

bc_bad:
    FAIL "Truncated bincode"

    .p2align 2
bc_u8:
    mov x11, x30
    mov x0, #1
    bl bc_need
    mov x30, x11
    ldrb w0, [x9], #1
    STG x9, g_bp, x10
    ret

    .p2align 2
bc_u32:
    mov x11, x30
    mov x0, #4
    bl bc_need
    mov x30, x11
    ldr w0, [x9], #4
    STG x9, g_bp, x10
    ret

    .p2align 2
bc_u64:
    mov x11, x30
    mov x0, #8
    bl bc_need
    mov x30, x11
    ldr x0, [x9], #8
    STG x9, g_bp, x10
    ret

// bc_skip(x0 = n) -> x0 = pointer to the n bytes.
    .p2align 2
bc_skip:
    mov x11, x30
    bl bc_need
    mov x30, x11
    add x10, x9, x0
    STG x10, g_bp, x12
    mov x0, x9
    ret

// bc_left -> x0 = remaining bytes.
    .p2align 2
bc_left:
    LDG x9, g_bp
    LDG x10, g_be
    sub x0, x10, x9
    ret

// bc_count(x0 = minimum element size) -> u64 count with count <= left and
// count <= left / min.
    .p2align 2
bc_count:
    ENTER
    mov x19, x0
    bl bc_u64
    mov x20, x0
    bl bc_left
    cmp x20, x0
    b.hi bc_bad
    udiv x9, x0, x19
    cmp x20, x9
    b.hi bc_bad
    mov x0, x20
    LEAVE

// bc_string -> x0 = ptr, x1 = len (UTF-8 checked).
    .p2align 2
bc_string:
    ENTER
    bl bc_u64
    mov x19, x0
    bl bc_left
    cmp x19, x0
    b.hi bc_bad
    mov x0, x19
    bl bc_skip
    mov x20, x0
    mov x1, x19
    bl _utf8_valid
    cbz x0, 9f
    mov x0, x20
    mov x1, x19
    LEAVE
9:  FAIL "Bincode string is not UTF-8"

// bc_option -> 0 / 1.
    .p2align 2
bc_option:
    ENTER
    bl bc_u8
    cmp x0, #1
    b.hi bc_bad
    LEAVE

// bc_cu16 -> compact-u16 (same rules as the transaction format).
    .p2align 2
bc_cu16:
    ENTER
    bl bc_u8
    tbz w0, #7, 9f
    and x19, x0, #0x7f
    bl bc_u8
    cbz w0, bc_bad
    and x9, x0, #0x7f
    orr x19, x19, x9, lsl #7
    tbz w0, #7, 8f
    bl bc_u8
    cbz w0, bc_bad
    cmp w0, #3
    b.hi bc_bad
    orr x19, x19, x0, lsl #14
8:  mov x0, x19
9:  LEAVE

// bc_meta(x0 = bytes, x1 = len) -> model: the five layouts of §11.4.
    .p2align 2
bc_meta:
    ENTER TRY_SIZE + 16
    mov x19, x0
    mov x20, x1
    LA x21, Lbc_layouts
    mov x22, #0
1:  cmp x22, #4
    b.hs 5f
    mov x0, sp
    bl _ob_try
    cbnz x0, 3f
    add x9, x21, x22, lsl #1
    ldrb w2, [x9]
    ldrb w3, [x9, #1]
    mov x0, x19
    mov x1, x20
    bl bc_meta_try
    str x0, [sp, #TRY_SIZE]
    bl bc_left
    cbnz x0, 2f
    mov x0, sp
    bl _ob_untry
    ldr x0, [sp, #TRY_SIZE]
    LEAVE TRY_SIZE + 16
2:  mov x0, sp
    bl _ob_untry
3:  add x22, x22, #1
    b 1b
5:  mov x0, x19
    mov x1, x20
    mov x2, #0
    mov x3, #3
    bl bc_meta_try
    LEAVE TRY_SIZE + 16

// bc_meta_try(x0 = bytes, x1 = len, x2 = legacy, x3 = token layout) -> model.
    .p2align 2
bc_meta_try:
    ENTER 16
    STG x0, g_bp, x9
    add x1, x0, x1
    STG x1, g_be, x9
    mov x21, x2
    mov x22, x3
    mov x0, #MT_SIZE
    bl _arena_alloc
    mov x19, x0
    bl bc_u32
    cmp x0, #1
    b.hi bc_bad
    b.ne 1f
    LDG x0, g_bp
    LDG x1, g_be
    str x0, [x19, #MT_ERR]
    mov x2, #0
    bl _txerr
    STG x0, g_bp, x9
    ldr x9, [x19, #MT_ERR]
    sub x9, x0, x9
    str x9, [x19, #MT_ERRLEN]
    mov x9, #1
    str x9, [x19, #MT_HASERR]
1:  bl bc_u64
    str x0, [x19, #MT_FEE]
    add x0, x19, #MT_PRE
    bl bc_u64_vec
    add x0, x19, #MT_POST
    bl bc_u64_vec
    // inner instructions
    bl bc_left
    cbz x0, 30f
    bl bc_option
    cbz x0, 20f
    mov x9, #1
    str x9, [x19, #MT_INNHAS]
    mov x0, #9
    bl bc_count
    mov x23, x0
10: cbz x23, 20f
    add x0, x19, #MT_INN
    mov x1, #GR_SIZE
    bl _vec_push
    mov x24, x0
    bl bc_u8
    str x0, [x24, #GR_INDEX]
    mov x0, #4
    mov x9, #3
    cmp x21, #0
    csel x0, x0, x9, eq
    bl bc_count
    mov x25, x0
11: cbz x25, 19f
    add x0, x24, #GR_IXS
    mov x1, #IX_SIZE
    bl _vec_push
    mov x26, x0
    bl bc_u8
    str x0, [x26, #IX_PID]
    bl bc_cu16
    str x0, [x26, #IX_NACC]
    bl bc_skip
    str x0, [x26, #IX_ACC]
    bl bc_cu16
    str x0, [x26, #IX_NDATA]
    bl bc_skip
    str x0, [x26, #IX_DATA]
    mov x9, #-1
    str x9, [x26, #IX_STACK]
    cbnz x21, 12f
    bl bc_option
    cbz x0, 12f
    bl bc_u32
    str x0, [x26, #IX_STACK]
12: sub x25, x25, #1
    b 11b
19: sub x23, x23, #1
    b 10b
20: // log messages
    bl bc_left
    cbz x0, 30f
    bl bc_option
    cbz x0, 22f
    mov x9, #1
    str x9, [x19, #MT_LOGHAS]
    mov x0, #8
    bl bc_count
    mov x23, x0
21: cbz x23, 22f
    bl bc_string
    stp x0, x1, [sp]
    add x0, x19, #MT_LOG
    mov x1, #16
    bl _vec_push
    ldp x9, x10, [sp]
    stp x9, x10, [x0]
    sub x23, x23, #1
    b 21b
22: // token balances (pre, post)
    mov x27, #0
23: cmp x27, #2
    b.hs 26f
    bl bc_left
    cbz x0, 30f
    bl bc_option
    cbz x0, 25f
    mov x9, #1
    add x10, x19, #MT_TBHAS
    str x9, [x10, x27, lsl #3]
    mov x0, #1
    bl bc_count
    mov x23, x0
24: cbz x23, 25f
    mov x9, #VEC_SIZE
    madd x0, x27, x9, x19
    add x0, x0, #MT_TB
    mov x1, x22
    bl bc_token
    sub x23, x23, #1
    b 24b
25: add x27, x27, #1
    b 23b
26: // rewards
    bl bc_left
    cbz x0, 30f
    bl bc_option
    cbz x0, 27f
    mov x9, #1
    str x9, [x19, #MT_RWHAS]
    mov x0, #16
    bl bc_count
    mov x23, x0
261: cbz x23, 27f
    add x0, x19, #MT_RW
    mov x1, #1
    bl bc_reward
    sub x23, x23, #1
    b 261b
27: // return data
    bl bc_left
    cbz x0, 30f
    bl bc_option
    cbz x0, 28f
    mov x9, #1
    str x9, [x19, #MT_RDHAS]
    mov x0, #32
    bl bc_skip
    str x0, [x19, #MT_RDPID]
    mov x9, #32
    str x9, [x19, #MT_RDPIDLEN]
    bl bc_u64
    mov x23, x0
    bl bc_left
    cmp x23, x0
    b.hi bc_bad
    mov x0, x23
    bl bc_skip
    stp x0, x23, [x19, #MT_RDDATA]
28: // compute units, cost units
    bl bc_left
    cbz x0, 30f
    bl bc_option
    cbz x0, 29f
    bl bc_u64
    mov x9, #1
    stp x9, x0, [x19, #MT_CUHAS]
29: bl bc_left
    cbz x0, 30f
    bl bc_option
    cbz x0, 30f
    bl bc_u64
    mov x9, #1
    stp x9, x0, [x19, #MT_COSTHAS]
30: mov x0, x19
    LEAVE 16

// bc_u64_vec(x0 = vec): Vec<u64>, pointing straight into the input.
    .p2align 2
bc_u64_vec:
    ENTER
    mov x19, x0
    mov x0, #8
    bl bc_count
    mov x20, x0
    lsl x0, x20, #3
    bl bc_skip
    str x0, [x19, #VEC_PTR]
    str x20, [x19, #VEC_N]
    str x20, [x19, #VEC_CAP]
    LEAVE

// bc_token(x0 = vec, x1 = layout 1 V1 / 2 V2 / 3 StoredTokenBalance)
    .p2align 2
bc_token:
    ENTER
    mov x20, x1
    mov x1, #TB_SIZE
    bl _vec_push
    mov x19, x0
    bl bc_u8
    str x0, [x19, #TB_AI]
    bl bc_string
    stp x0, x1, [x19, #TB_MINT]
    mov x0, #8
    bl bc_skip
    ldr x9, [x0]
    str x9, [x19, #TB_UI]
    mov x9, #1
    str x9, [x19, #TB_UIHAS]
    bl bc_u8
    str x0, [x19, #TB_DEC]
    bl bc_string
    stp x0, x1, [x19, #TB_AMT]
    cmp x20, #2
    b.lo 9f
    bl bc_left
    cbz x0, 9f
    bl bc_string
    stp x0, x1, [x19, #TB_OWNER]
    cmp x20, #3
    b.lo 9f
    bl bc_left
    cbz x0, 9f
    bl bc_string
    stp x0, x1, [x19, #TB_PROG]
9:  LEAVE

// bc_reward(x0 = vec, x1 = extended): StoredExtendedReward (or the legacy
// reward without commission).
    .p2align 2
bc_reward:
    ENTER
    mov x20, x1
    mov x1, #RW_SIZE
    bl _vec_push
    mov x19, x0
    mov x9, #-1
    str x9, [x19, #RW_COMM]
    bl bc_string
    stp x0, x1, [x19, #RW_PK]
    bl bc_u64
    str x0, [x19, #RW_LAM]
    cbz x20, 1f
    bl bc_left
    cbz x0, 9f
1:  bl bc_u64
    str x0, [x19, #RW_PB]
    cbz x20, 2f
    bl bc_left
    cbz x0, 9f
2:  bl bc_option
    cbz x0, 3f
    bl bc_u32
    cmp x0, #3
    b.hi bc_bad
    add x0, x0, #1
    str x0, [x19, #RW_TYPE]
3:  cbz x20, 9f
    bl bc_left
    cbz x0, 9f
    bl bc_option
    cbz x0, 9f
    bl bc_u8
    str x0, [x19, #RW_COMM]
9:  LEAVE

// bc_rewards(x0 = bytes, x1 = len): §11.5 attempts into g_rw_vec.
    .p2align 2
bc_rewards:
    ENTER TRY_SIZE + 16
    mov x19, x0
    mov x20, x1
    STG xzr, g_parts_has, x9
    mov x21, #0                  // attempt: 0 strict ext, 1 strict legacy
1:  cmp x21, #2
    b.hs 5f
    mov x0, sp
    bl _ob_try
    cbnz x0, 3f
    mov x0, x19
    mov x1, x20
    cmp x21, #0
    cset x2, eq
    bl bc_rewards_try
    bl bc_left
    cbnz x0, 2f
    mov x0, sp
    bl _ob_untry
    mov x0, #0
    LEAVE TRY_SIZE + 16
2:  mov x0, sp
    bl _ob_untry
3:  add x21, x21, #1
    b 1b
5:  mov x0, x19
    mov x1, x20
    mov x2, #1
    bl bc_rewards_try
    mov x0, #0
    LEAVE TRY_SIZE + 16

// bc_rewards_try(x0 = bytes, x1 = len, x2 = extended)
    .p2align 2
bc_rewards_try:
    ENTER
    STG x0, g_bp, x9
    add x1, x0, x1
    STG x1, g_be, x9
    mov x21, x2
    mov x0, #VEC_SIZE
    bl _arena_alloc
    mov x19, x0
    STG x19, g_rw_vec, x9
    mov x0, #16
    mov x9, #25
    cmp x21, #0
    csel x0, x9, x0, eq
    bl bc_count
    mov x20, x0
1:  cbz x20, 9f
    mov x0, x19
    mov x1, x21
    bl bc_reward
    sub x20, x20, #1
    b 1b
9:  LEAVE

// ====================================================== TransactionError

// txerr(x0 = p, x1 = end, x2 = emit JSON?) -> x0 = position after the
// bincode TransactionError (trailing bytes are allowed).
FN _txerr
    ENTER
    LDG x9, g_bp
    LDG x10, g_be
    stp x9, x10, [sp, #-16]!
    STG x0, g_bp, x9
    STG x1, g_be, x9
    mov x19, x2
    bl bc_u32
    cmp x0, #39
    b.hs 90f
    mov x20, x0
    LA x21, Lte_names
    cmp x20, #8
    b.ne 10f
    bl bc_u8
    mov x22, x0
    bl bc_u32
    cmp x0, #54
    b.hs 90f
    mov x23, x0
    cmp x23, #25
    b.ne 5f
    bl bc_u32
    cbz x19, 80f
    mov x2, x0
    mov x1, x22
    FMT "{\"InstructionError\":[%u,{\"Custom\":%u}]}"
    b 80f
5:  cbz x19, 80f
    LA x9, Lie_names
    ldr x2, [x9, x23, lsl #3]
    mov x1, x22
    FMT "{\"InstructionError\":[%u,\"%s\"]}"
    b 80f
10: cmp x20, #30
    b.ne 11f
    bl bc_u8
    cbz x19, 80f
    mov x1, x0
    FMT "{\"DuplicateInstruction\":%u}"
    b 80f
11: cmp x20, #31
    b.eq 12f
    cmp x20, #35
    b.ne 13f
12: bl bc_u8
    cbz x19, 80f
    mov x2, x0
    ldr x1, [x21, x20, lsl #3]
    FMT "{\"%s\":{\"account_index\":%u}}"
    b 80f
13: cbz x19, 80f
    ldr x1, [x21, x20, lsl #3]
    FMT "\"%s\""
80: LDG x0, g_bp
    ldp x9, x10, [sp], #16
    STG x9, g_bp, x11
    STG x10, g_be, x11
    LEAVE
90: FAIL "Invalid TransactionError"

    .section __TEXT,__const
// (legacy, token layout) for the four strict bincode attempts.
Lbc_layouts: .byte 0, 3, 1, 1, 1, 2, 1, 3

    .section __TEXT,__cstring
Lie0:  .asciz "GenericError"
Lie1:  .asciz "InvalidArgument"
Lie2:  .asciz "InvalidInstructionData"
Lie3:  .asciz "InvalidAccountData"
Lie4:  .asciz "AccountDataTooSmall"
Lie5:  .asciz "InsufficientFunds"
Lie6:  .asciz "IncorrectProgramId"
Lie7:  .asciz "MissingRequiredSignature"
Lie8:  .asciz "AccountAlreadyInitialized"
Lie9:  .asciz "UninitializedAccount"
Lie10: .asciz "UnbalancedInstruction"
Lie11: .asciz "ModifiedProgramId"
Lie12: .asciz "ExternalAccountLamportSpend"
Lie13: .asciz "ExternalAccountDataModified"
Lie14: .asciz "ReadonlyLamportChange"
Lie15: .asciz "ReadonlyDataModified"
Lie16: .asciz "DuplicateAccountIndex"
Lie17: .asciz "ExecutableModified"
Lie18: .asciz "RentEpochModified"
Lie19: .asciz "NotEnoughAccountKeys"
Lie20: .asciz "AccountDataSizeChanged"
Lie21: .asciz "AccountNotExecutable"
Lie22: .asciz "AccountBorrowFailed"
Lie23: .asciz "AccountBorrowOutstanding"
Lie24: .asciz "DuplicateAccountOutOfSync"
Lie25: .asciz "Custom"
Lie26: .asciz "InvalidError"
Lie27: .asciz "ExecutableDataModified"
Lie28: .asciz "ExecutableLamportChange"
Lie29: .asciz "ExecutableAccountNotRentExempt"
Lie30: .asciz "UnsupportedProgramId"
Lie31: .asciz "CallDepth"
Lie32: .asciz "MissingAccount"
Lie33: .asciz "ReentrancyNotAllowed"
Lie34: .asciz "MaxSeedLengthExceeded"
Lie35: .asciz "InvalidSeeds"
Lie36: .asciz "InvalidRealloc"
Lie37: .asciz "ComputationalBudgetExceeded"
Lie38: .asciz "PrivilegeEscalation"
Lie39: .asciz "ProgramEnvironmentSetupFailure"
Lie40: .asciz "ProgramFailedToComplete"
Lie41: .asciz "ProgramFailedToCompile"
Lie42: .asciz "Immutable"
Lie43: .asciz "IncorrectAuthority"
Lie44: .asciz "BorshIoError"
Lie45: .asciz "AccountNotRentExempt"
Lie46: .asciz "InvalidAccountOwner"
Lie47: .asciz "ArithmeticOverflow"
Lie48: .asciz "UnsupportedSysvar"
Lie49: .asciz "IllegalOwner"
Lie50: .asciz "MaxAccountsDataAllocationsExceeded"
Lie51: .asciz "MaxAccountsExceeded"
Lie52: .asciz "MaxInstructionTraceLengthExceeded"
Lie53: .asciz "BuiltinProgramsMustConsumeComputeUnits"
Lte0:  .asciz "AccountInUse"
Lte1:  .asciz "AccountLoadedTwice"
Lte2:  .asciz "AccountNotFound"
Lte3:  .asciz "ProgramAccountNotFound"
Lte4:  .asciz "InsufficientFundsForFee"
Lte5:  .asciz "InvalidAccountForFee"
Lte6:  .asciz "AlreadyProcessed"
Lte7:  .asciz "BlockhashNotFound"
Lte8:  .asciz "InstructionError"
Lte9:  .asciz "CallChainTooDeep"
Lte10: .asciz "MissingSignatureForFee"
Lte11: .asciz "InvalidAccountIndex"
Lte12: .asciz "SignatureFailure"
Lte13: .asciz "InvalidProgramForExecution"
Lte14: .asciz "SanitizeFailure"
Lte15: .asciz "ClusterMaintenance"
Lte16: .asciz "AccountBorrowOutstanding"
Lte17: .asciz "WouldExceedMaxBlockCostLimit"
Lte18: .asciz "UnsupportedVersion"
Lte19: .asciz "InvalidWritableAccount"
Lte20: .asciz "WouldExceedMaxAccountCostLimit"
Lte21: .asciz "WouldExceedAccountDataBlockLimit"
Lte22: .asciz "TooManyAccountLocks"
Lte23: .asciz "AddressLookupTableNotFound"
Lte24: .asciz "InvalidAddressLookupTableOwner"
Lte25: .asciz "InvalidAddressLookupTableData"
Lte26: .asciz "InvalidAddressLookupTableIndex"
Lte27: .asciz "InvalidRentPayingAccount"
Lte28: .asciz "WouldExceedMaxVoteCostLimit"
Lte29: .asciz "WouldExceedAccountDataTotalLimit"
Lte30: .asciz "DuplicateInstruction"
Lte31: .asciz "InsufficientFundsForRent"
Lte32: .asciz "MaxLoadedAccountsDataSizeExceeded"
Lte33: .asciz "InvalidLoadedAccountsDataSizeLimit"
Lte34: .asciz "ResanitizationNeeded"
Lte35: .asciz "ProgramExecutionTemporarilyRestricted"
Lte36: .asciz "UnbalancedTransaction"
Lte37: .asciz "ProgramCacheHitMaxLimit"
Lte38: .asciz "CommitCancelled"

    .section __DATA,__const
    .p2align 3
Lie_names:
    .quad Lie0, Lie1, Lie2, Lie3, Lie4, Lie5, Lie6, Lie7, Lie8, Lie9
    .quad Lie10, Lie11, Lie12, Lie13, Lie14, Lie15, Lie16, Lie17, Lie18, Lie19
    .quad Lie20, Lie21, Lie22, Lie23, Lie24, Lie25, Lie26, Lie27, Lie28, Lie29
    .quad Lie30, Lie31, Lie32, Lie33, Lie34, Lie35, Lie36, Lie37, Lie38, Lie39
    .quad Lie40, Lie41, Lie42, Lie43, Lie44, Lie45, Lie46, Lie47, Lie48, Lie49
    .quad Lie50, Lie51, Lie52, Lie53
Lte_names:
    .quad Lte0, Lte1, Lte2, Lte3, Lte4, Lte5, Lte6, Lte7, Lte8, Lte9
    .quad Lte10, Lte11, Lte12, Lte13, Lte14, Lte15, Lte16, Lte17, Lte18, Lte19
    .quad Lte20, Lte21, Lte22, Lte23, Lte24, Lte25, Lte26, Lte27, Lte28, Lte29
    .quad Lte30, Lte31, Lte32, Lte33, Lte34, Lte35, Lte36, Lte37, Lte38

    .data
    .p2align 3
g_bp:        .quad 0
g_be:        .quad 0
g_rw_vec:    .quad 0
g_parts_has: .quad 0
g_parts:     .quad 0
