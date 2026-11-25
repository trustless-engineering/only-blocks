// tx.s: Solana VersionedTransaction decoding and the getBlock transaction
// serializer for every encoding and detail level (WIRE_FORMATS §8, §13,
// §14), including signer/writable flags and the reserved-key list.

.include "defs.s"

    .text

// tx_init: decode the reserved keys (§14) once.
FN _tx_init
    ENTER
    LA x19, Lreserved_text
    LA x20, g_reserved
    mov x21, #0
1:  ldr x0, [x19, x21, lsl #3]
    cbz x0, 2f
    add x1, x20, x21, lsl #5
    bl _b58_decode32
    add x21, x21, #1
    b 1b
2:  STG x21, g_nreserved, x9
    LA x0, Lupgradeable
    LA x1, g_upgradeable
    bl _b58_decode32
    LEAVE

// ============================================================== decoding

// cu16 (local): compact-u16 at x19 (end x20) -> x0; advances x19.
    .p2align 2
cu16:
    cmp x19, x20
    b.hs tx_bad
    ldrb w0, [x19], #1
    tbz w0, #7, 9f
    and x0, x0, #0x7f
    cmp x19, x20
    b.hs tx_bad
    ldrb w9, [x19], #1
    cbz w9, tx_bad
    and w10, w9, #0x7f
    orr x0, x0, x10, lsl #7
    tbz w9, #7, 9f
    cmp x19, x20
    b.hs tx_bad
    ldrb w9, [x19], #1
    cbz w9, tx_bad
    cmp w9, #3
    b.hi tx_bad
    orr x0, x0, x9, lsl #14
9:  ret

tx_bad:
    FAIL "Undecodable transaction"

// need (local): at least x0 bytes left at x19.
    .p2align 2
need:
    sub x9, x20, x19
    cmp x0, x9
    b.hi tx_bad
    ret

// tx_parse(x0 = bytes, x1 = len) -> x0 = TX. The first byte b0 picks the
// layout (§8.2): b0 < 0x80 is the signature count of a legacy or v0
// transaction, 0x81 is a v1 (SIMD-0385) transaction, anything else throws.
FN _tx_parse
    ENTER
    mov x19, x0
    add x20, x0, x1
    mov x21, x0
    mov x0, #TX_SIZE
    bl _arena_alloc
    mov x22, x0
    mov x0, #1
    bl need
    ldrb w9, [x19]
    cmp w9, #0x81
    b.eq 60f
    cmp w9, #0x80
    b.hs tx_bad
    bl cu16
    str x0, [x22, #TX_NSIG]
    lsl x0, x0, #6
    bl need
    str x19, [x22, #TX_SIGS]
    add x19, x19, x0
    mov x0, #1
    bl need
    ldrb w9, [x19], #1
    cmp w9, #128
    b.hi tx_bad
    b.ne 1f
    mov w10, #TXK_V0
    strb w10, [x22, #TX_KIND]
    mov x0, #1
    bl need
    ldrb w9, [x19], #1
1:  strb w9, [x22, #TX_NRS]
    mov x0, #2
    bl need
    ldrb w9, [x19], #1
    strb w9, [x22, #TX_NROS]
    ldrb w9, [x19], #1
    strb w9, [x22, #TX_NROU]
    bl cu16
    str x0, [x22, #TX_NKEYS]
    lsl x0, x0, #5
    bl need
    str x19, [x22, #TX_KEYS]
    add x19, x19, x0
    mov x0, #32
    bl need
    str x19, [x22, #TX_BH]
    add x19, x19, #32
    bl cu16
    mov x23, x0
    str x23, [x22, #TX_NIX]
    mov x9, #3
    mul x0, x23, x9
    bl need
    mov x9, #IX_SIZE
    mul x0, x23, x9
    bl _arena_alloc
    str x0, [x22, #TX_IXS]
    mov x24, x0
2:  cbz x23, 3f
    mov x0, #1
    bl need
    ldrb w9, [x19], #1
    str x9, [x24, #IX_PID]
    bl cu16
    bl need
    str x19, [x24, #IX_ACC]
    str x0, [x24, #IX_NACC]
    add x19, x19, x0
    bl cu16
    bl need
    str x19, [x24, #IX_DATA]
    str x0, [x24, #IX_NDATA]
    add x19, x19, x0
    mov x9, #1
    str x9, [x24, #IX_STACK]
    add x24, x24, #IX_SIZE
    sub x23, x23, #1
    b 2b
3:  ldrb w9, [x22, #TX_KIND]
    cbz w9, 5f
    bl cu16
    mov x23, x0
    str x23, [x22, #TX_NLU]
    mov x9, #34
    mul x0, x23, x9
    bl need
    mov x9, #LU_SIZE
    mul x0, x23, x9
    bl _arena_alloc
    str x0, [x22, #TX_LUS]
    mov x24, x0
4:  cbz x23, 5f
    mov x0, #32
    bl need
    str x19, [x24, #LU_KEY]
    add x19, x19, #32
    bl cu16
    bl need
    str x19, [x24, #LU_W]
    str x0, [x24, #LU_NW]
    add x19, x19, x0
    bl cu16
    bl need
    str x19, [x24, #LU_R]
    str x0, [x24, #LU_NR]
    add x19, x19, x0
    add x24, x24, #LU_SIZE
    sub x23, x23, #1
    b 4b
5:  str x21, [x22, #TX_RAW]
    sub x9, x19, x21
    str x9, [x22, #TX_RAWLEN]
    mov x0, x22
    LEAVE

60: // v1: version byte, header, config_mask, lifetime, counts, static keys,
    // config values, instruction headers, instruction payloads, then
    // num_required_signatures x 64-byte signatures at the tail.
    add x19, x19, #1
    mov w9, #TXK_V1
    strb w9, [x22, #TX_KIND]
    mov x0, #7
    bl need
    ldrb w9, [x19], #1
    strb w9, [x22, #TX_NRS]
    ldrb w9, [x19], #1
    strb w9, [x22, #TX_NROS]
    ldrb w9, [x19], #1
    strb w9, [x22, #TX_NROU]
    ldr w25, [x19], #4           // config_mask (u32 LE)
    cmp w25, #0x1f
    b.hi tx_bad                  // unknown bit
    and w9, w25, #3
    sub w9, w9, #1
    cmp w9, #1
    b.ls tx_bad                  // priorityFee needs both bits 0 and 1
    str x25, [x22, #TX_MASK]
    mov x0, #34
    bl need
    str x19, [x22, #TX_BH]
    add x19, x19, #32
    ldrb w23, [x19], #1          // num_instructions
    ldrb w24, [x19], #1          // num_addresses
    str x23, [x22, #TX_NIX]
    str x24, [x22, #TX_NKEYS]
    lsl x0, x24, #5
    bl need
    str x19, [x22, #TX_KEYS]
    add x19, x19, x0
    and w9, w25, #3
    cbz w9, 61f
    mov x0, #8
    bl need
    ldr x9, [x19], #8
    str x9, [x22, #TX_PFEE]
61: tbz w25, #2, 62f
    mov x0, #4
    bl need
    ldr w9, [x19], #4
    str x9, [x22, #TX_CUL]
62: tbz w25, #3, 63f
    mov x0, #4
    bl need
    ldr w9, [x19], #4
    str x9, [x22, #TX_LADL]
63: tbz w25, #4, 64f
    mov x0, #4
    bl need
    ldr w9, [x19], #4
    str x9, [x22, #TX_HEAP]
64: lsl x0, x23, #2
    bl need
    mov x26, x19                 // instruction headers
    add x19, x19, x0
    mov x9, #IX_SIZE
    mul x0, x23, x9
    bl _arena_alloc
    str x0, [x22, #TX_IXS]
    mov x24, x0
65: cbz x23, 66f
    ldrb w9, [x26]
    str x9, [x24, #IX_PID]
    ldrb w0, [x26, #1]           // num_accounts
    bl need
    str x19, [x24, #IX_ACC]
    str x0, [x24, #IX_NACC]
    add x19, x19, x0
    ldrh w0, [x26, #2]           // data_len (u16 LE)
    bl need
    str x19, [x24, #IX_DATA]
    str x0, [x24, #IX_NDATA]
    add x19, x19, x0
    mov x9, #1
    str x9, [x24, #IX_STACK]
    add x24, x24, #IX_SIZE
    add x26, x26, #4
    sub x23, x23, #1
    b 65b
66: ldrb w9, [x22, #TX_NRS]
    str x9, [x22, #TX_NSIG]
    lsl x0, x9, #6
    bl need
    str x19, [x22, #TX_SIGS]
    add x19, x19, x0
    b 5b

// ================================================================ the loop

// block_txs(x0 = CX, x1 = entry links): ,"transactions":[...] or
// ,"signatures":[...].
FN _block_txs
    ENTER 48
    mov x19, x0
    mov x20, x1
    LDG x9, _gb_details
    cmp x9, #2
    b.eq 1f
    PUTS ",\"transactions\":["
    b 2f
1:  PUTS ",\"signatures\":["
2:  mov x21, #0                  // entry index
    mov x27, #0                  // items written
3:  ldr x9, [x20, #VEC_N]
    cmp x21, x9
    b.hs 90f
    ldr x10, [x20, #VEC_PTR]
    add x10, x10, x21, lsl #4
    ldp x1, x2, [x10]
    mov x0, x19
    mov x3, #1
    bl _car_node
    mov x22, x0                  // Entry NV
    bl _entry_hash
    mov x0, x22
    mov x1, #3
    bl _nv_elem
    ldr x1, [x22, #NV_END]
    bl _cbor_links
    mov x23, x0                  // tx links
    mov x24, #0
4:  ldr x9, [x23, #VEC_N]
    cmp x24, x9
    b.hs 80f
    ldr x10, [x23, #VEC_PTR]
    add x10, x10, x24, lsl #4
    ldp x1, x2, [x10]
    mov x0, x19
    mov x3, #0
    bl _car_node
    mov x25, x0                  // Transaction NV
    mov x1, #1
    bl _nv_elem
    mov x1, x0
    ldr x2, [x25, #NV_END]
    mov x0, x19
    bl _df_payload
    bl _tx_parse
    mov x26, x0                  // TX
    cbz x27, 5f
    mov x0, #','
    bl _out_byte
5:  add x27, x27, #1
    LDG x9, _gb_details
    cmp x9, #2
    b.ne 10f
    ldr x9, [x26, #TX_NSIG]
    cbz x9, 91f
    ldr x1, [x26, #TX_SIGS]
    FMT "%G"
    b 70f
10: // metadata
    mov x28, #0                  // model (0 = missing)
    mov x0, x25
    mov x1, #2
    bl _nv_elem
    cbz x0, 12f
    str x0, [sp]
    ldr x1, [x25, #NV_END]
    bl _cbor_major
    cmp x0, #4
    b.ne 12f
    ldr x1, [sp]
    ldr x2, [x25, #NV_END]
    mov x0, x19
    bl _df_payload
    bl _meta_decode
    mov x28, x0
12: ldrb w9, [x26, #TX_KIND]     // versioned (v0 or v1) -> default meta
    cbz w9, 13f
    cbnz x28, 13f
    bl _meta_default
    mov x28, x0
13: ldrb w9, [x26, #TX_KIND]
    cbz w9, 14f
    sub x9, x9, #1               // numeric version
    LDG x10, _gb_maxv            // -1 = none, so the signed compare gates it
    cmp x9, x10
    b.gt 92f
14: mov x0, x26
    mov x1, x28
    bl tx_json
70: add x24, x24, #1
    b 4b
80: add x21, x21, #1
    b 3b
90: mov x0, #']'
    bl _out_byte
    LEAVE 48
91: FAIL "Transaction has no signature"
92: LA x1, Lmsg_version0         // x9 = the rejected version (0 or 1)
    LA x10, Lmsg_version1
    cmp x9, #0
    csel x1, x10, x1, ne
    mov x0, #ERR_VERSION
    bl _ob_throw

// ============================================================ serializer

// tx_json(x0 = TX, x1 = model or 0)
    .p2align 2
tx_json:
    ENTER 32
    mov x19, x0
    mov x20, x1
    LDG x21, _gb_enc
    LDG x22, _gb_details         // 1 = accounts
    PUTS "{\"transaction\":"
    cmp x21, #2
    b.ne 1f
    ldr x1, [x19, #TX_RAW]
    ldr x2, [x19, #TX_RAWLEN]
    FMT "[%Y,\"base64\"]"
    b 50f
1:  cmp x21, #3
    b.ne 2f
    ldr x1, [x19, #TX_RAW]
    ldr x2, [x19, #TX_RAWLEN]
    FMT "[%B,\"base58\"]"
    b 50f
2:  bl build_keys
    PUTS "{\"signatures\":["
    mov x23, #0
3:  ldr x9, [x19, #TX_NSIG]
    cmp x23, x9
    b.hs 4f
    cbz x23, 31f
    mov x0, #','
    bl _out_byte
31: ldr x9, [x19, #TX_SIGS]
    add x1, x9, x23, lsl #6
    FMT "%G"
    add x23, x23, #1
    b 3b
4:  mov x0, #']'
    bl _out_byte
    cmp x22, #1
    b.ne 5f
    PUTS ",\"accountKeys\":"
    bl account_keys_json
    mov x0, #'}'
    bl _out_byte
    b 50f
5:  PUTS ",\"message\":{"
    cmp x21, #1
    b.ne 6f
    PUTS "\"accountKeys\":"
    bl account_keys_json
    b 8f
6:  ldrb w1, [x19, #TX_NRS]
    ldrb w2, [x19, #TX_NROS]
    ldrb w3, [x19, #TX_NROU]
    FMT "\"header\":{\"numRequiredSignatures\":%u,\"numReadonlySignedAccounts\":%u,\"numReadonlyUnsignedAccounts\":%u},\"accountKeys\":["
    mov x23, #0
7:  ldr x9, [x19, #TX_NKEYS]
    cmp x23, x9
    b.hs 71f
    cbz x23, 70f
    mov x0, #','
    bl _out_byte
70: ldr x9, [x19, #TX_KEYS]
    add x1, x9, x23, lsl #5
    FMT "%K"
    add x23, x23, #1
    b 7b
71: mov x0, #']'
    bl _out_byte
8:  ldr x1, [x19, #TX_BH]
    FMT ",\"recentBlockhash\":%K,\"instructions\":["
    mov x23, #0
9:  ldr x9, [x19, #TX_NIX]
    cmp x23, x9
    b.hs 10f
    cbz x23, 91f
    mov x0, #','
    bl _out_byte
91: ldr x9, [x19, #TX_IXS]
    mov x10, #IX_SIZE
    madd x0, x23, x10, x9
    cmp x21, #1
    cset x1, eq
    bl ix_json
    add x23, x23, #1
    b 9b
10: mov x0, #']'
    bl _out_byte
    ldrb w9, [x19, #TX_KIND]
    cmp w9, #TXK_V1
    b.ne 101f
    bl tx_config_json            // v1: transactionConfig, no lookups
    b 13f
101: cmp w9, #TXK_V0
    b.ne 13f
    PUTS ",\"addressTableLookups\":["
    mov x23, #0
11: ldr x9, [x19, #TX_NLU]
    cmp x23, x9
    b.hs 12f
    cbz x23, 111f
    mov x0, #','
    bl _out_byte
111: ldr x9, [x19, #TX_LUS]
    mov x10, #LU_SIZE
    madd x24, x23, x10, x9
    ldr x1, [x24, #LU_KEY]
    FMT "{\"accountKey\":%K,\"writableIndexes\":"
    ldp x0, x1, [x24, #LU_W]
    bl bytes_json
    PUTS ",\"readonlyIndexes\":"
    ldp x0, x1, [x24, #LU_R]
    bl bytes_json
    mov x0, #'}'
    bl _out_byte
    add x23, x23, #1
    b 11b
12: mov x0, #']'
    bl _out_byte
13: PUTS "}}"
50: PUTS ",\"meta\":"
    cbnz x20, 51f
    PUTS "null}"
    LEAVE 32
51: mov x0, x19
    mov x1, x20
    bl meta_json
    LDG x9, _gb_maxv
    cmn x9, #1
    b.eq 53f
    ldrb w9, [x19, #TX_KIND]
    cbz w9, 52f
    sub x1, x9, #1
    FMT ",\"version\":%u"
    b 53f
52: PUTS ",\"version\":\"legacy\""
53: mov x0, #'}'
    bl _out_byte
    LEAVE 32

// tx_config_json: v1 ,"transactionConfig":{...} with all four keys, each
// null unless its config_mask bit(s) are set (x19 = TX).
    .p2align 2
tx_config_json:
    ENTER
    ldr x20, [x19, #TX_MASK]
    PUTS ",\"transactionConfig\":{\"priorityFee\":"
    and x9, x20, #3
    cmp x9, #3
    b.ne 1f
    ldr x0, [x19, #TX_PFEE]
    bl _out_u64
    b 2f
1:  PUTS "null"
2:  PUTS ",\"computeUnitLimit\":"
    tbz x20, #2, 3f
    ldr x0, [x19, #TX_CUL]
    bl _out_u64
    b 4f
3:  PUTS "null"
4:  PUTS ",\"loadedAccountsDataSizeLimit\":"
    tbz x20, #3, 5f
    ldr x0, [x19, #TX_LADL]
    bl _out_u64
    b 6f
5:  PUTS "null"
6:  PUTS ",\"heapSize\":"
    tbz x20, #4, 7f
    ldr x0, [x19, #TX_HEAP]
    bl _out_u64
    b 8f
7:  PUTS "null"
8:  mov x0, #'}'
    bl _out_byte
    LEAVE

// build_keys: g_keys = static keys, plus (v0 with metadata) loaded
// writable then readonly; g_nkeys, g_nstatic, g_nwritable. Legacy and v1
// have no lookup tables, so their loaded addresses are ignored. Uses
// x19 = TX, x20 = model.
    .p2align 2
build_keys:
    ENTER
    ldr x21, [x19, #TX_NKEYS]
    mov x22, #0
    mov x23, #0
    ldrb w9, [x19, #TX_KIND]
    cmp w9, #TXK_V0
    b.ne 1f
    cbz x20, 1f
    ldr x22, [x20, #MT_LW + VEC_N]
    ldr x23, [x20, #MT_LR + VEC_N]
1:  STG x21, g_nstatic, x9
    STG x22, g_nwritable, x9
    add x24, x21, x22
    add x24, x24, x23
    STG x24, g_nkeys, x9
    lsl x0, x24, #3
    add x0, x0, #8
    bl _arena_alloc
    STG x0, g_keys, x9
    mov x25, x0
    mov x9, #0
    ldr x10, [x19, #TX_KEYS]
2:  cmp x9, x21
    b.hs 3f
    add x11, x10, x9, lsl #5
    str x11, [x25], #8
    add x9, x9, #1
    b 2b
3:  cbz x22, 5f
    ldr x10, [x20, #MT_LW + VEC_PTR]
    mov x9, #0
4:  cmp x9, x22
    b.hs 5f
    add x11, x10, x9, lsl #4
    ldr x11, [x11]
    str x11, [x25], #8
    add x9, x9, #1
    b 4b
5:  cbz x23, 7f
    ldr x10, [x20, #MT_LR + VEC_PTR]
    mov x9, #0
6:  cmp x9, x23
    b.hs 7f
    add x11, x10, x9, lsl #4
    ldr x11, [x11]
    str x11, [x25], #8
    add x9, x9, #1
    b 6b
7:  LEAVE

// account_keys_json: [{pubkey, writable, signer, source}...] (x19 = TX).
    .p2align 2
account_keys_json:
    ENTER
    // upgradeable loader present among the keys?
    mov x20, #0
    LDG x21, g_nkeys
    LDG x22, g_keys
    mov x23, #0
1:  cmp x23, x21
    b.hs 2f
    ldr x0, [x22, x23, lsl #3]
    LA x1, g_upgradeable
    mov x2, #32
    bl _memcmp
    cbnz w0, 11f
    mov x20, #1
11: add x23, x23, #1
    b 1b
2:  mov x0, #'['
    bl _out_byte
    mov x23, #0
3:  cmp x23, x21
    b.hs 9f
    cbz x23, 31f
    mov x0, #','
    bl _out_byte
31: // writable by position
    LDG x9, g_nstatic
    ldrb w10, [x19, #TX_NRS]
    cmp x23, x9
    b.lo 32f
    sub x11, x23, x9
    LDG x12, g_nwritable
    cmp x11, x12
    cset x24, lo
    b 35f
32: cmp x23, x10
    b.hs 33f
    ldrb w11, [x19, #TX_NROS]
    sub x12, x10, x11
    cmp x23, x12
    cset x24, lt
    b 35f
33: ldrb w11, [x19, #TX_NROU]
    sub x12, x9, x11
    cmp x23, x12
    cset x24, lt
35: cbz x24, 38f
    ldr x0, [x22, x23, lsl #3]
    bl is_reserved
    cbz x0, 36f
    mov x24, #0
    b 38f
36: cbnz x20, 38f
    // demoted when it is a top-level program id
    ldr x9, [x19, #TX_NIX]
    ldr x10, [x19, #TX_IXS]
    mov x11, #0
37: cmp x11, x9
    b.hs 38f
    mov x12, #IX_SIZE
    madd x12, x11, x12, x10
    ldr x13, [x12, #IX_PID]
    cmp x13, x23
    b.eq 371f
    add x11, x11, #1
    b 37b
371: mov x24, #0
38: ldr x1, [x22, x23, lsl #3]
    mov x2, x24
    ldrb w9, [x19, #TX_NRS]
    cmp x23, x9
    cset x3, lo
    LDG x9, g_nstatic
    LA x4, Lsrc_tx
    LA x10, Lsrc_lt
    cmp x23, x9
    csel x4, x10, x4, hs
    FMT "{\"pubkey\":%K,\"writable\":%b,\"signer\":%b,\"source\":\"%s\"}"
    add x23, x23, #1
    b 3b
9:  mov x0, #']'
    bl _out_byte
    LEAVE

// is_reserved(x0 = 32-byte key) -> 1 if on the §14 list.
    .p2align 2
is_reserved:
    ENTER
    mov x19, x0
    LDG x20, g_nreserved
    LA x21, g_reserved
    mov x22, #0
1:  cmp x22, x20
    b.hs 8f
    mov x0, x19
    add x1, x21, x22, lsl #5
    mov x2, #32
    bl _memcmp
    cbz w0, 9f
    add x22, x22, #1
    b 1b
8:  mov x0, #0
    LEAVE
9:  mov x0, #1
    LEAVE

// ix_json(x0 = IX, x1 = parsed form?)
    .p2align 2
ix_json:
    ENTER
    mov x19, x0
    cbnz x1, 5f
    ldr x1, [x19, #IX_PID]
    FMT "{\"programIdIndex\":%u,\"accounts\":"
    ldp x0, x1, [x19, #IX_ACC]
    bl bytes_json
    ldp x1, x2, [x19, #IX_DATA]
    FMT ",\"data\":%B,\"stackHeight\":"
    b 8f
5:  ldr x0, [x19, #IX_PID]
    bl key_at
    mov x1, x0
    FMT "{\"programId\":%K,\"accounts\":["
    ldp x20, x21, [x19, #IX_ACC]
    mov x22, #0
6:  cmp x22, x21
    b.hs 7f
    cbz x22, 61f
    mov x0, #','
    bl _out_byte
61: ldrb w0, [x20, x22]
    bl key_at
    mov x1, x0
    FMT "%K"
    add x22, x22, #1
    b 6b
7:  ldp x1, x2, [x19, #IX_DATA]
    FMT "],\"data\":%B,\"stackHeight\":"
8:  ldr x0, [x19, #IX_STACK]
    cmn x0, #1
    b.eq 9f
    bl _out_u64
    b 10f
9:  PUTS "null"
10: mov x0, #'}'
    bl _out_byte
    LEAVE

// key_at(x0 = index) -> key pointer (throws when out of range).
    .p2align 2
key_at:
    LDG x9, g_nkeys
    cmp x0, x9
    b.hs 1f
    LDG x9, g_keys
    ldr x0, [x9, x0, lsl #3]
    ret
1:  stp x29, x30, [sp, #-16]!
    FAIL "Instruction account index out of range"

// bytes_json(x0 = ptr, x1 = len): [u8, ...]
    .p2align 2
bytes_json:
    ENTER
    mov x19, x0
    mov x20, x1
    mov x0, #'['
    bl _out_byte
    mov x21, #0
1:  cmp x21, x20
    b.hs 2f
    cbz x21, 11f
    mov x0, #','
    bl _out_byte
11: ldrb w0, [x19, x21]
    bl _out_u64
    add x21, x21, #1
    b 1b
2:  mov x0, #']'
    bl _out_byte
    LEAVE

// u64s_json(x0 = vec of u64)
    .p2align 2
u64s_json:
    ENTER
    mov x19, x0
    mov x0, #'['
    bl _out_byte
    mov x20, #0
1:  ldr x9, [x19, #VEC_N]
    cmp x20, x9
    b.hs 2f
    cbz x20, 11f
    mov x0, #','
    bl _out_byte
11: ldr x9, [x19, #VEC_PTR]
    ldr x0, [x9, x20, lsl #3]
    bl _out_u64
    add x20, x20, #1
    b 1b
2:  mov x0, #']'
    bl _out_byte
    LEAVE

// meta_json(x0 = TX, x1 = model)
    .p2align 2
meta_json:
    ENTER 16
    mov x19, x0
    mov x20, x1
    LDG x21, _gb_enc
    LDG x22, _gb_details
    PUTS "{\"err\":"
    bl err_json
    PUTS ",\"status\":"
    ldr x9, [x20, #MT_HASERR]
    cbnz x9, 1f
    PUTS "{\"Ok\":null}"
    b 2f
1:  PUTS "{\"Err\":"
    bl err_json
    mov x0, #'}'
    bl _out_byte
2:  ldr x1, [x20, #MT_FEE]
    FMT ",\"fee\":%u,\"preBalances\":"
    add x0, x20, #MT_PRE
    bl u64s_json
    PUTS ",\"postBalances\":"
    add x0, x20, #MT_POST
    bl u64s_json
    PUTS ",\"preTokenBalances\":"
    mov x0, #0
    bl tb_json
    PUTS ",\"postTokenBalances\":"
    mov x0, #1
    bl tb_json
    LDG x9, _gb_rewards
    cbz x9, 4f
    PUTS ",\"rewards\":"
    ldr x9, [x20, #MT_RWHAS]
    cbz x9, 3f
    add x0, x20, #MT_RW
    bl _rewards_json
    b 5f
3:  PUTS "null"
    b 5f
4:  cmp x22, #1
    b.eq 5f
    PUTS ",\"rewards\":null"
5:  cmp x22, #1
    b.eq 90f
    PUTS ",\"innerInstructions\":"
    ldr x9, [x20, #MT_INNHAS]
    cbnz x9, 6f
    PUTS "null"
    b 10f
6:  mov x0, #'['
    bl _out_byte
    mov x23, #0
7:  ldr x9, [x20, #MT_INN + VEC_N]
    cmp x23, x9
    b.hs 9f
    cbz x23, 71f
    mov x0, #','
    bl _out_byte
71: ldr x9, [x20, #MT_INN + VEC_PTR]
    mov x10, #GR_SIZE
    madd x24, x23, x10, x9
    ldr x1, [x24, #GR_INDEX]
    FMT "{\"index\":%u,\"instructions\":["
    mov x25, #0
8:  ldr x9, [x24, #GR_IXS + VEC_N]
    cmp x25, x9
    b.hs 81f
    cbz x25, 80f
    mov x0, #','
    bl _out_byte
80: ldr x9, [x24, #GR_IXS + VEC_PTR]
    mov x10, #IX_SIZE
    madd x0, x25, x10, x9
    cmp x21, #1
    cset x1, eq
    bl ix_json
    add x25, x25, #1
    b 8b
81: PUTS "]}"
    add x23, x23, #1
    b 7b
9:  mov x0, #']'
    bl _out_byte
10: PUTS ",\"logMessages\":"
    ldr x9, [x20, #MT_LOGHAS]
    cbnz x9, 11f
    PUTS "null"
    b 13f
11: mov x0, #'['
    bl _out_byte
    mov x23, #0
12: ldr x9, [x20, #MT_LOG + VEC_N]
    cmp x23, x9
    b.hs 121f
    cbz x23, 120f
    mov x0, #','
    bl _out_byte
120: ldr x9, [x20, #MT_LOG + VEC_PTR]
    add x9, x9, x23, lsl #4
    ldp x0, x1, [x9]
    bl _out_jstr
    add x23, x23, #1
    b 12b
121: mov x0, #']'
    bl _out_byte
13: cmp x21, #1
    b.eq 16f
    PUTS ",\"loadedAddresses\":{\"writable\":"
    add x0, x20, #MT_LW
    bl keys_vec_json
    PUTS ",\"readonly\":"
    add x0, x20, #MT_LR
    bl keys_vec_json
    mov x0, #'}'
    bl _out_byte
16: ldr x9, [x20, #MT_RDHAS]
    cbz x9, 17f
    ldr x1, [x20, #MT_RDPID]
    ldr x2, [x20, #MT_RDDATA]
    ldr x3, [x20, #MT_RDDATALEN]
    FMT ",\"returnData\":{\"programId\":%K,\"data\":[%Y,\"base64\"]}"
17: ldr x9, [x20, #MT_CUHAS]
    cbz x9, 18f
    ldr x1, [x20, #MT_CU]
    FMT ",\"computeUnitsConsumed\":%u"
18: ldr x9, [x20, #MT_COSTHAS]
    cbz x9, 90f
    ldr x1, [x20, #MT_COST]
    FMT ",\"costUnits\":%u"
90: mov x0, #'}'
    bl _out_byte
    LEAVE 16

// err_json: null or the TransactionError JSON (x20 = model).
    .p2align 2
err_json:
    ENTER
    ldr x9, [x20, #MT_HASERR]
    cbnz x9, 1f
    PUTS "null"
    LEAVE
1:  ldr x0, [x20, #MT_ERR]
    ldr x1, [x20, #MT_ERRLEN]
    add x1, x0, x1
    mov x2, #1
    bl _txerr
    LEAVE

// keys_vec_json(x0 = vec of {ptr, len} 32-byte keys)
    .p2align 2
keys_vec_json:
    ENTER
    mov x19, x0
    mov x0, #'['
    bl _out_byte
    mov x20, #0
1:  ldr x9, [x19, #VEC_N]
    cmp x20, x9
    b.hs 2f
    cbz x20, 11f
    mov x0, #','
    bl _out_byte
11: ldr x9, [x19, #VEC_PTR]
    add x1, x9, x20, lsl #4
    ldr x1, [x1]
    FMT "%K"
    add x20, x20, #1
    b 1b
2:  mov x0, #']'
    bl _out_byte
    LEAVE

// tb_json(x0 = 0 pre / 1 post) with x20 = model.
    .p2align 2
tb_json:
    ENTER 16
    mov x19, x0
    add x9, x20, #MT_TBHAS
    ldr x9, [x9, x19, lsl #3]
    cbnz x9, 1f
    PUTS "null"
    LEAVE 16
1:  mov x9, #VEC_SIZE
    madd x21, x19, x9, x20
    add x21, x21, #MT_TB         // vec
    mov x0, #'['
    bl _out_byte
    mov x22, #0
2:  ldr x9, [x21, #VEC_N]
    cmp x22, x9
    b.hs 9f
    cbz x22, 21f
    mov x0, #','
    bl _out_byte
21: ldr x9, [x21, #VEC_PTR]
    mov x10, #TB_SIZE
    madd x23, x22, x10, x9
    ldr x1, [x23, #TB_AI]
    ldp x2, x3, [x23, #TB_MINT]
    FMT "{\"accountIndex\":%u,\"mint\":%S,\"uiTokenAmount\":{\"uiAmount\":"
    ldr x9, [x23, #TB_UIHAS]
    cbz x9, 22f
    ldr d0, [x23, #TB_UI]
    bl _out_f64
    b 23f
22: PUTS "null"
23: ldr x1, [x23, #TB_DEC]
    ldp x2, x3, [x23, #TB_AMT]
    FMT ",\"decimals\":%u,\"amount\":%S,\"uiAmountString\":"
    ldp x0, x1, [x23, #TB_UAS]
    cbnz x1, 24f
    ldp x0, x1, [x23, #TB_AMT]
    ldr x2, [x23, #TB_DEC]
    bl _ui_amount_string
24: bl _out_jstr
    mov x0, #'}'
    bl _out_byte
    ldp x1, x2, [x23, #TB_OWNER]
    cbz x2, 25f
    FMT ",\"owner\":%S"
25: ldp x1, x2, [x23, #TB_PROG]
    cbz x2, 26f
    FMT ",\"programId\":%S"
26: mov x0, #'}'
    bl _out_byte
    add x22, x22, #1
    b 2b
9:  mov x0, #']'
    bl _out_byte
    LEAVE 16

// rewards_json(x0 = vec of RW_SIZE)
FN _rewards_json
    ENTER
    mov x19, x0
    mov x0, #'['
    bl _out_byte
    mov x20, #0
1:  ldr x9, [x19, #VEC_N]
    cmp x20, x9
    b.hs 9f
    cbz x20, 11f
    mov x0, #','
    bl _out_byte
11: ldr x9, [x19, #VEC_PTR]
    mov x10, #RW_SIZE
    madd x21, x20, x10, x9
    ldp x1, x2, [x21, #RW_PK]
    ldp x3, x4, [x21, #RW_LAM]
    FMT "{\"pubkey\":%S,\"lamports\":%d,\"postBalance\":%u,\"rewardType\":"
    ldr x9, [x21, #RW_TYPE]
    cbz x9, 12f
    LA x10, Lreward_types
    sub x9, x9, #1
    ldr x1, [x10, x9, lsl #3]
    FMT "\"%s\""
    b 13f
12: PUTS "null"
13: PUTS ",\"commission\":"
    ldr x0, [x21, #RW_COMM]
    tbnz x0, #63, 14f
    bl _out_u64
    b 15f
14: PUTS "null"
15: mov x0, #'}'
    bl _out_byte
    add x20, x20, #1
    b 1b
9:  mov x0, #']'
    bl _out_byte
    LEAVE

// ui_amount_string(x0 = amount text, x1 = len, x2 = decimals) -> x0/x1 =
// real_number_string_trimmed(parse_u64(amount) or 0, decimals).
FN _ui_amount_string
    ENTER 32
    mov x19, x0
    mov x20, x1
    mov x21, x2
    bl _parse_u64_text
    cbnz x1, 1f
    mov x0, #0
1:  // decimal digits of x0, most significant first, at [sp, 0..20)
    add x22, sp, #24
    mov x23, x22
    mov x9, #10
2:  udiv x10, x0, x9
    msub x11, x10, x9, x0
    add w11, w11, #'0'
    strb w11, [x23, #-1]!
    mov x0, x10
    cbnz x0, 2b
    sub x24, x22, x23            // digit count
    add x0, x24, x21
    add x0, x0, #4
    bl _arena_alloc
    mov x25, x0
    mov x26, x0                  // write cursor
    cbnz x21, 3f
    mov x0, x25
    mov x1, x23
    mov x2, x24
    bl _memcpy
    mov x0, x25
    mov x1, x24
    LEAVE 32
3:  cmp x24, x21
    b.hi 5f
    // 0.000ddd
    mov w9, #'0'
    strb w9, [x26], #1
    mov w9, #'.'
    strb w9, [x26], #1
    sub x10, x21, x24
4:  cbz x10, 41f
    mov w9, #'0'
    strb w9, [x26], #1
    sub x10, x10, #1
    b 4b
41: mov x0, x26
    mov x1, x23
    mov x2, x24
    bl _memcpy
    add x26, x26, x24
    b 6f
5:  sub x27, x24, x21            // integer digits
    mov x0, x26
    mov x1, x23
    mov x2, x27
    bl _memcpy
    add x26, x26, x27
    mov w9, #'.'
    strb w9, [x26], #1
    mov x0, x26
    add x1, x23, x27
    mov x2, x21
    bl _memcpy
    add x26, x26, x21
6:  // strip trailing zeros, then one trailing '.'
    ldrb w9, [x26, #-1]
    cmp w9, #'0'
    b.ne 7f
    sub x26, x26, #1
    b 6b
7:  ldrb w9, [x26, #-1]
    cmp w9, #'.'
    b.ne 8f
    sub x26, x26, #1
8:  mov x0, x25
    sub x1, x26, x25
    LEAVE 32

// parse_u64_text(x0 = text, x1 = len) -> x0 = value, x1 = 1 if it is
// "+"? digits that fit in a u64 (Rust u64::from_str).
FN _parse_u64_text
    add x1, x0, x1
    cmp x0, x1
    b.hs 9f
    ldrb w9, [x0]
    cmp w9, #'+'
    b.ne 1f
    add x0, x0, #1
    cmp x0, x1
    b.hs 9f
1:  mov x10, #0
    mov x11, #10
2:  cmp x0, x1
    b.hs 3f
    ldrb w9, [x0], #1
    sub w9, w9, #'0'
    cmp w9, #9
    b.hi 9f
    umulh x12, x10, x11
    cbnz x12, 9f
    mul x10, x10, x11
    adds x10, x10, x9
    b.cs 9f
    b 2b
3:  mov x0, x10
    mov x1, #1
    ret
9:  mov x0, #0
    mov x1, #0
    ret

    .section __TEXT,__cstring
Lmsg_version0: .asciz "Transaction version (0) is not supported by the requesting client. Please try the request again with the following configuration parameter: \"maxSupportedTransactionVersion\": 0"
Lmsg_version1: .asciz "Transaction version (1) is not supported by the requesting client. Please try the request again with the following configuration parameter: \"maxSupportedTransactionVersion\": 1"
Lsrc_tx:      .asciz "transaction"
Lsrc_lt:      .asciz "lookupTable"
Lrt_fee:      .asciz "Fee"
Lrt_rent:     .asciz "Rent"
Lrt_staking:  .asciz "Staking"
Lrt_voting:   .asciz "Voting"
Lupgradeable: .asciz "BPFLoaderUpgradeab1e11111111111111111111111"
Lr00: .asciz "AddressLookupTab1e1111111111111111111111111"
Lr01: .asciz "BPFLoader2111111111111111111111111111111111"
Lr02: .asciz "BPFLoader1111111111111111111111111111111111"
Lr03: .asciz "BPFLoaderUpgradeab1e11111111111111111111111"
Lr04: .asciz "ComputeBudget111111111111111111111111111111"
Lr05: .asciz "Config1111111111111111111111111111111111111"
Lr06: .asciz "Ed25519SigVerify111111111111111111111111111"
Lr07: .asciz "Feature111111111111111111111111111111111111"
Lr08: .asciz "LoaderV411111111111111111111111111111111111"
Lr09: .asciz "KeccakSecp256k11111111111111111111111111111"
Lr10: .asciz "Secp256r1SigVerify1111111111111111111111111"
Lr11: .asciz "StakeConfig11111111111111111111111111111111"
Lr12: .asciz "Stake11111111111111111111111111111111111111"
Lr13: .asciz "11111111111111111111111111111111"
Lr14: .asciz "Vote111111111111111111111111111111111111111"
Lr15: .asciz "ZkE1Gama1Proof11111111111111111111111111111"
Lr16: .asciz "ZkTokenProof1111111111111111111111111111111"
Lr17: .asciz "SysvarC1ock11111111111111111111111111111111"
Lr18: .asciz "SysvarEpochRewards1111111111111111111111111"
Lr19: .asciz "SysvarEpochSchedu1e111111111111111111111111"
Lr20: .asciz "SysvarFees111111111111111111111111111111111"
Lr21: .asciz "Sysvar1nstructions1111111111111111111111111"
Lr22: .asciz "SysvarLastRestartS1ot1111111111111111111111"
Lr23: .asciz "SysvarRecentB1ockHashes11111111111111111111"
Lr24: .asciz "SysvarRent111111111111111111111111111111111"
Lr25: .asciz "SysvarRewards111111111111111111111111111111"
Lr26: .asciz "SysvarS1otHashes111111111111111111111111111"
Lr27: .asciz "SysvarS1otHistory11111111111111111111111111"
Lr28: .asciz "SysvarStakeHistory1111111111111111111111111"
Lr29: .asciz "NativeLoader1111111111111111111111111111111"
Lr30: .asciz "Sysvar1111111111111111111111111111111111111"

    .section __DATA,__const
    .p2align 3
Lreserved_text:
    .quad Lr00, Lr01, Lr02, Lr03, Lr04, Lr05, Lr06, Lr07, Lr08, Lr09
    .quad Lr10, Lr11, Lr12, Lr13, Lr14, Lr15, Lr16, Lr17, Lr18, Lr19
    .quad Lr20, Lr21, Lr22, Lr23, Lr24, Lr25, Lr26, Lr27, Lr28, Lr29
    .quad Lr30, 0
Lreward_types:
    .quad Lrt_fee, Lrt_rent, Lrt_staking, Lrt_voting

    .data
    .p2align 3
g_nreserved: .quad 0
g_keys:      .quad 0
g_nkeys:     .quad 0
g_nstatic:   .quad 0
g_nwritable: .quad 0
g_reserved:  .space 31 * 32
g_upgradeable: .space 32
