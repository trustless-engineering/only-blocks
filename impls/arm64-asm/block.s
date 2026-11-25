// block.s: the getBlock pipeline (SPEC §4.5): slot -> CAR slice -> Block
// node, blockhash, previousBlockhash via the cache or the parent's slice,
// then transactions and rewards.

.include "defs.s"

    .text

// block_run: writes the result object for _gb_slot to _g_out (throws on error).
FN _block_run
    ENTER 64
    LDG x19, _gb_slot
    mov x0, x19
    bl _load_slice
    bl _car_index
    mov x20, x0                  // CX
    ldp x0, x1, [x20, #CX_BLOCK]
    add x1, x0, x1
    mov x2, #2
    bl _node_view
    mov x21, x0                  // Block NV
    mov x1, #1
    bl _nv_elem
    ldr x1, [x21, #NV_END]
    bl _cbor_uint
    cbz x1, 90f
    cmp x0, x19
    b.ne 90f
    mov x0, x21
    mov x1, #3
    bl _nv_elem
    ldr x1, [x21, #NV_END]
    bl _cbor_links
    mov x22, x0                  // entry links
    // meta = [parent_slot, blocktime, block_height]
    stp xzr, xzr, [sp]           // parent, blockTime present
    stp xzr, xzr, [sp, #16]      // blockTime, blockHeight present
    str xzr, [sp, #32]           // blockHeight
    mov x0, x21
    mov x1, #4
    bl _nv_elem
    cbz x0, 10f
    mov x23, x0
    ldr x1, [x21, #NV_END]
    bl _cbor_major
    cmp x0, #4
    b.ne 10f
    mov x0, x23
    ldr x1, [x21, #NV_END]
    bl _item_end
    mov x1, x0
    mov x0, x23
    mov x2, #-1
    bl _node_view
    mov x23, x0
    mov x1, #0
    bl _nv_elem
    ldr x1, [x23, #NV_END]
    bl _cbor_uint
    cbz x1, 1f
    str x0, [sp]
1:  mov x0, x23
    mov x1, #1
    bl _nv_elem
    ldr x1, [x23, #NV_END]
    bl _cbor_i64
    cbz x1, 2f
    cbz x0, 2f                   // blockTime 0 is reported as null
    mov x9, #1
    str x9, [sp, #8]
    str x0, [sp, #16]
2:  mov x0, x23
    mov x1, #2
    bl _nv_elem
    ldr x1, [x23, #NV_END]
    bl _cbor_uint
    cbz x1, 10f
    mov x9, #1
    str x9, [sp, #24]
    str x0, [sp, #32]
10: // blockhash
    mov x0, x20
    mov x1, x22
    bl block_hash
    mov x24, x0
    LA x0, _g_hashes
    mov x1, x19
    bl _lru_put
    ldp x9, x10, [x24]
    stp x9, x10, [x0]
    ldp x9, x10, [x24, #16]
    stp x9, x10, [x0, #16]
    // previousBlockhash
    LA x25, Lzero32
    cbz x19, 20f
    ldr x26, [sp]
    LA x0, _g_hashes
    mov x1, x26
    bl _lru_get
    cbz x0, 15f
    mov x25, x0
    b 19f
15: mov x0, x26
    bl _load_slice
    bl _car_index
    mov x27, x0
    ldp x0, x1, [x27, #CX_BLOCK]
    add x1, x0, x1
    mov x2, #2
    bl _node_view
    mov x28, x0
    mov x1, #1
    bl _nv_elem
    ldr x1, [x28, #NV_END]
    bl _cbor_uint
    cbz x1, 91f
    mov x0, x28
    mov x1, #3
    bl _nv_elem
    ldr x1, [x28, #NV_END]
    bl _cbor_links
    mov x1, x0
    mov x0, x27
    bl block_hash
    mov x25, x0
    LA x0, _g_hashes
    mov x1, x26
    bl _lru_put
    ldp x9, x10, [x25]
    stp x9, x10, [x0]
    ldp x9, x10, [x25, #16]
    stp x9, x10, [x0, #16]
19: // keep a private copy (later cache writes may recycle the entry)
    mov x0, #32
    bl _arena_alloc
    ldp x9, x10, [x25]
    stp x9, x10, [x0]
    ldp x9, x10, [x25, #16]
    stp x9, x10, [x0, #16]
    mov x25, x0
20: mov x1, x25
    mov x2, x24
    ldr x3, [sp]
    FMT "{\"previousBlockhash\":%K,\"blockhash\":%K,\"parentSlot\":%u,\"blockTime\":"
    ldr x9, [sp, #8]
    cbz x9, 21f
    ldr x0, [sp, #16]
    bl _out_i64
    b 22f
21: PUTS "null"
22: PUTS ",\"blockHeight\":"
    ldr x9, [sp, #24]
    cbz x9, 23f
    ldr x0, [sp, #32]
    bl _out_u64
    b 24f
23: PUTS "null"
24: LDG x9, _gb_details
    cmp x9, #3
    b.eq 30f
    mov x0, x20
    mov x1, x22
    bl _block_txs
30: LDG x9, _gb_rewards
    cbz x9, 40f
    mov x0, x20
    mov x1, x21
    bl _block_rewards
40: mov x0, #'}'
    bl _out_byte
    LEAVE 64
90: FAIL "Block slot differs from the requested slot"
91: FAIL "Missing parent Block slot"

// block_hash(x0 = CX, x1 = entry links) -> x0 = 32-byte hash of the last
// Entry (32 zero bytes when there are none).
    .p2align 2
block_hash:
    ENTER
    ldr x9, [x1, #VEC_N]
    cbz x9, 8f
    sub x9, x9, #1
    ldr x10, [x1, #VEC_PTR]
    add x10, x10, x9, lsl #4
    ldp x1, x2, [x10]
    mov x3, #1
    bl _car_node
    mov x19, x0
    bl _entry_hash
    LEAVE
8:  LA x0, Lzero32
    LEAVE

// entry_hash(x0 = Entry NV) -> x0 = its 32-byte hash (element 2).
FN _entry_hash
    ENTER
    mov x19, x0
    mov x1, #2
    bl _nv_elem
    ldr x1, [x19, #NV_END]
    bl _cbor_bytes
    cbz x2, 9f
    cmp x1, #32
    b.ne 9f
    LEAVE
9:  FAIL "Invalid Entry hash"

    .section __TEXT,__const
    .p2align 4
    .globl _Lzero32
Lzero32:
_Lzero32:
    .space 32
