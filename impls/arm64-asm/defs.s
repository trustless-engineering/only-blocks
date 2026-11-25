// defs.s: shared macros, constants and struct layouts. Included by every
// translation unit with `.include "defs.s"`; it emits no code or data itself.
//
// Calling convention: plain AAPCS64 as used on Darwin. Every non-leaf
// function opens with ENTER (saves x19-x28, fp, lr and reserves locals) and
// closes with LEAVE. x18 is never touched. Variadic C calls (snprintf,
// curl_easy_setopt) pass their variadic arguments on the stack.

// ---------------------------------------------------------------- macros

.macro FN name
    .globl \name
    .p2align 2
\name:
.endm

// ENTER locals: frame = 96 bytes of saved registers + locals (16-aligned).
// Locals live at [sp, #0 .. locals).
.macro ENTER locals=0
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    .if \locals
    sub sp, sp, #\locals
    .endif
.endm

.macro LEAVE locals=0
    .if \locals
    add sp, sp, #\locals
    .endif
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp x29, x30, [sp], #96
    ret
.endm

// Arbitrary 64-bit constant.
.macro MOV64 reg, val
    movz \reg, #((\val) & 0xffff)
    movk \reg, #(((\val) >> 16) & 0xffff), lsl #16
    movk \reg, #(((\val) >> 32) & 0xffff), lsl #32
    movk \reg, #(((\val) >> 48) & 0xffff), lsl #48
.endm

// Address of a symbol in this image.
.macro LA reg, sym
    adrp \reg, \sym@PAGE
    add \reg, \reg, \sym@PAGEOFF
.endm

// 64-bit global load/store helpers.
.macro LDG reg, sym
    adrp \reg, \sym@PAGE
    ldr \reg, [\reg, \sym@PAGEOFF]
.endm

.macro STG reg, sym, tmp
    adrp \tmp, \sym@PAGE
    str \reg, [\tmp, \sym@PAGEOFF]
.endm

// The literal-string macros below put their text in __cstring under a
// unique \@ label, so they never capture numeric labels (1f, 2b) used by
// the surrounding code.

// Throw an internal error (-32603) with a literal message.
.macro FAIL msg
    adrp x1, Lmf\@@PAGE
    add x1, x1, Lmf\@@PAGEOFF
    movn x0, #32602              // -32603
    bl _ob_throw
    .pushsection __TEXT,__cstring
Lmf\@: .asciz "\msg"
    .popsection
.endm

// Throw a given code with a literal message.
.macro THROW code, msg
    adrp x1, Lmt\@@PAGE
    add x1, x1, Lmt\@@PAGEOFF
    mov x0, #\code
    bl _ob_throw
    .pushsection __TEXT,__cstring
Lmt\@: .asciz "\msg"
    .popsection
.endm

// Emit a literal C string to the output buffer.
.macro PUTS str
    adrp x0, Lmp\@@PAGE
    add x0, x0, Lmp\@@PAGEOFF
    bl _out_cstr
    .pushsection __TEXT,__cstring
Lmp\@: .asciz "\str"
    .popsection
.endm

// out_fmt with a literal format; arguments already in x1..x7.
.macro FMT str
    adrp x0, Lmo\@@PAGE
    add x0, x0, Lmo\@@PAGEOFF
    bl _out_fmt
    .pushsection __TEXT,__cstring
Lmo\@: .asciz "\str"
    .popsection
.endm

// ------------------------------------------------------------- constants

.equ ERR_INTERNAL, -32603
.equ ERR_PARAMS, -32602
.equ ERR_METHOD, -32601
.equ ERR_REQUEST, -32600
.equ ERR_PARSE, -32700
.equ ERR_UNAVAILABLE, -32004
.equ ERR_SKIPPED, -32007
.equ ERR_VERSION, -32015

.equ MAX_BODY, 1048576
.equ MAX_SLICE, 134217728
.equ MAX_ZSTD_OUT, 536870912
.equ SLOTS_PER_EPOCH, 432000
.equ BINCODE_CUTOFF, 67824000
.equ LRU_CAP, 100000

// Try frame (jump buffer): x19..x30, sp, previous frame.
.equ TRY_SIZE, 112

// Growable byte buffer.
.equ BUF_PTR, 0
.equ BUF_LEN, 8
.equ BUF_CAP, 16
.equ BUF_NEXT, 24
.equ BUF_SIZE, 32

// JSON request node (json.s).
.equ JN_TYPE, 0          // u8: 1 null 2 false 3 true 4 number 5 string 6 array 7 object
.equ JN_COUNT, 4         // u32 children
.equ JN_RAW, 8           // raw text ptr (number/string with quotes)
.equ JN_RAWLEN, 16
.equ JN_STR, 24          // decoded string ptr
.equ JN_STRLEN, 32
.equ JN_FIRST, 40        // first child
.equ JN_NEXT, 48         // next sibling
.equ JN_KEY, 56          // decoded key ptr (object members)
.equ JN_KEYLEN, 64
.equ JN_SIZE, 72

.equ JT_NULL, 1
.equ JT_FALSE, 2
.equ JT_TRUE, 3
.equ JT_NUMBER, 4
.equ JT_STRING, 5
.equ JT_ARRAY, 6
.equ JT_OBJECT, 7

// Parsed transaction (tx.s). For v1 the signatures sit at the tail of the
// wire bytes and TX_NSIG = num_required_signatures.
.equ TX_NSIG, 0
.equ TX_SIGS, 8
.equ TX_KIND, 16         // u8: TXK_LEGACY, TXK_V0 or TXK_V1
.equ TX_NRS, 17          // u8
.equ TX_NROS, 18         // u8
.equ TX_NROU, 19         // u8
.equ TX_NKEYS, 24
.equ TX_KEYS, 32
.equ TX_BH, 40
.equ TX_NIX, 48
.equ TX_IXS, 56          // array of IX_SIZE
.equ TX_NLU, 64
.equ TX_LUS, 72          // array of LU_SIZE
.equ TX_RAW, 80
.equ TX_RAWLEN, 88
.equ TX_MASK, 96         // v1 config_mask (u32, validated against 0x1F)
.equ TX_PFEE, 104        // v1 priorityFee (u64) when (mask & 3) == 3
.equ TX_CUL, 112         // v1 computeUnitLimit (u32) when mask & 4
.equ TX_LADL, 120        // v1 loadedAccountsDataSizeLimit (u32) when mask & 8
.equ TX_HEAP, 128        // v1 heapSize (u32) when mask & 16
.equ TX_SIZE, 136

// Transaction kinds (TX_KIND); the numeric version is kind - 1.
.equ TXK_LEGACY, 0
.equ TXK_V0, 1
.equ TXK_V1, 2

// Compiled instruction (top-level and inner).
.equ IX_PID, 0           // u64
.equ IX_ACC, 8
.equ IX_NACC, 16
.equ IX_DATA, 24
.equ IX_NDATA, 32
.equ IX_STACK, 40        // u64, or -1 for none
.equ IX_SIZE, 48

// Address table lookup.
.equ LU_KEY, 0
.equ LU_W, 8
.equ LU_NW, 16
.equ LU_R, 24
.equ LU_NR, 32
.equ LU_SIZE, 40

// Vector header (arena-backed, grows by doubling).
.equ VEC_PTR, 0
.equ VEC_N, 8
.equ VEC_CAP, 16
.equ VEC_SIZE, 24

// Transaction status metadata model (meta.s).
.equ MT_HASERR, 0        // u64 flag
.equ MT_ERR, 8           // ptr to bincode TransactionError bytes
.equ MT_ERRLEN, 16
.equ MT_FEE, 24
.equ MT_PRE, 32          // vec of u64
.equ MT_POST, 56         // vec of u64
.equ MT_INNHAS, 80
.equ MT_INN, 88          // vec of GR_SIZE
.equ MT_LOGHAS, 112
.equ MT_LOG, 120         // vec of {ptr, len}
.equ MT_TBHAS, 144       // 2 x u64 (pre, post)
.equ MT_TB, 160          // 2 x vec of TB_SIZE (pre at 160, post at 184)
.equ MT_RWHAS, 208
.equ MT_RW, 216          // vec of RW_SIZE
.equ MT_LW, 240          // vec of {ptr, len}
.equ MT_LR, 264          // vec of {ptr, len}
.equ MT_RDHAS, 288
.equ MT_RDPID, 296
.equ MT_RDPIDLEN, 304
.equ MT_RDDATA, 312
.equ MT_RDDATALEN, 320
.equ MT_CUHAS, 328
.equ MT_CU, 336
.equ MT_COSTHAS, 344
.equ MT_COST, 352
.equ MT_INNNONE, 360
.equ MT_LOGNONE, 368
.equ MT_RDNONE, 376
.equ MT_SIZE, 384

// Inner instruction group.
.equ GR_INDEX, 0
.equ GR_IXS, 8           // vec of IX_SIZE
.equ GR_SIZE, 32

// Token balance.
.equ TB_AI, 0
.equ TB_MINT, 8
.equ TB_MINTLEN, 16
.equ TB_OWNER, 24
.equ TB_OWNERLEN, 32
.equ TB_PROG, 40
.equ TB_PROGLEN, 48
.equ TB_UIHAS, 56        // 1 when ui_amount is present
.equ TB_UI, 64           // f64 bits
.equ TB_DEC, 72
.equ TB_AMT, 80
.equ TB_AMTLEN, 88
.equ TB_UAS, 96
.equ TB_UASLEN, 104
.equ TB_SIZE, 112

// Reward.
.equ RW_PK, 0
.equ RW_PKLEN, 8
.equ RW_LAM, 16
.equ RW_PB, 24
.equ RW_TYPE, 32         // 0 none, 1 Fee, 2 Rent, 3 Staking, 4 Voting
.equ RW_COMM, 40         // -1 none
.equ RW_SIZE, 48

// Node view: element positions of a decoded IPLD node (an array).
.equ NV_END, 0
.equ NV_COUNT, 8
.equ NV_POS, 16          // first 8 element positions
.equ NV_SIZE, 80

// CAR index.
.equ CX_ENT, 0           // vec of {cid, cidlen, node, nodelen}
.equ CX_TAB, 24          // u32 slots (entry index + 1)
.equ CX_MASK, 32
.equ CX_BLOCK, 40        // Block section node ptr
.equ CX_BLOCKLEN, 48
.equ CX_SIZE, 56
