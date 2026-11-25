// rpc.s: JSON-RPC 2.0 envelope, batches, getHealth and getBlock parameter
// validation (SPEC §5). The response is written to _g_out.

.include "defs.s"

    .text

// rpc_handle(x0 = body, x1 = len): the complete JSON response into _g_out.
FN _rpc_handle
    ENTER TRY_SIZE
    mov x19, x0
    mov x20, x1
    bl _arena_reset
    LA x9, _g_out
    str xzr, [x9, #BUF_LEN]
    mov x0, sp
    bl _ob_try
    cbnz x0, 8f
    mov x0, x19
    mov x1, x20
    bl _utf8_valid
    cbz x0, 7f
    mov x0, x19
    mov x1, x20
    bl _json_parse
    mov x21, x0
    mov x0, sp
    bl _ob_untry
    ldrb w9, [x21, #JN_TYPE]
    cmp w9, #JT_ARRAY
    b.eq 2f
    mov x0, x21
    bl rpc_dispatch
    LEAVE TRY_SIZE
2:  ldr w9, [x21, #JN_COUNT]
    cbz w9, 6f
    cmp w9, #100
    b.hi 6f
    mov x0, #'['
    bl _out_byte
    ldr x22, [x21, #JN_FIRST]
    mov x23, #0
3:  cbz x22, 5f
    cbz x23, 4f
    mov x0, #','
    bl _out_byte
4:  mov x0, x22
    bl rpc_dispatch
    ldr x22, [x22, #JN_NEXT]
    add x23, x23, #1
    b 3b
5:  mov x0, #']'
    bl _out_byte
    LEAVE TRY_SIZE
6:  mov x0, #ERR_REQUEST
    LA x1, Linvalid_req
    LA x2, Lnull_id
    mov x3, #4
    bl rpc_error
    LEAVE TRY_SIZE
7:  mov x0, sp
    bl _ob_untry
8:  mov x0, #ERR_PARSE
    LA x1, Lparse_err
    LA x2, Lnull_id
    mov x3, #4
    bl rpc_error
    LEAVE TRY_SIZE

// rpc_error(x0 = code, x1 = message C string, x2/x3 = raw id text).
    .p2align 2
rpc_error:
    ENTER
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    mov x0, x20
    bl _strlen
    mov x3, x0
    mov x1, x19
    mov x2, x20
    FMT "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":%S},\"id\":"
    mov x0, x21
    mov x1, x22
    bl _out_mem
    mov x0, #'}'
    bl _out_byte
    LEAVE

// rpc_dispatch(x0 = request node).
    .p2align 2
rpc_dispatch:
    ENTER 16
    mov x19, x0
    LA x20, Lnull_id             // raw id text
    mov x21, #4
    ldrb w9, [x19, #JN_TYPE]
    cmp w9, #JT_OBJECT
    b.ne 90f
    mov x0, x19
    LA x1, Lk_jsonrpc
    bl _json_val
    mov x22, x0
    mov x0, x19
    LA x1, Lk_method
    bl _json_val
    mov x23, x0
    mov x0, x19
    LA x1, Lk_id
    bl _json_get
    mov x24, x0
    cbz x22, 1f
    ldrb w9, [x22, #JN_TYPE]
    cmp w9, #JT_STRING
    b.ne 90f
1:  cbz x23, 2f
    ldrb w9, [x23, #JN_TYPE]
    cmp w9, #JT_STRING
    b.ne 90f
2:  cbz x24, 4f
    ldrb w9, [x24, #JN_TYPE]
    cmp w9, #JT_NULL
    b.eq 4f
    cmp w9, #JT_STRING
    b.eq 3f
    cmp w9, #JT_NUMBER
    b.ne 90f
3:  ldr x20, [x24, #JN_RAW]
    ldr x21, [x24, #JN_RAWLEN]
4:  mov x0, x22
    LA x1, Lv_20
    bl _json_str_is
    cbz x0, 90f
    cbz x23, 90f
    mov x0, x19
    LA x1, Lk_params
    bl _json_get
    mov x25, x0
    mov x0, x23
    LA x1, Lm_health
    bl _json_str_is
    cbnz x0, 10f
    mov x0, x23
    LA x1, Lm_block
    bl _json_str_is
    cbnz x0, 20f
    // -32601 "Method not found: <method>"
    ldr x1, [x23, #JN_STR]
    ldr x2, [x23, #JN_STRLEN]
    stp x1, x2, [sp]
    PUTS "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found: "
    ldp x0, x1, [sp]
    bl _out_jesc
    PUTS "\"},\"id\":"
    mov x0, x20
    mov x1, x21
    bl _out_mem
    mov x0, #'}'
    bl _out_byte
    LEAVE 16

10: // getHealth: params absent, null or []
    cbz x25, 11f
    ldrb w9, [x25, #JN_TYPE]
    cmp w9, #JT_NULL
    b.eq 11f
    cmp w9, #JT_ARRAY
    b.ne 12f
    ldr w9, [x25, #JN_COUNT]
    cbnz w9, 12f
11: PUTS "{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":"
    mov x0, x20
    mov x1, x21
    bl _out_mem
    mov x0, #'}'
    bl _out_byte
    LEAVE 16
12: mov x0, #ERR_PARAMS
    LA x1, Lbad_params
    mov x2, x20
    mov x3, x21
    bl rpc_error
    LEAVE 16

20: mov x0, x25
    mov x1, x20
    mov x2, x21
    bl rpc_getblock
    LEAVE 16

90: mov x0, #ERR_REQUEST
    LA x1, Linvalid_req
    mov x2, x20
    mov x3, x21
    bl rpc_error
    LEAVE 16

// rpc_getblock(x0 = params, x1/x2 = raw id).
    .p2align 2
rpc_getblock:
    ENTER TRY_SIZE + 16
    mov x19, x0
    mov x20, x1
    mov x21, x2
    bl block_params
    cbz x0, 9f
    LA x9, _g_out
    ldr x22, [x9, #BUF_LEN]      // rollback mark
    PUTS "{\"jsonrpc\":\"2.0\",\"result\":"
    add x0, sp, #16
    bl _ob_try
    cbnz x0, 8f
    bl _block_run
    add x0, sp, #16
    bl _ob_untry
    PUTS ",\"id\":"
    mov x0, x20
    mov x1, x21
    bl _out_mem
    mov x0, #'}'
    bl _out_byte
    LEAVE TRY_SIZE + 16
8:  LA x9, _g_out
    str x22, [x9, #BUF_LEN]
    LDG x1, _g_err_msg
    mov x2, x20
    mov x3, x21
    bl rpc_error
    LEAVE TRY_SIZE + 16
9:  mov x0, #ERR_PARAMS
    LA x1, Lbad_params
    mov x2, x20
    mov x3, x21
    bl rpc_error
    LEAVE TRY_SIZE + 16

// block_params(x0 = params) -> x0 = 1 if valid; fills the _gb_* globals.
    .p2align 2
block_params:
    ENTER
    mov x19, x0
    cbz x19, 90f
    ldrb w9, [x19, #JN_TYPE]
    cmp w9, #JT_ARRAY
    b.ne 90f
    ldr w20, [x19, #JN_COUNT]
    cmp w20, #1
    b.lo 90f
    cmp w20, #2
    b.hi 90f
    ldr x21, [x19, #JN_FIRST]
    mov x0, x21
    mov x1, #-1
    bl _json_uint
    cbz x1, 90f
    STG x0, _gb_slot, x9
    // defaults
    STG xzr, _gb_enc, x9
    STG xzr, _gb_details, x9
    mov x9, #1
    STG x9, _gb_rewards, x10
    mov x9, #-1
    STG x9, _gb_maxv, x10
    cmp w20, #2
    b.ne 80f
    ldr x22, [x21, #JN_NEXT]     // config
    ldrb w9, [x22, #JN_TYPE]
    cmp w9, #JT_NULL
    b.eq 80f
    cmp w9, #JT_STRING
    b.ne 10f
    mov x0, x22
    bl parse_encoding
    cbz x1, 90f
    b 80f
10: cmp w9, #JT_OBJECT
    b.ne 90f
    mov x0, x22
    LA x1, Lk_encoding
    bl _json_val
    cbz x0, 11f
    bl parse_encoding
    cbz x1, 90f
11: mov x0, x22
    LA x1, Lk_details
    bl _json_val
    cbz x0, 13f
    mov x23, x0
    LA x24, Ldetail_names
    mov x25, #0
12: cmp x25, #4
    b.hs 90f
    mov x0, x23
    ldr x1, [x24, x25, lsl #3]
    bl _json_str_is
    cbnz x0, 121f
    add x25, x25, #1
    b 12b
121: STG x25, _gb_details, x9
13: mov x0, x22
    LA x1, Lk_rewards
    bl _json_val
    cbz x0, 14f
    ldrb w9, [x0, #JN_TYPE]
    cmp w9, #JT_TRUE
    cset x10, eq
    cmp w9, #JT_FALSE
    b.eq 131f
    cbz x10, 90f
131: STG x10, _gb_rewards, x9
14: mov x0, x22
    LA x1, Lk_maxv
    bl _json_val
    cbz x0, 15f
    mov x1, #255
    bl _json_uint
    cbz x1, 90f
    STG x0, _gb_maxv, x9
15: mov x0, x22
    LA x1, Lk_commitment
    bl _json_val
    cbz x0, 80f
    mov x23, x0
    LA x1, Lc_finalized
    bl _json_str_is
    cbnz x0, 80f
    mov x0, x23
    LA x1, Lc_confirmed
    bl _json_str_is
    cbz x0, 90f
80: // accounts requires encoding json
    LDG x9, _gb_details
    cmp x9, #1
    b.ne 81f
    LDG x9, _gb_enc
    cbnz x9, 90f
81: mov x0, #1
    LEAVE
90: mov x0, #0
    LEAVE

// parse_encoding(x0 = node) -> x1 = 1 if a known encoding (sets _gb_enc).
    .p2align 2
parse_encoding:
    ENTER
    mov x19, x0
    LA x20, Lenc_names
    mov x21, #0
1:  cmp x21, #4
    b.hs 8f
    mov x0, x19
    ldr x1, [x20, x21, lsl #3]
    bl _json_str_is
    cbnz x0, 2f
    add x21, x21, #1
    b 1b
2:  STG x21, _gb_enc, x9
    mov x1, #1
    LEAVE
8:  mov x1, #0
    LEAVE

    .section __TEXT,__cstring
Lnull_id:     .asciz "null"
Linvalid_req: .asciz "Invalid Request"
Lparse_err:   .asciz "Parse error"
Lbad_params:  .asciz "Invalid params"
Lk_jsonrpc:   .asciz "jsonrpc"
Lk_method:    .asciz "method"
Lk_id:        .asciz "id"
Lk_params:    .asciz "params"
Lv_20:        .asciz "2.0"
Lm_health:    .asciz "getHealth"
Lm_block:     .asciz "getBlock"
Lk_encoding:  .asciz "encoding"
Lk_details:   .asciz "transactionDetails"
Lk_rewards:   .asciz "rewards"
Lk_maxv:      .asciz "maxSupportedTransactionVersion"
Lk_commitment: .asciz "commitment"
Lc_finalized: .asciz "finalized"
Lc_confirmed: .asciz "confirmed"
Le_json:      .asciz "json"
Le_parsed:    .asciz "jsonParsed"
Le_b64:       .asciz "base64"
Le_b58:       .asciz "base58"
Ld_full:      .asciz "full"
Ld_accounts:  .asciz "accounts"
Ld_sigs:      .asciz "signatures"
Ld_none:      .asciz "none"

    .section __DATA,__const
    .p2align 3
Lenc_names:    .quad Le_json, Le_parsed, Le_b64, Le_b58
Ldetail_names: .quad Ld_full, Ld_accounts, Ld_sigs, Ld_none

    .data
    .p2align 3
    .globl _gb_slot, _gb_enc, _gb_details, _gb_rewards, _gb_maxv
_gb_slot:    .quad 0
_gb_enc:     .quad 0     // 0 json, 1 jsonParsed, 2 base64, 3 base58
_gb_details: .quad 0     // 0 full, 1 accounts, 2 signatures, 3 none
_gb_rewards: .quad 1
_gb_maxv:    .quad -1    // -1 = none
