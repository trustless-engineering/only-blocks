/* Transaction metadata and rewards: zstd unwrapping, protobuf (prost semantics) and bincode. */
#include "model.h"

#include <stdio.h>

static const char *const INSTRUCTION_ERRORS[54] = {
    "GenericError", "InvalidArgument", "InvalidInstructionData", "InvalidAccountData", "AccountDataTooSmall",
    "InsufficientFunds", "IncorrectProgramId", "MissingRequiredSignature", "AccountAlreadyInitialized",
    "UninitializedAccount", "UnbalancedInstruction", "ModifiedProgramId", "ExternalAccountLamportSpend",
    "ExternalAccountDataModified", "ReadonlyLamportChange", "ReadonlyDataModified", "DuplicateAccountIndex",
    "ExecutableModified", "RentEpochModified", "NotEnoughAccountKeys", "AccountDataSizeChanged",
    "AccountNotExecutable", "AccountBorrowFailed", "AccountBorrowOutstanding", "DuplicateAccountOutOfSync",
    "Custom", "InvalidError", "ExecutableDataModified", "ExecutableLamportChange", "ExecutableAccountNotRentExempt",
    "UnsupportedProgramId", "CallDepth", "MissingAccount", "ReentrancyNotAllowed", "MaxSeedLengthExceeded",
    "InvalidSeeds", "InvalidRealloc", "ComputationalBudgetExceeded", "PrivilegeEscalation",
    "ProgramEnvironmentSetupFailure", "ProgramFailedToComplete", "ProgramFailedToCompile", "Immutable",
    "IncorrectAuthority", "BorshIoError", "AccountNotRentExempt", "InvalidAccountOwner", "ArithmeticOverflow",
    "UnsupportedSysvar", "IllegalOwner", "MaxAccountsDataAllocationsExceeded", "MaxAccountsExceeded",
    "MaxInstructionTraceLengthExceeded", "BuiltinProgramsMustConsumeComputeUnits",
};

static const char *const TRANSACTION_ERRORS[39] = {
    "AccountInUse", "AccountLoadedTwice", "AccountNotFound", "ProgramAccountNotFound", "InsufficientFundsForFee",
    "InvalidAccountForFee", "AlreadyProcessed", "BlockhashNotFound", "InstructionError", "CallChainTooDeep",
    "MissingSignatureForFee", "InvalidAccountIndex", "SignatureFailure", "InvalidProgramForExecution",
    "SanitizeFailure", "ClusterMaintenance", "AccountBorrowOutstanding", "WouldExceedMaxBlockCostLimit",
    "UnsupportedVersion", "InvalidWritableAccount", "WouldExceedMaxAccountCostLimit",
    "WouldExceedAccountDataBlockLimit", "TooManyAccountLocks", "AddressLookupTableNotFound",
    "InvalidAddressLookupTableOwner", "InvalidAddressLookupTableData", "InvalidAddressLookupTableIndex",
    "InvalidRentPayingAccount", "WouldExceedMaxVoteCostLimit", "WouldExceedAccountDataTotalLimit",
    "DuplicateInstruction", "InsufficientFundsForRent", "MaxLoadedAccountsDataSizeExceeded",
    "InvalidLoadedAccountsDataSizeLimit", "ResanitizationNeeded", "ProgramExecutionTemporarilyRestricted",
    "UnbalancedTransaction", "ProgramCacheHitMaxLimit", "CommitCancelled",
};

/* ================================================================== bincode */

enum { B_OK = 0, B_EOF = 1, B_OTHER = 2 };
#define B(x) do { int _e = (x); if (_e) return _e; } while (0)

typedef struct {
    ctx_t *c;
    const uint8_t *p;
    size_t n, pos;
} br_t;

static int b_fixed(br_t *r, size_t n, const uint8_t **out) {
    if (n > r->n - r->pos) return B_EOF; /* fixed-width EOF consumes nothing */
    *out = r->p + r->pos;
    r->pos += n;
    return B_OK;
}
static int b_u8(br_t *r, uint8_t *v) { const uint8_t *p; B(b_fixed(r, 1, &p)); *v = p[0]; return B_OK; }
static int b_u32(br_t *r, uint32_t *v) { const uint8_t *p; B(b_fixed(r, 4, &p)); *v = rd32le(p); return B_OK; }
static int b_u64(br_t *r, uint64_t *v) { const uint8_t *p; B(b_fixed(r, 8, &p)); *v = rd64le(p); return B_OK; }

static int b_option(br_t *r, bool *some) {
    uint8_t t;
    B(b_u8(r, &t));
    if (t > 1) return B_OTHER;
    *some = t == 1;
    return B_OK;
}

static int b_string(br_t *r, str_t *s) {
    uint64_t n;
    B(b_u64(r, &n));
    if (n > r->n - r->pos) return B_OTHER; /* bincode's byte-slice error is not an EOF */
    if (!utf8_valid(r->p + r->pos, (size_t)n)) return B_OTHER;
    s->p = (const char *)r->p + r->pos;
    s->n = (size_t)n;
    r->pos += (size_t)n;
    return B_OK;
}

static int b_compact(br_t *r, size_t *out) {
    uint32_t v = 0;
    for (int k = 0; k < 3; k++) {
        uint8_t b;
        B(b_u8(r, &b));
        if (k > 0 && b == 0) return B_OTHER;
        v |= (uint32_t)(b & 0x7F) << (7 * k);
        if (!(b & 0x80)) {
            if (v > 0xFFFF) return B_OTHER;
            *out = v;
            return B_OK;
        }
    }
    return B_OTHER;
}

/* short_vec<u8>: one fixed read per element, so a shortfall is an EOF after consuming the rest. */
static int b_short_bytes(br_t *r, bytes_t *out) {
    size_t n;
    B(b_compact(r, &n));
    if (n > r->n - r->pos) {
        r->pos = r->n;
        return B_EOF;
    }
    out->p = r->p + r->pos;
    out->n = n;
    r->pos += n;
    return B_OK;
}

static const char *render_txerr(ctx_t *c, uint32_t variant, uint8_t index, uint32_t ierr, uint32_t custom) {
    char tmp[160];
    switch (variant) {
    case 8:
        if (ierr == 25) snprintf(tmp, sizeof tmp, "{\"InstructionError\":[%u,{\"Custom\":%u}]}", index, custom);
        else snprintf(tmp, sizeof tmp, "{\"InstructionError\":[%u,\"%s\"]}", index, INSTRUCTION_ERRORS[ierr]);
        break;
    case 30: snprintf(tmp, sizeof tmp, "{\"DuplicateInstruction\":%u}", index); break;
    case 31:
    case 35: snprintf(tmp, sizeof tmp, "{\"%s\":{\"account_index\":%u}}", TRANSACTION_ERRORS[variant], index); break;
    default: snprintf(tmp, sizeof tmp, "\"%s\"", TRANSACTION_ERRORS[variant]);
    }
    return astrdup(c, tmp, strlen(tmp));
}

static int b_txerr(br_t *r, const char **json) {
    uint32_t variant, ierr = 0, custom = 0;
    uint8_t index = 0;
    B(b_u32(r, &variant));
    if (variant >= 39) return B_OTHER;
    if (variant == 8) {
        B(b_u8(r, &index));
        B(b_u32(r, &ierr));
        if (ierr >= 54) return B_OTHER;
        if (ierr == 25) B(b_u32(r, &custom));
    } else if (variant == 30 || variant == 31 || variant == 35) {
        B(b_u8(r, &index));
    }
    *json = render_txerr(r->c, variant, index, ierr, custom);
    return B_OK;
}

static int b_vec_len(br_t *r, uint64_t *n) { return b_u64(r, n); }

static int b_u64_vec(br_t *r, u64_vec_t *v) {
    uint64_t n;
    B(b_vec_len(r, &n));
    v->n = 0;
    for (uint64_t i = 0; i < n; i++) {
        uint64_t x;
        B(b_u64(r, &x));
        VPUSH(r->c, *v, x);
    }
    return B_OK;
}

static void set_ui_string(ctx_t *c, token_t *t) {
    uint64_t amount = 0;
    if (!parse_unsigned(t->amount.p, t->amount.n, UINT64_MAX, &amount)) amount = 0;
    t->ui_string.p = ui_amount_string(c, amount, t->decimals, &t->ui_string.n);
}

enum { TOK_V1 = 1, TOK_V2 = 2, TOK_STORED = 3 };

static int b_token(br_t *r, int layout, token_t *t) {
    memset(t, 0, sizeof *t);
    const uint8_t *f;
    B(b_u8(r, &t->account_index));
    B(b_string(r, &t->mint));
    B(b_fixed(r, 8, &f));
    uint64_t bits = rd64le(f);
    memcpy(&t->ui, &bits, 8);
    t->has_ui = true;
    B(b_u8(r, &t->decimals));
    B(b_string(r, &t->amount));
    if (layout == TOK_V2) {
        B(b_string(r, &t->owner));
    } else if (layout == TOK_STORED) {
        int e = b_string(r, &t->owner);
        if (e == B_EOF) t->owner.n = 0;
        else if (e) return e;
        e = b_string(r, &t->program_id);
        if (e == B_EOF) t->program_id.n = 0;
        else if (e) return e;
    }
    set_ui_string(r->c, t);
    return B_OK;
}

static int b_token_vec(br_t *r, int layout, tokens_vec_t *v) {
    uint64_t n;
    B(b_vec_len(r, &n));
    v->n = 0;
    for (uint64_t i = 0; i < n; i++) {
        token_t t;
        B(b_token(r, layout, &t));
        VPUSH(r->c, *v, t);
    }
    return B_OK;
}

static int b_reward_type(br_t *r, uint8_t *type) {
    uint32_t v;
    B(b_u32(r, &v));
    if (v > 3) return B_OTHER;
    *type = (uint8_t)(v + 1);
    return B_OK;
}

#define EOF_FIELD(expr, on_eof) do { int _e = (expr); if (_e == B_EOF) { on_eof; } else if (_e) return _e; } while (0)

static int b_opt_reward_type(br_t *r, uint8_t *type) {
    bool some;
    *type = 0;
    B(b_option(r, &some));
    if (some) B(b_reward_type(r, type));
    return B_OK;
}

static int b_opt_u8(br_t *r, bool *has, uint8_t *v) {
    bool some;
    *has = false;
    B(b_option(r, &some));
    if (some) { B(b_u8(r, v)); *has = true; }
    return B_OK;
}

static int b_reward(br_t *r, bool extended, reward_t *w) {
    memset(w, 0, sizeof *w);
    uint64_t lam;
    B(b_string(r, &w->pubkey));
    B(b_u64(r, &lam));
    w->lamports = (int64_t)lam;
    if (extended) {
        EOF_FIELD(b_u64(r, &w->post_balance), w->post_balance = 0);
        EOF_FIELD(b_opt_reward_type(r, &w->reward_type), w->reward_type = 0);
        EOF_FIELD(b_opt_u8(r, &w->has_commission, &w->commission), w->has_commission = false);
    } else {
        B(b_u64(r, &w->post_balance));
        B(b_opt_reward_type(r, &w->reward_type));
    }
    return B_OK;
}

static int b_reward_vec(br_t *r, bool extended, rewards_vec_t *v) {
    uint64_t n;
    B(b_vec_len(r, &n));
    v->n = 0;
    for (uint64_t i = 0; i < n; i++) {
        reward_t w;
        B(b_reward(r, extended, &w));
        VPUSH(r->c, *v, w);
    }
    return B_OK;
}

static int b_inner(br_t *r, bool legacy, meta_t *m) {
    bool some;
    m->has_inner = false;
    m->inner.n = 0;
    B(b_option(r, &some));
    if (!some) return B_OK;
    uint64_t groups;
    B(b_vec_len(r, &groups));
    for (uint64_t g = 0; g < groups; g++) {
        inner_t in;
        memset(&in, 0, sizeof in);
        B(b_u8(r, &in.index));
        uint64_t count;
        B(b_vec_len(r, &count));
        for (uint64_t i = 0; i < count; i++) {
            iix_t ix;
            memset(&ix, 0, sizeof ix);
            B(b_u8(r, &ix.program));
            B(b_short_bytes(r, &ix.accounts));
            B(b_short_bytes(r, &ix.data));
            if (!legacy) {
                bool has;
                B(b_option(r, &has));
                if (has) { B(b_u32(r, &ix.stack)); ix.has_stack = true; }
            }
            VPUSH(r->c, in.ix, ix);
        }
        VPUSH(r->c, m->inner, in);
    }
    m->has_inner = true;
    return B_OK;
}

static int b_logs(br_t *r, meta_t *m) {
    bool some;
    m->has_logs = false;
    m->logs.n = 0;
    B(b_option(r, &some));
    if (!some) return B_OK;
    uint64_t n;
    B(b_vec_len(r, &n));
    for (uint64_t i = 0; i < n; i++) {
        str_t s;
        B(b_string(r, &s));
        VPUSH(r->c, m->logs, s);
    }
    m->has_logs = true;
    return B_OK;
}

static int b_opt_tokens(br_t *r, int layout, bool *has, tokens_vec_t *v) {
    bool some;
    *has = false;
    v->n = 0;
    B(b_option(r, &some));
    if (!some) return B_OK;
    B(b_token_vec(r, layout, v));
    *has = true;
    return B_OK;
}

static int b_opt_rewards(br_t *r, meta_t *m) {
    bool some;
    m->has_rewards = false;
    m->rewards.n = 0;
    B(b_option(r, &some));
    if (!some) return B_OK;
    B(b_reward_vec(r, true, &m->rewards));
    m->has_rewards = true;
    return B_OK;
}

static int b_return_data(br_t *r, meta_t *m) {
    bool some;
    m->has_return = false;
    B(b_option(r, &some));
    if (!some) return B_OK;
    const uint8_t *pid;
    B(b_fixed(r, 32, &pid));
    uint64_t n;
    B(b_u64(r, &n));
    if (n > r->n - r->pos) {
        r->pos = r->n;
        return B_EOF;
    }
    m->return_program = pid;
    m->return_data.p = r->p + r->pos;
    m->return_data.n = (size_t)n;
    r->pos += (size_t)n;
    m->has_return = true;
    return B_OK;
}

static int b_opt_u64(br_t *r, bool *has, uint64_t *v) {
    bool some;
    *has = false;
    B(b_option(r, &some));
    if (some) { B(b_u64(r, v)); *has = true; }
    return B_OK;
}

static int b_meta(br_t *r, bool legacy_inner, int tokens, meta_t *m) {
    memset(m, 0, sizeof *m);
    uint32_t status;
    B(b_u32(r, &status));
    if (status == 1) B(b_txerr(r, &m->err_json));
    else if (status != 0) return B_OTHER;
    B(b_u64(r, &m->fee));
    B(b_u64_vec(r, &m->pre));
    B(b_u64_vec(r, &m->post));
    EOF_FIELD(b_inner(r, legacy_inner, m), (m->has_inner = false, m->inner.n = 0));
    EOF_FIELD(b_logs(r, m), (m->has_logs = false, m->logs.n = 0));
    EOF_FIELD(b_opt_tokens(r, tokens, &m->has_pre_tokens, &m->pre_tokens), m->has_pre_tokens = false);
    EOF_FIELD(b_opt_tokens(r, tokens, &m->has_post_tokens, &m->post_tokens), m->has_post_tokens = false);
    EOF_FIELD(b_opt_rewards(r, m), m->has_rewards = false);
    EOF_FIELD(b_return_data(r, m), m->has_return = false);
    EOF_FIELD(b_opt_u64(r, &m->has_cu, &m->cu), m->has_cu = false);
    EOF_FIELD(b_opt_u64(r, &m->has_cost, &m->cost), m->has_cost = false);
    return B_OK;
}

/* bincode_metadata: four strict layouts, then the lenient current layout. */
static meta_t *bincode_metadata(ctx_t *c, bytes_t b) {
    static const struct { bool legacy; int tokens; } layouts[4] = {
        {false, TOK_STORED}, {true, TOK_V1}, {true, TOK_V2}, {true, TOK_STORED}};
    meta_t *m = amalloc(c, sizeof *m);
    for (int i = 0; i < 4; i++) {
        br_t r = {c, b.p, b.n, 0};
        if (b_meta(&r, layouts[i].legacy, layouts[i].tokens, m) == B_OK && r.pos == r.n) return m;
    }
    br_t r = {c, b.p, b.n, 0};
    if (b_meta(&r, false, TOK_STORED, m) == B_OK) return m;
    return NULL;
}

static bool bincode_rewards(ctx_t *c, bytes_t b, rewards_vec_t *out) {
    br_t r = {c, b.p, b.n, 0};
    if (b_reward_vec(&r, true, out) == B_OK && r.pos == r.n) return true;
    r.pos = 0;
    if (b_reward_vec(&r, false, out) == B_OK && r.pos == r.n) return true;
    r.pos = 0;
    return b_reward_vec(&r, true, out) == B_OK;
}

/* ================================================================== protobuf */

typedef struct {
    ctx_t *c;
    const uint8_t *p;
    size_t n, pos;
} pr_t;

#define PFAIL(r, msg) fail((r)->c, E_INTERNAL, "protobuf: %s", (msg))

static uint64_t pr_varint(pr_t *r) {
    uint64_t v = 0;
    for (int i = 0; i < 10; i++) {
        if (r->pos >= r->n) PFAIL(r, "truncated varint");
        uint8_t b = r->p[r->pos++];
        if (i == 9 && b > 1) PFAIL(r, "invalid varint");
        v |= (uint64_t)(b & 0x7F) << (7 * i);
        if (b < 0x80) return v;
    }
    PFAIL(r, "invalid varint");
}

static bool pr_key(pr_t *r, uint32_t *field, int *wire) {
    if (r->pos >= r->n) return false;
    uint64_t key = pr_varint(r);
    if (key > 0xFFFFFFFFu) PFAIL(r, "invalid key");
    *wire = (int)(key & 7);
    *field = (uint32_t)(key >> 3);
    if (*wire > 5) PFAIL(r, "invalid wire type");
    if (*field == 0) PFAIL(r, "invalid tag 0");
    return true;
}

static bytes_t pr_len(pr_t *r) {
    uint64_t n = pr_varint(r);
    if (n > r->n - r->pos) PFAIL(r, "length exceeds enclosing message");
    bytes_t b = {r->p + r->pos, (size_t)n};
    r->pos += (size_t)n;
    return b;
}

static void pr_skip(pr_t *r, uint32_t field, int wire, int depth) {
    switch (wire) {
    case 0: pr_varint(r); return;
    case 1: if (8 > r->n - r->pos) PFAIL(r, "truncated fixed64"); r->pos += 8; return;
    case 2: pr_len(r); return;
    case 5: if (4 > r->n - r->pos) PFAIL(r, "truncated fixed32"); r->pos += 4; return;
    case 3:
        if (depth > 100) PFAIL(r, "group nesting too deep");
        for (;;) {
            uint32_t f;
            int w;
            if (!pr_key(r, &f, &w)) PFAIL(r, "unterminated group");
            if (w == 4) {
                if (f != field) PFAIL(r, "mismatched end group");
                return;
            }
            pr_skip(r, f, w, depth + 1);
        }
    default: PFAIL(r, "unexpected end group");
    }
}

static void expect_wire(pr_t *r, int wire, int want) {
    if (wire != want) PFAIL(r, "wrong wire type for a known field");
}
static uint64_t f_varint(pr_t *r, int wire) { expect_wire(r, wire, 0); return pr_varint(r); }
static bytes_t f_bytes(pr_t *r, int wire) { expect_wire(r, wire, 2); return pr_len(r); }
static str_t f_string(pr_t *r, int wire) {
    bytes_t b = f_bytes(r, wire);
    if (!utf8_valid(b.p, b.n)) PFAIL(r, "invalid UTF-8 string");
    str_t s = {(const char *)b.p, b.n};
    return s;
}
static double f_double(pr_t *r, int wire) {
    expect_wire(r, wire, 1);
    if (8 > r->n - r->pos) PFAIL(r, "truncated double");
    uint64_t bits = rd64le(r->p + r->pos);
    r->pos += 8;
    double d;
    memcpy(&d, &bits, 8);
    return d;
}

static pr_t sub(pr_t *r, bytes_t b) {
    pr_t s = {r->c, b.p, b.n, 0};
    return s;
}

static void f_repeated_u64(pr_t *r, int wire, u64_vec_t *v) {
    if (wire == 0) {
        VPUSH(r->c, *v, pr_varint(r));
    } else if (wire == 2) {
        pr_t s = sub(r, pr_len(r));
        while (s.pos < s.n) VPUSH(r->c, *v, pr_varint(&s));
    } else {
        PFAIL(r, "wrong wire type for a repeated uint64");
    }
}

/* Reward: converted as soon as its message ends (§10.3). */
static void pb_reward(pr_t *r, reward_t *w) {
    str_t commission = {0}, bps = {0};
    uint64_t type = 0;
    memset(w, 0, sizeof *w);
    w->pubkey.p = "";
    uint32_t field;
    int wire;
    while (pr_key(r, &field, &wire)) {
        switch (field) {
        case 1: w->pubkey = f_string(r, wire); break;
        case 2: w->lamports = (int64_t)f_varint(r, wire); break;
        case 3: w->post_balance = f_varint(r, wire); break;
        case 4: type = f_varint(r, wire); break;
        case 5: commission = f_string(r, wire); break;
        case 6: bps = f_string(r, wire); break;
        default: pr_skip(r, field, wire, 0);
        }
    }
    int32_t t = (int32_t)(uint32_t)type;
    w->reward_type = (t >= 1 && t <= 4) ? (uint8_t)t : 0;
    uint64_t v;
    if (parse_unsigned(commission.p, commission.n, 255, &v)) {
        w->has_commission = true;
        w->commission = (uint8_t)v;
    } else if (parse_unsigned(bps.p, bps.n, 65535, &v) && v / 100 <= 255) {
        w->has_commission = true;
        w->commission = (uint8_t)(v / 100);
    }
}

typedef struct {
    double ui;
    uint64_t decimals;
    str_t amount, ui_string;
} p_amount_t;

static void pb_amount(pr_t *r, p_amount_t *a) {
    uint32_t field;
    int wire;
    while (pr_key(r, &field, &wire)) {
        switch (field) {
        case 1: a->ui = f_double(r, wire); break;
        case 2: a->decimals = f_varint(r, wire); break;
        case 3: a->amount = f_string(r, wire); break;
        case 4: a->ui_string = f_string(r, wire); break;
        default: pr_skip(r, field, wire, 0);
        }
    }
}

static void pb_token(pr_t *r, token_t *t) {
    p_amount_t a = {0};
    a.amount.p = a.ui_string.p = "";
    uint64_t account_index = 0;
    memset(t, 0, sizeof *t);
    t->mint.p = t->owner.p = t->program_id.p = "";
    uint32_t field;
    int wire;
    while (pr_key(r, &field, &wire)) {
        switch (field) {
        case 1: account_index = f_varint(r, wire); break;
        case 2: t->mint = f_string(r, wire); break;
        case 3: { pr_t s = sub(r, f_bytes(r, wire)); pb_amount(&s, &a); break; } /* merged */
        case 4: t->owner = f_string(r, wire); break;
        case 5: t->program_id = f_string(r, wire); break;
        default: pr_skip(r, field, wire, 0);
        }
    }
    t->account_index = (uint8_t)account_index;
    t->decimals = (uint8_t)a.decimals;
    t->amount = a.amount;
    double mag = a.ui < 0 ? -a.ui : a.ui;
    t->has_ui = mag > 2.220446049250313e-16;
    t->ui = a.ui;
    if (a.ui_string.n) t->ui_string = a.ui_string;
    else set_ui_string(r->c, t);
}

static void pb_instruction(pr_t *r, iix_t *ix) {
    uint64_t program = 0;
    memset(ix, 0, sizeof *ix);
    ix->accounts.p = ix->data.p = (const uint8_t *)"";
    uint32_t field;
    int wire;
    while (pr_key(r, &field, &wire)) {
        switch (field) {
        case 1: program = f_varint(r, wire); break;
        case 2: ix->accounts = f_bytes(r, wire); break;
        case 3: ix->data = f_bytes(r, wire); break;
        case 4: ix->stack = (uint32_t)f_varint(r, wire); ix->has_stack = true; break;
        default: pr_skip(r, field, wire, 0);
        }
    }
    ix->program = (uint8_t)program;
}

static void pb_inner(pr_t *r, inner_t *in) {
    uint64_t index = 0;
    memset(in, 0, sizeof *in);
    uint32_t field;
    int wire;
    while (pr_key(r, &field, &wire)) {
        switch (field) {
        case 1: index = f_varint(r, wire); break;
        case 2: {
            pr_t s = sub(r, f_bytes(r, wire));
            VRESERVE(r->c, in->ix);
            pb_instruction(&s, &in->ix.v[in->ix.n++]);
            break;
        }
        default: pr_skip(r, field, wire, 0);
        }
    }
    in->index = (uint8_t)index;
}

typedef struct {
    meta_t m;
    bool err_present;
    bytes_t err_bytes;
    bytes_vec_t lw, lr;
    bool rd_present, rd_none, inner_none, logs_none;
    bytes_t rd_pid;
} p_meta_t;

static void pb_meta(pr_t *r, p_meta_t *p) {
    meta_t *m = &p->m;
    uint32_t field;
    int wire;
    while (pr_key(r, &field, &wire)) {
        switch (field) {
        case 1: { /* TransactionError { bytes err = 1 } (merged) */
            pr_t s = sub(r, f_bytes(r, wire));
            p->err_present = true;
            uint32_t f2;
            int w2;
            while (pr_key(&s, &f2, &w2)) {
                if (f2 == 1) p->err_bytes = f_bytes(&s, w2);
                else pr_skip(&s, f2, w2, 0);
            }
            break;
        }
        case 2: m->fee = f_varint(r, wire); break;
        case 3: f_repeated_u64(r, wire, &m->pre); break;
        case 4: f_repeated_u64(r, wire, &m->post); break;
        case 5: {
            pr_t s = sub(r, f_bytes(r, wire));
            VRESERVE(r->c, m->inner);
            pb_inner(&s, &m->inner.v[m->inner.n++]);
            break;
        }
        case 6: { str_t s = f_string(r, wire); VPUSH(r->c, m->logs, s); break; }
        case 7:
        case 8: {
            pr_t s = sub(r, f_bytes(r, wire));
            tokens_vec_t *v = field == 7 ? &m->pre_tokens : &m->post_tokens;
            VRESERVE(r->c, *v);
            pb_token(&s, &v->v[v->n++]);
            break;
        }
        case 9: {
            pr_t s = sub(r, f_bytes(r, wire));
            VRESERVE(r->c, m->rewards);
            pb_reward(&s, &m->rewards.v[m->rewards.n++]);
            break;
        }
        case 10: p->inner_none = f_varint(r, wire) != 0; break;
        case 11: p->logs_none = f_varint(r, wire) != 0; break;
        case 12: { bytes_t b = f_bytes(r, wire); VPUSH(r->c, p->lw, b); break; }
        case 13: { bytes_t b = f_bytes(r, wire); VPUSH(r->c, p->lr, b); break; }
        case 14: { /* ReturnData (merged) */
            pr_t s = sub(r, f_bytes(r, wire));
            if (!p->rd_present) {
                p->rd_present = true;
                p->rd_pid.p = m->return_data.p = (const uint8_t *)"";
                p->rd_pid.n = m->return_data.n = 0;
            }
            uint32_t f2;
            int w2;
            while (pr_key(&s, &f2, &w2)) {
                if (f2 == 1) p->rd_pid = f_bytes(&s, w2);
                else if (f2 == 2) m->return_data = f_bytes(&s, w2);
                else pr_skip(&s, f2, w2, 0);
            }
            break;
        }
        case 15: p->rd_none = f_varint(r, wire) != 0; break;
        case 16: m->cu = f_varint(r, wire); m->has_cu = true; break;
        case 17: m->cost = f_varint(r, wire); m->has_cost = true; break;
        default: pr_skip(r, field, wire, 0);
        }
    }
}

static void proto_meta_parse(ctx_t *c, void *arg) {
    void **io = arg;
    bytes_t *b = io[0];
    p_meta_t *p = acalloc(c, 1, sizeof *p);
    pr_t r = {c, b->p, b->n, 0};
    pb_meta(&r, p);
    io[1] = p;
}

/* Conversion errors are final (§9.2). */
static meta_t *proto_meta_convert(ctx_t *c, p_meta_t *p) {
    meta_t *m = &p->m;
    if (p->err_present) {
        br_t r = {c, p->err_bytes.p, p->err_bytes.n, 0};
        if (b_txerr(&r, &m->err_json) != B_OK) DIE(c, "invalid TransactionError in protobuf metadata");
    }
    m->has_inner = !p->inner_none;
    m->has_logs = !p->logs_none;
    m->has_pre_tokens = m->has_post_tokens = true;
    m->has_rewards = true;
    for (size_t i = 0; i < p->lw.n; i++) {
        if (p->lw.v[i].n != 32) DIE(c, "loaded address is not 32 bytes");
        VPUSH(c, m->loaded_w, p->lw.v[i].p);
    }
    for (size_t i = 0; i < p->lr.n; i++) {
        if (p->lr.v[i].n != 32) DIE(c, "loaded address is not 32 bytes");
        VPUSH(c, m->loaded_r, p->lr.v[i].p);
    }
    if (!p->rd_none && p->rd_present) {
        if (p->rd_pid.n != 32) DIE(c, "return data program id is not 32 bytes");
        m->has_return = true;
        m->return_program = p->rd_pid.p;
    }
    return m;
}

typedef struct {
    rewards_vec_t list;
    bool has_partitions;
    uint64_t partitions;
} p_rewards_t;

static void proto_rewards_parse(ctx_t *c, void *arg) {
    void **io = arg;
    bytes_t *b = io[0];
    p_rewards_t *p = acalloc(c, 1, sizeof *p);
    pr_t r = {c, b->p, b->n, 0};
    uint32_t field;
    int wire;
    while (pr_key(&r, &field, &wire)) {
        if (field == 1) {
            pr_t s = sub(&r, f_bytes(&r, wire));
            VRESERVE(c, p->list);
            pb_reward(&s, &p->list.v[p->list.n++]);
        } else if (field == 2) {
            pr_t s = sub(&r, f_bytes(&r, wire));
            p->has_partitions = true;
            uint32_t f2;
            int w2;
            while (pr_key(&s, &f2, &w2)) {
                if (f2 == 1) p->partitions = f_varint(&s, w2);
                else pr_skip(&s, f2, w2, 0);
            }
        } else {
            pr_skip(&r, field, wire, 0);
        }
    }
    io[1] = p;
}

/* ================================================================== payload split (§9.2) */

static void meta_payload(ctx_t *c, uint64_t slot, bytes_t b, void *out) {
    meta_t **result = out;
    void *io[2] = {&b, NULL};
    if (slot < BINCODE_SLOT_CUTOFF) {
        meta_t *m = bincode_metadata(c, b);
        if (m) { *result = m; return; }
        proto_meta_parse(c, io);
        *result = proto_meta_convert(c, io[1]);
        return;
    }
    if (attempt(c, proto_meta_parse, io) == 0) {
        *result = proto_meta_convert(c, io[1]);
        return;
    }
    meta_t *m = bincode_metadata(c, b);
    if (!m) DIE(c, "metadata is neither protobuf nor bincode");
    *result = m;
}

static void rewards_payload(ctx_t *c, uint64_t slot, bytes_t b, void *out) {
    block_rewards_t *result = out;
    block_rewards_t tmp = {0};
    void *io[2] = {&b, NULL};
    if (slot < BINCODE_SLOT_CUTOFF) {
        if (!bincode_rewards(c, b, &tmp.list)) {
            proto_rewards_parse(c, io);
            p_rewards_t *p = io[1];
            tmp.list.v = p->list.v;
            tmp.list.n = p->list.n;
            tmp.list.cap = p->list.cap;
            tmp.has_partitions = p->has_partitions;
            tmp.partitions = p->partitions;
        }
    } else if (attempt(c, proto_rewards_parse, io) == 0) {
        p_rewards_t *p = io[1];
        tmp.list.v = p->list.v;
        tmp.list.n = p->list.n;
        tmp.list.cap = p->list.cap;
        tmp.has_partitions = p->has_partitions;
        tmp.partitions = p->partitions;
    } else if (!bincode_rewards(c, b, &tmp.list)) {
        DIE(c, "rewards are neither protobuf nor bincode");
    }
    *result = tmp;
}

/* ================================================================== frame unwrapping (§9.1) */

typedef void (*payload_fn)(ctx_t *c, uint64_t slot, bytes_t b, void *out);

typedef struct {
    payload_fn fn;
    uint64_t slot;
    bytes_t in;
    void *out;
} payload_call_t;

static void payload_thunk(ctx_t *c, void *arg) {
    payload_call_t *p = arg;
    p->fn(c, p->slot, p->in, p->out);
}

typedef struct {
    bytes_t in, out;
} zstd_call_t;

static void zstd_thunk(ctx_t *c, void *arg) {
    zstd_call_t *z = arg;
    z->out = zstd_decompress(c, z->in.p, z->in.n);
}

static void unwrap_frame(ctx_t *c, uint64_t slot, bytes_t frame, payload_fn fn, void *out) {
    zstd_call_t z = {frame, {0}};
    if (frame.n >= 4 && rd32le(frame.p) == 0xFD2FB528u) {
        if (attempt(c, zstd_thunk, &z) == 0) fn(c, slot, z.out, out);
        else fn(c, slot, frame, out);
        return;
    }
    payload_call_t call = {fn, slot, frame, out};
    if (attempt(c, payload_thunk, &call) == 0) return;
    char first[sizeof c->msg];
    memcpy(first, c->msg, sizeof first);
    if (attempt(c, zstd_thunk, &z) == 0) {
        fn(c, slot, z.out, out);
        return;
    }
    DIE(c, "%s", first);
}

meta_t *decode_metadata(ctx_t *c, uint64_t slot, bytes_t frame) {
    if (frame.n == 0) return NULL;
    meta_t *m = NULL;
    unwrap_frame(c, slot, frame, meta_payload, &m);
    return m;
}

void decode_rewards(ctx_t *c, uint64_t slot, bytes_t frame, block_rewards_t *out) {
    memset(out, 0, sizeof *out);
    if (frame.n == 0) return;
    unwrap_frame(c, slot, frame, rewards_payload, out);
}
