# meta.awk: zstd unwrapping (decoder in zstd.awk), protobuf and bincode
# transaction metadata and rewards, TransactionError, and the getBlock JSON
# serializer.

# ------------------------------------------------------------------ unwrap

# WIRE_FORMATS §9.1 for kind "m" (metadata) or "r" (rewards). For metadata an
# empty frame sets QNONE.
function unwrap(kind, s, n,   ok, e1, m1) {
    if (n == 0) {
        if (kind == "m") QNONE = 1
        else { RW_N["b"] = 0; BPART = "" }
        return 1
    }
    if (n >= 4 && is_zstd_magic(s)) {
        if (zstd_dec(s, n)) return payload(kind, ZS_S, ZS_N)
        return payload(kind, s, n)
    }
    if (payload(kind, s, n)) return 1
    e1 = ERR; m1 = ERRMSG; ERR = 0
    if (!zstd_dec(s, n)) { ERR = e1; ERRMSG = m1; return 0 }
    return payload(kind, ZS_S, ZS_N)
}

# WIRE_FORMATS §9.2: the epoch-157 codec split with fallbacks.
function payload(kind, s, n) {
    if (kind == "m") {
        if (PRE157) {
            if (bc_meta(s, n)) return 1
            ERR = 0
            if (!pb_meta(s, n)) return fail(-32603, "Undecodable transaction metadata")
            return pb_meta_convert()
        }
        if (pb_meta(s, n)) return pb_meta_convert()
        ERR = 0
        if (bc_meta(s, n)) return 1
        return fail(-32603, "Undecodable transaction metadata")
    }
    if (PRE157) {
        if (bc_rewards(s, n)) return 1
        ERR = 0
        if (pb_rewards(s, n)) return 1
        return fail(-32603, "Undecodable block rewards")
    }
    if (pb_rewards(s, n)) return 1
    ERR = 0
    if (bc_rewards(s, n)) return 1
    return fail(-32603, "Undecodable block rewards")
}

# --------------------------------------------------------------- the model

function meta_reset() {
    QNONE = 0
    QERRJ = "null"; QERR_P = 0; QERR_S = 0; QERR_N = 0
    QFEE = "0"; QPRE_N = 0; QPOST_N = 0
    delete QPRE; delete QPOST
    QINN = 0; QINN_N = 0; QINN_NONE = 0
    delete QG_IDX; delete QG_N
    delete QIX_P; delete QIX_AS; delete QIX_AN; delete QIX_DS; delete QIX_DN; delete QIX_SH
    QLOG = 0; QLOG_N = 0; QLOG_NONE = 0
    delete QLOG_J
    QTB[1] = 0; QTB[2] = 0; QTB_N[1] = 0; QTB_N[2] = 0
    delete QTB_AI; delete QTB_MINT; delete QTB_OWN; delete QTB_PROG; delete QTB_UIA
    delete QTB_DEC; delete QTB_AMT; delete QTB_UAS
    RW_P["m"] = 0; RW_N["m"] = 0
    QLW_N = 0; QLR_N = 0
    delete QLW; delete QLR; delete QLWN; delete QLRN
    QRD = 0; QRD_NONE = 0; QRD_P = 0; QRD_PN = 0; QRD_DS = 0; QRD_DN = 0
    QCU = ""; QCOST = ""
}

# ----------------------------------------------------------------- strings

# parse_u64 / Rust from_str for unsigned text: digits with an optional "+".
# Returns the canonical decimal text, or "" when it does not parse or exceeds max.
function parse_uint(v, max,   d) {
    if (v !~ /^\+?[0-9]+$/) return ""
    d = v
    sub(/^\+/, "", d)
    sub(/^0+/, "", d)
    if (d == "") d = "0"
    if (length(d) > length(max) || (length(d) == length(max) && d > max)) return ""
    return d
}

# real_number_string_trimmed(amount, decimals).
function ui_amount_string(amount, decimals,   s) {
    s = parse_uint(amount, U64MAX)
    if (s == "") s = "0"
    if (decimals == 0) return s
    if (length(s) <= decimals) s = "0." sprintf("%0" (decimals - length(s)) "d", 0) s
    else s = substr(s, 1, length(s) - decimals) "." substr(s, length(s) - decimals + 1)
    sub(/0+$/, "", s)
    sub(/\.$/, "", s)
    return s
}

# ------------------------------------------------------- TransactionError

function txerr_init(   s) {
    s = "GenericError InvalidArgument InvalidInstructionData InvalidAccountData AccountDataTooSmall " \
        "InsufficientFunds IncorrectProgramId MissingRequiredSignature AccountAlreadyInitialized " \
        "UninitializedAccount UnbalancedInstruction ModifiedProgramId ExternalAccountLamportSpend " \
        "ExternalAccountDataModified ReadonlyLamportChange ReadonlyDataModified DuplicateAccountIndex " \
        "ExecutableModified RentEpochModified NotEnoughAccountKeys AccountDataSizeChanged " \
        "AccountNotExecutable AccountBorrowFailed AccountBorrowOutstanding DuplicateAccountOutOfSync " \
        "Custom InvalidError ExecutableDataModified ExecutableLamportChange ExecutableAccountNotRentExempt " \
        "UnsupportedProgramId CallDepth MissingAccount ReentrancyNotAllowed MaxSeedLengthExceeded " \
        "InvalidSeeds InvalidRealloc ComputationalBudgetExceeded PrivilegeEscalation " \
        "ProgramEnvironmentSetupFailure ProgramFailedToComplete ProgramFailedToCompile Immutable " \
        "IncorrectAuthority BorshIoError AccountNotRentExempt InvalidAccountOwner ArithmeticOverflow " \
        "UnsupportedSysvar IllegalOwner MaxAccountsDataAllocationsExceeded MaxAccountsExceeded " \
        "MaxInstructionTraceLengthExceeded BuiltinProgramsMustConsumeComputeUnits"
    N_IE = split(s, IE_NAME, " ")
    s = "AccountInUse AccountLoadedTwice AccountNotFound ProgramAccountNotFound InsufficientFundsForFee " \
        "InvalidAccountForFee AlreadyProcessed BlockhashNotFound InstructionError CallChainTooDeep " \
        "MissingSignatureForFee InvalidAccountIndex SignatureFailure InvalidProgramForExecution " \
        "SanitizeFailure ClusterMaintenance AccountBorrowOutstanding WouldExceedMaxBlockCostLimit " \
        "UnsupportedVersion InvalidWritableAccount WouldExceedMaxAccountCostLimit " \
        "WouldExceedAccountDataBlockLimit TooManyAccountLocks AddressLookupTableNotFound " \
        "InvalidAddressLookupTableOwner InvalidAddressLookupTableData InvalidAddressLookupTableIndex " \
        "InvalidRentPayingAccount WouldExceedMaxVoteCostLimit WouldExceedAccountDataTotalLimit " \
        "DuplicateInstruction InsufficientFundsForRent MaxLoadedAccountsDataSizeExceeded " \
        "InvalidLoadedAccountsDataSizeLimit ResanitizationNeeded ProgramExecutionTemporarilyRestricted " \
        "UnbalancedTransaction ProgramCacheHitMaxLimit CommitCancelled"
    N_TE = split(s, TE_NAME, " ")
}

# Bincode TransactionError at M[BP .. BE) (advances BP). Returns its JSON, or
# "" with BF set.
function bc_txerr(   v, i, k, c) {
    v = bu32(); if (BF) return ""
    if (v >= N_TE) { BF = 1; return "" }
    if (v == 8) {
        i = bu8(); k = bu32(); if (BF) return ""
        if (k >= N_IE) { BF = 1; return "" }
        if (k == 25) { c = bu32(); if (BF) return ""; return "{\"InstructionError\":[" i ",{\"Custom\":" c "}]}" }
        return "{\"InstructionError\":[" i ",\"" IE_NAME[k + 1] "\"]}"
    }
    if (v == 30) { i = bu8(); if (BF) return ""; return "{\"DuplicateInstruction\":" i "}" }
    if (v == 31 || v == 35) { i = bu8(); if (BF) return ""; return "{\"" TE_NAME[v + 1] "\":{\"account_index\":" i "}}" }
    return "\"" TE_NAME[v + 1] "\""
}

# ---------------------------------------------------------------- bincode

function bu8() { if (BP >= BE) { BF = 1; return 0 } return M[BP++] }
function bu32() { if (BP + 4 > BE) { BF = 1; return 0 } BP += 4; return le32(BP - 4) }
function bu64() { if (BP + 8 > BE) { BF = 1; return 0 } B_LO = le32(BP); B_HI = le32(BP + 4); BP += 8; return 1 }

# u64 element count that must satisfy count <= left / min_size.
function bcount(min,   n) {
    if (!bu64()) return 0
    if (B_HI || B_LO > BE - BP || B_LO > int((BE - BP) / min)) { BF = 1; return 0 }
    return B_LO
}

# String: sets BS_S/BS_N (UTF-8 checked).
function bstr() {
    if (!bu64()) return 0
    if (B_HI || B_LO > BE - BP) { BF = 1; return 0 }
    BS_S = BP; BS_N = B_LO; BP += B_LO
    if (!utf8ok(BS_S, BS_N)) { BF = 1; return 0 }
    return 1
}

function bopt(   t) {
    t = bu8(); if (BF) return 0
    if (t > 1) { BF = 1; return 0 }
    return t
}

function bcu16(   save, v) {
    VP = BP; VE = BE
    v = cu16()
    if (v < 0) { BF = 1; return 0 }
    BP = VP
    return v
}

# StoredExtendedReward (ext = 1) or the legacy reward without commission.
function bc_reward(t, ext,   i, i2) {
    i = RW_N[t]++
    if (!bstr()) return 0
    RW_PK[t, i] = jbytes(BS_S, BS_N)
    if (!bu64()) return 0
    RW_LAM[t, i] = i64s(B_HI, B_LO)
    RW_PB[t, i] = "0"; RW_RT[t, i] = "null"; RW_CM[t, i] = "null"
    if (ext && BP >= BE) return 1
    if (!bu64()) return 0
    RW_PB[t, i] = u64s(B_HI, B_LO)
    if (ext && BP >= BE) return 1
    if (bopt()) {
        i2 = bu32(); if (BF) return 0
        if (i2 > 3) { BF = 1; return 0 }
        RW_RT[t, i] = RT_NAME[i2 + 1]
    }
    if (BF) return 0
    if (ext && BP < BE) {
        if (bopt()) { RW_CM[t, i] = bu8() }
        if (BF) return 0
    }
    return 1
}

function bc_token(k, layout,   i, amt, dec, ui) {
    i = QTB_N[k]++
    QTB_AI[k, i] = bu8(); if (BF) return 0
    if (!bstr()) return 0
    QTB_MINT[k, i] = jbytes(BS_S, BS_N)
    if (BP + 8 > BE) { BF = 1; return 0 }
    ui = f64le(BP); QTB_UIA[k, i] = fjson(ui, F_BAD); BP += 8
    dec = bu8(); if (BF) return 0
    QTB_DEC[k, i] = dec
    if (!bstr()) return 0
    amt = mstr(BS_S, BS_N)
    QTB_AMT[k, i] = jbytes(BS_S, BS_N)
    QTB_UAS[k, i] = jstr(ui_amount_string(amt, dec))
    QTB_OWN[k, i] = ""; QTB_PROG[k, i] = ""
    if (layout >= 2 && BP < BE) { if (!bstr()) return 0; if (BS_N) QTB_OWN[k, i] = jbytes(BS_S, BS_N) }
    if (layout >= 3 && BP < BE) { if (!bstr()) return 0; if (BS_N) QTB_PROG[k, i] = jbytes(BS_S, BS_N) }
    return 1
}

# One bincode StoredTransactionStatusMeta attempt (legacy = no stack heights,
# layout 1/2/3 = token balance V1/V2/full). strict requires full consumption.
function bc_meta_try(s, n, legacy, layout, strict,   c, i, g, j, m, k, gi) {
    meta_reset()
    BP = s; BE = s + n; BF = 0
    c = bu32(); if (BF) return 0
    if (c > 1) return 0
    if (c == 1) { QERRJ = bc_txerr(); if (BF) return 0 }
    if (!bu64()) return 0
    QFEE = u64s(B_HI, B_LO)
    c = bcount(8); if (BF) return 0
    for (i = 0; i < c; i++) { bu64(); QPRE[i] = u64s(B_HI, B_LO) }
    QPRE_N = c
    c = bcount(8); if (BF) return 0
    for (i = 0; i < c; i++) { bu64(); QPOST[i] = u64s(B_HI, B_LO) }
    QPOST_N = c
    if (BP < BE) {
        if (bopt()) {
            QINN = 1
            g = bcount(9); if (BF) return 0
            for (gi = 0; gi < g; gi++) {
                QG_IDX[gi] = bu8(); if (BF) return 0
                m = bcount(legacy ? 3 : 4); if (BF) return 0
                for (j = 0; j < m; j++) {
                    QIX_P[gi, j] = bu8(); if (BF) return 0
                    k = bcu16(); if (BF) return 0
                    if (BP + k > BE) return 0
                    QIX_AS[gi, j] = BP; QIX_AN[gi, j] = k; BP += k
                    k = bcu16(); if (BF) return 0
                    if (BP + k > BE) return 0
                    QIX_DS[gi, j] = BP; QIX_DN[gi, j] = k; BP += k
                    QIX_SH[gi, j] = "null"
                    if (!legacy) {
                        if (bopt()) { QIX_SH[gi, j] = bu32() }
                        if (BF) return 0
                    }
                }
                QG_N[gi] = m
            }
            QINN_N = g
        }
        if (BF) return 0
    }
    if (BP < BE) {
        if (bopt()) {
            QLOG = 1
            c = bcount(8); if (BF) return 0
            for (i = 0; i < c; i++) { if (!bstr()) return 0; QLOG_J[i] = jbytes(BS_S, BS_N) }
            QLOG_N = c
        }
        if (BF) return 0
    }
    for (k = 1; k <= 2; k++) {
        if (BP < BE) {
            if (bopt()) {
                QTB[k] = 1
                c = bcount(1); if (BF) return 0
                for (i = 0; i < c; i++) if (!bc_token(k, layout)) return 0
            }
            if (BF) return 0
        }
    }
    if (BP < BE) {
        if (bopt()) {
            RW_P["m"] = 1
            c = bcount(16); if (BF) return 0
            for (i = 0; i < c; i++) if (!bc_reward("m", 1)) return 0
        }
        if (BF) return 0
    }
    if (BP < BE) {
        if (bopt()) {
            if (BP + 32 > BE) return 0
            QRD = 1; QRD_P = BP; QRD_PN = 32; BP += 32
            if (!bu64()) return 0
            if (B_HI || B_LO > BE - BP) return 0
            QRD_DS = BP; QRD_DN = B_LO; BP += B_LO
        }
        if (BF) return 0
    }
    if (BP < BE) { if (bopt()) { bu64(); QCU = u64s(B_HI, B_LO) } if (BF) return 0 }
    if (BP < BE) { if (bopt()) { bu64(); QCOST = u64s(B_HI, B_LO) } if (BF) return 0 }
    if (strict && BP != BE) return 0
    return 1
}

function bc_meta(s, n) {
    if (bc_meta_try(s, n, 0, 3, 1)) return 1
    if (bc_meta_try(s, n, 1, 1, 1)) return 1
    if (bc_meta_try(s, n, 1, 2, 1)) return 1
    if (bc_meta_try(s, n, 1, 3, 1)) return 1
    if (bc_meta_try(s, n, 0, 3, 0)) return 1
    return fail(-32603, "Undecodable bincode transaction metadata")
}

function bc_rewards_try(s, n, ext, strict,   c, i) {
    RW_N["b"] = 0; BPART = ""
    BP = s; BE = s + n; BF = 0
    c = bcount(ext ? 16 : 25); if (BF) return 0
    for (i = 0; i < c; i++) if (!bc_reward("b", ext)) return 0
    if (strict && BP != BE) return 0
    return 1
}

function bc_rewards(s, n) {
    if (bc_rewards_try(s, n, 1, 1)) return 1
    if (bc_rewards_try(s, n, 0, 1)) return 1
    if (bc_rewards_try(s, n, 1, 0)) return 1
    return fail(-32603, "Undecodable bincode rewards")
}

# --------------------------------------------------------------- protobuf

# Reads one field at M[p .. e). Sets PB_F, PB_W and the value (PB_HI/PB_LO,
# or PB_VS/PB_VN). Returns the position after it, or -1.
function pb_field(p, e) {
    VP = p; VE = e
    if (!uvarint()) return -1
    if (V_HI || V_LO < 8) return -1
    PB_F = int(V_LO / 8); PB_W = V_LO % 8
    if (PB_W == 0) { if (!uvarint()) return -1; PB_HI = V_HI; PB_LO = V_LO }
    else if (PB_W == 1) { if (VP + 8 > VE) return -1; PB_VS = VP; VP += 8 }
    else if (PB_W == 2) {
        if (!uvarint()) return -1
        if (V_HI || V_LO > VE - VP) return -1
        PB_VS = VP; PB_VN = V_LO; VP += V_LO
    } else if (PB_W == 5) { if (VP + 4 > VE) return -1; PB_VS = VP; VP += 4 }
    else if (PB_W == 3) { if (!pb_group(PB_F, 0)) return -1 }
    else return -1
    return VP
}

function pb_group(field, depth,   f, w) {
    if (depth >= 100) return 0
    while (1) {
        if (!uvarint()) return 0
        if (V_HI || V_LO < 8) return 0
        f = int(V_LO / 8); w = V_LO % 8
        if (w == 4) return f == field
        if (w == 0) { if (!uvarint()) return 0 }
        else if (w == 1) { if (VP + 8 > VE) return 0; VP += 8 }
        else if (w == 2) { if (!uvarint()) return 0; if (V_HI || V_LO > VE - VP) return 0; VP += V_LO }
        else if (w == 5) { if (VP + 4 > VE) return 0; VP += 4 }
        else if (w == 3) { if (!pb_group(f, depth + 1)) return 0 }
        else return 0
    }
}

# Appends the varints of a repeated uint64 (packed or not) to arr.
function pb_u64s(arr, cnt, w, vs, vn, hi, lo,   e) {
    if (w == 0) { arr[cnt++] = u64s(hi, lo); return cnt }
    if (w != 2) return -1
    VP = vs; e = vs + vn
    while (VP < e) {
        VE = e
        if (!uvarint()) return -1
        arr[cnt++] = u64s(V_HI, V_LO)
    }
    return cnt
}

function pb_meta(s, n,   p, e, f, w, vs, vn, hi, lo, c) {
    meta_reset()
    QTB[1] = 1; QTB[2] = 1; RW_P["m"] = 1
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        f = PB_F; w = PB_W; vs = PB_VS; vn = PB_VN; hi = PB_HI; lo = PB_LO
        if (f == 1) { if (w != 2 || !pb_err(vs, vn)) return 0 }
        else if (f == 2) { if (w != 0) return 0; QFEE = u64s(hi, lo) }
        else if (f == 3) { c = pb_u64s(QPRE, QPRE_N, w, vs, vn, hi, lo); if (c < 0) return 0; QPRE_N = c }
        else if (f == 4) { c = pb_u64s(QPOST, QPOST_N, w, vs, vn, hi, lo); if (c < 0) return 0; QPOST_N = c }
        else if (f == 5) { if (w != 2 || !pb_inner(vs, vn)) return 0 }
        else if (f == 6) {
            if (w != 2 || !utf8ok(vs, vn)) return 0
            QLOG_J[QLOG_N++] = jbytes(vs, vn)
        } else if (f == 7 || f == 8) { if (w != 2 || !pb_token(f - 6, vs, vn)) return 0 }
        else if (f == 9) { if (w != 2 || !pb_reward("m", vs, vn)) return 0 }
        else if (f == 10) { if (w != 0) return 0; QINN_NONE = (hi || lo) }
        else if (f == 11) { if (w != 0) return 0; QLOG_NONE = (hi || lo) }
        else if (f == 12) { if (w != 2) return 0; QLW[QLW_N] = vs; QLWN[QLW_N++] = vn }
        else if (f == 13) { if (w != 2) return 0; QLR[QLR_N] = vs; QLRN[QLR_N++] = vn }
        else if (f == 14) { if (w != 2 || !pb_retdata(vs, vn)) return 0 }
        else if (f == 15) { if (w != 0) return 0; QRD_NONE = (hi || lo) }
        else if (f == 16) { if (w != 0) return 0; QCU = u64s(hi, lo) }
        else if (f == 17) { if (w != 0) return 0; QCOST = u64s(hi, lo) }
    }
    return 1
}

function pb_err(s, n,   p, e) {
    QERR_P = 1
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        if (PB_F == 1) { if (PB_W != 2) return 0; QERR_S = PB_VS; QERR_N = PB_VN }
    }
    return 1
}

function pb_retdata(s, n,   p, e) {
    if (!QRD) { QRD = 1; QRD_PN = 0; QRD_DN = 0; QRD_DS = 0 }
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        if (PB_F == 1) { if (PB_W != 2) return 0; QRD_P = PB_VS; QRD_PN = PB_VN }
        else if (PB_F == 2) { if (PB_W != 2) return 0; QRD_DS = PB_VS; QRD_DN = PB_VN }
    }
    return 1
}

function pb_inner(s, n,   p, e, g, f, w, vs, vn, lo) {
    g = QINN_N++
    QG_IDX[g] = 0; QG_N[g] = 0
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        f = PB_F; w = PB_W; vs = PB_VS; vn = PB_VN; lo = PB_LO
        if (f == 1) { if (w != 0) return 0; QG_IDX[g] = lo % 256 }
        else if (f == 2) { if (w != 2 || !pb_ix(g, vs, vn)) return 0 }
    }
    return 1
}

function pb_ix(g, s, n,   p, e, j) {
    j = QG_N[g]++
    QIX_P[g, j] = 0; QIX_AS[g, j] = 0; QIX_AN[g, j] = 0; QIX_DS[g, j] = 0; QIX_DN[g, j] = 0; QIX_SH[g, j] = "null"
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        if (PB_F == 1) { if (PB_W != 0) return 0; QIX_P[g, j] = PB_LO % 256 }
        else if (PB_F == 2) { if (PB_W != 2) return 0; QIX_AS[g, j] = PB_VS; QIX_AN[g, j] = PB_VN }
        else if (PB_F == 3) { if (PB_W != 2) return 0; QIX_DS[g, j] = PB_VS; QIX_DN[g, j] = PB_VN }
        else if (PB_F == 4) { if (PB_W != 0) return 0; QIX_SH[g, j] = PB_LO }
    }
    return 1
}

function pb_token(k, s, n,   p, e, i, f, w, vs, vn, lo, amt, uas, dec, ui, uibad, uip) {
    i = QTB_N[k]++
    QTB_AI[k, i] = 0; QTB_MINT[k, i] = "\"\""; QTB_OWN[k, i] = ""; QTB_PROG[k, i] = ""
    TA_UI = 0; TA_UIP = 0; TA_UIBAD = 0; TA_DEC = 0; TA_AMT = ""; TA_AMTJ = "\"\""; TA_UAS = ""; TA_UASJ = ""
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        f = PB_F; w = PB_W; vs = PB_VS; vn = PB_VN; lo = PB_LO
        if (f == 1) { if (w != 0) return 0; QTB_AI[k, i] = lo % 256 }
        else if (f == 2) { if (w != 2 || !utf8ok(vs, vn)) return 0; QTB_MINT[k, i] = jbytes(vs, vn) }
        else if (f == 3) { if (w != 2 || !pb_amount(vs, vn)) return 0 }
        else if (f == 4) { if (w != 2 || !utf8ok(vs, vn)) return 0; QTB_OWN[k, i] = vn ? jbytes(vs, vn) : "" }
        else if (f == 5) { if (w != 2 || !utf8ok(vs, vn)) return 0; QTB_PROG[k, i] = vn ? jbytes(vs, vn) : "" }
    }
    QTB_DEC[k, i] = TA_DEC
    QTB_AMT[k, i] = TA_AMTJ
    if (TA_UIP && !TA_UIBAD && (TA_UI > 2.220446049250313e-16 || TA_UI < -2.220446049250313e-16))
        QTB_UIA[k, i] = fjson(TA_UI, 0)
    else QTB_UIA[k, i] = "null"
    QTB_UAS[k, i] = (TA_UAS != "") ? TA_UASJ : jstr(ui_amount_string(TA_AMT, TA_DEC))
    return 1
}

function pb_amount(s, n,   p, e) {
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        if (PB_F == 1) { if (PB_W != 1) return 0; TA_UI = f64le(PB_VS); TA_UIBAD = F_BAD; TA_UIP = 1 }
        else if (PB_F == 2) { if (PB_W != 0) return 0; TA_DEC = PB_LO % 256 }
        else if (PB_F == 3) {
            if (PB_W != 2 || !utf8ok(PB_VS, PB_VN)) return 0
            TA_AMT = mstr(PB_VS, PB_VN); TA_AMTJ = jbytes(PB_VS, PB_VN)
        } else if (PB_F == 4) {
            if (PB_W != 2 || !utf8ok(PB_VS, PB_VN)) return 0
            TA_UAS = PB_VN ? "x" : ""; TA_UASJ = jbytes(PB_VS, PB_VN)
        }
    }
    return 1
}

# Reward message into RW_*[t, i] (shared by metadata and block rewards).
function pb_reward(t, s, n,   p, e, i, f, w, vs, vn, hi, lo, cm, bps, rt) {
    i = RW_N[t]++
    RW_PK[t, i] = "\"\""; RW_LAM[t, i] = "0"; RW_PB[t, i] = "0"; RW_RT[t, i] = "null"
    cm = ""; bps = ""; rt = 0
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        f = PB_F; w = PB_W; vs = PB_VS; vn = PB_VN; hi = PB_HI; lo = PB_LO
        if (f == 1) { if (w != 2 || !utf8ok(vs, vn)) return 0; RW_PK[t, i] = jbytes(vs, vn) }
        else if (f == 2) { if (w != 0) return 0; RW_LAM[t, i] = i64s(hi, lo) }
        else if (f == 3) { if (w != 0) return 0; RW_PB[t, i] = u64s(hi, lo) }
        else if (f == 4) { if (w != 0) return 0; rt = lo }
        else if (f == 5) { if (w != 2 || !utf8ok(vs, vn)) return 0; cm = mstr(vs, vn) }
        else if (f == 6) { if (w != 2 || !utf8ok(vs, vn)) return 0; bps = mstr(vs, vn) }
    }
    RW_RT[t, i] = (rt >= 1 && rt <= 4) ? RT_NAME[rt] : "null"
    cm = parse_uint(cm, "255")
    if (cm == "") {
        bps = parse_uint(bps, "65535")
        if (bps != "" && int(bps / 100) <= 255) cm = int(bps / 100)
    }
    RW_CM[t, i] = (cm == "") ? "null" : cm
    return 1
}

function pb_rewards(s, n,   p, e) {
    RW_N["b"] = 0; BPART = ""
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        if (PB_F == 1) { if (PB_W != 2 || !pb_reward("b", PB_VS, PB_VN)) return 0 }
        else if (PB_F == 2) {
            if (PB_W != 2) return 0
            if (BPART == "") BPART = "0"
            if (!pb_partitions(PB_VS, PB_VN)) return 0
        }
    }
    return 1
}

function pb_partitions(s, n,   p, e) {
    p = s; e = s + n
    while (p < e) {
        p = pb_field(p, e); if (p < 0) return 0
        if (PB_F == 1) { if (PB_W != 0) return 0; BPART = u64s(PB_HI, PB_LO) }
    }
    return 1
}

# §10.3 conversion checks; their failures are final.
function pb_meta_convert(   i) {
    if (QERR_P) {
        BP = QERR_S; BE = QERR_S + QERR_N; BF = 0
        QERRJ = bc_txerr()
        if (BF) return fail(-32603, "Invalid TransactionError in metadata")
    }
    if (QINN_NONE) QINN = 0; else QINN = 1
    if (QLOG_NONE) QLOG = 0; else QLOG = 1
    for (i = 0; i < QLW_N; i++) if (QLWN[i] != 32) return fail(-32603, "Loaded address is not 32 bytes")
    for (i = 0; i < QLR_N; i++) if (QLRN[i] != 32) return fail(-32603, "Loaded address is not 32 bytes")
    if (QRD_NONE) QRD = 0
    else if (QRD && QRD_PN != 32) return fail(-32603, "Return data program id is not 32 bytes")
    return 1
}

# ------------------------------------------------------------ serializer

function emit(s) { OUT[++ON] = s }

function rewards_json(t,   i, out) {
    out = "["
    for (i = 0; i < RW_N[t]; i++)
        out = out (i ? "," : "") "{\"pubkey\":" RW_PK[t, i] ",\"lamports\":" RW_LAM[t, i] \
              ",\"postBalance\":" RW_PB[t, i] ",\"rewardType\":" RW_RT[t, i] ",\"commission\":" RW_CM[t, i] "}"
    return out "]"
}

function bytes_list(s, n,   i, out) {
    out = "["
    for (i = 0; i < n; i++) out = out (i ? "," : "") M[s + i]
    return out "]"
}

# Combined key list (KEYS[0..NKEYS)) and the account flags of §14.
function build_keys(   i, n, s, w, nrs, prog, upg) {
    NKEYS = 0
    for (i = 0; i < TXNKEY; i++) KEYS[NKEYS++] = b58(TXKEY + 32 * i, 32)
    S_KEYS = NKEYS; W_KEYS = 0
    if (TXV0 && !QNONE) {
        for (i = 0; i < QLW_N; i++) KEYS[NKEYS++] = b58(QLW[i], 32)
        W_KEYS = QLW_N
        for (i = 0; i < QLR_N; i++) KEYS[NKEYS++] = b58(QLR[i], 32)
    }
}

function account_keys_json(   i, upg, prog, nrs, w, out) {
    upg = 0
    for (i = 0; i < NKEYS; i++) if (KEYS[i] == UPGRADEABLE) upg = 1
    delete prog
    for (i = 0; i < TXNIX; i++) prog[TXIX_P[i]] = 1
    nrs = TXNRS
    out = "["
    for (i = 0; i < NKEYS; i++) {
        if (i >= S_KEYS) w = (i - S_KEYS) < W_KEYS
        else if (i < nrs) w = i < nrs - TXNROS
        else w = i < S_KEYS - TXNROU
        if (w && (KEYS[i] in RESERVED)) w = 0
        if (w && !upg && (i in prog)) w = 0
        out = out (i ? "," : "") "{\"pubkey\":\"" KEYS[i] "\",\"writable\":" (w ? "true" : "false") \
              ",\"signer\":" (i < nrs ? "true" : "false") ",\"source\":\"" (i >= S_KEYS ? "lookupTable" : "transaction") "\"}"
    }
    return out "]"
}

function key_at(i) {
    if (i >= NKEYS) { fail(-32603, "Instruction account index out of range"); return "" }
    return "\"" KEYS[i] "\""
}

# Instruction JSON; parsed = 1 uses KEYS (partially decoded form).
function ix_json(parsed, pid, as, an, ds, dn, sh,   out, i, k) {
    if (!parsed) return "{\"programIdIndex\":" pid ",\"accounts\":" bytes_list(as, an) ",\"data\":\"" b58(ds, dn) "\",\"stackHeight\":" sh "}"
    out = "{\"programId\":" key_at(pid) ",\"accounts\":["
    for (i = 0; i < an; i++) { k = key_at(M[as + i]); out = out (i ? "," : "") k }
    if (ERR) return ""
    return out "],\"data\":\"" b58(ds, dn) "\",\"stackHeight\":" sh "}"
}

function sigs_json(   i, out) {
    out = "["
    for (i = 0; i < TXNSIG; i++) out = out (i ? "," : "") "\"" b58(TXSIG + 64 * i, 64) "\""
    return out "]"
}

function tx_body_json(enc, accounts,   parsed, out, i, j, ix) {
    if (enc == "base64") return "[\"" b64(TXRAW, TXRAWN) "\",\"base64\"]"
    if (enc == "base58") return "[\"" b58(TXRAW, TXRAWN) "\",\"base58\"]"
    parsed = (enc == "jsonParsed")
    if (accounts) return "{\"signatures\":" sigs_json() ",\"accountKeys\":" account_keys_json() "}"
    out = "{\"signatures\":" sigs_json() ",\"message\":{"
    if (parsed) out = out "\"accountKeys\":" account_keys_json()
    else {
        out = out "\"header\":{\"numRequiredSignatures\":" TXNRS ",\"numReadonlySignedAccounts\":" TXNROS \
              ",\"numReadonlyUnsignedAccounts\":" TXNROU "},\"accountKeys\":["
        for (i = 0; i < TXNKEY; i++) out = out (i ? "," : "") "\"" KEYS[i] "\""
        out = out "]"
    }
    out = out ",\"recentBlockhash\":\"" b58(TXBH, 32) "\",\"instructions\":["
    for (i = 0; i < TXNIX; i++) {
        ix = ix_json(parsed, TXIX_P[i], TXIX_AS[i], TXIX_AN[i], TXIX_DS[i], TXIX_DN[i], 1)
        if (ERR) return ""
        out = out (i ? "," : "") ix
    }
    out = out "]"
    if (TXV0) {
        out = out ",\"addressTableLookups\":["
        for (i = 0; i < TXNLU; i++)
            out = out (i ? "," : "") "{\"accountKey\":\"" b58(TXLU_K[i], 32) "\",\"writableIndexes\":" \
                  bytes_list(TXLU_WS[i], TXLU_WN[i]) ",\"readonlyIndexes\":" bytes_list(TXLU_RS[i], TXLU_RN[i]) "}"
        out = out "]"
    }
    if (TXV1)
        out = out ",\"transactionConfig\":{\"priorityFee\":" TXCF_PF ",\"computeUnitLimit\":" TXCF_CU \
              ",\"loadedAccountsDataSizeLimit\":" TXCF_LA ",\"heapSize\":" TXCF_HS "}"
    return out "}}"
}

function tb_json(k,   i, out) {
    if (!QTB[k]) return "null"
    out = "["
    for (i = 0; i < QTB_N[k]; i++) {
        out = out (i ? "," : "") "{\"accountIndex\":" QTB_AI[k, i] ",\"mint\":" QTB_MINT[k, i] \
              ",\"uiTokenAmount\":{\"uiAmount\":" QTB_UIA[k, i] ",\"decimals\":" QTB_DEC[k, i] \
              ",\"amount\":" QTB_AMT[k, i] ",\"uiAmountString\":" QTB_UAS[k, i] "}"
        if (QTB_OWN[k, i] != "") out = out ",\"owner\":" QTB_OWN[k, i]
        if (QTB_PROG[k, i] != "") out = out ",\"programId\":" QTB_PROG[k, i]
        out = out "}"
    }
    return out "]"
}

function meta_json(enc, accounts,   parsed, out, i, g, j, ix, list) {
    parsed = (enc == "jsonParsed")
    out = "{\"err\":" QERRJ ",\"status\":" (QERRJ == "null" ? "{\"Ok\":null}" : "{\"Err\":" QERRJ "}") \
          ",\"fee\":" QFEE ",\"preBalances\":["
    for (i = 0; i < QPRE_N; i++) out = out (i ? "," : "") QPRE[i]
    out = out "],\"postBalances\":["
    for (i = 0; i < QPOST_N; i++) out = out (i ? "," : "") QPOST[i]
    out = out "],\"preTokenBalances\":" tb_json(1) ",\"postTokenBalances\":" tb_json(2)
    if (GB_REWARDS) out = out ",\"rewards\":" (RW_P["m"] ? rewards_json("m") : "null")
    else if (!accounts) out = out ",\"rewards\":null"
    if (!accounts) {
        out = out ",\"innerInstructions\":"
        if (!QINN) out = out "null"
        else {
            out = out "["
            for (g = 0; g < QINN_N; g++) {
                out = out (g ? "," : "") "{\"index\":" QG_IDX[g] ",\"instructions\":["
                for (j = 0; j < QG_N[g]; j++) {
                    ix = ix_json(parsed, QIX_P[g, j], QIX_AS[g, j], QIX_AN[g, j], QIX_DS[g, j], QIX_DN[g, j], QIX_SH[g, j])
                    if (ERR) return ""
                    out = out (j ? "," : "") ix
                }
                out = out "]}"
            }
            out = out "]"
        }
        out = out ",\"logMessages\":"
        if (!QLOG) out = out "null"
        else {
            out = out "["
            for (i = 0; i < QLOG_N; i++) out = out (i ? "," : "") QLOG_J[i]
            out = out "]"
        }
        if (!parsed) {
            out = out ",\"loadedAddresses\":{\"writable\":["
            for (i = 0; i < QLW_N; i++) out = out (i ? "," : "") "\"" b58(QLW[i], 32) "\""
            out = out "],\"readonly\":["
            for (i = 0; i < QLR_N; i++) out = out (i ? "," : "") "\"" b58(QLR[i], 32) "\""
            out = out "]}"
        }
        if (QRD) out = out ",\"returnData\":{\"programId\":\"" b58(QRD_P, 32) "\",\"data\":[\"" b64(QRD_DS, QRD_DN) "\",\"base64\"]}"
        if (QCU != "") out = out ",\"computeUnitsConsumed\":" QCU
        if (QCOST != "") out = out ",\"costUnits\":" QCOST
    }
    return out "}"
}
