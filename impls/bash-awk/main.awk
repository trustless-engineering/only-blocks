# main.awk: the persistent JSON-RPC engine. server.bash feeds it one request
# per message on stdin and reads one reply per message from stdout:
#
#   in:  "Q <seq> <length>\n" <body> "\001"
#   out: "R <seq> <length>\n" <json> "\n"
#
# Both RAM-only LRU caches live in this process for its whole lifetime.

BEGIN {
    lib_init()
    txerr_init()
    RT_NAME[1] = "\"Fee\""; RT_NAME[2] = "\"Rent\""; RT_NAME[3] = "\"Staking\""; RT_NAME[4] = "\"Voting\""
    split("AddressLookupTab1e1111111111111111111111111 BPFLoader2111111111111111111111111111111111 " \
          "BPFLoader1111111111111111111111111111111111 BPFLoaderUpgradeab1e11111111111111111111111 " \
          "ComputeBudget111111111111111111111111111111 Config1111111111111111111111111111111111111 " \
          "Ed25519SigVerify111111111111111111111111111 Feature111111111111111111111111111111111111 " \
          "LoaderV411111111111111111111111111111111111 KeccakSecp256k11111111111111111111111111111 " \
          "Secp256r1SigVerify1111111111111111111111111 StakeConfig11111111111111111111111111111111 " \
          "Stake11111111111111111111111111111111111111 11111111111111111111111111111111 " \
          "Vote111111111111111111111111111111111111111 ZkE1Gama1Proof11111111111111111111111111111 " \
          "ZkTokenProof1111111111111111111111111111111 SysvarC1ock11111111111111111111111111111111 " \
          "SysvarEpochRewards1111111111111111111111111 SysvarEpochSchedu1e111111111111111111111111 " \
          "SysvarFees111111111111111111111111111111111 Sysvar1nstructions1111111111111111111111111 " \
          "SysvarLastRestartS1ot1111111111111111111111 SysvarRecentB1ockHashes11111111111111111111 " \
          "SysvarRent111111111111111111111111111111111 SysvarRewards111111111111111111111111111111 " \
          "SysvarS1otHashes111111111111111111111111111 SysvarS1otHistory11111111111111111111111111 " \
          "SysvarStakeHistory1111111111111111111111111 NativeLoader1111111111111111111111111111111 " \
          "Sysvar1111111111111111111111111111111111111", rl, " ")
    for (i in rl) RESERVED[rl[i]] = 1
    UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111"
    ZERO_HASH = "11111111111111111111111111111111"
    LRU_CAP = 100000
    srand()

    base = ENVIRON["OB_BASE"]; DIR = ENVIRON["OB_DIR"]; BASHBIN = ENVIRON["OB_BASH"]
    OD = ENVIRON["OB_OD"]; CURL = ENVIRON["OB_CURL"]
    # Base URL pieces (server.bash already normalized and validated it).
    BASE_URL = base
    BASE_SCHEME = substr(base, 1, index(base, ":") - 1)
    rest = substr(base, length(BASE_SCHEME) + 4)
    slash = index(rest, "/")
    hostport = slash ? substr(rest, 1, slash - 1) : rest
    BASE_PATH = slash ? substr(rest, slash) : ""
    if (hostport ~ /^\[/) {
        BASE_HOST = substr(hostport, 2, index(hostport, "]") - 2)
        BASE_PORT = substr(hostport, index(hostport, "]") + 2)
    } else if (index(hostport, ":")) {
        BASE_HOST = substr(hostport, 1, index(hostport, ":") - 1)
        BASE_PORT = substr(hostport, index(hostport, ":") + 1)
    } else {
        BASE_HOST = hostport
        BASE_PORT = ""
    }
    sub(/^.*@/, "", BASE_HOST)
    if (BASE_PORT == "") BASE_PORT = (BASE_SCHEME == "https") ? "443" : "80"

    while (1) {
        RS = "\n"
        if ((getline head) <= 0) break
        split(head, hf, " ")
        if (hf[1] != "Q") continue
        RS = "\001"
        if ((getline body) <= 0) body = ""
        RS = "\n"
        if (length(body) != hf[3] + 0) body = "\001"
        ON = 0
        delete OUT
        handle(body)
        total = 0
        for (i = 1; i <= ON; i++) total += length(OUT[i])
        printf "R %s %d\n", hf[2], total
        for (i = 1; i <= ON; i++) printf "%s", OUT[i]
        printf "\n"
        fflush()
    }
}

function emit_err(idraw, code, msg) {
    emit("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":" code ",\"message\":" jstr(msg) "},\"id\":" idraw "}")
}

function handle(body,   root, n, i) {
    if (index(body, "\001") || (body ~ /[\200-\377]/ && !utf8str(body))) { emit_err("null", -32700, "Parse error"); return }
    root = jparse(body)
    if (!root) { emit_err("null", -32700, "Parse error"); return }
    if (JT[root] == "a") {
        n = JN[root]
        if (n == 0 || n > 100) { emit_err("null", -32600, "Invalid Request"); return }
        emit("[")
        for (i = 1; i <= n; i++) {
            if (i > 1) emit(",")
            dispatch(JCH[root, i])
        }
        emit("]")
        return
    }
    dispatch(root)
}

function dispatch(r,   jr, m, idn, idraw, method, p) {
    if (JT[r] != "o") { emit_err("null", -32600, "Invalid Request"); return }
    jr = oval(r, "jsonrpc"); m = oval(r, "method"); idn = oget(r, "id")
    if ((jr && JT[jr] != "s") || (m && JT[m] != "s")) { emit_err("null", -32600, "Invalid Request"); return }
    if (idn && JT[idn] != "s" && JT[idn] != "n" && JT[idn] != "z") { emit_err("null", -32600, "Invalid Request"); return }
    idraw = !idn ? "null" : (JT[idn] == "s") ? JRAW[idn] : (JT[idn] == "n") ? JV[idn] : "null"
    if (!jr || JV[jr] != "2.0" || !m) { emit_err(idraw, -32600, "Invalid Request"); return }
    method = JV[m]
    p = oget(r, "params")
    if (method == "getHealth") {
        if (p && JT[p] != "z" && !(JT[p] == "a" && JN[p] == 0)) { emit_err(idraw, -32602, "Invalid params: getHealth takes no parameters"); return }
        emit("{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":" idraw "}")
        return
    }
    if (method == "getBlock") { getblock(p, idraw); return }
    emit_err(idraw, -32601, "Method not found: " method)
}

# Validates getBlock params (SPEC §5.4) into GB_*; 0 on invalid params.
function block_params(p,   s, c, k, v) {
    if (!p || JT[p] != "a" || JN[p] < 1 || JN[p] > 2) return 0
    s = JCH[p, 1]
    if (JT[s] != "n") return 0
    v = JV[s] ""
    if (v !~ /^(0|[1-9][0-9]*)$/ || length(v) > 20 || (length(v) == 20 && v > U64MAX)) return 0
    if (!dec2pair(v)) return 0
    GB_SLOT = v; GB_HI = P_HI; GB_LO = P_LO
    GB_ENC = "json"; GB_DETAILS = "full"; GB_REWARDS = 1; GB_MAXV = ""
    if (JN[p] == 2) {
        c = JCH[p, 2]
        if (JT[c] == "s") GB_ENC = JV[c]
        else if (JT[c] == "o") {
            if ((k = oval(c, "encoding"))) { if (JT[k] != "s") return 0; GB_ENC = JV[k] }
            if ((k = oval(c, "transactionDetails"))) { if (JT[k] != "s") return 0; GB_DETAILS = JV[k] }
            if ((k = oval(c, "rewards"))) { if (JT[k] != "t" && JT[k] != "f") return 0; GB_REWARDS = (JT[k] == "t") }
            if ((k = oval(c, "maxSupportedTransactionVersion"))) {
                if (JT[k] != "n" || JV[k] !~ /^(0|[1-9][0-9]?[0-9]?)$/ || JV[k] + 0 > 255) return 0
                GB_MAXV = JV[k] + 0
            }
            if ((k = oval(c, "commitment"))) {
                if (JT[k] != "s" || (JV[k] != "finalized" && JV[k] != "confirmed")) return 0
            }
        } else if (JT[c] != "z") return 0
    }
    if (GB_ENC != "json" && GB_ENC != "jsonParsed" && GB_ENC != "base64" && GB_ENC != "base58") return 0
    if (GB_DETAILS != "full" && GB_DETAILS != "accounts" && GB_DETAILS != "signatures" && GB_DETAILS != "none") return 0
    if (GB_DETAILS == "accounts" && GB_ENC != "json") return 0
    return 1
}

function getblock(p, idraw,   mark) {
    if (!block_params(p)) { emit_err(idraw, -32602, "Invalid params"); return }
    mark = ON
    ERR = 0; ERRMSG = ""
    emit("{\"jsonrpc\":\"2.0\",\"result\":")
    if (!gb_run() || ERR) {
        ON = mark
        if (!ERR) { ERR = -32603; ERRMSG = "Internal error" }
        emit_err(idraw, ERR, ERRMSG)
        return
    }
    emit(",\"id\":" idraw "}")
}

# Hash of the last Entry of the indexed block (32 zero bytes when it has none).
function last_entry_hash(ix, n, list,   en, h) {
    if (n == 0) return ZERO_HASH
    en = ix_node(ix, list[n], 1)
    if (!en) return ""
    h = cb_at(en, 2)
    if (!h || CK[h] != "b" || CN[h] != 32) { fail(-32603, "Invalid Entry hash"); return "" }
    return b58(CS[h], 32)
}

function gb_run(   blk, sv, ne, info, phi, plo, pdec, bt, ht, bh, prev, pblk, pn, e, en, h, nt, t, tn, mn, first, body, metaj, ver, r, rn, accounts) {
    delete M; MTOP = 0
    CBN = 0; delete CK; delete CHI; delete CLO; delete CS; delete CN; delete CI; delete CC
    delete IX_S; delete IX_N; delete IX_BLOCK
    delete ENTRIES; delete PENTRIES
    PRE157 = (GB_HI == 0 && GB_LO < 67824000)

    if (!load_slice(GB_SLOT, GB_HI, GB_LO)) return 0
    if (!car_index(1, LB_S, LB_N)) return 0
    blk = cb_parse(IX_S[1, IX_BLOCK[1]], IX_N[1, IX_BLOCK[1]])
    if (!blk || !cb_kind(blk, 2)) return fail(-32603, "Invalid Block node")
    sv = cb_at(blk, 1)
    if (!sv || CK[sv] != "u" || CHI[sv] != GB_HI || CLO[sv] != GB_LO) return fail(-32603, "Block slot differs from the requested slot")
    ne = cb_links(cb_at(blk, 3), ENTRIES)
    if (ne < 0) return fail(-32603, "Invalid Entry link")
    info = cb_at(blk, 4)
    if (info && CK[info] != "a") info = 0
    phi = 0; plo = 0
    if (info && cb_u64(cb_at(info, 0))) { phi = U_HI; plo = U_LO }
    pdec = u64s(phi, plo)
    bt = "null"
    if (info && cb_i64(cb_at(info, 1)) && (I_HI || I_LO)) bt = i64s(I_HI, I_LO)
    ht = "null"
    if (info && cb_u64(cb_at(info, 2))) ht = u64s(U_HI, U_LO)

    bh = last_entry_hash(1, ne, ENTRIES)
    if (ERR) return 0
    lru_put("h", GB_SLOT, bh)

    if (GB_HI == 0 && GB_LO == 0) prev = ZERO_HASH
    else {
        prev = lru_get("h", pdec)
        if (prev == "") {
            if (!load_slice(pdec, phi, plo)) return 0
            if (!car_index(2, LB_S, LB_N)) return 0
            pblk = cb_parse(IX_S[2, IX_BLOCK[2]], IX_N[2, IX_BLOCK[2]])
            if (!pblk || !cb_kind(pblk, 2)) return fail(-32603, "Invalid parent Block node")
            if (!cb_u64(cb_at(pblk, 1))) return fail(-32603, "Missing parent Block slot")
            pn = cb_links(cb_at(pblk, 3), PENTRIES)
            if (pn < 0) return fail(-32603, "Invalid parent Entry link")
            prev = last_entry_hash(2, pn, PENTRIES)
            if (ERR) return 0
            lru_put("h", pdec, prev)
        }
    }

    emit("{\"previousBlockhash\":\"" prev "\",\"blockhash\":\"" bh "\",\"parentSlot\":" pdec \
         ",\"blockTime\":" bt ",\"blockHeight\":" ht)

    if (GB_DETAILS != "none") {
        accounts = (GB_DETAILS == "accounts")
        emit(",\"" (GB_DETAILS == "signatures" ? "signatures" : "transactions") "\":[")
        first = 1
        for (e = 1; e <= ne; e++) {
            en = ix_node(1, ENTRIES[e], 1)
            if (!en) return 0
            h = cb_at(en, 2)
            if (!h || CK[h] != "b" || CN[h] != 32) return fail(-32603, "Invalid Entry hash")
            delete TXL
            nt = cb_links(cb_at(en, 3), TXL)
            if (nt < 0) return fail(-32603, "Invalid transaction link")
            for (t = 1; t <= nt; t++) {
                tn = ix_node(1, TXL[t], 0)
                if (!tn) return 0
                if (!df_payload(1, cb_at(tn, 1))) return 0
                if (!tx_parse(DF_S, DF_N)) return fail(-32603, "Undecodable transaction")
                if (GB_DETAILS == "signatures") {
                    if (TXNSIG == 0) return fail(-32603, "Transaction has no signature")
                    emit((first ? "" : ",") "\"" b58(TXSIG, 64) "\"")
                    first = 0
                    continue
                }
                meta_reset()
                QNONE = 1
                mn = cb_at(tn, 2)
                if (mn && CK[mn] == "a") {
                    if (!df_payload(1, mn)) return 0
                    QNONE = 0
                    if (!unwrap("m", DF_S, DF_N)) return 0
                }
                if (QNONE && TXV0) meta_reset()
                if (TXV0 && GB_MAXV == "")
                    return fail(-32015, "Transaction version (0) is not supported by the requesting client. Please try the request again with the following configuration parameter: \"maxSupportedTransactionVersion\": 0")
                build_keys()
                body = tx_body_json(GB_ENC, accounts)
                if (ERR) return 0
                if (QNONE) metaj = "null"
                else {
                    metaj = meta_json(GB_ENC, accounts)
                    if (ERR) return 0
                }
                ver = ""
                if (!QNONE && GB_MAXV != "") ver = TXV0 ? "0" : "\"legacy\""
                emit((first ? "" : ",") "{\"transaction\":" body ",\"meta\":" metaj (ver != "" ? ",\"version\":" ver : "") "}")
                first = 0
            }
        }
        emit("]")
    }

    if (GB_REWARDS) {
        RW_N["b"] = 0; BPART = ""
        r = cb_at(blk, 5)
        if (r && CK[r] == "b") {
            if (!cb_link(r)) return fail(-32603, "Invalid rewards link")
            if (!LK_ABSENT && ((1, LK) in IX_S)) {
                rn = ix_node(1, LK, 5)
                if (!rn) return 0
                if (CC[rn] > 2) {
                    if (!df_payload(1, CI[rn, 2])) return 0
                    if (!unwrap("r", DF_S, DF_N)) return 0
                }
            }
        }
        emit(",\"rewards\":" rewards_json("b"))
        if (BPART != "") emit(",\"numRewardPartitions\":" BPART)
    }
    emit("}")
    return 1
}
