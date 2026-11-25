# wire.awk: Old Faithful Range reads, CARv1 + DAG-CBOR, DataFrame reassembly
# and the Solana VersionedTransaction wire format.
#
# Every byte lives in M[0 .. MTOP). Functions that can fail set ERR (the
# JSON-RPC code) and ERRMSG and return; callers check ERR after each call.

function fail(code, msg) {
    if (!ERR) { ERR = code; ERRMSG = msg }
    return 0
}

# Appends the hex tokens printed by `od -An -v -tx1` to M; returns the count.
function slurp(cmd,   line, n, t, k, c) {
    c = 0
    while ((cmd | getline line) > 0) {
        n = split(line, t, " ")
        for (k = 1; k <= n; k++) M[MTOP++] = HEX[t[k]]
        c += n
    }
    close(cmd)
    return c
}

# --------------------------------------------------------------- HTTP client

# One Range GET. The raw HTTP/1.1 response lands at M[s .. s+n). Sets
# HR_STATUS (0 = transport failure), HR_RETRY ("" or seconds), HR_BS/HR_BN
# (the de-framed body) and HR_CAP (1 when the body passed the cap).
function http_attempt(path, first, last, cap,   cmd, s, n, i, hend, line, name, val, cl, chunked, p, end, size, ext, bs, bn, hdr, lines, status) {
    HR_STATUS = 0; HR_RETRY = ""; HR_CAPX = 0
    if (BASE_SCHEME == "https")
        cmd = CURL " -sS --http1.1 --raw -i --connect-timeout 10 --max-time 60" \
              " -H " shq("Range: bytes=" first "-" last) " -H 'User-Agent: onlyblocks/bash-awk'" \
              " " shq(BASE_URL path) " 2>/dev/null | " OD " -An -v -tx1"
    else
        cmd = shq(BASHBIN) " " shq(DIR "/fetch.bash") " " shq(BASE_HOST) " " shq(BASE_PORT) " " \
              shq(BASE_PATH path) " " shq(first "-" last)
    s = MTOP
    n = slurp(cmd)
    # Header block: up to the first CRLF CRLF.
    hend = -1
    for (i = 0; i + 3 < n; i++) {
        if (M[s + i] == 13 && M[s + i + 1] == 10 && M[s + i + 2] == 13 && M[s + i + 3] == 10) { hend = i; break }
        if (i > 65536) break
    }
    if (hend < 0) { MTOP = s; return }
    hdr = mstr(s, hend)
    gsub(/\r/, "", hdr)
    split(hdr, lines, "\n")
    if (lines[1] !~ /^HTTP\/1\.[01] [0-9][0-9][0-9]/) { MTOP = s; return }
    status = substr(lines[1], 10, 3) + 0
    cl = -1; chunked = 0
    for (i = 2; (i in lines); i++) {
        line = lines[i]
        p = index(line, ":")
        if (!p) continue
        name = tolower(substr(line, 1, p - 1))
        val = substr(line, p + 1)
        gsub(/^[ \t]+|[ \t]+$/, "", val)
        if (name == "content-length") {
            if (val !~ /^[0-9]+$/) { MTOP = s; return }
            cl = val + 0
        } else if (name == "transfer-encoding") {
            if (tolower(val) ~ /chunked/) chunked = 1
        } else if (name == "retry-after") HR_RETRY = val
    }
    delete lines
    bs = s + hend + 4
    end = s + n
    if (status != 206) { HR_STATUS = status; MTOP = s; return }
    if (!chunked && cl > cap) { HR_STATUS = 206; HR_CAPX = 1; MTOP = s; return }
    if (chunked) {
        # Decode in place: chunk data is copied down over the chunk headers.
        p = bs; bn = 0
        while (1) {
            line = ""
            while (p < end && M[p] != 13) { line = line CHR[M[p]]; p++; if (length(line) > 64) { MTOP = s; return } }
            if (p + 1 >= end || M[p + 1] != 10) { MTOP = s; return }
            p += 2
            ext = index(line, ";")
            if (ext) line = substr(line, 1, ext - 1)
            gsub(/[ \t]/, "", line)
            if (line !~ /^[0-9a-fA-F]+$/) { MTOP = s; return }
            size = 0
            for (i = 1; i <= length(line); i++) size = size * 16 + index("0123456789abcdef", tolower(substr(line, i, 1))) - 1
            if (size == 0) break
            if (bn + size > cap) { HR_STATUS = 206; HR_CAPX = 1; MTOP = s; return }
            if (p + size + 2 > end) { MTOP = s; return }
            for (i = 0; i < size; i++) M[bs + bn + i] = M[p + i]
            bn += size
            p += size + 2
        }
    } else if (cl >= 0) {
        if (end - bs < cl) { MTOP = s; return }
        bn = cl
    } else {
        bn = end - bs
        if (bn > cap) { HR_STATUS = 206; HR_CAPX = 1; MTOP = s; return }
    }
    # Move the body to the start of the scratch area.
    for (i = 0; i < bn; i++) M[s + i] = M[bs + i]
    MTOP = s + bn
    HR_STATUS = 206; HR_BS = s; HR_BN = bn
}

# Retry-After as seconds (delta-seconds or an HTTP-date), or -1 if unparseable.
function retry_after(v,   d, now, t, mon) {
    if (v ~ /^[0-9]+$/) return v + 0
    # IMF-fixdate / RFC 850 / asctime: pull day, month, year and time.
    if (!match(v, /[0-9][0-9]?[ -][A-Z][a-z][a-z][ -][0-9][0-9]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) return -1
    t = substr(v, RSTART, RLENGTH)
    gsub(/-/, " ", t)
    split(t, d, /[ :]/)
    mon = index("JanFebMarAprMayJunJulAugSepOctNovDec", d[2])
    if (!mon) return -1
    mon = (mon + 2) / 3
    if (d[3] < 100) d[3] += (d[3] < 70) ? 2000 : 1900
    srand(); now = srand()
    t = civil_days(d[3], mon, d[1]) * 86400 + d[4] * 3600 + d[5] * 60 + d[6]
    return (t > now) ? t - now : 0
}

function civil_days(y, m, d,   era, yoe, doy, doe) {
    if (m <= 2) y--
    era = int((y >= 0 ? y : y - 399) / 400)
    yoe = y - era * 400
    doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
    doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
    return era * 146097 + doe - 719468
}

# Range GET with the SPEC §4.3 retry policy. On success the body is
# M[RG_S .. RG_S+want). want is the exact expected length.
function range_get(slot, epoch, suffix, first, last, want, cap,   attempt, wait, ra) {
    for (attempt = 0; ; attempt++) {
        http_attempt("/" epoch "/epoch-" epoch suffix, first, last, cap)
        if (HR_STATUS == 206) {
            if (HR_CAPX) return fail(-32603, "Archive body exceeds the range cap")
            if (HR_BN != want) { MTOP = HR_BS; return fail(-32603, "Archive range body has the wrong length") }
            RG_S = HR_BS
            return 1
        }
        if (HR_STATUS == 404)
            return fail(-32004, "Block not available for slot " slot ": epoch " epoch " is not archived in Old Faithful (historical-only server)")
        if (HR_STATUS != 0 && HR_STATUS != 429 && (HR_STATUS < 500 || HR_STATUS > 599))
            return fail(-32603, "Unexpected archive HTTP status " HR_STATUS)
        if (attempt >= 4) return fail(-32603, "Archive range retries exhausted")
        ra = (HR_RETRY != "") ? retry_after(HR_RETRY) : -1
        if (ra >= 0) wait = (ra > 10) ? 10 : ra
        else {
            wait = 0.2 * 2 ^ attempt
            if (wait > 10) wait = 10
            wait = wait * (0.5 + rand() * 0.5)
        }
        if (wait > 0) system("/bin/sleep " sprintf("%.3f", wait))
    }
}

# Range read 1 (cached) then range read 2. Sets LB_S/LB_N to the CAR slice.
function load_slice(slot, hi, lo,   epoch, idx, v, off_lo, off_hi, len, end_lo, end_hi, f) {
    v = lru_get("r", slot)
    if (v == "") {
        divmod(hi, lo, 432000)
        epoch = u64s(DQ_HI, DQ_LO)
        idx = DR
        if (!range_get(slot, epoch, "-slot-ranges.raw", idx * 12, idx * 12 + 11, 12, 12)) return 0
        off_lo = le32(RG_S); off_hi = le32(RG_S + 4); len = le32(RG_S + 8)
        MTOP = RG_S
        v = epoch " " off_hi " " off_lo " " len
        lru_put("r", slot, v)
    }
    split(v, f, " ")
    epoch = f[1]; off_hi = f[2] + 0; off_lo = f[3] + 0; len = f[4] + 0
    if (len == 0) return fail(-32007, "Slot " slot " was skipped, or missing in long-term storage")
    if (len > 134217728) return fail(-32603, "Archive slice exceeds 128 MiB")
    end_lo = off_lo + len - 1; end_hi = off_hi
    if (end_lo >= TWO32) { end_lo -= TWO32; end_hi++ }
    if (end_hi >= TWO32) return fail(-32603, "Archive range end overflows u64")
    if (!range_get(slot, epoch, ".car", u64s(off_hi, off_lo), u64s(end_hi, end_lo), len, 134217728)) return 0
    LB_S = RG_S; LB_N = len
    return 1
}

# --------------------------------------------------------------------- LRUs

# Bounded LRU caches (doubly linked lists threaded through awk arrays).
function lru_get(c, k,   key) {
    key = c SUBSEP k
    if (!(key in LV)) return ""
    lru_unlink(c, key); lru_front(c, key)
    return LV[key]
}

function lru_put(c, k, v,   key, tail) {
    key = c SUBSEP k
    if (key in LV) lru_unlink(c, key)
    else LCOUNT[c]++
    LV[key] = v
    lru_front(c, key)
    if (LCOUNT[c] > LRU_CAP) {
        tail = LTAIL[c]
        lru_unlink(c, tail)
        delete LV[tail]; delete LPREV[tail]; delete LNEXT[tail]
        LCOUNT[c]--
    }
}

function lru_unlink(c, key,   p, n) {
    p = LPREV[key]; n = LNEXT[key]
    if (p != "") LNEXT[p] = n; else LHEAD[c] = n
    if (n != "") LPREV[n] = p; else LTAIL[c] = p
}

function lru_front(c, key,   h) {
    h = LHEAD[c]
    LPREV[key] = ""; LNEXT[key] = h
    if (h != "") LPREV[h] = key; else LTAIL[c] = key
    LHEAD[c] = key
}

# ------------------------------------------------------------------- varints

# Unsigned LEB128 at M[VP] (bounded by VE); sets V_HI/V_LO; 0 on error.
function uvarint(   shift, i, b, x) {
    V_HI = 0; V_LO = 0; shift = 0
    for (i = 0; i < 10; i++) {
        if (VP >= VE) return 0
        b = M[VP++]
        x = (b >= 128) ? b - 128 : b
        if (i == 9 && x > 1) return 0
        if (shift + 7 <= 32) V_LO += x * 2 ^ shift
        else if (shift >= 32) V_HI += x * 2 ^ (shift - 32)
        else {
            V_LO += (x % 2 ^ (32 - shift)) * 2 ^ shift
            V_HI += int(x / 2 ^ (32 - shift))
        }
        if (b < 128) return 1
        shift += 7
    }
    return 0
}

# ----------------------------------------------------------------------- CID

# Parses a CID at M[VP .. VE). Sets CID_S/CID_N and CID_ABSENT; 0 on error.
function cid_parse(   start, a, b, hc) {
    start = VP
    if (!uvarint()) return 0
    a = V_LO + V_HI * TWO32
    if (!uvarint()) return 0
    b = V_LO + V_HI * TWO32
    CID_ABSENT = 0
    if (a == 18 && b == 32) {
        if (VP + 32 > VE) return 0
        VP += 32
    } else {
        if (a != 1) return 0
        if (!uvarint()) return 0
        hc = V_LO + V_HI * TWO32
        if (!uvarint()) return 0
        if (V_HI || V_LO > 64) return 0
        if (VP + V_LO > VE) return 0
        CID_ABSENT = (hc == 0 && V_LO == 0)
        VP += V_LO
    }
    CID_S = start; CID_N = VP - start
    return 1
}

# ------------------------------------------------------------------ DAG-CBOR

# Node kinds in CK[]: u n b t a m f T F z. Ints keep their argument in
# CHI/CLO; strings their bytes at CS/CN; containers their children in
# CI[id, i] (0-based; maps alternate key, value) and their size in CC.
function cb_parse(s, n,   id) {
    CP = s; CE = s + n; CBERR = 0
    id = cb_item(0)
    if (CBERR || CP != CE) return 0
    return id
}

function cb_arg(info,   v, k) {
    CA_HI = 0
    if (info < 24) { CA_LO = info; return 1 }
    if (info == 24) k = 1
    else if (info == 25) k = 2
    else if (info == 26) k = 4
    else if (info == 27) k = 8
    else return 0
    if (CP + k > CE) return 0
    if (k == 8) {
        CA_HI = ((M[CP] * 256 + M[CP + 1]) * 256 + M[CP + 2]) * 256 + M[CP + 3]
        CP += 4; k = 4
    }
    v = 0
    while (k-- > 0) v = v * 256 + M[CP++]
    CA_LO = v
    return 1
}

function cb_item(depth,   h, major, info, id, i, cnt, c, start, total, ch) {
    if (depth > 128 || CP >= CE) { CBERR = 1; return 0 }
    h = M[CP++]
    major = int(h / 32); info = h % 32
    id = ++CBN
    if (major == 7) {
        if (info == 20) CK[id] = "F"
        else if (info == 21) CK[id] = "T"
        else if (info == 22 || info == 23) CK[id] = "z"
        else if (info == 25 || info == 26 || info == 27) {
            c = (info == 25) ? 2 : (info == 26) ? 4 : 8
            if (CP + c > CE) { CBERR = 1; return 0 }
            CP += c; CK[id] = "f"
        } else { CBERR = 1; return 0 }
        return id
    }
    if (info == 31) {
        if (major < 2 || major > 5) { CBERR = 1; return 0 }
        if (major <= 3) {
            # Indefinite string: concatenate definite chunks of the same major.
            start = MTOP; total = 0
            while (1) {
                if (CP >= CE) { CBERR = 1; return 0 }
                if (M[CP] == 255) { CP++; break }
                h = M[CP++]
                if (int(h / 32) != major || h % 32 == 31) { CBERR = 1; return 0 }
                if (!cb_arg(h % 32) || CA_HI || CP + CA_LO > CE) { CBERR = 1; return 0 }
                if (major == 3 && !utf8ok(CP, CA_LO)) { CBERR = 1; return 0 }
                for (i = 0; i < CA_LO; i++) M[MTOP++] = M[CP + i]
                CP += CA_LO; total += CA_LO
            }
            CK[id] = (major == 2) ? "b" : "t"; CS[id] = start; CN[id] = total
            return id
        }
        cnt = 0
        while (1) {
            if (CP >= CE) { CBERR = 1; return 0 }
            if (M[CP] == 255) { CP++; break }
            ch = cb_item(depth + 1); if (CBERR) return 0
            CI[id, cnt++] = ch
            if (major == 5) { ch = cb_item(depth + 1); if (CBERR) return 0; CI[id, cnt++] = ch }
        }
        CK[id] = (major == 4) ? "a" : "m"; CC[id] = (major == 4) ? cnt : cnt / 2
        return id
    }
    if (!cb_arg(info)) { CBERR = 1; return 0 }
    if (major == 0 || major == 1) {
        CK[id] = (major == 0) ? "u" : "n"; CHI[id] = CA_HI; CLO[id] = CA_LO
        return id
    }
    if (major == 6) return cb_item(depth + 1)
    if (major == 2 || major == 3) {
        if (CA_HI || CP + CA_LO > CE) { CBERR = 1; return 0 }
        if (major == 3 && !utf8ok(CP, CA_LO)) { CBERR = 1; return 0 }
        CK[id] = (major == 2) ? "b" : "t"; CS[id] = CP; CN[id] = CA_LO
        CP += CA_LO
        return id
    }
    # Arrays and maps.
    if (CA_HI || CA_LO * (major == 4 ? 1 : 2) > CE - CP) { CBERR = 1; return 0 }
    cnt = CA_LO * (major == 4 ? 1 : 2)
    for (i = 0; i < cnt; i++) {
        ch = cb_item(depth + 1)
        if (CBERR) return 0
        CI[id, i] = ch
    }
    CK[id] = (major == 4) ? "a" : "m"; CC[id] = (major == 4) ? cnt : cnt / 2
    return id
}

# Element i of array node a, or 0 when absent.
function cb_at(a, i) { return (CK[a] == "a" && i < CC[a]) ? CI[a, i] : 0 }

function cb_u64(v) { if (v && CK[v] == "u") { U_HI = CHI[v]; U_LO = CLO[v]; return 1 } return 0 }

# as_i64: sets I_HI/I_LO in two's complement.
function cb_i64(v) {
    if (!v) return 0
    if (CK[v] == "u" && CHI[v] < 2147483648) { I_HI = CHI[v]; I_LO = CLO[v]; return 1 }
    if (CK[v] == "n" && CHI[v] < 2147483648) { I_HI = TWO32 - 1 - CHI[v]; I_LO = TWO32 - 1 - CLO[v]; return 1 }
    return 0
}

function cb_kind(node, kind,   k) {
    k = cb_at(node, 0)
    return (k && CK[k] == "u" && CHI[k] == 0 && CLO[k] == kind)
}

# A DAG-CBOR link (bytes 00 + CID): sets LK (the CID key) and LK_ABSENT.
function cb_link(v) {
    if (!v || CK[v] != "b" || CN[v] < 1 || M[CS[v]] != 0) return 0
    VP = CS[v] + 1; VE = CS[v] + CN[v]
    if (!cid_parse()) return 0
    LK = mhex(CID_S, CID_N); LK_ABSENT = CID_ABSENT
    return 1
}

# Collects the links of array v into LKS[1..n] (n returned; -1 on error).
function cb_links(v, out,   n, i) {
    if (!v || CK[v] != "a") return 0
    n = CC[v]
    for (i = 0; i < n; i++) {
        if (!cb_link(CI[v, i])) return -1
        out[i + 1] = LK
    }
    return n
}

# ---------------------------------------------------------------- CAR index

# Indexes a headerless CARv1 section stream into IX_S/IX_N[ix, cid].
# Sets IX_BLOCK[ix] to the last Block section's node key.
function car_index(ix, s, n,   end, len, first, sec_s, sec_e, h, info, hs, node_s, id, key, k, found) {
    VP = s; end = s + n; first = 1; IX_BLOCK[ix] = ""
    while (VP < end) {
        VE = end
        if (!uvarint()) return fail(-32603, "Bad CAR section length")
        if (V_HI || V_LO > 33554432) return fail(-32603, "Oversize CAR section")
        len = V_LO
        if (len == 0) continue
        if (VP + len > end) return fail(-32603, "Truncated CAR section")
        sec_s = VP; sec_e = VP + len
        if (first) {
            first = 0
            if (int(M[sec_s] / 32) == 5) {
                id = cb_parse(sec_s, len)
                if (id && CK[id] == "m") {
                    found = 0
                    for (k = 0; k < CC[id]; k++) {
                        key = CI[id, 2 * k]
                        if (CK[key] == "t" && mstr(CS[key], CN[key]) == "version") found = 1
                    }
                    if (found) { VP = sec_e; continue }
                }
            }
        }
        VP = sec_s; VE = sec_e
        if (!cid_parse()) return fail(-32603, "Bad CID in CAR section")
        node_s = VP
        key = mhex(CID_S, CID_N)
        IX_S[ix, key] = node_s; IX_N[ix, key] = sec_e - node_s
        if (sec_e > node_s) {
            h = M[node_s]
            if (int(h / 32) == 4) {
                info = h % 32
                hs = (info < 24 || info == 31) ? 1 : (info == 24) ? 2 : (info == 25) ? 3 : (info == 26) ? 5 : (info == 27) ? 9 : 0
                if (hs && node_s + hs < sec_e && M[node_s + hs] == 2) IX_BLOCK[ix] = key
            }
        }
        VP = sec_e
    }
    if (IX_BLOCK[ix] == "") return fail(-32603, "CAR slice is missing its Block node")
    return 1
}

# Parses the indexed node under key and checks its kind; 0 (ERR) on failure.
function ix_node(ix, key, kind,   id) {
    if (!((ix, key) in IX_S)) return fail(-32603, "CID missing from CAR slice")
    id = cb_parse(IX_S[ix, key], IX_N[ix, key])
    if (!id) return fail(-32603, "Invalid DAG-CBOR node")
    if (!cb_kind(id, kind)) return fail(-32603, "Unexpected IPLD node kind")
    return id
}

# --------------------------------------------------------------- DataFrames

# Reassembles the DataFrame node df; sets DF_S/DF_N.
function df_payload(ix, df,   d, nx, n, stack, sp, i, seen, key, node, out, cnt, hashv, links, l2) {
    if (!cb_kind(df, 6)) return fail(-32603, "Expected a DataFrame")
    d = cb_at(df, 4)
    hashv = cb_at(df, 1)
    nx = cb_at(df, 5)
    n = cb_links(nx, links)
    if (n < 0) return fail(-32603, "Invalid DataFrame link")
    if (d && CK[d] == "b") { DF_S = CS[d]; DF_N = CN[d] } else { DF_S = MTOP; DF_N = 0 }
    if (n > 0) {
        out = MTOP
        for (i = 0; i < DF_N; i++) M[MTOP++] = M[DF_S + i]
        sp = 0
        for (i = n; i >= 1; i--) stack[++sp] = links[i]
        while (sp > 0) {
            key = stack[sp--]
            if (key in seen) return fail(-32603, "Repeated DataFrame CID")
            seen[key] = 1
            node = ix_node(ix, key, 6)
            if (!node) return 0
            d = cb_at(node, 4)
            if (d && CK[d] == "b") for (i = 0; i < CN[d]; i++) M[MTOP++] = M[CS[d] + i]
            delete l2
            cnt = cb_links(cb_at(node, 5), l2)
            if (cnt < 0) return fail(-32603, "Invalid DataFrame link")
            for (i = cnt; i >= 1; i--) stack[++sp] = l2[i]
        }
        DF_S = out; DF_N = MTOP - out
    }
    if (hashv && CK[hashv] == "u") {
        crc64(DF_S, DF_N)
        if (!(H_HI == CHI[hashv] && H_LO == CLO[hashv])) {
            fnv1a(DF_S, DF_N)
            if (!(H_HI == CHI[hashv] && H_LO == CLO[hashv])) return fail(-32603, "DataFrame hash mismatch")
        }
    }
    return 1
}

# ------------------------------------------------------ VersionedTransaction

function cu16(   b, v) {
    if (VP >= VE) return -1
    b = M[VP++]
    if (b < 128) return b
    v = b - 128
    if (VP >= VE) return -1
    b = M[VP++]
    if (b == 0) return -1
    if (b < 128) return v + b * 128
    v += (b - 128) * 128
    if (VP >= VE) return -1
    b = M[VP++]
    if (b == 0 || b > 3) return -1
    return v + b * 16384
}

# Parses the transaction at M[s .. s+n) into the TX* globals; 0 on error.
function tx_parse(s, n,   c, i, k, p) {
    VP = s; VE = s + n
    c = cu16(); if (c < 0 || c * 64 > VE - VP) return 0
    TXNSIG = c; TXSIG = VP; VP += 64 * c
    if (VP >= VE) return 0
    p = M[VP++]
    if (p > 128) return 0
    TXV0 = (p == 128)
    if (TXV0) { if (VP >= VE) return 0; TXNRS = M[VP++] } else TXNRS = p
    if (VP + 2 > VE) return 0
    TXNROS = M[VP++]; TXNROU = M[VP++]
    c = cu16(); if (c < 0 || c * 32 > VE - VP) return 0
    TXNKEY = c; TXKEY = VP; VP += 32 * c
    if (VP + 32 > VE) return 0
    TXBH = VP; VP += 32
    c = cu16(); if (c < 0 || c * 3 > VE - VP) return 0
    TXNIX = c
    for (i = 0; i < c; i++) {
        if (VP >= VE) return 0
        TXIX_P[i] = M[VP++]
        k = cu16(); if (k < 0 || VP + k > VE) return 0
        TXIX_AS[i] = VP; TXIX_AN[i] = k; VP += k
        k = cu16(); if (k < 0 || VP + k > VE) return 0
        TXIX_DS[i] = VP; TXIX_DN[i] = k; VP += k
    }
    TXNLU = 0
    if (TXV0) {
        c = cu16(); if (c < 0 || c * 34 > VE - VP) return 0
        TXNLU = c
        for (i = 0; i < c; i++) {
            if (VP + 32 > VE) return 0
            TXLU_K[i] = VP; VP += 32
            k = cu16(); if (k < 0 || VP + k > VE) return 0
            TXLU_WS[i] = VP; TXLU_WN[i] = k; VP += k
            k = cu16(); if (k < 0 || VP + k > VE) return 0
            TXLU_RS[i] = VP; TXLU_RN[i] = k; VP += k
        }
    }
    TXRAW = s; TXRAWN = VP - s
    return 1
}
