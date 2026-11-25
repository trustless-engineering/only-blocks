# zstd.awk: an RFC 8878 Zstandard decoder in plain BWK awk, ported from
# docs/ZSTD_MINI_SPEC.md. It needs no zstd library, no CLI and no child
# process. It handles frame headers, skippable and concatenated frames, Raw,
# RLE and Compressed blocks, Raw, RLE, Compressed and Treeless literals, 1- and
# 4-stream Huffman with direct or FSE-coded weights, Predefined, RLE, FSE and
# Repeat sequence tables, the [1, 4, 8] repeat offsets, the XXH64 content
# checksum and the 512 MiB output cap.
#
# BWK awk has no integers and no bitwise operators, only IEEE doubles:
#
# * A bitstream is read through one exact "bit container" C holding the next
#   N (<= 53) unread bits as a number. Taking the top k bits is
#   int(C / 2^(N-k)), and dropping them is C % 2^(N-k).
# * FSE tables of every kind share the flat arrays ZTS/ZTN/ZTB (symbol,
#   nb_bits, baseline), 512 cells per slot: 0-2 are this frame's LL/OF/ML
#   tables, 3 holds Huffman weights, and 4-6 hold the predefined tables.
# * XXH64 works on four exact 16-bit limbs (ZX[]), with XOR from lib.awk's
#   byte table X[].
#
# Input is M[s .. s+n) and output is appended at M[MTOP ..). zstd_dec()
# returns 1 with the output at M[ZS_S .. ZS_S+ZS_N), or 0 with MTOP restored.
# A failure never sets ERR: WIRE_FORMATS §9.1 then falls back to the raw bytes.

function is_zstd_magic(p) { return M[p] == 40 && M[p + 1] == 181 && M[p + 2] == 47 && M[p + 3] == 253 }

function zs_init(   i, v, t) {
    if (ZS_READY) return
    v = 1
    for (i = 0; i <= 60; i++) { ZP2[i] = v; v *= 2 }
    for (i = 0; i < 12; i++) for (v = ZP2[i]; v < ZP2[i + 1]; v++) ZHB[v] = i
    ZS_CAP = 536870912
    zs_list(ZLLB, "0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 18 20 22 24 28 32 40 48 64 128 256 512 1024 2048 4096 8192 16384 32768 65536")
    zs_list(ZLLX, "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 1 2 2 3 3 4 6 7 8 9 10 11 12 13 14 15 16")
    zs_list(ZMLB, "3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 37 39 41 43 47 51 59 67 83 99 131 259 515 1027 2051 4099 8195 16387 32771 65539")
    zs_list(ZMLX, "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 1 2 2 3 3 4 4 5 7 8 9 10 11 12 13 14 15 16")
    # Per kind (0 LL, 1 OF, 2 ML): largest symbol, largest accuracy log, and
    # the predefined distribution (RFC 8878 §3.1.1.3.2.2), built once.
    ZMSYM[0] = 35; ZMLOG[0] = 9; ZDLOG[0] = 6
    ZMSYM[1] = 31; ZMLOG[1] = 8; ZDLOG[1] = 5
    ZMSYM[2] = 52; ZMLOG[2] = 9; ZDLOG[2] = 6
    ZNS = zs_list(ZPR, "4 3 2 2 2 2 2 2 2 2 2 2 2 1 1 1 2 2 2 2 2 2 2 2 2 3 2 1 1 1 1 1 -1 -1 -1 -1")
    zs_fse_build(2048, 6)
    ZNS = zs_list(ZPR, "1 1 1 1 1 1 2 2 2 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 -1 -1 -1 -1 -1")
    zs_fse_build(2560, 5)
    ZNS = zs_list(ZPR, "1 4 3 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 -1 -1 -1 -1 -1 -1 -1")
    zs_fse_build(3072, 6)
    # XXH64 primes P1..P5 at ZX[0], [4], ... [16]; 2^64 - P1 at ZX[20].
    split("9e3779b185ebca87 c2b2ae3d27d4eb4f 165667b19e3779f9 85ebca77c2b2ae63 27d4eb2f165667c5 61c8864e7a143579", t, " ")
    for (i = 1; i <= 6; i++) zx_hex((i - 1) * 4, t[i])
    ZS_READY = 1
}

# Fills a[0 .. n) with the numbers in the space-separated list; returns n.
function zs_list(a, s,   t, n, i) {
    n = split(s, t, " ")
    for (i = 1; i <= n; i++) a[i - 1] = t[i] + 0
    return n
}

# ------------------------------------------------------------------- frames

function zstd_dec(s, n,   p, e, d, single, chk, k, i, csz, win, fs, hdr, last, type, size, bmax, lim, q, v) {
    zs_init()
    p = s; e = s + n; ZS0 = MTOP
    while (p < e) {
        if (p + 4 > e) return zs_fail()
        if (M[p] >= 80 && M[p] <= 95 && M[p + 1] == 42 && M[p + 2] == 77 && M[p + 3] == 24) {
            if (p + 8 > e) return zs_fail()
            size = le32(p + 4)
            if (p + 8 + size > e) return zs_fail()
            p += 8 + size
            continue
        }
        if (!is_zstd_magic(p)) return zs_fail()
        p += 4
        if (p >= e) return zs_fail()
        d = M[p++]
        if (int(d / 8) % 2) return zs_fail()
        single = int(d / 32) % 2
        chk = int(d / 4) % 2
        win = -1
        if (!single) {
            if (p >= e) return zs_fail()
            v = M[p++]
            win = ZP2[10 + int(v / 8)]
            win += (win / 8) * (v % 8)
        }
        k = d % 4; k = (k == 3) ? 4 : k
        if (p + k > e) return zs_fail()
        for (i = 0; i < k; i++) if (M[p++]) return zs_fail()
        k = int(d / 64); k = (k == 0) ? single : (k == 1) ? 2 : (k == 2) ? 4 : 8
        if (p + k > e) return zs_fail()
        csz = -1
        if (k > 0) {
            # Content sizes of 2^32 or more are over the cap anyway (no 2^53 issue).
            if (k == 8 && (M[p + 4] || M[p + 5] || M[p + 6] || M[p + 7])) return zs_fail()
            csz = 0
            for (i = (k == 8 ? 4 : k) - 1; i >= 0; i--) csz = csz * 256 + M[p + i]
            if (k == 2) csz += 256
            p += k
            if (csz > ZS_CAP - (MTOP - ZS0)) return zs_fail()
        }
        if (single) win = csz
        ZWIN = win
        bmax = (win < 131072) ? win : 131072
        fs = MTOP
        ZR0 = 1; ZR1 = 4; ZR2 = 8
        ZHOK = 0
        ZTK[0] = ZTK[1] = ZTK[2] = -1
        do {
            if (p + 3 > e) return zs_fail()
            hdr = M[p] + M[p + 1] * 256 + M[p + 2] * 65536
            p += 3
            last = hdr % 2; type = int(hdr / 2) % 4; size = int(hdr / 8)
            if (size > bmax || type == 3) return zs_fail()
            # This block's output limit: block size, total cap, content size.
            lim = bmax
            if (ZS_CAP - (MTOP - ZS0) < lim) lim = ZS_CAP - (MTOP - ZS0)
            if (csz >= 0 && csz - (MTOP - fs) < lim) lim = csz - (MTOP - fs)
            if (type == 0) {
                if (size > lim || p + size > e) return zs_fail()
                for (i = 0; i < size; i++) M[MTOP++] = M[p + i]
                p += size
            } else if (type == 1) {
                if (size > lim || p >= e) return zs_fail()
                v = M[p++]
                for (i = 0; i < size; i++) M[MTOP++] = v
            } else {
                if (p + size > e) return zs_fail()
                q = zs_literals(p, p + size, lim)
                if (q < 0 || !zs_sequences(q, p + size, fs, MTOP + lim)) return zs_fail()
                p += size
            }
        } while (!last)
        if (csz >= 0 && MTOP - fs != csz) return zs_fail()
        if (chk) {
            if (p + 4 > e) return zs_fail()
            if (zx_xxh64(fs, MTOP - fs) != le32(p)) return zs_fail()
            p += 4
        }
    }
    ZS_S = ZS0; ZS_N = MTOP - ZS0
    return 1
}

function zs_fail() { MTOP = ZS0; return 0 }

# --------------------------------------------------------------- bitstreams

# Forward read of n (<= 17) bits at bit position bp; bytes at or past lim are 0.
function zs_fpeek(bp, n, lim,   q, w) {
    q = int(bp / 8)
    w = (q < lim) ? M[q] : 0
    if (q + 1 < lim) w += M[q + 1] * 256
    if (q + 2 < lim) w += M[q + 2] * 65536
    return int(w / ZP2[bp - q * 8]) % ZP2[n]
}

# Backward bitstream M[s .. e) (§2): the container ZBC holds ZBN bits, the
# next byte to load is M[ZBP - 1]. Bits left = ZBN + 8 * (ZBP - ZBS), which
# goes negative once reads pass the start (they then return zero bits).
function zs_br_init(s, e,   x) {
    if (e <= s) return 0
    x = M[e - 1]
    if (x == 0) return 0
    ZBN = ZHB[x]; ZBC = x - ZP2[ZBN]; ZBP = e - 1; ZBS = s
    return 1
}

function zs_rd(n,   v) {
    if (n <= 0) return 0
    if (ZBN < n) {
        while (ZBN <= 45 && ZBP > ZBS) { ZBC = ZBC * 256 + M[--ZBP]; ZBN += 8 }
        if (ZBN < n) {
            v = (ZBN > 0) ? ZBC * ZP2[n - ZBN] : 0
            ZBC = 0; ZBN -= n
            return v
        }
    }
    ZBN -= n
    v = int(ZBC / ZP2[ZBN])
    ZBC -= v * ZP2[ZBN]
    return v
}

# --------------------------------------------------------------------- FSE

# FSE table description (§3.1) at M[pos .. lim): probabilities into
# ZPR[0 .. ZNS), accuracy log into ZAL. Returns the end position, or -1.
function zs_fse_desc(pos, lim, maxsym, maxlog,   bp, al, rem, thr, nb, ns, big, low, v, prob, rep, end) {
    bp = pos * 8
    al = zs_fpeek(bp, 4, lim) + 5; bp += 4
    if (al > maxlog) return -1
    thr = ZP2[al]; rem = thr + 1; nb = al + 1; ns = 0
    while (rem > 1) {
        if (ns > maxsym) return -1
        big = 2 * thr - 1 - rem
        low = zs_fpeek(bp, nb - 1, lim)
        if (low < big) { v = low; bp += nb - 1 }
        else {
            v = zs_fpeek(bp, nb, lim); bp += nb
            if (v >= thr) v -= big
        }
        prob = v - 1
        ZPR[ns++] = prob
        rem -= (prob < 0) ? -prob : prob
        if (prob == 0) {
            do {
                rep = zs_fpeek(bp, 2, lim); bp += 2
                for (v = 0; v < rep; v++) ZPR[ns++] = 0
                if (ns > maxsym + 1) return -1
            } while (rep == 3)
        }
        while (rem < thr) { nb--; thr /= 2 }
    }
    if (rem != 1 || ns > maxsym + 1) return -1
    end = int((bp + 7) / 8)
    if (end > lim) return -1
    ZAL = al; ZNS = ns
    return end
}

# Decoding table (§3.2) for ZPR[0 .. ZNS) at accuracy log al into slot base b.
function zs_fse_build(b, al,   size, high, s, p, step, pos, cell, x, nb, cnt) {
    size = ZP2[al]; high = size - 1
    for (s = 0; s < ZNS; s++) {
        p = ZPR[s]
        if (p == -1) { ZTS[b + high] = s; high--; cnt[s] = 1 }
        else cnt[s] = p
    }
    step = size / 2 + size / 8 + 3
    pos = 0
    for (s = 0; s < ZNS; s++)
        for (p = ZPR[s]; p > 0; p--) {
            ZTS[b + pos] = s
            do pos = (pos + step) % size; while (pos > high)
        }
    if (pos != 0) return 0
    for (cell = 0; cell < size; cell++) {
        s = ZTS[b + cell]
        x = cnt[s]++
        nb = al - ZHB[x]
        ZTN[b + cell] = nb
        ZTB[b + cell] = x * ZP2[nb] - size
    }
    return 1
}

# ----------------------------------------------------------------- Huffman

# Huffman tree description (§4.1) at M[pos .. lim) into ZHS/ZHN/ZHM.
# Returns the end position, or -1.
function zs_huf_desc(pos, lim,   h, end, p, al, s1, s2, nw, i, n) {
    if (pos >= lim) return -1
    h = M[pos++]
    nw = 0
    if (h < 128) {
        end = pos + h
        if (end > lim) return -1
        p = zs_fse_desc(pos, end, 255, 6)
        if (p < 0 || !zs_fse_build(1536, ZAL) || !zs_br_init(p, end)) return -1
        al = ZAL
        s1 = zs_rd(al); s2 = zs_rd(al)
        if (ZBN < 0) return -1
        while (1) {
            if (nw > 255) return -1
            ZW[nw++] = ZTS[1536 + s1]
            s1 = ZTB[1536 + s1] + zs_rd(ZTN[1536 + s1])
            if (ZBN < 0) { ZW[nw++] = ZTS[1536 + s2]; break }
            ZW[nw++] = ZTS[1536 + s2]
            s2 = ZTB[1536 + s2] + zs_rd(ZTN[1536 + s2])
            if (ZBN < 0) { ZW[nw++] = ZTS[1536 + s1]; break }
        }
    } else {
        n = h - 127
        end = pos + int((n + 1) / 2)
        if (end > lim) return -1
        for (i = 0; i < n; i++) {
            h = M[pos + int(i / 2)]
            ZW[nw++] = (i % 2) ? h % 16 : int(h / 16)
        }
    }
    return zs_huf_build(nw) ? end : -1
}

# Flat decoding table from the weights ZW[0 .. nw) plus the implied last one.
function zs_huf_build(nw,   total, i, w, mb, rest, cnt, nc, start, k, c, j, nb) {
    if (nw > 255) return 0
    total = 0
    for (i = 0; i < nw; i++) {
        w = ZW[i]
        if (w > 11) return 0
        if (w > 0) total += ZP2[w - 1]
    }
    if (total == 0 || total >= 2048) return 0
    mb = ZHB[total] + 1
    rest = ZP2[mb] - total
    if (ZP2[ZHB[rest]] != rest) return 0
    ZW[nw++] = ZHB[rest] + 1
    for (w = 1; w <= mb; w++) cnt[w] = 0
    for (i = 0; i < nw; i++) if (ZW[i] > 0) cnt[ZW[i]]++
    start = 0
    for (w = 1; w <= mb; w++) { nc[w] = start; start += cnt[w] * ZP2[w - 1] }
    for (i = 0; i < nw; i++) {
        w = ZW[i]
        if (w == 0) continue
        k = nc[w]; c = ZP2[w - 1]; nb = mb + 1 - w
        for (j = 0; j < c; j++) { ZHS[k + j] = i; ZHN[k + j] = nb }
        nc[w] = k + c
    }
    ZHM = mb; ZHOK = 1
    return 1
}

# Decodes cnt symbols of the backward Huffman stream M[s .. e) (§4.2) into
# ZL[o ..). The bit reader is inlined: this is the hottest loop.
function zs_huf_stream(s, e, cnt, o,   C, n, p, mb, i, x) {
    if (e <= s) return 0
    x = M[e - 1]
    if (x == 0) return 0
    n = ZHB[x]; C = x - ZP2[n]; p = e - 1; mb = ZHM
    for (i = 0; i < cnt; i++) {
        if (n < mb) while (n <= 45 && p > s) { C = C * 256 + M[--p]; n += 8 }
        x = (n >= mb) ? int(C / ZP2[n - mb]) : C * ZP2[mb - n]
        ZL[o++] = ZHS[x]
        n -= ZHN[x]
        if (n < 0) return 0
        C %= ZP2[n]
    }
    return n == 0 && p == s
}

# ---------------------------------------------------------------- literals

# Literals section (§5) at M[pos .. end) into ZL[0 .. ZLN), at most lim
# bytes. Returns the position after it, or -1.
function zs_literals(pos, end, lim,   b0, lt, sf, size, i, v, ns, hl, wd, h, reg, le, s1, s2, s3, s4, q) {
    if (pos >= end) return -1
    b0 = M[pos]
    lt = b0 % 4; sf = int(b0 / 4) % 4
    if (lt < 2) {
        if (sf != 1 && sf != 3) { size = int(b0 / 8); pos++ }
        else if (sf == 1) {
            if (pos + 2 > end) return -1
            size = int(b0 / 16) + M[pos + 1] * 16; pos += 2
        } else {
            if (pos + 3 > end) return -1
            size = int(b0 / 16) + M[pos + 1] * 16 + M[pos + 2] * 4096; pos += 3
        }
        if (size > lim) return -1
        ZLN = size
        if (lt == 0) {
            if (pos + size > end) return -1
            for (i = 0; i < size; i++) ZL[i] = M[pos + i]
            return pos + size
        }
        if (pos >= end) return -1
        v = M[pos]
        for (i = 0; i < size; i++) ZL[i] = v
        return pos + 1
    }
    if (sf == 0) { ns = 1; hl = 3; wd = 10 }
    else if (sf == 1) { ns = 4; hl = 3; wd = 10 }
    else if (sf == 2) { ns = 4; hl = 4; wd = 14 }
    else { ns = 4; hl = 5; wd = 18 }
    if (pos + hl > end) return -1
    h = 0
    for (i = hl - 1; i >= 0; i--) h = h * 256 + M[pos + i]
    reg = int(h / 16) % ZP2[wd]
    le = pos + hl + int(h / ZP2[4 + wd]) % ZP2[wd]
    pos += hl
    if (le > end || reg > lim) return -1
    if (lt == 2) { pos = zs_huf_desc(pos, le); if (pos < 0) return -1 }
    else if (!ZHOK) return -1
    ZLN = reg
    if (ns == 1) return zs_huf_stream(pos, le, reg, 0) ? le : -1
    if (pos + 6 > le) return -1
    s1 = M[pos] + M[pos + 1] * 256
    s2 = M[pos + 2] + M[pos + 3] * 256
    s3 = M[pos + 4] + M[pos + 5] * 256
    pos += 6
    s4 = le - pos - s1 - s2 - s3
    q = int((reg + 3) / 4)
    if (s4 < 1 || reg - 3 * q < 0) return -1
    if (!zs_huf_stream(pos, pos + s1, q, 0)) return -1
    pos += s1
    if (!zs_huf_stream(pos, pos + s2, q, q)) return -1
    pos += s2
    if (!zs_huf_stream(pos, pos + s3, q, 2 * q)) return -1
    pos += s3
    return zs_huf_stream(pos, le, reg - 3 * q, 3 * q) ? le : -1
}

# --------------------------------------------------------------- sequences

# Table for kind k in mode md (§6.1) at M[pos .. end); returns the next
# position, or -1. ZTK[k] is the table's slot base and ZTL[k] its log.
function zs_seq_table(pos, end, md, k) {
    if (md == 0) { ZTK[k] = 2048 + k * 512; ZTL[k] = ZDLOG[k]; return pos }
    if (md == 1) {
        if (pos >= end || M[pos] > ZMSYM[k]) return -1
        ZTS[k * 512] = M[pos]; ZTN[k * 512] = 0; ZTB[k * 512] = 0
        ZTK[k] = k * 512; ZTL[k] = 0
        return pos + 1
    }
    if (md == 2) {
        pos = zs_fse_desc(pos, end, ZMSYM[k], ZMLOG[k])
        if (pos < 0 || !zs_fse_build(k * 512, ZAL)) return -1
        ZTK[k] = k * 512; ZTL[k] = ZAL
        return pos
    }
    return (ZTK[k] < 0) ? -1 : pos
}

# Sequences section (§6) at M[pos .. end), executed (§6.3) straight onto
# M[MTOP ..) with literals from ZL. fs is the frame's first output byte and
# bend the block's output limit. Returns 1, or 0 on error.
function zs_sequences(pos, end, fs, bend,   b0, cnt, md, bl, bo, bm, sl, so, sm, i, oc, mc, lc, ov, ml, ll, lit, o, off, k, src) {
    if (pos >= end) return 0
    b0 = M[pos]
    cnt = 0
    if (b0 == 0) {
        if (pos + 1 != end) return 0
    } else {
        if (b0 < 128) { cnt = b0; pos++ }
        else if (b0 < 255) {
            if (pos + 2 > end) return 0
            cnt = (b0 - 128) * 256 + M[pos + 1]; pos += 2
        } else {
            if (pos + 3 > end) return 0
            cnt = M[pos + 1] + M[pos + 2] * 256 + 32512; pos += 3
        }
        # Every sequence emits at least 3 bytes.
        if (pos >= end || cnt == 0 || cnt * 3 > bend - MTOP) return 0
        md = M[pos++]
        if (md % 4) return 0
        pos = zs_seq_table(pos, end, int(md / 64), 0)
        if (pos >= 0) pos = zs_seq_table(pos, end, int(md / 16) % 4, 1)
        if (pos >= 0) pos = zs_seq_table(pos, end, int(md / 4) % 4, 2)
        if (pos < 0 || !zs_br_init(pos, end)) return 0
    }
    bl = ZTK[0]; bo = ZTK[1]; bm = ZTK[2]
    if (cnt) { sl = zs_rd(ZTL[0]); so = zs_rd(ZTL[1]); sm = zs_rd(ZTL[2]) }
    lit = 0; o = MTOP
    for (i = 0; i < cnt; i++) {
        oc = ZTS[bo + so]; mc = ZTS[bm + sm]; lc = ZTS[bl + sl]
        ov = ZP2[oc] + zs_rd(oc)
        ml = ZMLB[mc] + zs_rd(ZMLX[mc])
        ll = ZLLB[lc] + zs_rd(ZLLX[lc])
        if (i < cnt - 1) {
            sl = ZTB[bl + sl] + zs_rd(ZTN[bl + sl])
            sm = ZTB[bm + sm] + zs_rd(ZTN[bm + sm])
            so = ZTB[bo + so] + zs_rd(ZTN[bo + so])
        }
        if (lit + ll > ZLN || o + ll + ml > bend) return 0
        for (k = 0; k < ll; k++) M[o++] = ZL[lit++]
        if (ov > 3) { off = ov - 3; ZR2 = ZR1; ZR1 = ZR0; ZR0 = off }
        else {
            k = ov - 1 + (ll == 0)
            if (k == 0) off = ZR0
            else if (k == 1) { off = ZR1; ZR1 = ZR0; ZR0 = off }
            else if (k == 2) { off = ZR2; ZR2 = ZR1; ZR1 = ZR0; ZR0 = off }
            else { off = ZR0 - 1; ZR2 = ZR1; ZR1 = ZR0; ZR0 = off }
        }
        if (off <= 0 || off > o - fs || off > ZWIN) return 0
        src = o - off
        for (k = 0; k < ml; k++) M[o++] = M[src++]
    }
    if (cnt && ZBN + 8 * (ZBP - ZBS) != 0) return 0
    if (o + ZLN - lit > bend) return 0
    while (lit < ZLN) M[o++] = ZL[lit++]
    MTOP = o
    return 1
}

# ------------------------------------------------------------------- XXH64

# u64 values are four 16-bit limbs, least significant first, at ZX[b .. b+3].
function zx_hex(b, h,   i, j, v) {
    for (i = 0; i < 4; i++) {
        v = 0
        for (j = 1; j <= 4; j++) v = v * 16 + index(HEXD, substr(h, 13 - i * 4 + j - 1, 1)) - 1
        ZX[b + i] = v
    }
}

function zx_set(b, v,   i) { for (i = 0; i < 4; i++) { ZX[b + i] = v % 65536; v = int(v / 65536) } }

function zx_copy(d, a,   i) { for (i = 0; i < 4; i++) ZX[d + i] = ZX[a + i] }

function zx_add(d, a, b,   i, c, v) {
    c = 0
    for (i = 0; i < 4; i++) {
        v = ZX[a + i] + ZX[b + i] + c
        c = (v >= 65536)
        ZX[d + i] = v - c * 65536
    }
}

function zx_mul(d, a, b,   a0, a1, a2, a3, b0, b1, b2, b3, r, c) {
    a0 = ZX[a]; a1 = ZX[a + 1]; a2 = ZX[a + 2]; a3 = ZX[a + 3]
    b0 = ZX[b]; b1 = ZX[b + 1]; b2 = ZX[b + 2]; b3 = ZX[b + 3]
    r = a0 * b0
    c = int(r / 65536); ZX[d] = r - c * 65536
    r = a0 * b1 + a1 * b0 + c
    c = int(r / 65536); ZX[d + 1] = r - c * 65536
    r = a0 * b2 + a1 * b1 + a2 * b0 + c
    c = int(r / 65536); ZX[d + 2] = r - c * 65536
    ZX[d + 3] = (a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + c) % 65536
}

function zx_xor(d, a, b,   i, x, y) {
    for (i = 0; i < 4; i++) {
        x = ZX[a + i]; y = ZX[b + i]
        ZX[d + i] = X[int(x / 256) * 256 + int(y / 256)] * 256 + X[(x % 256) * 256 + y % 256]
    }
}

# d = rotl(a, r) for 0 < r < 64.
function zx_rotl(d, a, r,   q, s, i, t, lo, hi) {
    q = int(r / 16); s = r % 16
    for (i = 0; i < 4; i++) t[i] = ZX[a + (i - q + 4) % 4]
    lo = ZP2[s]; hi = ZP2[16 - s]
    for (i = 0; i < 4; i++) ZX[d + i] = (t[i] * lo) % 65536 + int(t[(i + 3) % 4] / hi)
}

# a ^= a >> r for 0 < r < 64.
function zx_shrxor(a, r,   q, s, i, t, u, lo, hi) {
    q = int(r / 16); s = r % 16
    lo = ZP2[s]; hi = ZP2[16 - s]
    for (i = 0; i < 4; i++) {
        t = (i + q < 4) ? int(ZX[a + i + q] / lo) : 0
        if (s && i + q + 1 < 4) t += (ZX[a + i + q + 1] * hi) % 65536
        u[i] = t
    }
    for (i = 0; i < 4; i++) ZX[44 + i] = u[i]
    zx_xor(a, a, 44)
}

# The lane M[p .. p+8) into ZX[d].
function zx_lane(d, p) {
    ZX[d] = M[p] + M[p + 1] * 256; ZX[d + 1] = M[p + 2] + M[p + 3] * 256
    ZX[d + 2] = M[p + 4] + M[p + 5] * 256; ZX[d + 3] = M[p + 6] + M[p + 7] * 256
}

# acc = rotl(acc + lane * P2, 31) * P1.
function zx_round(acc, lane) {
    zx_mul(52, lane, 4)
    zx_add(acc, acc, 52)
    zx_rotl(acc, acc, 31)
    zx_mul(acc, acc, 0)
}

# h = (h ^ round(0, v)) * P1 + P4.
function zx_merge(v) {
    zx_set(48, 0)
    zx_round(48, v)
    zx_xor(40, 40, 48)
    zx_mul(40, 40, 0)
    zx_add(40, 40, 12)
}

# Low 32 bits of XXH64(M[s .. s+n), seed 0), as a number.
function zx_xxh64(s, n,   i, j) {
    xor_init()
    i = 0
    if (n >= 32) {
        zx_add(24, 0, 4); zx_copy(28, 4); zx_set(32, 0); zx_copy(36, 20)
        for (; i + 32 <= n; i += 32)
            for (j = 0; j < 4; j++) { zx_lane(56, s + i + 8 * j); zx_round(24 + 4 * j, 56) }
        zx_rotl(40, 24, 1)
        zx_rotl(48, 28, 7); zx_add(40, 40, 48)
        zx_rotl(48, 32, 12); zx_add(40, 40, 48)
        zx_rotl(48, 36, 18); zx_add(40, 40, 48)
        for (j = 0; j < 4; j++) zx_merge(24 + 4 * j)
    } else zx_copy(40, 16)
    zx_set(48, n); zx_add(40, 40, 48)
    for (; i + 8 <= n; i += 8) {
        zx_lane(56, s + i)
        zx_set(48, 0); zx_round(48, 56)
        zx_xor(40, 40, 48); zx_rotl(40, 40, 27)
        zx_mul(40, 40, 0); zx_add(40, 40, 12)
    }
    if (i + 4 <= n) {
        zx_set(48, le32(s + i)); zx_mul(48, 48, 0)
        zx_xor(40, 40, 48); zx_rotl(40, 40, 23)
        zx_mul(40, 40, 4); zx_add(40, 40, 8)
        i += 4
    }
    for (; i < n; i++) {
        zx_set(48, M[s + i]); zx_mul(48, 48, 16)
        zx_xor(40, 40, 48); zx_rotl(40, 40, 11)
        zx_mul(40, 40, 0)
    }
    zx_shrxor(40, 33); zx_mul(40, 40, 4)
    zx_shrxor(40, 29); zx_mul(40, 40, 8)
    zx_shrxor(40, 32)
    return ZX[40] + ZX[41] * 65536
}
