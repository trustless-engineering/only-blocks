# lib.awk: byte tables, exact 64-bit arithmetic on 32-bit halves, Base58,
# Base64, JSON string escaping, UTF-8 validation, CRC-64/GO-ISO and FNV-1a.
#
# BWK awk has no bitwise operators and only IEEE doubles, so every byte lives
# in the flat memory array M[] as a number 0..255, a u64 is a (hi, lo) pair of
# exact 32-bit halves, and XOR is a 64 Ki-entry lookup table.

function lib_init(   i, h, c) {
    HEXD = "0123456789abcdef"
    for (i = 0; i < 256; i++) {
        h = substr(HEXD, int(i / 16) + 1, 1) substr(HEXD, i % 16 + 1, 1)
        HEX[h] = i
        HEXS[i] = h
        if (i > 0) {
            c = sprintf("%c", i)
            CHR[i] = c
            ORD[c] = i
        }
        if (i < 32) JESC[i] = sprintf("\\u%04x", i)
    }
    CHR[0] = ""
    JESC[8] = "\\b"; JESC[9] = "\\t"; JESC[10] = "\\n"; JESC[12] = "\\f"; JESC[13] = "\\r"
    B58A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    for (i = 0; i < 58; i++) B58C[i] = substr(B58A, i + 1, 1)
    B64A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for (i = 0; i < 64; i++) B64C[i] = substr(B64A, i + 1, 1)
    TWO32 = 4294967296
    U64MAX = "18446744073709551615"
    B58LIMB = 656356768            # 58^5, so limb * 256 + carry stays exact
    XOR_READY = 0
}

# ---------------------------------------------------------------- XOR, hashes

function xor_init(   a, b, n4, hi) {
    if (XOR_READY) return
    for (a = 0; a < 16; a++)
        for (b = 0; b < 16; b++)
            n4[a * 16 + b] = nib_xor(a, b)
    for (a = 0; a < 256; a++) {
        hi = int(a / 16)
        for (b = 0; b < 256; b++)
            X[a * 256 + b] = n4[hi * 16 + int(b / 16)] * 16 + n4[(a % 16) * 16 + b % 16]
    }
    crc_table_init()
    XOR_READY = 1
}

function nib_xor(a, b,   r, bit) {
    r = 0
    for (bit = 1; bit < 16; bit *= 2) {
        if ((int(a / bit) % 2) != (int(b / bit) % 2)) r += bit
    }
    return r
}

# CT[i * 8 + k] is byte k (little-endian) of the reflected CRC-64/ISO table entry i.
function crc_table_init(   i, k, r, t, lsb) {
    for (i = 0; i < 256; i++) {
        t[0] = i
        for (k = 1; k < 8; k++) t[k] = 0
        for (r = 0; r < 8; r++) {
            lsb = t[0] % 2
            for (k = 0; k < 7; k++) t[k] = int(t[k] / 2) + (t[k + 1] % 2) * 128
            t[7] = int(t[7] / 2)
            if (lsb) t[7] = X[t[7] * 256 + 216]
        }
        for (k = 0; k < 8; k++) CT[i * 8 + k] = t[k]
    }
}

# Sets H_HI/H_LO to crc64_go_iso(M[s .. s+n)).
function crc64(s, n,   c0, c1, c2, c3, c4, c5, c6, c7, i, x) {
    xor_init()
    c0 = c1 = c2 = c3 = c4 = c5 = c6 = c7 = 255
    for (i = 0; i < n; i++) {
        x = X[c0 * 256 + M[s + i]] * 8
        c0 = X[c1 * 256 + CT[x]]
        c1 = X[c2 * 256 + CT[x + 1]]
        c2 = X[c3 * 256 + CT[x + 2]]
        c3 = X[c4 * 256 + CT[x + 3]]
        c4 = X[c5 * 256 + CT[x + 4]]
        c5 = X[c6 * 256 + CT[x + 5]]
        c6 = X[c7 * 256 + CT[x + 6]]
        c7 = CT[x + 7]
    }
    H_LO = (255 - c0) + (255 - c1) * 256 + (255 - c2) * 65536 + (255 - c3) * 16777216
    H_HI = (255 - c4) + (255 - c5) * 256 + (255 - c6) * 65536 + (255 - c7) * 16777216
}

# Sets H_HI/H_LO to fnv1a_64(M[s .. s+n)): h = (h ^ b) * (2^40 + 0x1b3) mod 2^64.
function fnv1a(s, n,   h, r, i, k, v, carry) {
    xor_init()
    h[0] = 37; h[1] = 35; h[2] = 34; h[3] = 132; h[4] = 228; h[5] = 156; h[6] = 242; h[7] = 203
    for (i = 0; i < n; i++) {
        h[0] = X[h[0] * 256 + M[s + i]]
        carry = 0
        for (k = 0; k < 8; k++) {
            v = h[k] * 435 + carry
            if (k >= 5) v += h[k - 5]
            carry = int(v / 256)
            r[k] = v - carry * 256
        }
        for (k = 0; k < 8; k++) h[k] = r[k]
    }
    H_LO = h[0] + h[1] * 256 + h[2] * 65536 + h[3] * 16777216
    H_HI = h[4] + h[5] * 256 + h[6] * 65536 + h[7] * 16777216
}

# ------------------------------------------------------------- u64 / i64 text

# Exact decimal text of the u64 hi * 2^32 + lo.
function u64s(hi, lo,   s, q, r, v) {
    s = ""
    while (hi >= 2097152) {
        q = int(hi / 10); r = hi - q * 10; hi = q
        v = r * TWO32 + lo; q = int(v / 10); s = (v - q * 10) s; lo = q
    }
    v = hi * TWO32 + lo
    if (v > 0 || s == "") s = sprintf("%.0f", v) s
    return s
}

# Exact decimal text of the two's-complement i64 (hi, lo).
function i64s(hi, lo) {
    if (hi < 2147483648) return u64s(hi, lo)
    lo = TWO32 - lo; hi = TWO32 - 1 - hi
    if (lo == TWO32) { lo = 0; hi++ }
    return "-" u64s(hi, lo)
}

# Little-endian u32 at M[p].
function le32(p) { return M[p] + M[p + 1] * 256 + M[p + 2] * 65536 + M[p + 3] * 16777216 }

# Parses decimal digits (already validated, at most 20) into P_HI/P_LO; 0 on overflow.
function dec2pair(s,   i, n, lo, hi, c) {
    hi = 0; lo = 0; n = length(s)
    for (i = 1; i <= n; i++) {
        lo = lo * 10 + (substr(s, i, 1) + 0)
        c = int(lo / TWO32); lo -= c * TWO32
        hi = hi * 10 + c
        if (hi >= TWO32) return 0
    }
    P_HI = hi; P_LO = lo
    return 1
}

# (hi, lo) / d for d < 2^20: sets DQ_HI, DQ_LO, DR.
function divmod(hi, lo, d,   q, r, t) {
    q = int(hi / d); r = hi - q * d
    t = r * TWO32 + lo
    DQ_HI = q; DQ_LO = int(t / d); DR = t - DQ_LO * d
}

# Little-endian IEEE-754 double at M[p] as an awk number; F_BAD = 1 for NaN/Inf.
function f64le(p,   e, m, sign, k, v) {
    F_BAD = 0
    sign = M[p + 7] >= 128
    e = (M[p + 7] % 128) * 16 + int(M[p + 6] / 16)
    m = M[p + 6] % 16
    for (k = 5; k >= 0; k--) m = m * 256 + M[p + k]
    if (e == 2047) { F_BAD = 1; return 0 }
    if (e == 0) v = m * 2 ^ -1074
    else v = (m + 4503599627370496) * 2 ^ (e - 1075)
    return sign ? -v : v
}

# JSON text of a double: shortest-enough round trip via %.17g, null for NaN/Inf.
function fjson(v, bad,   s) {
    if (bad) return "null"
    s = sprintf("%.17g", v)
    if (s ~ /^-?[0-9]+$/) s = s ".0"
    return s
}

# ------------------------------------------------------------------- encoders

function b58(s, n,   zeros, i, j, nd, D, carry, out, top, k, d, t) {
    zeros = 0
    while (zeros < n && M[s + zeros] == 0) zeros++
    nd = 0
    for (i = zeros; i < n; i++) {
        carry = M[s + i]
        for (j = 0; j < nd; j++) {
            carry += D[j] * 256
            t = int(carry / B58LIMB)
            D[j] = carry - t * B58LIMB
            carry = t
        }
        while (carry > 0) {
            t = int(carry / B58LIMB)
            D[nd++] = carry - t * B58LIMB
            carry = t
        }
    }
    out = ""
    for (i = 0; i < zeros; i++) out = out "1"
    for (j = nd - 1; j >= 0; j--) {
        d = D[j]; t = ""
        for (k = 0; k < 5; k++) {
            t = B58C[d % 58] t
            d = int(d / 58)
            if (j == nd - 1 && d == 0) break
        }
        out = out t
    }
    return out
}

function b64(s, n,   i, out, v, r) {
    out = ""
    for (i = 0; i + 2 < n; i += 3) {
        v = M[s + i] * 65536 + M[s + i + 1] * 256 + M[s + i + 2]
        out = out B64C[int(v / 262144)] B64C[int(v / 4096) % 64] B64C[int(v / 64) % 64] B64C[v % 64]
    }
    r = n - i
    if (r == 1) {
        v = M[s + i] * 65536
        out = out B64C[int(v / 262144)] B64C[int(v / 4096) % 64] "=="
    } else if (r == 2) {
        v = M[s + i] * 65536 + M[s + i + 1] * 256
        out = out B64C[int(v / 262144)] B64C[int(v / 4096) % 64] B64C[int(v / 64) % 64] "="
    }
    return out
}

# JSON string literal (with quotes) for the bytes M[s .. s+n).
function jbytes(s, n,   i, b, out, part) {
    out = "\""; part = ""
    for (i = 0; i < n; i++) {
        b = M[s + i]
        if (b < 32) part = part JESC[b]
        else if (b == 34) part = part "\\\""
        else if (b == 92) part = part "\\\\"
        else part = part CHR[b]
        if (length(part) >= 256) { out = out part; part = "" }
    }
    return out part "\""
}

# JSON string literal for an awk string (only ASCII-safe escaping is needed).
function jstr(v,   i, n, c, out) {
    if (v !~ /["\\\001-\037]/) return "\"" v "\""
    out = "\""; n = length(v)
    for (i = 1; i <= n; i++) {
        c = substr(v, i, 1)
        if (c == "\"") out = out "\\\""
        else if (c == "\\") out = out "\\\\"
        else if (ORD[c] < 32) out = out JESC[ORD[c]]
        else out = out c
    }
    return out "\""
}

# awk string from the bytes M[s .. s+n) (NUL becomes U+0001; only used for compares).
function mstr(s, n,   i, out) {
    out = ""
    for (i = 0; i < n; i++) out = out (M[s + i] ? CHR[M[s + i]] : "\001")
    return out
}

# Strict UTF-8 validation (no overlongs, surrogates or code points > U+10FFFF).
function utf8ok(s, n,   i, b, c, need, lo, hi) {
    i = 0
    while (i < n) {
        b = M[s + i++]
        if (b < 128) continue
        lo = 128; hi = 191
        if (b >= 194 && b <= 223) need = 1
        else if (b == 224) { need = 2; lo = 160 }
        else if (b == 237) { need = 2; hi = 159 }
        else if (b >= 225 && b <= 239) need = 2
        else if (b == 240) { need = 3; lo = 144 }
        else if (b == 244) { need = 3; hi = 143 }
        else if (b >= 241 && b <= 243) need = 3
        else return 0
        if (i + need > n) return 0
        c = M[s + i++]
        if (c < lo || c > hi) return 0
        while (--need > 0) {
            c = M[s + i++]
            if (c < 128 || c > 191) return 0
        }
    }
    return 1
}

# Same validation for an awk string (request bodies), 4 KiB at a time so a
# 1 MiB body never costs one strlen() per character.
function utf8str(v,   n, k, cn, ca, j, b, need, lo, hi) {
    n = length(v); need = 0
    for (k = 0; k * 4096 < n; k++) {
        cn = split(substr(v, k * 4096 + 1, 4096), ca, "")
        for (j = 1; j <= cn; j++) {
            b = ORD[ca[j]]
            if (need > 0) {
                if (b < lo || b > hi) return 0
                lo = 128; hi = 191; need--
                continue
            }
            if (b < 128) continue
            lo = 128; hi = 191
            if (b >= 194 && b <= 223) need = 1
            else if (b == 224) { need = 2; lo = 160 }
            else if (b == 237) { need = 2; hi = 159 }
            else if (b >= 225 && b <= 239) need = 2
            else if (b == 240) { need = 3; lo = 144 }
            else if (b == 244) { need = 3; hi = 143 }
            else if (b >= 241 && b <= 243) need = 3
            else return 0
        }
    }
    return need == 0
}

# Hex text of M[s .. s+n), used as CID map keys.
function mhex(s, n,   i, out) {
    out = ""
    for (i = 0; i < n; i++) out = out HEXS[M[s + i]]
    return out
}

# Shell single-quote.
function shq(v) {
    gsub(/'/, "'\\''", v)
    return "'" v "'"
}
