# json.awk: RFC 8259 parser for request bodies.
#
# BWK awk's substr() calls strlen() on its whole argument, so walking a 1 MiB
# body one substr() per character would be quadratic. The reader instead
# splits the body into 4 KiB chunks of single characters on demand.
#
# Nodes: JT[id] is o(bject) a(rray) s(tring) n(umber) t(rue) f(alse) z(null).
# JV[id] holds a string's decoded value or a number's source text, JRAW[id] a
# string's source text with quotes, JN[id] a container's size, and
# JKEY[id, i] / JCH[id, i] (1-based) its member keys and children.

function js_init(s) {
    JB = s; JBN = length(s); JPOS = 1; JCK = -1; JERR = 0; JNID = 0
    delete JT; delete JV; delete JRAW; delete JN; delete JKEY; delete JCH
}

function js_load(k) {
    JCS = substr(JB, k * 4096 + 1, 4096)
    split(JCS, JCA, "")
    JCK = k
}

function jpeek(   k) {
    if (JPOS > JBN) return ""
    k = int((JPOS - 1) / 4096)
    if (k != JCK) js_load(k)
    return JCA[JPOS - k * 4096]
}

# Source text JB[start .. JPOS-1], cheap when it lies inside the current chunk.
function jcap(start,   ks) {
    if (JPOS <= start) return ""
    ks = int((start - 1) / 4096)
    if (ks == JCK && int((JPOS - 2) / 4096) == JCK)
        return substr(JCS, start - ks * 4096, JPOS - start)
    return substr(JB, start, JPOS - start)
}

function jws(   c) {
    while (1) {
        c = jpeek()
        if (c == " " || c == "\t" || c == "\n" || c == "\r") JPOS++
        else return c
    }
}

# Parses the whole body; returns the root id, or 0 (JERR) on any syntax error.
function jparse(body,   root) {
    js_init(body)
    root = jvalue(1)
    if (JERR) return 0
    jws()
    if (JPOS <= JBN) { JERR = 1; return 0 }
    return root
}

function jvalue(depth,   c) {
    if (depth > 128) { JERR = 1; return 0 }
    c = jws()
    if (c == "{") return jobject(depth)
    if (c == "[") return jarray(depth)
    if (c == "\"") return jstring()
    if (c == "t") return jlit("true", "t")
    if (c == "f") return jlit("false", "f")
    if (c == "n") return jlit("null", "z")
    if (c == "-" || (c >= "0" && c <= "9")) return jnumber()
    JERR = 1
    return 0
}

function jlit(word, type,   i, n, id) {
    n = length(word)
    for (i = 1; i <= n; i++) {
        if (jpeek() != substr(word, i, 1)) { JERR = 1; return 0 }
        JPOS++
    }
    id = ++JNID; JT[id] = type
    return id
}

function jdigits(   c, n) {
    n = 0
    while (1) {
        c = jpeek()
        if (c >= "0" && c <= "9" && length(c) == 1) { JPOS++; n++ }
        else return n
    }
}

function jnumber(   start, c, id) {
    start = JPOS
    if (jpeek() == "-") JPOS++
    c = jpeek()
    if (c == "0") JPOS++
    else if (c >= "1" && c <= "9") jdigits()
    else { JERR = 1; return 0 }
    if (jpeek() == ".") {
        JPOS++
        if (!jdigits()) { JERR = 1; return 0 }
    }
    c = jpeek()
    if (c == "e" || c == "E") {
        JPOS++
        c = jpeek()
        if (c == "+" || c == "-") JPOS++
        if (!jdigits()) { JERR = 1; return 0 }
    }
    id = ++JNID; JT[id] = "n"; JV[id] = jcap(start)
    return id
}

function jhex4(   i, c, v, d) {
    v = 0
    for (i = 0; i < 4; i++) {
        c = jpeek()
        if (c >= "0" && c <= "9") d = c + 0
        else if (c >= "a" && c <= "f") d = index("abcdef", c) + 9
        else if (c >= "A" && c <= "F") d = index("ABCDEF", c) + 9
        else return -1
        if (length(c) != 1) return -1
        v = v * 16 + d
        JPOS++
    }
    return v
}

function utf8enc(cp) {
    if (cp == 0) return "\001"
    if (cp < 128) return CHR[cp]
    if (cp < 2048) return CHR[192 + int(cp / 64)] CHR[128 + cp % 64]
    if (cp < 65536) return CHR[224 + int(cp / 4096)] CHR[128 + int(cp / 64) % 64] CHR[128 + cp % 64]
    return CHR[240 + int(cp / 262144)] CHR[128 + int(cp / 4096) % 64] CHR[128 + int(cp / 64) % 64] CHR[128 + cp % 64]
}

function jstring(   start, run, v, c, cp, lo, save, id) {
    start = JPOS
    JPOS++
    v = ""; run = JPOS
    while (1) {
        c = jpeek()
        if (c == "") { JERR = 1; return 0 }
        if (c == "\"") {
            v = v jcap(run)
            JPOS++
            break
        }
        if (c == "\\") {
            v = v jcap(run)
            JPOS++
            c = jpeek()
            JPOS++
            if (c == "\"" || c == "\\" || c == "/") v = v c
            else if (c == "b") v = v "\b"
            else if (c == "f") v = v "\f"
            else if (c == "n") v = v "\n"
            else if (c == "r") v = v "\r"
            else if (c == "t") v = v "\t"
            else if (c == "u") {
                cp = jhex4()
                if (cp < 0) { JERR = 1; return 0 }
                if (cp >= 55296 && cp <= 56319 && jpeek() == "\\") {
                    save = JPOS
                    JPOS++
                    if (jpeek() == "u") {
                        JPOS++
                        lo = jhex4()
                        if (lo >= 56320 && lo <= 57343) cp = 65536 + (cp - 55296) * 1024 + (lo - 56320)
                        else JPOS = save
                    } else JPOS = save
                }
                v = v utf8enc(cp)
            } else { JERR = 1; return 0 }
            run = JPOS
            continue
        }
        if (ORD[c] < 32) { JERR = 1; return 0 }
        JPOS++
    }
    id = ++JNID; JT[id] = "s"; JV[id] = v; JRAW[id] = jcap(start)
    return id
}

function jarray(depth,   id, n, ch, c) {
    JPOS++
    id = ++JNID; JT[id] = "a"; n = 0
    if (jws() == "]") { JPOS++; JN[id] = 0; return id }
    while (1) {
        ch = jvalue(depth + 1)
        if (JERR) return 0
        JCH[id, ++n] = ch
        c = jws()
        JPOS++
        if (c == "]") break
        if (c != ",") { JERR = 1; return 0 }
    }
    JN[id] = n
    return id
}

function jobject(depth,   id, n, k, ch, c) {
    JPOS++
    id = ++JNID; JT[id] = "o"; n = 0
    if (jws() == "}") { JPOS++; JN[id] = 0; return id }
    while (1) {
        if (jws() != "\"") { JERR = 1; return 0 }
        k = jstring()
        if (JERR) return 0
        if (jws() != ":") { JERR = 1; return 0 }
        JPOS++
        ch = jvalue(depth + 1)
        if (JERR) return 0
        n++
        JKEY[id, n] = JV[k]
        JCH[id, n] = ch
        c = jws()
        JPOS++
        if (c == "}") break
        if (c != ",") { JERR = 1; return 0 }
    }
    JN[id] = n
    return id
}

# Child of object id under key (last occurrence wins), or 0.
function oget(id, key,   i) {
    for (i = JN[id]; i >= 1; i--)
        if (JKEY[id, i] == key) return JCH[id, i]
    return 0
}

# Like oget, but an explicit null counts as absent.
function oval(id, key,   ch) {
    ch = oget(id, key)
    return (ch && JT[ch] != "z") ? ch : 0
}
