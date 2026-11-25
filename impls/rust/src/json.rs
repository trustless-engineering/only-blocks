//! A small, strict RFC 8259 JSON parser and a streaming JSON writer.
//!
//! The parser keeps every number as its raw lexeme, so a request `id` is echoed back
//! byte-for-byte and a slot is accepted only when it is a genuine integer literal.

use std::fmt::Write as _;

/// Maximum nesting depth (serde_json's default recursion limit).
pub const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Raw number lexeme exactly as written (already validated against the RFC grammar).
    Number(String),
    Str(String),
    Array(Vec<Json>),
    /// Members in source order. Lookups take the *last* duplicate, like serde_json.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// The value as `u64` if it is a plain non-negative integer literal (no sign, fraction
    /// or exponent) that fits. Mirrors `serde_json::Value::as_u64`.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(raw) if raw.bytes().all(|b| b.is_ascii_digit()) => raw.parse().ok(),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    /// Object member lookup (last duplicate wins).
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Serialize compactly into `out`.
    pub fn write_to(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Number(raw) => out.push_str(raw),
            Json::Str(s) => write_str(out, s),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_to(out);
                }
                out.push(']');
            }
            Json::Object(members) => {
                out.push('{');
                for (i, (k, v)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(out, k);
                    out.push(':');
                    v.write_to(out);
                }
                out.push('}');
            }
        }
    }
}

/// Parse a complete JSON document (surrounding whitespace allowed, nothing else).
pub fn parse(input: &[u8]) -> Result<Json, String> {
    let text = std::str::from_utf8(input).map_err(|e| format!("invalid UTF-8: {e}"))?;
    let mut p = Parser { s: text.as_bytes(), pos: 0 };
    p.ws();
    let value = p.value(0)?;
    p.ws();
    if p.pos != p.s.len() {
        return Err(format!("trailing characters at byte {}", p.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while let Some(&b) = self.s.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("{what} at byte {}", self.pos))
    }

    fn literal(&mut self, word: &[u8], value: Json) -> Result<Json, String> {
        if self.s[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(value)
        } else {
            self.err("invalid literal")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        match self.s.get(self.pos) {
            None => self.err("unexpected end of input"),
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => {
                if depth >= MAX_DEPTH {
                    return self.err("recursion limit exceeded");
                }
                self.pos += 1;
                let mut items = Vec::new();
                self.ws();
                if self.s.get(self.pos) == Some(&b']') {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                loop {
                    self.ws();
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.s.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Json::Array(items));
                        }
                        _ => return self.err("expected `,` or `]`"),
                    }
                }
            }
            Some(b'{') => {
                if depth >= MAX_DEPTH {
                    return self.err("recursion limit exceeded");
                }
                self.pos += 1;
                let mut members = Vec::new();
                self.ws();
                if self.s.get(self.pos) == Some(&b'}') {
                    self.pos += 1;
                    return Ok(Json::Object(members));
                }
                loop {
                    self.ws();
                    if self.s.get(self.pos) != Some(&b'"') {
                        return self.err("expected object key");
                    }
                    let key = self.string()?;
                    self.ws();
                    if self.s.get(self.pos) != Some(&b':') {
                        return self.err("expected `:`");
                    }
                    self.pos += 1;
                    self.ws();
                    let value = self.value(depth + 1)?;
                    members.push((key, value));
                    self.ws();
                    match self.s.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Json::Object(members));
                        }
                        _ => return self.err("expected `,` or `}`"),
                    }
                }
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.err("unexpected character"),
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while self.s.get(self.pos).is_some_and(u8::is_ascii_digit) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.s[self.pos] == b'-' {
            self.pos += 1;
        }
        match self.s.get(self.pos) {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return self.err("invalid number"),
        }
        if self.s.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            if self.digits() == 0 {
                return self.err("invalid number fraction");
            }
        }
        if matches!(self.s.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.s.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return self.err("invalid number exponent");
            }
        }
        // The input is valid UTF-8 and the lexeme is ASCII.
        let raw = String::from_utf8_lossy(&self.s[start..self.pos]).into_owned();
        Ok(Json::Number(raw))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self.s.get(self.pos..self.pos + 4).ok_or("truncated \\u escape")?;
        let text = std::str::from_utf8(digits).map_err(|_| "invalid \\u escape")?;
        let v = u32::from_str_radix(text, 16).map_err(|_| format!("invalid \\u escape at byte {}", self.pos))?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return self.err("invalid \\u escape");
        }
        self.pos += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(&b) = self.s.get(self.pos) {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            // Safe: the whole input was validated as UTF-8 and we split on ASCII bytes.
            out.push_str(std::str::from_utf8(&self.s[start..self.pos]).map_err(|e| e.to_string())?);
            match self.s.get(self.pos) {
                None => return self.err("unterminated string"),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let esc = *self.s.get(self.pos).ok_or("unterminated escape")?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                    return self.err("lone leading surrogate");
                                }
                                self.pos += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return self.err("invalid trailing surrogate");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return self.err("lone trailing surrogate");
                            } else {
                                hi
                            };
                            out.push(char::from_u32(code).ok_or("invalid code point")?);
                        }
                        _ => return self.err("invalid escape"),
                    }
                }
                Some(_) => return self.err("control character in string"),
            }
        }
    }
}

/// Append `s` as a JSON string literal.
pub fn write_str(out: &mut String, s: &str) {
    out.push('"');
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &str = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0x08 => "\\b",
            0x0c => "\\f",
            0..=0x1f => "",
            _ => continue,
        };
        out.push_str(&s[start..i]);
        if esc.is_empty() {
            let _ = write!(out, "\\u{:04x}", b);
        } else {
            out.push_str(esc);
        }
        start = i + 1;
    }
    out.push_str(&s[start..]);
    out.push('"');
}

/// A tiny streaming writer for building large JSON documents without an intermediate tree.
///
/// Commas are managed with a stack of "first element" flags: call [`Writer::begin_obj`] /
/// [`Writer::begin_arr`], then [`Writer::key`] (objects) or [`Writer::item`] (arrays) before
/// every value, then the matching `end_*`.
pub struct Writer {
    pub out: String,
    first: Vec<bool>,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Writer { out: String::new(), first: Vec::with_capacity(16) }
    }

    pub fn with_capacity(n: usize) -> Self {
        Writer { out: String::with_capacity(n), first: Vec::with_capacity(16) }
    }

    fn sep(&mut self) {
        if let Some(first) = self.first.last_mut() {
            if *first {
                *first = false;
            } else {
                self.out.push(',');
            }
        }
    }

    pub fn begin_obj(&mut self) {
        self.out.push('{');
        self.first.push(true);
    }
    pub fn end_obj(&mut self) {
        self.first.pop();
        self.out.push('}');
    }
    pub fn begin_arr(&mut self) {
        self.out.push('[');
        self.first.push(true);
    }
    pub fn end_arr(&mut self) {
        self.first.pop();
        self.out.push(']');
    }

    /// Start an object member.
    pub fn key(&mut self, k: &str) {
        self.sep();
        write_str(&mut self.out, k);
        self.out.push(':');
    }

    /// Start an array element.
    pub fn item(&mut self) {
        self.sep();
    }

    pub fn null(&mut self) {
        self.out.push_str("null");
    }
    pub fn bool(&mut self, v: bool) {
        self.out.push_str(if v { "true" } else { "false" });
    }
    pub fn str(&mut self, s: &str) {
        write_str(&mut self.out, s);
    }
    pub fn u64(&mut self, v: u64) {
        let _ = write!(self.out, "{v}");
    }
    pub fn i64(&mut self, v: i64) {
        let _ = write!(self.out, "{v}");
    }
    /// Shortest round-tripping representation; NaN and infinities become `null`.
    pub fn f64(&mut self, v: f64) {
        if v.is_finite() {
            let _ = write!(self.out, "{v:?}");
        } else {
            self.out.push_str("null");
        }
    }
    pub fn raw(&mut self, s: &str) {
        self.out.push_str(s);
    }

    // Convenience key/value helpers.
    pub fn kv_str(&mut self, k: &str, v: &str) {
        self.key(k);
        self.str(v);
    }
    pub fn kv_u64(&mut self, k: &str, v: u64) {
        self.key(k);
        self.u64(v);
    }
    pub fn kv_null(&mut self, k: &str) {
        self.key(k);
        self.null();
    }
    pub fn kv_bool(&mut self, k: &str, v: bool) {
        self.key(k);
        self.bool(v);
    }
    pub fn item_str(&mut self, v: &str) {
        self.item();
        self.str(v);
    }
    pub fn item_u64(&mut self, v: u64) {
        self.item();
        self.u64(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_roundtrips() {
        let v = parse(br#" {"a":[1,-2.5e3,true,null,"x\u00e9\ud83d\ude00"],"b":{}} "#).unwrap();
        let mut s = String::new();
        v.write_to(&mut s);
        assert_eq!(s, "{\"a\":[1,-2.5e3,true,null,\"x\u{e9}\u{1F600}\"],\"b\":{}}");
    }

    #[test]
    fn rejects_bad_json() {
        for bad in [
            &b"{bad"[..], b"", b"[1,]", b"01", b"1.", b"-", b"\"\\ud800\"", b"[1] x", b"{\"a\" 1}",
            b"\"\x01\"", b"NaN", b"tru",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let deep = "[".repeat(200_000);
        assert!(parse(deep.as_bytes()).is_err());
    }

    #[test]
    fn integer_accessor_matches_serde() {
        assert_eq!(parse(b"42").unwrap().as_u64(), Some(42));
        assert_eq!(parse(b"18446744073709551615").unwrap().as_u64(), Some(u64::MAX));
        for s in ["18446744073709551616", "-1", "-0", "1.0", "1e3", "\"1\""] {
            assert_eq!(parse(s.as_bytes()).unwrap().as_u64(), None, "{s}");
        }
    }

    #[test]
    fn last_duplicate_key_wins() {
        let v = parse(br#"{"k":1,"k":2}"#).unwrap();
        assert_eq!(v.get("k").and_then(Json::as_u64), Some(2));
    }

    #[test]
    fn escapes_strings() {
        let mut s = String::new();
        write_str(&mut s, "a\"b\\c\n\u{1}\u{7f}é");
        assert_eq!(s, "\"a\\\"b\\\\c\\n\\u0001\u{7f}é\"");
    }

    #[test]
    fn writer_commas() {
        let mut w = Writer::new();
        w.begin_obj();
        w.kv_u64("a", 1);
        w.key("b");
        w.begin_arr();
        w.item_str("x");
        w.item();
        w.f64(5e-6);
        w.item();
        w.f64(f64::NAN);
        w.end_arr();
        w.end_obj();
        assert_eq!(w.out, "{\"a\":1,\"b\":[\"x\",5e-6,null]}");
    }
}
