//! DAG-CBOR decoding (the RFC 8949 subset described in WIRE_FORMATS.md §4).
//!
//! Byte and text strings borrow from the input whenever they are definite-length, so the
//! multi-megabyte DataFrame payloads inside an Old Faithful CAR slice are never copied.

use std::borrow::Cow;

use crate::bail;
use crate::error::DResult;

pub const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub enum Cbor<'a> {
    Uint(u64),
    /// Negative integer `-1 - n`.
    Nint(u64),
    Bytes(Cow<'a, [u8]>),
    Text(Cow<'a, str>),
    Array(Vec<Cbor<'a>>),
    Map(Vec<(Cbor<'a>, Cbor<'a>)>),
    Bool(bool),
    Null,
    Float(f64),
}

impl<'a> Cbor<'a> {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Cbor::Uint(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Cbor::Uint(n) if *n <= i64::MAX as u64 => Some(*n as i64),
            Cbor::Nint(n) if *n <= i64::MAX as u64 => Some(-1 - *n as i64),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Cbor<'a>]> {
        match self {
            Cbor::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Move a byte string out of the tree (borrowed payloads stay borrowed).
    pub fn take_bytes(&mut self) -> Option<Cow<'a, [u8]>> {
        match std::mem::replace(self, Cbor::Null) {
            Cbor::Bytes(b) => Some(b),
            other => {
                *self = other;
                None
            }
        }
    }
}

/// Decode exactly one CBOR item; trailing bytes are an error.
pub fn parse(data: &[u8]) -> DResult<Cbor<'_>> {
    let mut d = Decoder { data, pos: 0 };
    let item = d.item(0)?;
    if d.pos != data.len() {
        bail!("trailing bytes after CBOR item ({} of {})", d.pos, data.len());
    }
    Ok(item)
}

/// Length in bytes of the initial byte plus argument of an item header, if `b` is a valid
/// header byte for an array (major 4, info 0..27 or 31).
pub fn array_header_len(b: u8) -> Option<usize> {
    if b >> 5 != 4 {
        return None;
    }
    match b & 0x1F {
        0..=23 | 31 => Some(1),
        24 => Some(2),
        25 => Some(3),
        26 => Some(5),
        27 => Some(9),
        _ => None,
    }
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

enum Head {
    Definite(u64),
    Indefinite,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn byte(&mut self) -> DResult<u8> {
        match self.data.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                Ok(b)
            }
            None => bail!("truncated CBOR"),
        }
    }

    fn take(&mut self, n: u64) -> DResult<&'a [u8]> {
        if n > self.remaining() as u64 {
            bail!("truncated CBOR string ({n} bytes)");
        }
        let n = n as usize;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn arg(&mut self, info: u8) -> DResult<Head> {
        Ok(Head::Definite(match info {
            0..=23 => info as u64,
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap_or([0; 2])) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap_or([0; 4])) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap_or([0; 8])),
            31 => return Ok(Head::Indefinite),
            _ => bail!("reserved CBOR additional info {info}"),
        }))
    }

    /// Concatenate the definite-length chunks of an indefinite byte/text string.
    fn chunks(&mut self, major: u8) -> DResult<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let b = self.byte()?;
            if b == 0xFF {
                return Ok(out);
            }
            if b >> 5 != major {
                bail!("bad chunk in indefinite-length CBOR string");
            }
            match self.arg(b & 0x1F)? {
                Head::Definite(n) => out.extend_from_slice(self.take(n)?),
                Head::Indefinite => bail!("nested indefinite-length CBOR string"),
            }
        }
    }

    fn item(&mut self, depth: usize) -> DResult<Cbor<'a>> {
        if depth > MAX_DEPTH {
            bail!("CBOR nesting too deep");
        }
        let b = self.byte()?;
        let major = b >> 5;
        let info = b & 0x1F;
        match major {
            0 => match self.arg(info)? {
                Head::Definite(n) => Ok(Cbor::Uint(n)),
                Head::Indefinite => bail!("indefinite CBOR integer"),
            },
            1 => match self.arg(info)? {
                Head::Definite(n) => Ok(Cbor::Nint(n)),
                Head::Indefinite => bail!("indefinite CBOR integer"),
            },
            2 => match self.arg(info)? {
                Head::Definite(n) => Ok(Cbor::Bytes(Cow::Borrowed(self.take(n)?))),
                Head::Indefinite => Ok(Cbor::Bytes(Cow::Owned(self.chunks(2)?))),
            },
            3 => {
                let bytes: Cow<'a, [u8]> = match self.arg(info)? {
                    Head::Definite(n) => Cow::Borrowed(self.take(n)?),
                    Head::Indefinite => Cow::Owned(self.chunks(3)?),
                };
                Ok(Cbor::Text(match bytes {
                    Cow::Borrowed(b) => Cow::Borrowed(std::str::from_utf8(b).map_err(|_| crate::error::DecodeError::new("invalid UTF-8 in CBOR text"))?),
                    Cow::Owned(v) => Cow::Owned(String::from_utf8(v).map_err(|_| crate::error::DecodeError::new("invalid UTF-8 in CBOR text"))?),
                }))
            }
            4 => {
                let mut items = Vec::new();
                match self.arg(info)? {
                    Head::Definite(n) => {
                        // Every item takes at least one byte: never trust `n` for allocation.
                        if n > self.remaining() as u64 {
                            bail!("CBOR array length {n} exceeds input");
                        }
                        items.reserve(n as usize);
                        for _ in 0..n {
                            items.push(self.item(depth + 1)?);
                        }
                    }
                    Head::Indefinite => loop {
                        if self.data.get(self.pos) == Some(&0xFF) {
                            self.pos += 1;
                            break;
                        }
                        items.push(self.item(depth + 1)?);
                    },
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let mut pairs = Vec::new();
                match self.arg(info)? {
                    Head::Definite(n) => {
                        if n > (self.remaining() / 2) as u64 {
                            bail!("CBOR map length {n} exceeds input");
                        }
                        pairs.reserve(n as usize);
                        for _ in 0..n {
                            let k = self.item(depth + 1)?;
                            let v = self.item(depth + 1)?;
                            pairs.push((k, v));
                        }
                    }
                    Head::Indefinite => loop {
                        if self.data.get(self.pos) == Some(&0xFF) {
                            self.pos += 1;
                            break;
                        }
                        let k = self.item(depth + 1)?;
                        let v = self.item(depth + 1)?;
                        pairs.push((k, v));
                    },
                }
                Ok(Cbor::Map(pairs))
            }
            6 => match self.arg(info)? {
                // Tags (including tag 42 CID links) are discarded; the item is kept as is.
                Head::Definite(_) => self.item(depth + 1),
                Head::Indefinite => bail!("indefinite CBOR tag"),
            },
            _ => match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 | 23 => Ok(Cbor::Null),
                25 => {
                    let h = u16::from_be_bytes(self.take(2)?.try_into().unwrap_or([0; 2]));
                    Ok(Cbor::Float(half_to_f64(h)))
                }
                26 => {
                    let v = f32::from_be_bytes(self.take(4)?.try_into().unwrap_or([0; 4]));
                    Ok(Cbor::Float(v as f64))
                }
                27 => Ok(Cbor::Float(f64::from_be_bytes(self.take(8)?.try_into().unwrap_or([0; 8])))),
                31 => bail!("unexpected CBOR break"),
                _ => bail!("unsupported CBOR simple value {info}"),
            },
        }
    }
}

fn half_to_f64(h: u16) -> f64 {
    let sign = if h & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = ((h >> 10) & 0x1F) as i32;
    let mant = (h & 0x3FF) as f64;
    sign * match exp {
        0 => mant * 2f64.powi(-24),
        31 => {
            if mant == 0.0 {
                f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => (1.0 + mant / 1024.0) * 2f64.powi(exp - 15),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_basic_items() {
        assert_eq!(parse(&[0x0a]).unwrap(), Cbor::Uint(10));
        assert_eq!(parse(&[0x1b, 0x70, 0x28, 0x0d, 0xc4, 0xad, 0x6a, 0xcf, 0xd7]).unwrap(), Cbor::Uint(0x7028_0dc4_ad6a_cfd7));
        assert_eq!(parse(&[0x20]).unwrap().as_i64(), Some(-1));
        assert_eq!(parse(&[0xf6]).unwrap(), Cbor::Null);
        assert_eq!(parse(&[0xf7]).unwrap(), Cbor::Null);
        assert_eq!(parse(&[0xf9, 0x3c, 0x00]).unwrap(), Cbor::Float(1.0));
        // tag 42 wrapping bytes(2)
        assert_eq!(parse(&[0xd8, 0x2a, 0x42, 0x00, 0x01]).unwrap(), Cbor::Bytes(Cow::Owned(vec![0, 1])));
        // indefinite bytes and array
        assert_eq!(parse(&[0x5f, 0x41, 0x01, 0x42, 0x02, 0x03, 0xff]).unwrap(), Cbor::Bytes(Cow::Owned(vec![1, 2, 3])));
        assert_eq!(parse(&[0x9f, 0x01, 0x02, 0xff]).unwrap(), Cbor::Array(vec![Cbor::Uint(1), Cbor::Uint(2)]));
        assert_eq!(parse(&[0xa1, 0x61, b'a', 0x01]).unwrap(), Cbor::Map(vec![(Cbor::Text(Cow::Borrowed("a")), Cbor::Uint(1))]));
    }

    #[test]
    fn rejects_malformed() {
        for bad in [&[0x01, 0x02][..], &[0x1c], &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], &[0x62, 0xff, 0xfe], &[0xff], &[0x58]] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let deep = vec![0x81; 10_000];
        assert!(parse(&deep).is_err());
    }
}
