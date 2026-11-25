//! Zero-copy CARv1 section indexer: LEB128 varints, CIDv0/CIDv1 (WIRE_FORMATS.md §3).

use std::collections::HashMap;

use crate::bail;
use crate::cbor::{self, Cbor};
use crate::error::DResult;

pub const MAX_SECTION_BYTES: u64 = 32 * 1024 * 1024;

/// Read an unsigned LEB128 varint (at most 10 bytes).
pub fn read_uvarint(data: &[u8], pos: &mut usize) -> DResult<u64> {
    let mut x: u64 = 0;
    let mut shift = 0u32;
    for i in 0..10 {
        let Some(&b) = data.get(*pos) else { bail!("truncated varint") };
        *pos += 1;
        if b < 0x80 {
            if i == 9 && b > 1 {
                bail!("varint overflows u64");
            }
            return Ok(x | (b as u64) << shift);
        }
        x |= ((b & 0x7F) as u64) << shift;
        shift += 7;
    }
    bail!("varint longer than 10 bytes")
}

/// A parsed CID: its total encoded length plus the fields we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cid {
    pub len: usize,
    pub version: u64,
    pub codec: u64,
    pub hash_code: u64,
    pub hash_len: u64,
}

impl Cid {
    /// `bafkqaaa`-style "absent" CID: identity multihash of length 0.
    pub fn is_empty_identity(&self) -> bool {
        self.hash_code == 0 && self.hash_len == 0
    }
}

/// Parse a CID at the start of `data`.
pub fn parse_cid(data: &[u8]) -> DResult<Cid> {
    let mut pos = 0;
    let a = read_uvarint(data, &mut pos)?;
    let b = read_uvarint(data, &mut pos)?;
    if a == 0x12 && b == 0x20 {
        if data.len() - pos < 32 {
            bail!("truncated CIDv0 digest");
        }
        return Ok(Cid { len: pos + 32, version: 0, codec: 0x70, hash_code: 0x12, hash_len: 32 });
    }
    match a {
        0 => bail!("explicit CIDv0 is not allowed"),
        1 => {}
        v => bail!("unsupported CID version {v}"),
    }
    let hash_code = read_uvarint(data, &mut pos)?;
    let hash_len = read_uvarint(data, &mut pos)?;
    if hash_len > 64 {
        bail!("CID digest too long ({hash_len})");
    }
    if (data.len() - pos) < hash_len as usize {
        bail!("truncated CID digest");
    }
    Ok(Cid { len: pos + hash_len as usize, version: 1, codec: b, hash_code, hash_len })
}

/// Decode a DAG-CBOR link (tag 42 is already stripped by the CBOR decoder): a byte string
/// whose first byte is the `0x00` multibase prefix, followed by a CID. Returns the raw CID
/// bytes (trailing bytes after the CID are ignored).
pub fn link_cid<'b>(v: &'b Cbor<'_>) -> DResult<(&'b [u8], Cid)> {
    let Some(bytes) = v.as_bytes() else { bail!("CID link is not a byte string") };
    if bytes.first() != Some(&0x00) {
        bail!("CID link is missing the 0x00 multibase prefix");
    }
    let cid = parse_cid(&bytes[1..])?;
    Ok((&bytes[1..1 + cid.len], cid))
}

/// Raw CID bytes → node DAG-CBOR bytes, borrowed from the CAR slice.
pub struct CarIndex<'a> {
    nodes: HashMap<&'a [u8], &'a [u8]>,
    /// The last section that looks like a `Block` node (kind 2).
    pub block: Option<&'a [u8]>,
}

impl<'a> CarIndex<'a> {
    pub fn parse(slice: &'a [u8]) -> DResult<Self> {
        let mut nodes = HashMap::new();
        let mut block = None;
        let mut pos = 0usize;
        let mut seen_non_empty = false;
        while pos < slice.len() {
            let len = read_uvarint(slice, &mut pos)?;
            if len == 0 {
                continue;
            }
            if len > MAX_SECTION_BYTES {
                bail!("CAR section of {len} bytes exceeds 32 MiB");
            }
            if len > (slice.len() - pos) as u64 {
                bail!("truncated CAR section ({len} bytes, {} left)", slice.len() - pos);
            }
            let section = &slice[pos..pos + len as usize];
            pos += len as usize;
            let first = !seen_non_empty;
            seen_non_empty = true;
            if first && section[0] & 0xE0 == 0xA0 && is_car_header(section) {
                continue;
            }
            let cid = parse_cid(section)?;
            let (cid_bytes, node) = section.split_at(cid.len);
            nodes.insert(cid_bytes, node);
            if let Some(h) = node.first().and_then(|&b| cbor::array_header_len(b)) {
                if node.get(h) == Some(&0x02) {
                    block = Some(node);
                }
            }
        }
        Ok(CarIndex { nodes, block })
    }

    pub fn get(&self, cid: &[u8]) -> Option<&'a [u8]> {
        self.nodes.get(cid).copied()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// A CARv1 header: one CBOR map with a text key `"version"`.
fn is_car_header(section: &[u8]) -> bool {
    match cbor::parse(section) {
        Ok(Cbor::Map(pairs)) => pairs.iter().any(|(k, _)| matches!(k, Cbor::Text(t) if t == "version")),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for (bytes, want) in [(&[0x4a][..], 74u64), (&[0xac, 0x02], 300), (&[0x80, 0x80, 0x04], 65536)] {
            let mut p = 0;
            assert_eq!(read_uvarint(bytes, &mut p).unwrap(), want);
            assert_eq!(p, bytes.len());
        }
        let mut p = 0;
        assert!(read_uvarint(&[0x80], &mut p).is_err());
        let mut p = 0;
        assert!(read_uvarint(&[0xff; 9].iter().chain(&[0x02]).copied().collect::<Vec<_>>(), &mut p).is_err());
    }

    #[test]
    fn cids() {
        let mut v1 = vec![0x01, 0x71, 0x12, 0x20];
        v1.extend([7u8; 32]);
        let c = parse_cid(&v1).unwrap();
        assert_eq!(c.len, 36);
        assert!(!c.is_empty_identity());
        let id = parse_cid(&[0x01, 0x55, 0x00, 0x00]).unwrap();
        assert_eq!(id.len, 4);
        assert!(id.is_empty_identity());
        let mut v0 = vec![0x12, 0x20];
        v0.extend([1u8; 32]);
        assert_eq!(parse_cid(&v0).unwrap().len, 34);
        assert!(parse_cid(&[0x00, 0x71]).is_err());
        assert!(parse_cid(&[0x02, 0x71, 0x12, 0x00]).is_err());
        assert!(parse_cid(&[0x01, 0x71, 0x12, 0x41]).is_err());
    }
}
