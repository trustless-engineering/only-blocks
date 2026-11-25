//! Solana `VersionedTransaction` wire format with compact-u16 lengths (WIRE_FORMATS.md §8).

use crate::bail;
use crate::error::DResult;
use crate::model::Pubkey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressTableLookup {
    pub account_key: Pubkey,
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedTransaction {
    pub signatures: Vec<[u8; 64]>,
    /// `None` for a legacy message, `Some(0)` for v0.
    pub version: Option<u8>,
    /// `num_required_signatures`, `num_readonly_signed_accounts`, `num_readonly_unsigned_accounts`.
    pub header: [u8; 3],
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
    pub address_table_lookups: Vec<AddressTableLookup>,
    /// Bytes consumed by the parser: the canonical re-serialization used by base58/base64.
    pub wire_len: usize,
}

pub struct Cursor<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn u8(&mut self) -> DResult<u8> {
        let Some(&b) = self.data.get(self.pos) else { bail!("truncated transaction") };
        self.pos += 1;
        Ok(b)
    }

    pub fn bytes(&mut self, n: usize) -> DResult<&'a [u8]> {
        if n > self.remaining() {
            bail!("truncated transaction ({n} bytes wanted, {} left)", self.remaining());
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn array<const N: usize>(&mut self) -> DResult<[u8; N]> {
        let s = self.bytes(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// compact-u16 (`short_vec` length), strictly canonical.
    pub fn compact_u16(&mut self) -> DResult<u16> {
        let mut value: u32 = 0;
        for k in 0..3 {
            let b = self.u8()?;
            if k > 0 && b == 0 {
                bail!("non-canonical compact-u16");
            }
            value |= ((b & 0x7F) as u32) << (7 * k);
            if b & 0x80 == 0 {
                if value > 0xFFFF {
                    bail!("compact-u16 overflow");
                }
                return Ok(value as u16);
            }
            if k == 2 {
                bail!("compact-u16 longer than 3 bytes");
            }
        }
        bail!("compact-u16 overflow")
    }

    pub fn short_vec_bytes(&mut self) -> DResult<Vec<u8>> {
        let n = self.compact_u16()? as usize;
        Ok(self.bytes(n)?.to_vec())
    }
}

fn keys(c: &mut Cursor<'_>) -> DResult<Vec<Pubkey>> {
    let n = c.compact_u16()? as usize;
    if n * 32 > c.remaining() {
        bail!("truncated account keys");
    }
    (0..n).map(|_| c.array::<32>()).collect()
}

pub fn parse_compiled_instruction(c: &mut Cursor<'_>) -> DResult<CompiledInstruction> {
    let program_id_index = c.u8()?;
    let accounts = c.short_vec_bytes()?;
    let data = c.short_vec_bytes()?;
    Ok(CompiledInstruction { program_id_index, accounts, data })
}

pub fn parse_versioned_transaction(bytes: &[u8]) -> DResult<VersionedTransaction> {
    let mut c = Cursor::new(bytes);
    let num_sigs = c.compact_u16()? as usize;
    if num_sigs * 64 > c.remaining() {
        bail!("truncated signatures");
    }
    let signatures = (0..num_sigs).map(|_| c.array::<64>()).collect::<DResult<Vec<_>>>()?;
    let prefix = c.u8()?;
    let version = if prefix & 0x80 == 0 {
        c.pos -= 1; // legacy: the prefix is num_required_signatures
        None
    } else {
        match prefix & 0x7F {
            0 => Some(0),
            127 => bail!("off-chain messages are not accepted"),
            v => bail!("unsupported transaction version {v}"),
        }
    };
    let header = [c.u8()?, c.u8()?, c.u8()?];
    let account_keys = keys(&mut c)?;
    let recent_blockhash = c.array::<32>()?;
    let n = c.compact_u16()? as usize;
    let mut instructions = Vec::with_capacity(n.min(c.remaining()));
    for _ in 0..n {
        instructions.push(parse_compiled_instruction(&mut c)?);
    }
    let mut address_table_lookups = Vec::new();
    if version.is_some() {
        let t = c.compact_u16()? as usize;
        address_table_lookups.reserve(t.min(c.remaining() / 34));
        for _ in 0..t {
            let account_key = c.array::<32>()?;
            let writable_indexes = c.short_vec_bytes()?;
            let readonly_indexes = c.short_vec_bytes()?;
            address_table_lookups.push(AddressTableLookup { account_key, writable_indexes, readonly_indexes });
        }
    }
    Ok(VersionedTransaction {
        signatures,
        version,
        header,
        account_keys,
        recent_blockhash,
        instructions,
        address_table_lookups,
        wire_len: c.pos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_u16_vectors() {
        for (bytes, want) in [
            (&[0x00][..], 0u16),
            (&[0x7f], 127),
            (&[0x80, 0x01], 128),
            (&[0xff, 0x7f], 16383),
            (&[0x80, 0x80, 0x01], 16384),
            (&[0xff, 0xff, 0x03], 65535),
        ] {
            let mut c = Cursor::new(bytes);
            assert_eq!(c.compact_u16().unwrap(), want);
            assert_eq!(c.pos, bytes.len());
        }
        for bad in [&[0x80, 0x00][..], &[0x80, 0x80, 0x00], &[0xff, 0xff, 0x04], &[0x80, 0x80, 0x80, 0x01], &[0x80]] {
            assert!(Cursor::new(bad).compact_u16().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn parses_legacy_fixture_transaction() {
        let mut tx = vec![0x01];
        tx.extend([0x3e; 64]);
        tx.extend([0x01, 0x00, 0x01, 0x03]);
        tx.extend([0x01; 32]);
        tx.extend([0x02; 32]);
        tx.extend([0x05; 32]);
        tx.extend([0x29; 32]);
        tx.extend([0x01, 0x02, 0x02, 0x00, 0x01, 0x04, 0x00, 0x01, 0x2a, 0xff]);
        assert_eq!(tx.len(), 207);
        tx.extend([0xde, 0xad]); // trailing bytes are ignored
        let parsed = parse_versioned_transaction(&tx).unwrap();
        assert_eq!(parsed.version, None);
        assert_eq!(parsed.header, [1, 0, 1]);
        assert_eq!(parsed.account_keys.len(), 3);
        assert_eq!(parsed.instructions[0].accounts, vec![0, 1]);
        assert_eq!(parsed.instructions[0].data, vec![0x00, 0x01, 0x2a, 0xff]);
        assert_eq!(parsed.wire_len, 207);
    }
}
