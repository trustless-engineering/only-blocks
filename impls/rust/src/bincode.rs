//! Bincode 1.x (fixint, little-endian) decoding of pre-epoch-157 metadata and rewards, and of
//! `TransactionError` (WIRE_FORMATS.md §11).
//!
//! The reader reproduces bincode's `SliceReader` + `default_on_eof` behaviour: a fixed-width
//! read that runs out of bytes fails with [`BErr::Eof`] *without consuming anything*, and an
//! `eof` field turns exactly that error into its default value. A truncated string payload
//! is a different error and is never defaulted.

use crate::codec::{parse_unsigned, real_number_string_trimmed};
use crate::model::*;
use crate::tx::CompiledInstruction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BErr {
    Eof,
    Other(String),
}

impl std::fmt::Display for BErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BErr::Eof => f.write_str("io error: unexpected end of file"),
            BErr::Other(m) => f.write_str(m),
        }
    }
}

type BResult<T> = Result<T, BErr>;

fn other<T>(msg: impl Into<String>) -> BResult<T> {
    Err(BErr::Other(msg.into()))
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn fixed(&mut self, n: usize) -> BResult<&'a [u8]> {
        if n > self.remaining() {
            return Err(BErr::Eof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> BResult<u8> {
        Ok(self.fixed(1)?[0])
    }
    fn u32(&mut self) -> BResult<u32> {
        Ok(u32::from_le_bytes(self.fixed(4)?.try_into().unwrap_or([0; 4])))
    }
    fn u64(&mut self) -> BResult<u64> {
        Ok(u64::from_le_bytes(self.fixed(8)?.try_into().unwrap_or([0; 8])))
    }
    fn i64(&mut self) -> BResult<i64> {
        Ok(self.u64()? as i64)
    }
    fn f64(&mut self) -> BResult<f64> {
        Ok(f64::from_bits(self.u64()?))
    }
    fn pubkey(&mut self) -> BResult<Pubkey> {
        Ok(self.fixed(32)?.try_into().unwrap_or([0; 32]))
    }

    fn option_tag(&mut self) -> BResult<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            t => other(format!("invalid Option tag {t}")),
        }
    }

    fn option<T>(&mut self, f: impl FnOnce(&mut Self) -> BResult<T>) -> BResult<Option<T>> {
        if self.option_tag()? {
            f(self).map(Some)
        } else {
            Ok(None)
        }
    }

    fn len(&mut self) -> BResult<u64> {
        self.u64()
    }

    fn vec<T>(&mut self, mut f: impl FnMut(&mut Self) -> BResult<T>) -> BResult<Vec<T>> {
        let n = self.len()?;
        // Each element needs at least one byte; never pre-allocate from an untrusted length.
        let mut v = Vec::with_capacity((n as usize).min(self.remaining()).min(4096));
        for _ in 0..n {
            v.push(f(self)?);
        }
        Ok(v)
    }

    fn string(&mut self) -> BResult<String> {
        let n = self.len()?;
        if n > self.remaining() as u64 {
            // bincode's `get_byte_slice` error, which `default_on_eof` does not match.
            return other("io error: ");
        }
        let s = &self.buf[self.pos..self.pos + n as usize];
        self.pos += n as usize;
        std::str::from_utf8(s).map(str::to_owned).map_err(|e| BErr::Other(format!("invalid UTF-8: {e}")))
    }

    /// `Vec<u8>` serialized as a sequence: length, then one fixed read per element.
    fn byte_seq(&mut self) -> BResult<Vec<u8>> {
        let n = self.len()?;
        if n > self.remaining() as u64 {
            self.pos = self.buf.len();
            return Err(BErr::Eof);
        }
        Ok(self.fixed(n as usize)?.to_vec())
    }

    /// compact-u16 length read byte by byte (each byte is a fixed read).
    fn compact_u16(&mut self) -> BResult<u16> {
        let mut value: u32 = 0;
        for k in 0..3 {
            let b = self.u8()?;
            if k > 0 && b == 0 {
                return other("short_vec alias");
            }
            value |= ((b & 0x7F) as u32) << (7 * k);
            if b & 0x80 == 0 {
                if value > 0xFFFF {
                    return other("short_vec overflow");
                }
                return Ok(value as u16);
            }
            if k == 2 {
                return other("short_vec byte three continues");
            }
        }
        other("short_vec overflow")
    }

    fn short_vec_bytes(&mut self) -> BResult<Vec<u8>> {
        let n = self.compact_u16()? as usize;
        let mut v = Vec::with_capacity(n.min(self.remaining()));
        for _ in 0..n {
            v.push(self.u8()?);
        }
        Ok(v)
    }

    fn compiled_instruction(&mut self) -> BResult<CompiledInstruction> {
        Ok(CompiledInstruction {
            program_id_index: self.u8()?,
            accounts: self.short_vec_bytes()?,
            data: self.short_vec_bytes()?,
        })
    }

    fn finish_strict(&self) -> BResult<()> {
        if self.pos != self.buf.len() {
            return other("Slice had bytes remaining after deserialization");
        }
        Ok(())
    }
}

/// An `eof` field: a fixed-width EOF anywhere inside it yields the default value.
fn eof<T: Default>(r: BResult<T>) -> BResult<T> {
    match r {
        Err(BErr::Eof) => Ok(T::default()),
        r => r,
    }
}

// ------------------------------------------------------------------------------------
// TransactionError
// ------------------------------------------------------------------------------------

fn instruction_error(r: &mut Reader<'_>) -> BResult<InstructionError> {
    match r.u32()? {
        25 => Ok(InstructionError::Custom(r.u32()?)),
        v if v < 54 => Ok(InstructionError::Unit(v)),
        v => other(format!("invalid InstructionError variant index {v}")),
    }
}

fn transaction_error(r: &mut Reader<'_>) -> BResult<TransactionError> {
    match r.u32()? {
        8 => {
            let index = r.u8()?;
            Ok(TransactionError::InstructionError(index, instruction_error(r)?))
        }
        30 => Ok(TransactionError::DuplicateInstruction(r.u8()?)),
        31 => Ok(TransactionError::InsufficientFundsForRent(r.u8()?)),
        35 => Ok(TransactionError::ProgramExecutionTemporarilyRestricted(r.u8()?)),
        v if v < 39 => Ok(TransactionError::Unit(v)),
        v => other(format!("invalid TransactionError variant index {v}")),
    }
}

/// `bincode::deserialize::<TransactionError>` (trailing bytes allowed).
pub fn transaction_error_lenient(bytes: &[u8]) -> Result<TransactionError, BErr> {
    transaction_error(&mut Reader::new(bytes))
}

fn status(r: &mut Reader<'_>) -> BResult<Option<TransactionError>> {
    match r.u32()? {
        0 => Ok(None),
        1 => Ok(Some(transaction_error(r)?)),
        v => other(format!("invalid Result variant index {v}")),
    }
}

// ------------------------------------------------------------------------------------
// StoredTransactionStatusMeta and its legacy layouts
// ------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenLayout {
    /// `{account_index, mint, ui_token_amount}`
    V1,
    /// `{account_index, mint, ui_token_amount, owner}`
    V2,
    /// `StoredTransactionTokenBalance` with `eof` owner and program_id.
    Stored,
}

fn token_amount(r: &mut Reader<'_>) -> BResult<(f64, u8, String)> {
    Ok((r.f64()?, r.u8()?, r.string()?))
}

fn token_balance(r: &mut Reader<'_>, layout: TokenLayout) -> BResult<TokenBalance> {
    let account_index = r.u8()?;
    let mint = r.string()?;
    let (ui_amount, decimals, amount) = token_amount(r)?;
    let (owner, program_id) = match layout {
        TokenLayout::V1 => (String::new(), String::new()),
        TokenLayout::V2 => (r.string()?, String::new()),
        TokenLayout::Stored => {
            let owner = eof(r.string())?;
            let program_id = eof(r.string())?;
            (owner, program_id)
        }
    };
    let ui_amount_string = real_number_string_trimmed(parse_unsigned(&amount, u64::MAX).unwrap_or(0), decimals);
    Ok(TokenBalance {
        account_index,
        mint,
        owner,
        program_id,
        ui_amount: Some(ui_amount),
        decimals,
        amount,
        ui_amount_string,
    })
}

fn reward_type(r: &mut Reader<'_>) -> BResult<u8> {
    match r.u32()? {
        v @ 0..=3 => Ok(v as u8 + 1),
        v => other(format!("invalid RewardType variant index {v}")),
    }
}

/// `StoredExtendedReward` (with `eof` trailing fields) or the commission-less legacy layout.
fn reward(r: &mut Reader<'_>, extended: bool) -> BResult<Reward> {
    let pubkey = r.string()?;
    let lamports = r.i64()?;
    if extended {
        let post_balance = eof(r.u64())?;
        let reward_type = eof(r.option(reward_type))?;
        let commission = eof(r.option(Reader::u8))?;
        Ok(Reward { pubkey, lamports, post_balance, reward_type, commission })
    } else {
        let post_balance = r.u64()?;
        let reward_type = r.option(reward_type)?;
        Ok(Reward { pubkey, lamports, post_balance, reward_type, commission: None })
    }
}

fn meta(r: &mut Reader<'_>, legacy_inner: bool, tokens: TokenLayout) -> BResult<Meta> {
    let status = status(r)?;
    let fee = r.u64()?;
    let pre_balances = r.vec(Reader::u64)?;
    let post_balances = r.vec(Reader::u64)?;
    let inner_instructions = eof(r.option(|r| {
        r.vec(|r| {
            let index = r.u8()?;
            let instructions = r.vec(|r| {
                let ix = r.compiled_instruction()?;
                let stack_height = if legacy_inner { None } else { r.option(Reader::u32)? };
                Ok(InnerInstruction {
                    program_id_index: ix.program_id_index,
                    accounts: ix.accounts,
                    data: ix.data,
                    stack_height,
                })
            })?;
            Ok(InnerInstructions { index, instructions })
        })
    }))?;
    let log_messages = eof(r.option(|r| r.vec(Reader::string)))?;
    let pre_token_balances = eof(r.option(|r| r.vec(|r| token_balance(r, tokens))))?;
    let post_token_balances = eof(r.option(|r| r.vec(|r| token_balance(r, tokens))))?;
    let rewards = eof(r.option(|r| r.vec(|r| reward(r, true))))?;
    let return_data = eof(r.option(|r| Ok(ReturnData { program_id: r.pubkey()?, data: r.byte_seq()? })))?;
    let compute_units_consumed = eof(r.option(Reader::u64))?;
    let cost_units = eof(r.option(Reader::u64))?;
    Ok(Meta {
        status,
        fee,
        pre_balances,
        post_balances,
        inner_instructions,
        log_messages,
        pre_token_balances,
        post_token_balances,
        rewards,
        loaded_writable: Vec::new(),
        loaded_readonly: Vec::new(),
        return_data,
        compute_units_consumed,
        cost_units,
    })
}

fn strict<T>(bytes: &[u8], f: impl FnOnce(&mut Reader<'_>) -> BResult<T>) -> BResult<T> {
    let mut r = Reader::new(bytes);
    let v = f(&mut r)?;
    r.finish_strict()?;
    Ok(v)
}

/// `bincode_metadata(b)`: the four strict layouts in order, then lenient current layout.
pub fn transaction_status_meta(bytes: &[u8]) -> Result<Meta, String> {
    if let Ok(m) = strict(bytes, |r| meta(r, false, TokenLayout::Stored)) {
        return Ok(m);
    }
    for tokens in [TokenLayout::V1, TokenLayout::V2, TokenLayout::Stored] {
        if let Ok(m) = strict(bytes, |r| meta(r, true, tokens)) {
            return Ok(m);
        }
    }
    meta(&mut Reader::new(bytes), false, TokenLayout::Stored).map_err(|e| e.to_string())
}

/// `bincode_rewards(b)`: strict extended, strict commission-less, then lenient extended.
pub fn rewards(bytes: &[u8]) -> Result<Vec<Reward>, String> {
    if let Ok(v) = strict(bytes, |r| r.vec(|r| reward(r, true))) {
        return Ok(v);
    }
    if let Ok(v) = strict(bytes, |r| r.vec(|r| reward(r, false))) {
        return Ok(v);
    }
    Reader::new(bytes).vec(|r| reward(r, true)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_error_example() {
        let bytes = [0x08, 0, 0, 0, 0x00, 0x19, 0, 0, 0, 0x2a, 0, 0, 0];
        assert_eq!(
            transaction_error_lenient(&bytes).unwrap(),
            TransactionError::InstructionError(0, InstructionError::Custom(42))
        );
        assert_eq!(transaction_error_lenient(&[39, 0, 0, 0]).map_err(|_| ()), Err(()));
        assert_eq!(
            transaction_error_lenient(&[31, 0, 0, 0, 3]).unwrap(),
            TransactionError::InsufficientFundsForRent(3)
        );
        // BorshIoError (44) is a unit variant: a historical trailing string is ignored.
        assert_eq!(
            transaction_error_lenient(&[8, 0, 0, 0, 1, 44, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            TransactionError::InstructionError(1, InstructionError::Unit(44))
        );
    }

    #[test]
    fn eof_fields_default() {
        // status Ok, fee 5000, empty balances, then EOF: every optional field is None.
        let mut b = vec![0, 0, 0, 0];
        b.extend(5000u64.to_le_bytes());
        b.extend(0u64.to_le_bytes());
        b.extend(0u64.to_le_bytes());
        let m = transaction_status_meta(&b).unwrap();
        assert_eq!(m.fee, 5000);
        assert_eq!(m.inner_instructions, None);
        assert_eq!(m.cost_units, None);
        // Truncated before `post_balances`: a non-eof field, so it fails.
        assert!(transaction_status_meta(&b[..20]).is_err());
    }

    #[test]
    fn rewards_layouts() {
        let mut b = 1u64.to_le_bytes().to_vec();
        b.extend(1u64.to_le_bytes());
        b.push(b'k');
        b.extend(2500i64.to_le_bytes());
        b.extend(50000u64.to_le_bytes());
        b.extend([1, 0, 0, 0, 0]); // Some(Fee)
        b.push(0); // commission None
        let r = rewards(&b).unwrap();
        assert_eq!(r, vec![Reward { pubkey: "k".into(), lamports: 2500, post_balance: 50000, reward_type: Some(1), commission: None }]);
        // Without the commission byte the extended layout still matches via `eof`.
        let r2 = rewards(&b[..b.len() - 1]).unwrap();
        assert_eq!(r2[0].reward_type, Some(1));
    }
}
