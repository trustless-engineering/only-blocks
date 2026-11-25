//! Protobuf wire reader for `solana.storage.ConfirmedBlock` (WIRE_FORMATS.md §10), with
//! prost semantics: unknown fields skipped, wrong wire types rejected, packed or unpacked
//! repeated scalars, last-wins scalars and field-merged sub-messages.

use crate::bincode;
use crate::codec::{parse_unsigned, real_number_string_trimmed};
use crate::error::{DResult, DecodeError};
use crate::model::*;

const RECURSION_LIMIT: u32 = 100;

type PResult<T> = Result<T, String>;

const VARINT: u8 = 0;
const I64: u8 = 1;
const LEN: u8 = 2;
const SGROUP: u8 = 3;
const EGROUP: u8 = 4;
const I32: u8 = 5;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn varint(&mut self) -> PResult<u64> {
        let mut x: u64 = 0;
        for i in 0..10 {
            let Some(&b) = self.buf.get(self.pos) else { return Err("truncated varint".into()) };
            self.pos += 1;
            if i == 9 && b > 1 {
                return Err("invalid varint".into());
            }
            x |= ((b & 0x7F) as u64) << (7 * i);
            if b < 0x80 {
                return Ok(x);
            }
        }
        Err("invalid varint".into())
    }

    fn key(&mut self) -> PResult<(u32, u8)> {
        let k = self.varint()?;
        if k > u32::MAX as u64 {
            return Err(format!("invalid key value: {k}"));
        }
        let wire = (k & 7) as u8;
        if wire > 5 {
            return Err(format!("invalid wire type value: {wire}"));
        }
        let field = (k >> 3) as u32;
        if field == 0 {
            return Err("invalid tag value: 0".into());
        }
        Ok((field, wire))
    }

    fn fixed<const N: usize>(&mut self) -> PResult<[u8; N]> {
        if N > self.buf.len() - self.pos {
            return Err("buffer underflow".into());
        }
        let mut a = [0u8; N];
        a.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(a)
    }

    fn len_delimited(&mut self) -> PResult<&'a [u8]> {
        let n = self.varint()?;
        if n > (self.buf.len() - self.pos) as u64 {
            return Err("buffer underflow".into());
        }
        let s = &self.buf[self.pos..self.pos + n as usize];
        self.pos += n as usize;
        Ok(s)
    }

    fn skip(&mut self, field: u32, wire: u8, depth: u32) -> PResult<()> {
        match wire {
            VARINT => {
                self.varint()?;
            }
            I64 => {
                self.fixed::<8>()?;
            }
            LEN => {
                self.len_delimited()?;
            }
            I32 => {
                self.fixed::<4>()?;
            }
            SGROUP => {
                if depth >= RECURSION_LIMIT {
                    return Err("recursion limit reached".into());
                }
                loop {
                    if self.done() {
                        return Err("unexpected end of group".into());
                    }
                    let (f, w) = self.key()?;
                    if w == EGROUP {
                        if f != field {
                            return Err("unexpected end group tag".into());
                        }
                        break;
                    }
                    self.skip(f, w, depth + 1)?;
                }
            }
            _ => return Err("unexpected end group tag".into()),
        }
        Ok(())
    }
}

fn expect(wire: u8, want: u8, field: u32) -> PResult<()> {
    if wire == want {
        Ok(())
    } else {
        Err(format!("invalid wire type {wire} for field {field} (expected {want})"))
    }
}

fn read_string(r: &mut Reader<'_>, wire: u8, field: u32) -> PResult<String> {
    expect(wire, LEN, field)?;
    let b = r.len_delimited()?;
    std::str::from_utf8(b).map(str::to_owned).map_err(|_| "invalid string value: data is not UTF-8 encoded".into())
}

fn read_bytes(r: &mut Reader<'_>, wire: u8, field: u32) -> PResult<Vec<u8>> {
    expect(wire, LEN, field)?;
    Ok(r.len_delimited()?.to_vec())
}

fn read_varint(r: &mut Reader<'_>, wire: u8, field: u32) -> PResult<u64> {
    expect(wire, VARINT, field)?;
    r.varint()
}

/// Repeated `uint64`, packed (wire type 2) or unpacked (wire type 0).
fn read_repeated_u64(r: &mut Reader<'_>, wire: u8, field: u32, out: &mut Vec<u64>) -> PResult<()> {
    match wire {
        VARINT => out.push(r.varint()?),
        LEN => {
            let mut inner = Reader::new(r.len_delimited()?);
            while !inner.done() {
                out.push(inner.varint()?);
            }
        }
        _ => return Err(format!("invalid wire type {wire} for packed field {field}")),
    }
    Ok(())
}

/// Parse a nested message by merging into `msg` (prost semantics for repeated occurrences).
fn merge_message<T>(
    r: &mut Reader<'_>,
    wire: u8,
    field: u32,
    depth: u32,
    msg: &mut T,
    f: fn(&mut T, &mut Reader<'_>, u32) -> PResult<()>,
) -> PResult<()> {
    expect(wire, LEN, field)?;
    if depth >= RECURSION_LIMIT {
        return Err("recursion limit reached".into());
    }
    let mut inner = Reader::new(r.len_delimited()?);
    f(msg, &mut inner, depth + 1)
}

// ------------------------------------------------------------------------------------
// Raw protobuf messages
// ------------------------------------------------------------------------------------

#[derive(Default)]
struct PbMeta {
    err: Option<Vec<u8>>,
    fee: u64,
    pre_balances: Vec<u64>,
    post_balances: Vec<u64>,
    inner_instructions: Vec<PbInnerInstructions>,
    log_messages: Vec<String>,
    pre_token_balances: Vec<PbTokenBalance>,
    post_token_balances: Vec<PbTokenBalance>,
    rewards: Vec<PbReward>,
    inner_instructions_none: bool,
    log_messages_none: bool,
    loaded_writable: Vec<Vec<u8>>,
    loaded_readonly: Vec<Vec<u8>>,
    return_data: Option<PbReturnData>,
    return_data_none: bool,
    compute_units_consumed: Option<u64>,
    cost_units: Option<u64>,
}

#[derive(Default)]
struct PbInnerInstructions {
    index: u32,
    instructions: Vec<PbInnerInstruction>,
}

#[derive(Default)]
struct PbInnerInstruction {
    program_id_index: u32,
    accounts: Vec<u8>,
    data: Vec<u8>,
    stack_height: Option<u32>,
}

#[derive(Default)]
struct PbTokenBalance {
    account_index: u32,
    mint: String,
    ui_token_amount: Option<PbUiTokenAmount>,
    owner: String,
    program_id: String,
}

#[derive(Default)]
struct PbUiTokenAmount {
    ui_amount: f64,
    decimals: u32,
    amount: String,
    ui_amount_string: String,
}

#[derive(Default)]
struct PbReturnData {
    program_id: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Default)]
struct PbReward {
    pubkey: String,
    lamports: i64,
    post_balance: u64,
    reward_type: i32,
    commission: String,
    commission_bps: String,
}

#[derive(Default)]
struct PbRewards {
    rewards: Vec<PbReward>,
    num_partitions: Option<u64>,
}

/// Iterate a message's fields, dispatching known ones to `known` (which returns `false` for
/// unknown field numbers so they get skipped).
fn fields(r: &mut Reader<'_>, depth: u32, mut known: impl FnMut(&mut Reader<'_>, u32, u8) -> PResult<bool>) -> PResult<()> {
    while !r.done() {
        let (field, wire) = r.key()?;
        if !known(r, field, wire)? {
            r.skip(field, wire, depth)?;
        }
    }
    Ok(())
}

fn parse_meta(m: &mut PbMeta, r: &mut Reader<'_>, depth: u32) -> PResult<()> {
    fields(r, depth, |r, field, wire| {
        match field {
            1 => {
                // TransactionError { bytes err = 1 }: merge semantics.
                let mut err = m.err.take().unwrap_or_default();
                merge_message(r, wire, field, depth, &mut err, |e, r, depth| {
                    fields(r, depth, |r, f, w| {
                        if f == 1 {
                            *e = read_bytes(r, w, f)?;
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    })
                })?;
                m.err = Some(err);
            }
            2 => m.fee = read_varint(r, wire, field)?,
            3 => read_repeated_u64(r, wire, field, &mut m.pre_balances)?,
            4 => read_repeated_u64(r, wire, field, &mut m.post_balances)?,
            5 => {
                let mut ii = PbInnerInstructions::default();
                merge_message(r, wire, field, depth, &mut ii, parse_inner_instructions)?;
                m.inner_instructions.push(ii);
            }
            6 => m.log_messages.push(read_string(r, wire, field)?),
            7 => {
                let mut tb = PbTokenBalance::default();
                merge_message(r, wire, field, depth, &mut tb, parse_token_balance)?;
                m.pre_token_balances.push(tb);
            }
            8 => {
                let mut tb = PbTokenBalance::default();
                merge_message(r, wire, field, depth, &mut tb, parse_token_balance)?;
                m.post_token_balances.push(tb);
            }
            9 => {
                let mut rw = PbReward::default();
                merge_message(r, wire, field, depth, &mut rw, parse_reward)?;
                m.rewards.push(rw);
            }
            10 => m.inner_instructions_none = read_varint(r, wire, field)? != 0,
            11 => m.log_messages_none = read_varint(r, wire, field)? != 0,
            12 => m.loaded_writable.push(read_bytes(r, wire, field)?),
            13 => m.loaded_readonly.push(read_bytes(r, wire, field)?),
            14 => {
                let mut rd = m.return_data.take().unwrap_or_default();
                merge_message(r, wire, field, depth, &mut rd, |rd, r, depth| {
                    fields(r, depth, |r, f, w| {
                        match f {
                            1 => rd.program_id = read_bytes(r, w, f)?,
                            2 => rd.data = read_bytes(r, w, f)?,
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })
                })?;
                m.return_data = Some(rd);
            }
            15 => m.return_data_none = read_varint(r, wire, field)? != 0,
            16 => m.compute_units_consumed = Some(read_varint(r, wire, field)?),
            17 => m.cost_units = Some(read_varint(r, wire, field)?),
            _ => return Ok(false),
        }
        Ok(true)
    })
}

fn parse_inner_instructions(ii: &mut PbInnerInstructions, r: &mut Reader<'_>, depth: u32) -> PResult<()> {
    fields(r, depth, |r, field, wire| {
        match field {
            1 => ii.index = read_varint(r, wire, field)? as u32,
            2 => {
                let mut ix = PbInnerInstruction::default();
                merge_message(r, wire, field, depth, &mut ix, |ix, r, depth| {
                    fields(r, depth, |r, f, w| {
                        match f {
                            1 => ix.program_id_index = read_varint(r, w, f)? as u32,
                            2 => ix.accounts = read_bytes(r, w, f)?,
                            3 => ix.data = read_bytes(r, w, f)?,
                            4 => ix.stack_height = Some(read_varint(r, w, f)? as u32),
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })
                })?;
                ii.instructions.push(ix);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })
}

fn parse_token_balance(tb: &mut PbTokenBalance, r: &mut Reader<'_>, depth: u32) -> PResult<()> {
    fields(r, depth, |r, field, wire| {
        match field {
            1 => tb.account_index = read_varint(r, wire, field)? as u32,
            2 => tb.mint = read_string(r, wire, field)?,
            3 => {
                let mut amt = tb.ui_token_amount.take().unwrap_or_default();
                merge_message(r, wire, field, depth, &mut amt, |a, r, depth| {
                    fields(r, depth, |r, f, w| {
                        match f {
                            1 => {
                                expect(w, I64, f)?;
                                a.ui_amount = f64::from_le_bytes(r.fixed::<8>()?);
                            }
                            2 => a.decimals = read_varint(r, w, f)? as u32,
                            3 => a.amount = read_string(r, w, f)?,
                            4 => a.ui_amount_string = read_string(r, w, f)?,
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })
                })?;
                tb.ui_token_amount = Some(amt);
            }
            4 => tb.owner = read_string(r, wire, field)?,
            5 => tb.program_id = read_string(r, wire, field)?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

fn parse_reward(rw: &mut PbReward, r: &mut Reader<'_>, depth: u32) -> PResult<()> {
    fields(r, depth, |r, field, wire| {
        match field {
            1 => rw.pubkey = read_string(r, wire, field)?,
            2 => rw.lamports = read_varint(r, wire, field)? as i64,
            3 => rw.post_balance = read_varint(r, wire, field)?,
            4 => rw.reward_type = read_varint(r, wire, field)? as i32,
            5 => rw.commission = read_string(r, wire, field)?,
            6 => rw.commission_bps = read_string(r, wire, field)?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

fn parse_rewards_msg(rs: &mut PbRewards, r: &mut Reader<'_>, depth: u32) -> PResult<()> {
    fields(r, depth, |r, field, wire| {
        match field {
            1 => {
                let mut rw = PbReward::default();
                merge_message(r, wire, field, depth, &mut rw, parse_reward)?;
                rs.rewards.push(rw);
            }
            2 => {
                let mut n = rs.num_partitions.unwrap_or(0);
                merge_message(r, wire, field, depth, &mut n, |n, r, depth| {
                    fields(r, depth, |r, f, w| {
                        if f == 1 {
                            *n = read_varint(r, w, f)?;
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    })
                })?;
                rs.num_partitions = Some(n);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })
}

// ------------------------------------------------------------------------------------
// Conversion to the internal model (§10.3)
// ------------------------------------------------------------------------------------

fn convert_reward(r: PbReward) -> Reward {
    let commission = parse_unsigned(&r.commission, u8::MAX as u64).map(|v| v as u8).or_else(|| {
        parse_unsigned(&r.commission_bps, u16::MAX as u64).and_then(|bps| u8::try_from(bps / 100).ok())
    });
    Reward {
        pubkey: r.pubkey,
        lamports: r.lamports,
        post_balance: r.post_balance,
        reward_type: matches!(r.reward_type, 1..=4).then_some(r.reward_type as u8),
        commission,
    }
}

fn convert_token_balance(tb: PbTokenBalance) -> TokenBalance {
    let amt = tb.ui_token_amount.unwrap_or_default();
    let decimals = amt.decimals as u8;
    let ui_amount = ((amt.ui_amount - 0.0).abs() > f64::EPSILON).then_some(amt.ui_amount);
    let ui_amount_string = if amt.ui_amount_string.is_empty() {
        real_number_string_trimmed(parse_unsigned(&amt.amount, u64::MAX).unwrap_or(0), decimals)
    } else {
        amt.ui_amount_string
    };
    TokenBalance {
        account_index: tb.account_index as u8,
        mint: tb.mint,
        owner: tb.owner,
        program_id: tb.program_id,
        ui_amount,
        decimals,
        amount: amt.amount,
        ui_amount_string,
    }
}

fn pubkey(bytes: Vec<u8>, what: &str) -> DResult<Pubkey> {
    let len = bytes.len();
    bytes.try_into().map_err(|_| DecodeError(format!("{what} must be 32 bytes, got {len}")))
}

/// Parse a protobuf `TransactionStatusMeta`. `Err(Ok(..))`-style layering: the outer error is a
/// protobuf *parse* failure (callers may fall back to bincode), the inner one a conversion
/// failure (final).
pub fn parse_transaction_status_meta(bytes: &[u8]) -> Result<DResult<Meta>, String> {
    let mut m = PbMeta::default();
    parse_meta(&mut m, &mut Reader::new(bytes), 0)?;
    Ok(convert_meta(m))
}

fn convert_meta(m: PbMeta) -> DResult<Meta> {
    let status = match m.err {
        None => None,
        Some(err) => Some(
            bincode::transaction_error_lenient(&err)
                .map_err(|e| DecodeError(format!("failed to deserialize bincode TransactionError: {e}")))?,
        ),
    };
    let inner_instructions = (!m.inner_instructions_none).then(|| {
        m.inner_instructions
            .into_iter()
            .map(|ii| InnerInstructions {
                index: ii.index as u8,
                instructions: ii
                    .instructions
                    .into_iter()
                    .map(|ix| InnerInstruction {
                        program_id_index: ix.program_id_index as u8,
                        accounts: ix.accounts,
                        data: ix.data,
                        stack_height: ix.stack_height,
                    })
                    .collect(),
            })
            .collect()
    });
    let log_messages = (!m.log_messages_none).then_some(m.log_messages);
    let loaded_writable = m.loaded_writable.into_iter().map(|b| pubkey(b, "loaded address")).collect::<DResult<_>>()?;
    let loaded_readonly = m.loaded_readonly.into_iter().map(|b| pubkey(b, "loaded address")).collect::<DResult<_>>()?;
    let return_data = if m.return_data_none {
        None
    } else {
        match m.return_data {
            Some(rd) => Some(ReturnData { program_id: pubkey(rd.program_id, "return data program id")?, data: rd.data }),
            None => None,
        }
    };
    Ok(Meta {
        status,
        fee: m.fee,
        pre_balances: m.pre_balances,
        post_balances: m.post_balances,
        inner_instructions,
        log_messages,
        pre_token_balances: Some(m.pre_token_balances.into_iter().map(convert_token_balance).collect()),
        post_token_balances: Some(m.post_token_balances.into_iter().map(convert_token_balance).collect()),
        rewards: Some(m.rewards.into_iter().map(convert_reward).collect()),
        loaded_writable,
        loaded_readonly,
        return_data,
        compute_units_consumed: m.compute_units_consumed,
        cost_units: m.cost_units,
    })
}

/// Parse a protobuf `Rewards` message.
pub fn parse_rewards(bytes: &[u8]) -> Result<BlockRewards, String> {
    let mut rs = PbRewards::default();
    parse_rewards_msg(&mut rs, &mut Reader::new(bytes), 0)?;
    Ok(BlockRewards { rewards: rs.rewards.into_iter().map(convert_reward).collect(), num_partitions: rs.num_partitions })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_and_unpacked_balances_mix() {
        // field 3 packed [50000, 1], then field 3 unpacked 7
        let bytes = [0x1a, 0x04, 0xd0, 0x86, 0x03, 0x01, 0x18, 0x07, 0x10, 0x88, 0x27];
        let meta = parse_transaction_status_meta(&bytes).unwrap().unwrap();
        assert_eq!(meta.pre_balances, vec![50000, 1, 7]);
        assert_eq!(meta.fee, 5000);
        assert_eq!(meta.rewards, Some(vec![]));
        assert_eq!(meta.inner_instructions, Some(vec![]));
    }

    #[test]
    fn wrong_wire_type_and_truncation_fail() {
        assert!(parse_transaction_status_meta(&[0x11, 0, 0, 0, 0, 0, 0, 0, 0]).is_err()); // fee as I64
        assert!(parse_transaction_status_meta(&[0x32, 0x05, b'a']).is_err());
        assert!(parse_transaction_status_meta(&[0x32, 0x01, 0xff]).is_err()); // invalid UTF-8
        assert!(parse_transaction_status_meta(&[0x00]).is_err()); // field 0
        // unknown fields of every wire type are skipped, including groups
        let ok = [0xf8, 0x01, 0x05, 0xfa, 0x01, 0x01, 0x00, 0xfd, 0x01, 1, 2, 3, 4, 0xfb, 0x01, 0x08, 0x01, 0xfc, 0x01];
        assert!(parse_transaction_status_meta(&ok).is_ok());
    }

    #[test]
    fn rewards_and_commission() {
        // Reward { pubkey "a", lamports -5, reward_type 4, commission "+7" }, num_partitions {4}
        let reward = [0x0a, 0x01, b'a', 0x10, 0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x20, 0x04, 0x2a, 0x02, b'+', b'7'];
        let mut bytes = vec![0x0a, reward.len() as u8];
        bytes.extend(reward);
        bytes.extend([0x12, 0x02, 0x08, 0x04]);
        let r = parse_rewards(&bytes).unwrap();
        assert_eq!(r.num_partitions, Some(4));
        assert_eq!(r.rewards[0].lamports, -5);
        assert_eq!(r.rewards[0].reward_type, Some(4));
        assert_eq!(r.rewards[0].commission, Some(7));
        // commission_bps fallback
        let rw = PbReward { commission_bps: "750".into(), ..Default::default() };
        assert_eq!(convert_reward(rw).commission, Some(7));
        let rw = PbReward { commission_bps: "30000".into(), ..Default::default() };
        assert_eq!(convert_reward(rw).commission, None);
        assert_eq!(parse_rewards(&[]).unwrap(), BlockRewards::default());
    }
}
