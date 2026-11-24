//! Decoders for Solana `TransactionStatusMeta` and `Rewards` stored inside Old Faithful CAR
//! `DataFrame` payloads.
//!
//! Handles the historical format split at Epoch 157 (slot `67_824_000`):
//! - Slots `< 67_824_000` (Epoch `< 157`): bincode-encoded `StoredTransactionStatusMeta` and
//!   `StoredExtendedRewards` (with fallback to protobuf if an archive slot uses protobuf).
//! - Slots `>= 67_824_000` (Epoch `>= 157`): zstd-compressed protobuf `TransactionStatusMeta` and
//!   `Rewards` (with fallback to bincode if needed).
//!
//! Pure-Rust `prost` definitions avoid C++ `protoc` build dependencies while maintaining exact
//! wire parity with `solana.storage.ConfirmedBlock`.

use std::io::Read;
use std::str::FromStr;

use bincode::Options as _;
use prost::Message;
use serde::{Deserialize, Serialize};
use solana_account_decoder_client_types::token::UiTokenAmount;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::v0::LoadedAddresses;
use solana_pubkey::Pubkey;
use solana_reward_info::RewardType;
use solana_serde::default_on_eof;
use solana_transaction_context::TransactionReturnData;
use solana_transaction_error::{TransactionError, TransactionResult};
use solana_transaction_status::{
    InnerInstruction, InnerInstructions, Reward, Rewards, TransactionStatusMeta,
    TransactionTokenBalance,
};
use thiserror::Error;

use crate::old_faithful::SLOTS_PER_EPOCH;

/// First epoch where Old Faithful stores transaction metadata and rewards in protobuf format.
pub const BINCODE_EPOCH_CUTOFF: u64 = 157;

/// First slot of Epoch 157 (`157 * 432_000 = 67_824_000`).
pub const BINCODE_SLOT_CUTOFF: u64 = BINCODE_EPOCH_CUTOFF * SLOTS_PER_EPOCH;

/// Maximum uncompressed payload size accepted from a single zstd frame (512 MiB).
///
/// Safely accommodates ~55 MiB compressed epoch-boundary reward blocks while preventing
/// unbounded memory allocation from corrupted or malicious zstd decompression bombs.
pub const MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;

/// Errors returned while decoding Solana transaction status metadata or block rewards.
#[derive(Debug, Error)]
pub enum ProtoDecodeError {
    #[error("zstd decompression failed: {0}")]
    Zstd(String),

    #[error("failed to decode transaction status metadata for slot {slot}: {reason}")]
    TransactionMeta { slot: u64, reason: String },

    #[error("failed to decode rewards for slot {slot}: {reason}")]
    Rewards { slot: u64, reason: String },

    #[error("invalid pubkey bytes (expected 32 bytes, got {actual_len})")]
    InvalidPubkeyLength { actual_len: usize },

    #[error("failed to deserialize bincode TransactionError: {0}")]
    TransactionErrorBincode(String),
}

/// Decoded block rewards plus optional partitioned-rewards count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecodedRewards {
    pub rewards: Rewards,
    pub num_partitions: Option<u64>,
}

// ---------------------------------------------------------------------------
// Protobuf wire structs (`solana.storage.ConfirmedBlock`)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoTransactionStatusMeta {
    #[prost(message, optional, tag = "1")]
    pub err: Option<ProtoTransactionError>,
    #[prost(uint64, tag = "2")]
    pub fee: u64,
    #[prost(uint64, repeated, tag = "3")]
    pub pre_balances: Vec<u64>,
    #[prost(uint64, repeated, tag = "4")]
    pub post_balances: Vec<u64>,
    #[prost(message, repeated, tag = "5")]
    pub inner_instructions: Vec<ProtoInnerInstructions>,
    #[prost(bool, tag = "10")]
    pub inner_instructions_none: bool,
    #[prost(string, repeated, tag = "6")]
    pub log_messages: Vec<String>,
    #[prost(bool, tag = "11")]
    pub log_messages_none: bool,
    #[prost(message, repeated, tag = "7")]
    pub pre_token_balances: Vec<ProtoTokenBalance>,
    #[prost(message, repeated, tag = "8")]
    pub post_token_balances: Vec<ProtoTokenBalance>,
    #[prost(message, repeated, tag = "9")]
    pub rewards: Vec<ProtoReward>,
    #[prost(bytes = "vec", repeated, tag = "12")]
    pub loaded_writable_addresses: Vec<Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "13")]
    pub loaded_readonly_addresses: Vec<Vec<u8>>,
    #[prost(message, optional, tag = "14")]
    pub return_data: Option<ProtoReturnData>,
    #[prost(bool, tag = "15")]
    pub return_data_none: bool,
    #[prost(uint64, optional, tag = "16")]
    pub compute_units_consumed: Option<u64>,
    #[prost(uint64, optional, tag = "17")]
    pub cost_units: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoTransactionError {
    #[prost(bytes = "vec", tag = "1")]
    pub err: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoInnerInstructions {
    #[prost(uint32, tag = "1")]
    pub index: u32,
    #[prost(message, repeated, tag = "2")]
    pub instructions: Vec<ProtoInnerInstruction>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoInnerInstruction {
    #[prost(uint32, tag = "1")]
    pub program_id_index: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub accounts: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub data: Vec<u8>,
    #[prost(uint32, optional, tag = "4")]
    pub stack_height: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoTokenBalance {
    #[prost(uint32, tag = "1")]
    pub account_index: u32,
    #[prost(string, tag = "2")]
    pub mint: String,
    #[prost(message, optional, tag = "3")]
    pub ui_token_amount: Option<ProtoUiTokenAmount>,
    #[prost(string, tag = "4")]
    pub owner: String,
    #[prost(string, tag = "5")]
    pub program_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoUiTokenAmount {
    #[prost(double, tag = "1")]
    pub ui_amount: f64,
    #[prost(uint32, tag = "2")]
    pub decimals: u32,
    #[prost(string, tag = "3")]
    pub amount: String,
    #[prost(string, tag = "4")]
    pub ui_amount_string: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoReturnData {
    #[prost(bytes = "vec", tag = "1")]
    pub program_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoReward {
    #[prost(string, tag = "1")]
    pub pubkey: String,
    #[prost(int64, tag = "2")]
    pub lamports: i64,
    #[prost(uint64, tag = "3")]
    pub post_balance: u64,
    #[prost(int32, tag = "4")]
    pub reward_type: i32,
    #[prost(string, tag = "5")]
    pub commission: String,
    /// Optional basis-point commission introduced in Agave 4.x (SIMD-0291).
    #[prost(string, tag = "6")]
    pub commission_bps: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoRewards {
    #[prost(message, repeated, tag = "1")]
    pub rewards: Vec<ProtoReward>,
    #[prost(message, optional, tag = "2")]
    pub num_partitions: Option<ProtoNumPartitions>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtoNumPartitions {
    #[prost(uint64, tag = "1")]
    pub num_partitions: u64,
}

// ---------------------------------------------------------------------------
// Pre-Epoch 157 bincode wire structs (`solana-storage-proto`)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub(crate) struct StoredExtendedReward {
    pub pubkey: String,
    pub lamports: i64,
    #[serde(deserialize_with = "default_on_eof")]
    pub post_balance: u64,
    #[serde(deserialize_with = "default_on_eof")]
    pub reward_type: Option<RewardType>,
    #[serde(deserialize_with = "default_on_eof")]
    pub commission: Option<u8>,
}

pub(crate) type StoredExtendedRewards = Vec<StoredExtendedReward>;

impl From<StoredExtendedReward> for Reward {
    fn from(value: StoredExtendedReward) -> Self {
        Self {
            pubkey: value.pubkey,
            lamports: value.lamports,
            post_balance: value.post_balance,
            reward_type: value.reward_type,
            commission: value.commission,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StoredTokenAmount {
    pub ui_amount: f64,
    pub decimals: u8,
    pub amount: String,
}

impl From<StoredTokenAmount> for UiTokenAmount {
    fn from(value: StoredTokenAmount) -> Self {
        let ui_amount_string =
            real_number_string_trimmed(u64::from_str(&value.amount).unwrap_or(0), value.decimals);
        Self {
            ui_amount: Some(value.ui_amount),
            decimals: value.decimals,
            amount: value.amount,
            ui_amount_string,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StoredTransactionTokenBalance {
    pub account_index: u8,
    pub mint: String,
    pub ui_token_amount: StoredTokenAmount,
    #[serde(deserialize_with = "default_on_eof")]
    pub owner: String,
    #[serde(deserialize_with = "default_on_eof")]
    pub program_id: String,
}

impl From<StoredTransactionTokenBalance> for TransactionTokenBalance {
    fn from(value: StoredTransactionTokenBalance) -> Self {
        Self {
            account_index: value.account_index,
            mint: value.mint,
            ui_token_amount: value.ui_token_amount.into(),
            owner: value.owner,
            program_id: value.program_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StoredTransactionStatusMeta {
    pub status: TransactionResult<()>,
    pub fee: u64,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    #[serde(deserialize_with = "default_on_eof")]
    pub inner_instructions: Option<Vec<InnerInstructions>>,
    #[serde(deserialize_with = "default_on_eof")]
    pub log_messages: Option<Vec<String>>,
    #[serde(deserialize_with = "default_on_eof")]
    pub pre_token_balances: Option<Vec<StoredTransactionTokenBalance>>,
    #[serde(deserialize_with = "default_on_eof")]
    pub post_token_balances: Option<Vec<StoredTransactionTokenBalance>>,
    #[serde(deserialize_with = "default_on_eof")]
    pub rewards: Option<Vec<StoredExtendedReward>>,
    #[serde(deserialize_with = "default_on_eof")]
    pub return_data: Option<TransactionReturnData>,
    #[serde(deserialize_with = "default_on_eof")]
    pub compute_units_consumed: Option<u64>,
    #[serde(deserialize_with = "default_on_eof")]
    pub cost_units: Option<u64>,
}

impl From<StoredTransactionStatusMeta> for TransactionStatusMeta {
    fn from(value: StoredTransactionStatusMeta) -> Self {
        Self {
            status: value.status,
            fee: value.fee,
            pre_balances: value.pre_balances,
            post_balances: value.post_balances,
            inner_instructions: value.inner_instructions,
            log_messages: value.log_messages,
            pre_token_balances: value
                .pre_token_balances
                .map(|balances| balances.into_iter().map(Into::into).collect()),
            post_token_balances: value
                .post_token_balances
                .map(|balances| balances.into_iter().map(Into::into).collect()),
            rewards: value
                .rewards
                .map(|rewards| rewards.into_iter().map(Into::into).collect()),
            loaded_addresses: LoadedAddresses::default(),
            return_data: value.return_data,
            compute_units_consumed: value.compute_units_consumed,
            cost_units: value.cost_units,
        }
    }
}

// ---------------------------------------------------------------------------
// Conversions from protobuf structs to `solana-transaction-status` types
// ---------------------------------------------------------------------------

fn pubkey_from_vec(bytes: Vec<u8>) -> Result<Pubkey, ProtoDecodeError> {
    let actual_len = bytes.len();
    Pubkey::try_from(bytes).map_err(|_| ProtoDecodeError::InvalidPubkeyLength { actual_len })
}

impl From<ProtoReward> for Reward {
    fn from(reward: ProtoReward) -> Self {
        let commission = reward.commission.parse::<u8>().ok().or_else(|| {
            reward
                .commission_bps
                .parse::<u16>()
                .ok()
                .and_then(|bps| u8::try_from(bps / 100).ok())
        });
        Self {
            pubkey: reward.pubkey,
            lamports: reward.lamports,
            post_balance: reward.post_balance,
            reward_type: match reward.reward_type {
                1 => Some(RewardType::Fee),
                2 => Some(RewardType::Rent),
                3 => Some(RewardType::Staking),
                4 => Some(RewardType::Voting),
                _ => None,
            },
            commission,
        }
    }
}

impl From<ProtoInnerInstruction> for InnerInstruction {
    fn from(value: ProtoInnerInstruction) -> Self {
        Self {
            instruction: CompiledInstruction {
                program_id_index: value.program_id_index as u8,
                accounts: value.accounts,
                data: value.data,
            },
            stack_height: value.stack_height,
        }
    }
}

impl From<ProtoInnerInstructions> for InnerInstructions {
    fn from(value: ProtoInnerInstructions) -> Self {
        Self {
            index: value.index as u8,
            instructions: value.instructions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<ProtoTokenBalance> for TransactionTokenBalance {
    fn from(value: ProtoTokenBalance) -> Self {
        let ui_token_amount = value.ui_token_amount.unwrap_or_default();
        let decimals = ui_token_amount.decimals as u8;
        let ui_amount_string = if !ui_token_amount.ui_amount_string.is_empty() {
            ui_token_amount.ui_amount_string
        } else {
            real_number_string_trimmed(
                u64::from_str(&ui_token_amount.amount).unwrap_or(0),
                decimals,
            )
        };
        Self {
            account_index: value.account_index as u8,
            mint: value.mint,
            ui_token_amount: UiTokenAmount {
                ui_amount: if (ui_token_amount.ui_amount - f64::default()).abs() > f64::EPSILON {
                    Some(ui_token_amount.ui_amount)
                } else {
                    None
                },
                decimals,
                amount: ui_token_amount.amount,
                ui_amount_string,
            },
            owner: value.owner,
            program_id: value.program_id,
        }
    }
}

impl TryFrom<ProtoReturnData> for TransactionReturnData {
    type Error = ProtoDecodeError;

    fn try_from(value: ProtoReturnData) -> Result<Self, Self::Error> {
        Ok(Self {
            program_id: pubkey_from_vec(value.program_id)?,
            data: value.data,
        })
    }
}

impl TryFrom<ProtoTransactionStatusMeta> for TransactionStatusMeta {
    type Error = ProtoDecodeError;

    fn try_from(value: ProtoTransactionStatusMeta) -> Result<Self, Self::Error> {
        let status = match value.err {
            None => Ok(()),
            Some(tx_err) => {
                let err: TransactionError = bincode::deserialize(&tx_err.err)
                    .map_err(|e| ProtoDecodeError::TransactionErrorBincode(e.to_string()))?;
                Err(err)
            }
        };

        let inner_instructions = if value.inner_instructions_none {
            None
        } else {
            Some(
                value
                    .inner_instructions
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
        };

        let log_messages = if value.log_messages_none {
            None
        } else {
            Some(value.log_messages)
        };

        let pre_token_balances = Some(
            value
                .pre_token_balances
                .into_iter()
                .map(Into::into)
                .collect(),
        );
        let post_token_balances = Some(
            value
                .post_token_balances
                .into_iter()
                .map(Into::into)
                .collect(),
        );
        let rewards = Some(value.rewards.into_iter().map(Into::into).collect());

        let loaded_addresses = LoadedAddresses {
            writable: value
                .loaded_writable_addresses
                .into_iter()
                .map(pubkey_from_vec)
                .collect::<Result<Vec<_>, _>>()?,
            readonly: value
                .loaded_readonly_addresses
                .into_iter()
                .map(pubkey_from_vec)
                .collect::<Result<Vec<_>, _>>()?,
        };

        let return_data = if value.return_data_none {
            None
        } else {
            value
                .return_data
                .map(TransactionReturnData::try_from)
                .transpose()?
        };

        Ok(Self {
            status,
            fee: value.fee,
            pre_balances: value.pre_balances,
            post_balances: value.post_balances,
            inner_instructions,
            log_messages,
            pre_token_balances,
            post_token_balances,
            rewards,
            loaded_addresses,
            return_data,
            compute_units_consumed: value.compute_units_consumed,
            cost_units: value.cost_units,
        })
    }
}

/// Format an integer token amount with `decimals` decimal places, trimming trailing zeros
/// (matches `solana_account_decoder::parse_token::real_number_string_trimmed` and safely
/// handles all `decimals: u8` values `0..=255` without `10u64.pow` overflow).
pub(crate) fn real_number_string_trimmed(amount: u64, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let digits = amount.to_string();
    let dec = usize::from(decimals);
    let mut s = if digits.len() <= dec {
        format!("0.{:0>width$}", digits, width = dec)
    } else {
        let split = digits.len() - dec;
        format!("{}.{}", &digits[..split], &digits[split..])
    };
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    s.truncate(trimmed.len());
    s
}

// ---------------------------------------------------------------------------
// Public entry points (zstd + Epoch 157 split)
// ---------------------------------------------------------------------------

/// Decompress a zstd-compressed slice into a `Vec<u8>`, enforcing [`MAX_DECOMPRESSED_BYTES`].
pub fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, ProtoDecodeError> {
    decompress_zstd_with_limit(data, MAX_DECOMPRESSED_BYTES)
}

/// Decompress a zstd-compressed slice with an explicit maximum output byte cap.
pub(crate) fn decompress_zstd_with_limit(
    data: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, ProtoDecodeError> {
    let decoder = zstd::Decoder::new(data).map_err(|e| ProtoDecodeError::Zstd(e.to_string()))?;
    let mut limited = decoder.take((max_bytes as u64).saturating_add(1));
    let mut out = Vec::new();
    limited
        .read_to_end(&mut out)
        .map_err(|e| ProtoDecodeError::Zstd(e.to_string()))?;
    if out.len() > max_bytes {
        return Err(ProtoDecodeError::Zstd(format!(
            "decompressed payload exceeds maximum allowed size ({max_bytes} bytes)"
        )));
    }
    Ok(out)
}

/// Returns `true` if the byte slice begins with the standard zstd frame magic (`0xFD2FB528` LE).
#[inline]
fn has_zstd_magic(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0x28, 0xB5, 0x2F, 0xFD]
}

/// Decode a reassembled transaction metadata `DataFrame` payload (possibly zstd-compressed).
///
/// Returns `Ok(None)` when `frame_bytes` is empty (very early genesis slots without metadata).
pub fn decode_transaction_status_meta_frame(
    slot: u64,
    frame_bytes: &[u8],
) -> Result<Option<TransactionStatusMeta>, ProtoDecodeError> {
    if frame_bytes.is_empty() {
        return Ok(None);
    }

    if has_zstd_magic(frame_bytes) {
        match decompress_zstd(frame_bytes) {
            Ok(decompressed) => {
                return decode_transaction_status_meta_bytes(slot, &decompressed).map(Some);
            }
            Err(zstd_err) => {
                // Fall back to raw decode in case non-zstd bytes happened to start with magic.
                return decode_transaction_status_meta_bytes(slot, frame_bytes)
                    .map(Some)
                    .map_err(|raw_err| ProtoDecodeError::TransactionMeta {
                        slot,
                        reason: format!("zstd failed ({zstd_err}); raw decode failed ({raw_err})"),
                    });
            }
        }
    }

    // Not starting with zstd magic: try raw first, then zstd as last resort.
    match decode_transaction_status_meta_bytes(slot, frame_bytes) {
        Ok(meta) => Ok(Some(meta)),
        Err(raw_err) => match decompress_zstd(frame_bytes) {
            Ok(decompressed) => decode_transaction_status_meta_bytes(slot, &decompressed).map(Some),
            Err(_) => Err(raw_err),
        },
    }
}

/// Pre-Solana v1.14.6 `InnerInstructions` bincode layout (before `stack_height: Option<u32>`
/// was added to `InnerInstruction`).
#[derive(Deserialize)]
struct LegacyInnerInstructions {
    index: u8,
    instructions: Vec<CompiledInstruction>,
}

impl From<LegacyInnerInstructions> for InnerInstructions {
    fn from(value: LegacyInnerInstructions) -> Self {
        Self {
            index: value.index,
            instructions: value
                .instructions
                .into_iter()
                .map(|instruction| InnerInstruction {
                    instruction,
                    stack_height: None,
                })
                .collect(),
        }
    }
}

/// Pre-Solana v1.6 token balance bincode layout (no `owner` or `program_id` fields).
#[derive(Deserialize)]
struct LegacyTokenBalanceV1 {
    account_index: u8,
    mint: String,
    ui_token_amount: StoredTokenAmount,
}

impl From<LegacyTokenBalanceV1> for TransactionTokenBalance {
    fn from(value: LegacyTokenBalanceV1) -> Self {
        Self {
            account_index: value.account_index,
            mint: value.mint,
            ui_token_amount: value.ui_token_amount.into(),
            owner: String::new(),
            program_id: String::new(),
        }
    }
}

/// Solana v1.6–v1.9 token balance bincode layout (`owner` present, no `program_id`).
#[derive(Deserialize)]
struct LegacyTokenBalanceV2 {
    account_index: u8,
    mint: String,
    ui_token_amount: StoredTokenAmount,
    owner: String,
}

impl From<LegacyTokenBalanceV2> for TransactionTokenBalance {
    fn from(value: LegacyTokenBalanceV2) -> Self {
        Self {
            account_index: value.account_index,
            mint: value.mint,
            ui_token_amount: value.ui_token_amount.into(),
            owner: value.owner,
            program_id: String::new(),
        }
    }
}

/// Parameterized legacy `StoredTransactionStatusMeta` for historical bincode formats
/// written before Solana v1.14.6 (where `InnerInstruction` had no `stack_height` field, and
/// earlier token balances omitted `owner` and/or `program_id`).
#[derive(Deserialize)]
#[serde(bound(deserialize = "TB: Deserialize<'de>"))]
struct LegacyStoredTransactionStatusMeta<TB> {
    status: TransactionResult<()>,
    fee: u64,
    pre_balances: Vec<u64>,
    post_balances: Vec<u64>,
    #[serde(deserialize_with = "default_on_eof")]
    inner_instructions: Option<Vec<LegacyInnerInstructions>>,
    #[serde(deserialize_with = "default_on_eof")]
    log_messages: Option<Vec<String>>,
    #[serde(deserialize_with = "default_on_eof")]
    pre_token_balances: Option<Vec<TB>>,
    #[serde(deserialize_with = "default_on_eof")]
    post_token_balances: Option<Vec<TB>>,
    #[serde(deserialize_with = "default_on_eof")]
    rewards: Option<Vec<StoredExtendedReward>>,
    #[serde(deserialize_with = "default_on_eof")]
    return_data: Option<TransactionReturnData>,
    #[serde(deserialize_with = "default_on_eof")]
    compute_units_consumed: Option<u64>,
    #[serde(deserialize_with = "default_on_eof")]
    cost_units: Option<u64>,
}

impl<TB: Into<TransactionTokenBalance>> From<LegacyStoredTransactionStatusMeta<TB>>
    for TransactionStatusMeta
{
    fn from(value: LegacyStoredTransactionStatusMeta<TB>) -> Self {
        Self {
            status: value.status,
            fee: value.fee,
            pre_balances: value.pre_balances,
            post_balances: value.post_balances,
            inner_instructions: value
                .inner_instructions
                .map(|ixs| ixs.into_iter().map(Into::into).collect()),
            log_messages: value.log_messages,
            pre_token_balances: value
                .pre_token_balances
                .map(|balances| balances.into_iter().map(Into::into).collect()),
            post_token_balances: value
                .post_token_balances
                .map(|balances| balances.into_iter().map(Into::into).collect()),
            rewards: value
                .rewards
                .map(|rewards| rewards.into_iter().map(Into::into).collect()),
            loaded_addresses: LoadedAddresses::default(),
            return_data: value.return_data,
            compute_units_consumed: value.compute_units_consumed,
            cost_units: value.cost_units,
        }
    }
}

/// Try decoding bincode `TransactionStatusMeta` across all historical Solana bincode layouts,
/// requiring exact buffer consumption (`reject_trailing_bytes`) so an older layout cannot
/// accidentally truncate newer fields.
fn deserialize_bincode_meta(bytes: &[u8]) -> Result<TransactionStatusMeta, String> {
    let strict = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes();

    if let Ok(m) = strict.deserialize::<StoredTransactionStatusMeta>(bytes) {
        return Ok(m.into());
    }
    if let Ok(m) =
        strict.deserialize::<LegacyStoredTransactionStatusMeta<LegacyTokenBalanceV1>>(bytes)
    {
        return Ok(m.into());
    }
    if let Ok(m) =
        strict.deserialize::<LegacyStoredTransactionStatusMeta<LegacyTokenBalanceV2>>(bytes)
    {
        return Ok(m.into());
    }
    if let Ok(m) = strict
        .deserialize::<LegacyStoredTransactionStatusMeta<StoredTransactionTokenBalance>>(bytes)
    {
        return Ok(m.into());
    }

    // Final attempt with default bincode options to return the most informative error.
    bincode::deserialize::<StoredTransactionStatusMeta>(bytes)
        .map(Into::into)
        .map_err(|e| e.to_string())
}

/// Decode uncompressed `TransactionStatusMeta` bytes respecting the Epoch 157 bincode/protobuf split.
pub fn decode_transaction_status_meta_bytes(
    slot: u64,
    bytes: &[u8],
) -> Result<TransactionStatusMeta, ProtoDecodeError> {
    if slot < BINCODE_SLOT_CUTOFF {
        match deserialize_bincode_meta(bytes) {
            Ok(meta) => return Ok(meta),
            Err(bin_err) => {
                // Fallback to protobuf if a pre-157 archive slot was stored in protobuf.
                return ProtoTransactionStatusMeta::decode(bytes)
                    .map_err(|proto_err| ProtoDecodeError::TransactionMeta {
                        slot,
                        reason: format!(
                            "bincode failed ({bin_err}); protobuf failed ({proto_err})"
                        ),
                    })?
                    .try_into();
            }
        }
    }

    match ProtoTransactionStatusMeta::decode(bytes) {
        Ok(proto) => proto.try_into(),
        Err(proto_err) => {
            // Fallback to bincode just in case.
            deserialize_bincode_meta(bytes).map_err(|bin_err| ProtoDecodeError::TransactionMeta {
                slot,
                reason: format!("protobuf failed ({proto_err}); bincode failed ({bin_err})"),
            })
        }
    }
}

/// Decode a reassembled `Rewards` `DataFrame` payload (possibly zstd-compressed).
pub fn decode_rewards_frame(
    slot: u64,
    frame_bytes: &[u8],
) -> Result<DecodedRewards, ProtoDecodeError> {
    if frame_bytes.is_empty() {
        return Ok(DecodedRewards::default());
    }

    if has_zstd_magic(frame_bytes) {
        match decompress_zstd(frame_bytes) {
            Ok(decompressed) => return decode_rewards_bytes(slot, &decompressed),
            Err(zstd_err) => {
                return decode_rewards_bytes(slot, frame_bytes).map_err(|raw_err| {
                    ProtoDecodeError::Rewards {
                        slot,
                        reason: format!("zstd failed ({zstd_err}); raw decode failed ({raw_err})"),
                    }
                });
            }
        }
    }

    match decode_rewards_bytes(slot, frame_bytes) {
        Ok(rewards) => Ok(rewards),
        Err(raw_err) => match decompress_zstd(frame_bytes) {
            Ok(decompressed) => decode_rewards_bytes(slot, &decompressed),
            Err(_) => Err(raw_err),
        },
    }
}

/// Pre-Solana v1.5 reward bincode layout (before `commission: Option<u8>` was added).
#[derive(Deserialize)]
struct LegacyStoredRewardNoCommission {
    pubkey: String,
    lamports: i64,
    post_balance: u64,
    reward_type: Option<RewardType>,
}

impl From<LegacyStoredRewardNoCommission> for Reward {
    fn from(value: LegacyStoredRewardNoCommission) -> Self {
        Self {
            pubkey: value.pubkey,
            lamports: value.lamports,
            post_balance: value.post_balance,
            reward_type: value.reward_type,
            commission: None,
        }
    }
}

fn deserialize_bincode_rewards(bytes: &[u8]) -> Result<DecodedRewards, String> {
    let strict = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes();

    if let Ok(stored) = strict.deserialize::<StoredExtendedRewards>(bytes) {
        return Ok(DecodedRewards {
            rewards: stored.into_iter().map(Into::into).collect(),
            num_partitions: None,
        });
    }
    if let Ok(stored) = strict.deserialize::<Vec<LegacyStoredRewardNoCommission>>(bytes) {
        return Ok(DecodedRewards {
            rewards: stored.into_iter().map(Into::into).collect(),
            num_partitions: None,
        });
    }

    bincode::deserialize::<StoredExtendedRewards>(bytes)
        .map(|stored| DecodedRewards {
            rewards: stored.into_iter().map(Into::into).collect(),
            num_partitions: None,
        })
        .map_err(|e| e.to_string())
}

/// Decode uncompressed `Rewards` bytes respecting the Epoch 157 bincode/protobuf split.
pub fn decode_rewards_bytes(slot: u64, bytes: &[u8]) -> Result<DecodedRewards, ProtoDecodeError> {
    if slot < BINCODE_SLOT_CUTOFF {
        match deserialize_bincode_rewards(bytes) {
            Ok(decoded) => return Ok(decoded),
            Err(bin_err) => {
                let proto =
                    ProtoRewards::decode(bytes).map_err(|proto_err| ProtoDecodeError::Rewards {
                        slot,
                        reason: format!(
                            "bincode failed ({bin_err}); protobuf failed ({proto_err})"
                        ),
                    })?;
                return Ok(DecodedRewards {
                    rewards: proto.rewards.into_iter().map(Into::into).collect(),
                    num_partitions: proto.num_partitions.map(|p| p.num_partitions),
                });
            }
        }
    }

    match ProtoRewards::decode(bytes) {
        Ok(proto) => Ok(DecodedRewards {
            rewards: proto.rewards.into_iter().map(Into::into).collect(),
            num_partitions: proto.num_partitions.map(|p| p.num_partitions),
        }),
        Err(proto_err) => {
            deserialize_bincode_rewards(bytes).map_err(|bin_err| ProtoDecodeError::Rewards {
                slot,
                reason: format!("protobuf failed ({proto_err}); bincode failed ({bin_err})"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zstd_compress(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(data, 1).expect("zstd compress")
    }

    #[test]
    fn decodes_pre_epoch_157_bincode_meta_raw_and_zstd() {
        let stored = StoredTransactionStatusMeta {
            status: Ok(()),
            fee: 5_000,
            pre_balances: vec![100_000, 200_000],
            post_balances: vec![95_000, 200_000],
            inner_instructions: None,
            log_messages: Some(vec!["Program log: ok".to_string()]),
            pre_token_balances: Some(vec![]),
            post_token_balances: Some(vec![]),
            rewards: Some(vec![]),
            return_data: None,
            compute_units_consumed: Some(1_234),
            cost_units: None,
        };
        let raw = bincode::serialize(&stored).expect("bincode serialize");
        let compressed = zstd_compress(&raw);

        let decoded_raw = decode_transaction_status_meta_frame(43_200_000, &raw)
            .expect("decode raw")
            .expect("some meta");
        assert_eq!(decoded_raw.fee, 5_000);
        assert_eq!(decoded_raw.compute_units_consumed, Some(1_234));

        let decoded_zstd = decode_transaction_status_meta_frame(43_200_000, &compressed)
            .expect("decode zstd")
            .expect("some meta");
        assert_eq!(decoded_zstd, decoded_raw);
    }

    #[test]
    fn decodes_modern_protobuf_meta_zstd() {
        let proto = ProtoTransactionStatusMeta {
            err: None,
            fee: 10_000,
            pre_balances: vec![50_000, 10_000],
            post_balances: vec![40_000, 10_000],
            inner_instructions: vec![],
            inner_instructions_none: false,
            log_messages: vec!["hello".to_string()],
            log_messages_none: false,
            pre_token_balances: vec![],
            post_token_balances: vec![],
            rewards: vec![],
            loaded_writable_addresses: vec![],
            loaded_readonly_addresses: vec![],
            return_data: None,
            return_data_none: true,
            compute_units_consumed: Some(450),
            cost_units: Some(900),
        };
        let encoded = proto.encode_to_vec();
        let compressed = zstd_compress(&encoded);

        let decoded = decode_transaction_status_meta_frame(302_400_001, &compressed)
            .expect("decode proto")
            .expect("some meta");
        assert_eq!(decoded.fee, 10_000);
        assert_eq!(decoded.log_messages, Some(vec!["hello".to_string()]));
        assert_eq!(decoded.compute_units_consumed, Some(450));
        assert_eq!(decoded.cost_units, Some(900));
    }

    #[test]
    fn decodes_pre_epoch_157_bincode_rewards_and_modern_protobuf_rewards() {
        let bincode_rewards: StoredExtendedRewards = vec![StoredExtendedReward {
            pubkey: "11111111111111111111111111111111".to_string(),
            lamports: 42,
            post_balance: 1_042,
            reward_type: Some(RewardType::Fee),
            commission: None,
        }];
        let raw_bin = bincode::serialize(&bincode_rewards).expect("serialize");
        let decoded_bin =
            decode_rewards_frame(43_200_000, &zstd_compress(&raw_bin)).expect("decode bincode");
        assert_eq!(decoded_bin.rewards.len(), 1);
        assert_eq!(decoded_bin.rewards[0].lamports, 42);
        assert_eq!(decoded_bin.num_partitions, None);

        let proto_rewards = ProtoRewards {
            rewards: vec![ProtoReward {
                pubkey: "11111111111111111111111111111111".to_string(),
                lamports: 100,
                post_balance: 5_000,
                reward_type: 3, // Staking
                commission: "5".to_string(),
                commission_bps: String::new(),
            }],
            num_partitions: Some(ProtoNumPartitions { num_partitions: 4 }),
        };
        let raw_proto = proto_rewards.encode_to_vec();
        let decoded_proto =
            decode_rewards_frame(302_400_000, &zstd_compress(&raw_proto)).expect("decode proto");
        assert_eq!(decoded_proto.rewards.len(), 1);
        assert_eq!(
            decoded_proto.rewards[0].reward_type,
            Some(RewardType::Staking)
        );
        assert_eq!(decoded_proto.rewards[0].commission, Some(5));
        assert_eq!(decoded_proto.num_partitions, Some(4));
    }

    #[test]
    fn empty_frames_return_none_and_empty_rewards() {
        assert_eq!(
            decode_transaction_status_meta_frame(1, &[]).expect("empty meta"),
            None
        );
        let rewards = decode_rewards_frame(1, &[]).expect("empty rewards");
        assert!(rewards.rewards.is_empty());
        assert_eq!(rewards.num_partitions, None);
    }

    #[test]
    fn decodes_legacy_bincode_meta_without_stack_height_or_token_owner() {
        #[derive(Serialize)]
        struct OldInnerInstructions {
            index: u8,
            instructions: Vec<CompiledInstruction>,
        }
        #[derive(Serialize)]
        struct OldTokenBalance {
            account_index: u8,
            mint: String,
            ui_token_amount: StoredTokenAmount,
        }
        #[derive(Serialize)]
        struct OldMeta {
            status: TransactionResult<()>,
            fee: u64,
            pre_balances: Vec<u64>,
            post_balances: Vec<u64>,
            inner_instructions: Option<Vec<OldInnerInstructions>>,
            log_messages: Option<Vec<String>>,
            pre_token_balances: Option<Vec<OldTokenBalance>>,
            post_token_balances: Option<Vec<OldTokenBalance>>,
        }

        let old = OldMeta {
            status: Ok(()),
            fee: 5_000,
            pre_balances: vec![10_000],
            post_balances: vec![5_000],
            inner_instructions: Some(vec![OldInnerInstructions {
                index: 0,
                instructions: vec![CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: vec![42, 43],
                }],
            }]),
            log_messages: Some(vec!["legacy".to_string()]),
            pre_token_balances: Some(vec![OldTokenBalance {
                account_index: 0,
                mint: "So11111111111111111111111111111111111111112".to_string(),
                ui_token_amount: StoredTokenAmount {
                    ui_amount: 1.5,
                    decimals: 6,
                    amount: "1500000".to_string(),
                },
            }]),
            post_token_balances: Some(vec![]),
        };
        let bytes = bincode::serialize(&old).expect("serialize old meta");
        let decoded =
            decode_transaction_status_meta_bytes(43_200_000, &bytes).expect("decode legacy meta");
        assert_eq!(decoded.fee, 5_000);
        let ixs = decoded.inner_instructions.expect("inner ixs");
        assert_eq!(ixs.len(), 1);
        assert_eq!(ixs[0].instructions[0].stack_height, None);
        assert_eq!(ixs[0].instructions[0].instruction.data, vec![42, 43]);
        let pre_tb = decoded.pre_token_balances.expect("pre tb");
        assert_eq!(pre_tb.len(), 1);
        assert_eq!(pre_tb[0].ui_token_amount.ui_amount_string, "1.5");
    }

    #[test]
    fn real_number_string_trimmed_matches_solana_formatting() {
        assert_eq!(real_number_string_trimmed(1_000_000, 6), "1");
        assert_eq!(real_number_string_trimmed(1_250_000, 6), "1.25");
        assert_eq!(real_number_string_trimmed(5, 6), "0.000005");
        assert_eq!(real_number_string_trimmed(0, 6), "0");
        assert_eq!(real_number_string_trimmed(42, 0), "42");
        // Decimals >= 20 must not overflow u64::pow.
        assert_eq!(real_number_string_trimmed(1, 20), "0.00000000000000000001");
        assert_eq!(real_number_string_trimmed(0, 255), "0");
        assert_eq!(
            real_number_string_trimmed(u64::MAX, 20),
            "0.18446744073709551615"
        );
    }

    #[test]
    fn decompress_zstd_enforces_upper_bound() {
        let payload = vec![0x41u8; 4096];
        let compressed = zstd_compress(&payload);

        let ok = decompress_zstd_with_limit(&compressed, 4096).expect("exact limit ok");
        assert_eq!(ok.len(), 4096);

        let err = decompress_zstd_with_limit(&compressed, 1024).expect_err("over limit rejected");
        assert!(matches!(err, ProtoDecodeError::Zstd(_)));
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn proto_reward_commission_bps_rejects_out_of_range_values() {
        let valid: Reward = ProtoReward {
            pubkey: "11111111111111111111111111111111".to_string(),
            lamports: 10,
            post_balance: 20,
            reward_type: 3,
            commission: String::new(),
            commission_bps: "750".to_string(),
        }
        .into();
        assert_eq!(valid.commission, Some(7));

        let overflow: Reward = ProtoReward {
            pubkey: "11111111111111111111111111111111".to_string(),
            lamports: 10,
            post_balance: 20,
            reward_type: 3,
            commission: String::new(),
            commission_bps: "30000".to_string(),
        }
        .into();
        assert_eq!(overflow.commission, None);
    }
}
