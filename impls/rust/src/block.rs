//! From a CAR slice to an internal block (WIRE_FORMATS.md §7 and §9).

use crate::bail;
use crate::car::CarIndex;
use crate::error::{DResult, DecodeError};
use crate::ipld::{self, Block};
use crate::model::{BlockRewards, Meta};
use crate::tx::{parse_versioned_transaction, VersionedTransaction};
use crate::{bincode, proto, zstd};

/// First slot of epoch 157: older slots prefer bincode, newer prefer protobuf.
pub const BINCODE_SLOT_CUTOFF: u64 = 157 * 432_000;

pub enum TxWithMeta {
    Complete(VersionedTransaction, Meta),
    /// A legacy transaction whose metadata frame is empty.
    MissingMetadata(VersionedTransaction),
}

impl TxWithMeta {
    pub fn tx(&self) -> &VersionedTransaction {
        match self {
            TxWithMeta::Complete(tx, _) | TxWithMeta::MissingMetadata(tx) => tx,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DecodeOptions {
    pub transactions: bool,
    pub metadata: bool,
    pub rewards: bool,
}

/// Parse the slice's `Block` node, check its slot when one is expected, and compute its
/// blockhash (the hash of the last entry, or 32 zero bytes without entries).
pub fn block_header(index: &CarIndex<'_>, expected_slot: Option<u64>) -> DResult<(Block, [u8; 32])> {
    let Some(node) = index.block else {
        bail!("no Block node in CAR slice for slot {}", expected_slot.unwrap_or(0));
    };
    let block = ipld::parse_block(node)?;
    if let Some(slot) = expected_slot {
        if block.slot != slot {
            bail!("slot mismatch: requested {slot}, CAR Block node has {}", block.slot);
        }
    }
    let hash = match block.entries.last() {
        None => [0u8; 32],
        Some(cid) => {
            let Some(entry) = index.get(cid) else { bail!("missing Entry CID") };
            ipld::parse_entry(entry)?.hash
        }
    };
    Ok((block, hash))
}

/// Decode every transaction in entry order. With `keep_raw`, the reassembled wire bytes are
/// returned alongside (for the `base64`/`base58` encodings).
pub fn decode_transactions(
    slot: u64,
    index: &CarIndex<'_>,
    block: &Block,
    with_meta: bool,
    keep_raw: bool,
) -> DResult<(Vec<TxWithMeta>, Vec<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut raw = Vec::new();
    for entry_cid in &block.entries {
        let Some(node) = index.get(entry_cid) else { bail!("missing Entry CID") };
        let entry = ipld::parse_entry(node)?;
        out.reserve(entry.transactions.len());
        for tx_cid in &entry.transactions {
            let Some(node) = index.get(tx_cid) else { bail!("missing Transaction CID") };
            let tx_node = ipld::parse_transaction(node)?;
            let tx_bytes = ipld::reassemble(index, tx_node.data)?;
            let tx = parse_versioned_transaction(&tx_bytes)
                .map_err(|e| DecodeError(format!("failed to decode VersionedTransaction: {e}")))?;
            if keep_raw {
                raw.push(tx_bytes[..tx.wire_len].to_vec());
            }
            if !with_meta {
                out.push(TxWithMeta::MissingMetadata(tx));
                continue;
            }
            let meta_bytes = ipld::reassemble(index, tx_node.metadata)?;
            out.push(match decode_metadata_frame(slot, &meta_bytes)? {
                Some(meta) => TxWithMeta::Complete(tx, meta),
                None if tx.version.is_none() => TxWithMeta::MissingMetadata(tx),
                None => TxWithMeta::Complete(tx, Meta::default()),
            });
        }
    }
    Ok((out, raw))
}

pub fn decode_block_rewards(slot: u64, index: &CarIndex<'_>, block: &Block) -> DResult<BlockRewards> {
    let Some(cid) = &block.rewards else { return Ok(BlockRewards::default()) };
    let Some(node) = index.get(cid) else { return Ok(BlockRewards::default()) };
    let frame = ipld::parse_rewards(node)?;
    let bytes = ipld::reassemble(index, frame)?;
    decode_rewards_frame(slot, &bytes)
}

// ---------------------------------------------------------------------------------------
// §9: frame unwrapping and the epoch-157 split
// ---------------------------------------------------------------------------------------

fn decode_metadata_bytes(slot: u64, b: &[u8]) -> Result<Meta, String> {
    if slot < BINCODE_SLOT_CUTOFF {
        match bincode::transaction_status_meta(b) {
            Ok(m) => Ok(m),
            Err(bin_err) => match proto::parse_transaction_status_meta(b) {
                Ok(converted) => converted.map_err(|e| e.0),
                Err(pb_err) => Err(format!("bincode failed ({bin_err}); protobuf failed ({pb_err})")),
            },
        }
    } else {
        match proto::parse_transaction_status_meta(b) {
            Ok(converted) => converted.map_err(|e| e.0),
            Err(pb_err) => bincode::transaction_status_meta(b)
                .map_err(|bin_err| format!("protobuf failed ({pb_err}); bincode failed ({bin_err})")),
        }
    }
}

fn decode_rewards_bytes(slot: u64, b: &[u8]) -> Result<BlockRewards, String> {
    let from_bincode = |v: Vec<_>| BlockRewards { rewards: v, num_partitions: None };
    if slot < BINCODE_SLOT_CUTOFF {
        match bincode::rewards(b) {
            Ok(v) => Ok(from_bincode(v)),
            Err(bin_err) => proto::parse_rewards(b)
                .map_err(|pb_err| format!("bincode failed ({bin_err}); protobuf failed ({pb_err})")),
        }
    } else {
        match proto::parse_rewards(b) {
            Ok(r) => Ok(r),
            Err(pb_err) => bincode::rewards(b)
                .map(from_bincode)
                .map_err(|bin_err| format!("protobuf failed ({pb_err}); bincode failed ({bin_err})")),
        }
    }
}

/// Shared zstd-or-raw unwrapping (§9.1).
fn unwrap_frame<T>(frame: &[u8], decode: impl Fn(&[u8]) -> Result<T, String>) -> Result<T, String> {
    if zstd::has_magic(frame) {
        match zstd::decompress(frame) {
            Ok(plain) => decode(&plain),
            Err(z) => decode(frame).map_err(|raw| format!("{z}; raw decode failed ({raw})")),
        }
    } else {
        match decode(frame) {
            Ok(v) => Ok(v),
            Err(raw) => match zstd::decompress(frame) {
                Ok(plain) => decode(&plain),
                Err(_) => Err(raw),
            },
        }
    }
}

pub fn decode_metadata_frame(slot: u64, frame: &[u8]) -> DResult<Option<Meta>> {
    if frame.is_empty() {
        return Ok(None);
    }
    unwrap_frame(frame, |b| decode_metadata_bytes(slot, b))
        .map(Some)
        .map_err(|e| DecodeError(format!("transaction metadata for slot {slot}: {e}")))
}

pub fn decode_rewards_frame(slot: u64, frame: &[u8]) -> DResult<BlockRewards> {
    if frame.is_empty() {
        return Ok(BlockRewards::default());
    }
    unwrap_frame(frame, |b| decode_rewards_bytes(slot, b)).map_err(|e| DecodeError(format!("rewards for slot {slot}: {e}")))
}
