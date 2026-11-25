//! Zero-disk, low-allocation CARv1 / IPLD DAG-CBOR decoder for Old Faithful slot slices.
//!
//! - [`CarIndex`] parses a contiguous headerless CARv1 slot slice in-place without copying
//!   section payloads.
//! - [`decode_block_from_car`] decodes a full (or partial, per [`DecodeOptions`]) Solana
//!   [`ConfirmedBlock`], handling multi-frame `DataFrame` reassembly and the pre-Epoch 157
//!   bincode/protobuf split.
//! - [`extract_blockhash_from_car`] reads only the `Block` node and its last `Entry` hash so
//!   `previousBlockhash` resolution avoids decoding transactions or rewards.
//! - [`encode_block`] delegates to `solana-transaction-status` for
//!   full Solana JSON-RPC parity across all 4 encodings (`json`, `jsonParsed`, `base64`, `base58`).

use std::collections::{HashMap, HashSet};
use std::hash::Hasher;

use cid::Cid;
use crc::{Crc, CRC_64_GO_ISO};
use fnv::FnvHasher;
use serde_cbor::Value as CborValue;
use solana_hash::{Hash, HASH_BYTES};
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status::{
    BlockEncodingOptions, ConfirmedBlock, EncodeError, TransactionWithStatusMeta, UiConfirmedBlock,
    UiTransactionEncoding, VersionedTransactionWithStatusMeta,
};
use thiserror::Error;

use crate::proto::{
    decode_rewards_frame, decode_transaction_status_meta_frame, DecodedRewards, ProtoDecodeError,
};

/// Maximum single CARv1 section size allowed while parsing (32 MiB, matching Old Faithful).
pub const MAX_CAR_SECTION_SIZE: usize = 32 * 1024 * 1024;

const MAX_VARINT_LEN_64: usize = 10;

/// Old Faithful IPLD node kind discriminants (element 0 of each DAG-CBOR array).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum NodeKind {
    Transaction = 0,
    Entry = 1,
    Block = 2,
    Subset = 3,
    Epoch = 4,
    Rewards = 5,
    DataFrame = 6,
}

impl NodeKind {
    pub const fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Transaction),
            1 => Some(Self::Entry),
            2 => Some(Self::Block),
            3 => Some(Self::Subset),
            4 => Some(Self::Epoch),
            5 => Some(Self::Rewards),
            6 => Some(Self::DataFrame),
            _ => None,
        }
    }
}

/// Errors produced while parsing CARv1 sections, IPLD DAG-CBOR nodes, or Solana payloads.
#[derive(Debug, Error)]
pub enum DecoderError {
    #[error("invalid CARv1 uvarint: {0}")]
    InvalidVarint(&'static str),

    #[error("CARv1 section size {size} exceeds maximum {max}")]
    SectionTooLarge { size: u64, max: usize },

    #[error("unexpected EOF while reading CARv1 slice (needed {needed} bytes, {remaining} left)")]
    UnexpectedEof { needed: usize, remaining: usize },

    #[error("invalid CID in CARv1 section: {0}")]
    InvalidCid(String),

    #[error("invalid DAG-CBOR payload: {0}")]
    Cbor(String),

    #[error("invalid DAG-CBOR CID link")]
    InvalidCborLink,

    #[error("unexpected IPLD node kind: expected {expected}, got {actual}")]
    UnexpectedNodeKind {
        expected: &'static str,
        actual: String,
    },

    #[error("no Block node found in CAR slice for slot {slot}")]
    MissingBlockNode { slot: u64 },

    #[error("slot mismatch: requested slot {requested}, CAR Block node contains slot {actual}")]
    SlotMismatch { requested: u64, actual: u64 },

    #[error("missing referenced CID {cid} in slot CAR slice")]
    MissingCid { cid: String },

    #[error("cyclic DataFrame continuation detected at CID {cid}")]
    CyclicDataFrame { cid: String },

    #[error("DataFrame hash mismatch: expected {expected}, got crc64={crc64}, fnv={fnv}")]
    DataFrameHashMismatch { expected: u64, crc64: u64, fnv: u64 },

    #[error("invalid Entry hash length: expected {HASH_BYTES} bytes, got {actual}")]
    InvalidEntryHashLength { actual: usize },

    #[error("failed to deserialize Solana VersionedTransaction: {0}")]
    TransactionDeserialize(String),

    #[error(transparent)]
    Proto(#[from] ProtoDecodeError),
}

// ---------------------------------------------------------------------------
// IPLD DAG-CBOR node types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct IpldDataFrame {
    pub hash: Option<u64>,
    pub data: Vec<u8>,
    pub next: Option<Vec<Cid>>,
}

#[derive(Debug, Clone)]
pub(crate) struct IpldSlotMeta {
    pub parent_slot: u64,
    pub blocktime: Option<i64>,
    pub block_height: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct IpldBlock {
    pub slot: u64,
    pub entries: Vec<Cid>,
    pub meta: IpldSlotMeta,
    pub rewards: Option<Cid>,
}

#[derive(Debug, Clone)]
pub(crate) struct IpldEntry {
    pub hash: [u8; HASH_BYTES],
    pub transactions: Vec<Cid>,
}

#[derive(Debug, Clone)]
pub(crate) struct IpldTransaction {
    pub data: IpldDataFrame,
    pub metadata: IpldDataFrame,
}

#[derive(Debug, Clone)]
pub(crate) struct IpldRewards {
    pub data: IpldDataFrame,
}

fn cbor_as_u64(val: &CborValue) -> Option<u64> {
    match val {
        CborValue::Integer(i) if *i >= 0 => u64::try_from(*i).ok(),
        _ => None,
    }
}

fn cbor_as_i64(val: &CborValue) -> Option<i64> {
    match val {
        CborValue::Integer(i) => i64::try_from(*i).ok(),
        _ => None,
    }
}

fn cid_from_cbor_link(val: &CborValue) -> Result<Cid, DecoderError> {
    if let CborValue::Bytes(b) = val {
        if b.first() == Some(&0) {
            return Cid::try_from(&b[1..]).map_err(|e| DecoderError::InvalidCid(e.to_string()));
        }
    }
    Err(DecoderError::InvalidCborLink)
}

fn is_empty_identity_cid(cid: &Cid) -> bool {
    // Old Faithful represents absent rewards links as `bafkqaaa` (CIDv1, raw=0x55, identity=0x00, len=0).
    cid.hash().code() == 0x00 && cid.hash().size() == 0
}

fn parse_dataframe_cbor(val: CborValue) -> Result<IpldDataFrame, DecoderError> {
    let CborValue::Array(mut arr) = val else {
        return Err(DecoderError::Cbor("DataFrame is not a CBOR array".into()));
    };
    let kind = arr.first().and_then(cbor_as_u64);
    if kind != Some(NodeKind::DataFrame as u64) {
        return Err(DecoderError::UnexpectedNodeKind {
            expected: "DataFrame(6)",
            actual: format!("{kind:?}"),
        });
    }

    let hash = arr.get(1).and_then(cbor_as_u64);
    let data = if arr.len() > 4 {
        match std::mem::replace(&mut arr[4], CborValue::Null) {
            CborValue::Bytes(b) => b,
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let next = if let Some(CborValue::Array(links)) = arr.get(5) {
        if links.is_empty() {
            None
        } else {
            let mut cids = Vec::with_capacity(links.len());
            for link in links {
                cids.push(cid_from_cbor_link(link)?);
            }
            Some(cids)
        }
    } else {
        None
    };

    Ok(IpldDataFrame { hash, data, next })
}

fn parse_block_cbor(cbor: &[u8]) -> Result<IpldBlock, DecoderError> {
    let val: CborValue =
        serde_cbor::from_slice(cbor).map_err(|e| DecoderError::Cbor(e.to_string()))?;
    let CborValue::Array(arr) = val else {
        return Err(DecoderError::Cbor("Block is not a CBOR array".into()));
    };
    let kind = arr.first().and_then(cbor_as_u64);
    if kind != Some(NodeKind::Block as u64) {
        return Err(DecoderError::UnexpectedNodeKind {
            expected: "Block(2)",
            actual: format!("{kind:?}"),
        });
    }

    let slot = arr
        .get(1)
        .and_then(cbor_as_u64)
        .ok_or_else(|| DecoderError::Cbor("Block missing slot".into()))?;

    let mut entries = Vec::new();
    if let Some(CborValue::Array(entry_links)) = arr.get(3) {
        entries.reserve(entry_links.len());
        for link in entry_links {
            entries.push(cid_from_cbor_link(link)?);
        }
    }

    let meta = if let Some(CborValue::Array(meta_arr)) = arr.get(4) {
        let parent_slot = meta_arr.first().and_then(cbor_as_u64).unwrap_or(0);
        let raw_blocktime = meta_arr.get(1).and_then(cbor_as_i64);
        // Old Faithful encodes unset genesis blocktimes as 0 (or null).
        let blocktime = raw_blocktime.filter(|&t| t != 0);
        let block_height = meta_arr.get(2).and_then(cbor_as_u64);
        IpldSlotMeta {
            parent_slot,
            blocktime,
            block_height,
        }
    } else {
        IpldSlotMeta {
            parent_slot: 0,
            blocktime: None,
            block_height: None,
        }
    };

    let rewards = match arr.get(5) {
        Some(v @ CborValue::Bytes(_)) => {
            let cid = cid_from_cbor_link(v)?;
            if is_empty_identity_cid(&cid) {
                None
            } else {
                Some(cid)
            }
        }
        _ => None,
    };

    Ok(IpldBlock {
        slot,
        entries,
        meta,
        rewards,
    })
}

fn parse_entry_cbor(cbor: &[u8]) -> Result<IpldEntry, DecoderError> {
    let val: CborValue =
        serde_cbor::from_slice(cbor).map_err(|e| DecoderError::Cbor(e.to_string()))?;
    let CborValue::Array(arr) = val else {
        return Err(DecoderError::Cbor("Entry is not a CBOR array".into()));
    };
    let kind = arr.first().and_then(cbor_as_u64);
    if kind != Some(NodeKind::Entry as u64) {
        return Err(DecoderError::UnexpectedNodeKind {
            expected: "Entry(1)",
            actual: format!("{kind:?}"),
        });
    }

    let hash_bytes = match arr.get(2) {
        Some(CborValue::Bytes(b)) => b,
        _ => return Err(DecoderError::InvalidEntryHashLength { actual: 0 }),
    };
    let hash: [u8; HASH_BYTES] =
        hash_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DecoderError::InvalidEntryHashLength {
                actual: hash_bytes.len(),
            })?;

    let mut transactions = Vec::new();
    if let Some(CborValue::Array(tx_links)) = arr.get(3) {
        transactions.reserve(tx_links.len());
        for link in tx_links {
            transactions.push(cid_from_cbor_link(link)?);
        }
    }

    Ok(IpldEntry { hash, transactions })
}

fn parse_transaction_cbor(cbor: &[u8]) -> Result<IpldTransaction, DecoderError> {
    let val: CborValue =
        serde_cbor::from_slice(cbor).map_err(|e| DecoderError::Cbor(e.to_string()))?;
    let CborValue::Array(mut arr) = val else {
        return Err(DecoderError::Cbor("Transaction is not a CBOR array".into()));
    };
    let kind = arr.first().and_then(cbor_as_u64);
    if kind != Some(NodeKind::Transaction as u64) {
        return Err(DecoderError::UnexpectedNodeKind {
            expected: "Transaction(0)",
            actual: format!("{kind:?}"),
        });
    }

    let data = if arr.len() > 1 {
        parse_dataframe_cbor(std::mem::replace(&mut arr[1], CborValue::Null))?
    } else {
        return Err(DecoderError::Cbor(
            "Transaction missing data DataFrame".into(),
        ));
    };

    let metadata = if arr.len() > 2 {
        match std::mem::replace(&mut arr[2], CborValue::Null) {
            v @ CborValue::Array(_) => parse_dataframe_cbor(v)?,
            _ => IpldDataFrame {
                hash: None,
                data: Vec::new(),
                next: None,
            },
        }
    } else {
        IpldDataFrame {
            hash: None,
            data: Vec::new(),
            next: None,
        }
    };

    Ok(IpldTransaction { data, metadata })
}

fn parse_rewards_cbor(cbor: &[u8]) -> Result<IpldRewards, DecoderError> {
    let val: CborValue =
        serde_cbor::from_slice(cbor).map_err(|e| DecoderError::Cbor(e.to_string()))?;
    let CborValue::Array(mut arr) = val else {
        return Err(DecoderError::Cbor("Rewards is not a CBOR array".into()));
    };
    let kind = arr.first().and_then(cbor_as_u64);
    if kind != Some(NodeKind::Rewards as u64) {
        return Err(DecoderError::UnexpectedNodeKind {
            expected: "Rewards(5)",
            actual: format!("{kind:?}"),
        });
    }

    let data = if arr.len() > 2 {
        parse_dataframe_cbor(std::mem::replace(&mut arr[2], CborValue::Null))?
    } else {
        IpldDataFrame {
            hash: None,
            data: Vec::new(),
            next: None,
        }
    };

    Ok(IpldRewards { data })
}

// ---------------------------------------------------------------------------
// Zero-copy CARv1 section index
// ---------------------------------------------------------------------------

/// Read an unsigned LEB128 varint from `slice`, advancing `slice` past the varint.
fn read_uvarint(slice: &mut &[u8]) -> Result<u64, DecoderError> {
    let mut x = 0u64;
    let mut s = 0u32;

    for i in 0..MAX_VARINT_LEN_64 {
        if slice.is_empty() {
            return Err(DecoderError::UnexpectedEof {
                needed: 1,
                remaining: 0,
            });
        }
        let b = slice[0];
        *slice = &slice[1..];

        if b < 0x80 {
            if i == MAX_VARINT_LEN_64 - 1 && b > 1 {
                return Err(DecoderError::InvalidVarint("uvarint overflow"));
            }
            return Ok(x | (u64::from(b) << s));
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
        if s > 63 {
            return Err(DecoderError::InvalidVarint("uvarint too long"));
        }
    }
    Err(DecoderError::InvalidVarint("uvarint overflow"))
}

/// Peek the Old Faithful IPLD node `Kind` discriminant from raw CBOR bytes in O(1).
fn peek_cbor_node_kind(cbor: &[u8]) -> Option<NodeKind> {
    let b0 = *cbor.first()?;
    // Major type 4 = CBOR array (top 3 bits == 0b100_00000 == 0x80).
    if (b0 & 0xe0) != 0x80 {
        return None;
    }
    let header_len = match b0 & 0x1f {
        0..=23 | 31 => 1,
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        _ => return None,
    };
    let kind_byte = *cbor.get(header_len)?;
    // Major type 0 small unsigned integer (0..=6).
    if kind_byte <= 6 {
        NodeKind::from_u64(u64::from(kind_byte))
    } else {
        None
    }
}

/// Zero-copy index of all CARv1 sections in a single slot's byte slice.
///
/// Indexing borrows directly into the underlying CAR bytes so large (~55 MiB) epoch-boundary
/// reward blocks incur minimal overhead before callers decide which nodes to decode.
pub struct CarIndex<'a> {
    sections: HashMap<Cid, &'a [u8]>,
    block_cbor: Option<&'a [u8]>,
    section_count: usize,
}

impl<'a> CarIndex<'a> {
    /// Parse a contiguous CARv1 slot slice into a zero-copy [`CarIndex`].
    ///
    /// Also tolerates an optional leading CARv1 file header (CBOR map `{ "version": 1, "roots": ... }`),
    /// which is useful for synthetic test fixtures or full CAR files.
    pub fn parse(mut bytes: &'a [u8]) -> Result<Self, DecoderError> {
        let mut sections = HashMap::new();
        let mut block_cbor = None;
        let mut section_count = 0usize;
        let mut is_first = true;

        while !bytes.is_empty() {
            let section_len_u64 = read_uvarint(&mut bytes)?;
            if section_len_u64 == 0 {
                continue;
            }
            if section_len_u64 > MAX_CAR_SECTION_SIZE as u64 {
                return Err(DecoderError::SectionTooLarge {
                    size: section_len_u64,
                    max: MAX_CAR_SECTION_SIZE,
                });
            }
            let section_len = section_len_u64 as usize;
            if bytes.len() < section_len {
                return Err(DecoderError::UnexpectedEof {
                    needed: section_len,
                    remaining: bytes.len(),
                });
            }

            let mut section = &bytes[..section_len];
            bytes = &bytes[section_len..];

            // Detect and skip an optional CARv1 file header (starts with a CBOR map, major type 5).
            if is_first {
                is_first = false;
                if section.first().is_some_and(|&b| (b & 0xe0) == 0xa0) {
                    if let Ok(CborValue::Map(map)) = serde_cbor::from_slice::<CborValue>(section) {
                        if map.contains_key(&CborValue::Text("version".to_string())) {
                            continue;
                        }
                    }
                }
            }

            let cid = Cid::read_bytes(&mut section)
                .map_err(|e| DecoderError::InvalidCid(e.to_string()))?;
            let cbor = section;

            if peek_cbor_node_kind(cbor) == Some(NodeKind::Block) {
                block_cbor = Some(cbor);
            }

            sections.insert(cid, cbor);
            section_count += 1;
        }

        Ok(Self {
            sections,
            block_cbor,
            section_count,
        })
    }

    /// Number of CARv1 sections indexed.
    pub fn section_count(&self) -> usize {
        self.section_count
    }

    /// Look up raw CBOR bytes by CID.
    pub fn get_cbor(&self, cid: &Cid) -> Option<&'a [u8]> {
        self.sections.get(cid).copied()
    }

    /// Parse and return the slot's [`IpldBlock`] node.
    pub(crate) fn block(&self, expected_slot: Option<u64>) -> Result<IpldBlock, DecoderError> {
        let cbor = self.block_cbor.ok_or(DecoderError::MissingBlockNode {
            slot: expected_slot.unwrap_or(0),
        })?;
        let block = parse_block_cbor(cbor)?;
        if let Some(requested) = expected_slot {
            if block.slot != requested {
                return Err(DecoderError::SlotMismatch {
                    requested,
                    actual: block.slot,
                });
            }
        }
        Ok(block)
    }

    /// Reassemble a single- or multi-frame `DataFrame` chain, verifying its optional CRC64/FNV
    /// checksum and rejecting continuation cycles.
    pub(crate) fn reassemble_dataframe(
        &self,
        first: &IpldDataFrame,
    ) -> Result<Vec<u8>, DecoderError> {
        let Some(first_next) = first.next.as_deref() else {
            if let Some(expected_hash) = first.hash {
                verify_dataframe_hash(&first.data, expected_hash)?;
            }
            return Ok(first.data.clone());
        };

        // Iterative DFS traversal so both linked-list and fan-out continuations preserve order.
        let mut visited = HashSet::new();
        let mut stack: Vec<Cid> = Vec::with_capacity(first_next.len());
        for cid in first_next.iter().rev() {
            stack.push(*cid);
        }

        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut total_len = first.data.len();

        while let Some(cid) = stack.pop() {
            if !visited.insert(cid) {
                return Err(DecoderError::CyclicDataFrame {
                    cid: cid.to_string(),
                });
            }
            let cbor = self
                .get_cbor(&cid)
                .ok_or_else(|| DecoderError::MissingCid {
                    cid: cid.to_string(),
                })?;
            let val: CborValue =
                serde_cbor::from_slice(cbor).map_err(|e| DecoderError::Cbor(e.to_string()))?;
            let frame = parse_dataframe_cbor(val)?;
            total_len = total_len.saturating_add(frame.data.len());
            chunks.push(frame.data);
            if let Some(next_cids) = frame.next {
                for next_cid in next_cids.into_iter().rev() {
                    stack.push(next_cid);
                }
            }
        }

        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&first.data);
        for chunk in chunks {
            out.extend_from_slice(&chunk);
        }

        if let Some(expected_hash) = first.hash {
            verify_dataframe_hash(&out, expected_hash)?;
        }
        Ok(out)
    }

    /// Extract the blockhash (the hash of the last `Entry` in `block.entries`).
    pub fn extract_blockhash(&self) -> Result<Hash, DecoderError> {
        let block = self.block(None)?;
        self.extract_blockhash_for_block(&block)
    }

    pub(crate) fn extract_blockhash_for_block(
        &self,
        block: &IpldBlock,
    ) -> Result<Hash, DecoderError> {
        let Some(last_entry_cid) = block.entries.last() else {
            return Ok(Hash::default());
        };
        let entry_cbor = self
            .get_cbor(last_entry_cid)
            .ok_or_else(|| DecoderError::MissingCid {
                cid: last_entry_cid.to_string(),
            })?;
        let entry = parse_entry_cbor(entry_cbor)?;
        Ok(Hash::new_from_array(entry.hash))
    }

    /// Decode only lightweight block header metadata (slot, parent_slot, blockhash, block_time,
    /// block_height) without decoding transactions or rewards.
    pub fn decode_header(&self, expected_slot: Option<u64>) -> Result<BlockHeader, DecoderError> {
        let block = self.block(expected_slot)?;
        let blockhash = self.extract_blockhash_for_block(&block)?;
        Ok(BlockHeader {
            slot: block.slot,
            parent_slot: block.meta.parent_slot,
            blockhash,
            block_time: block.meta.blocktime,
            block_height: block.meta.block_height,
        })
    }

    /// Decode transaction status metadata from its IPLD `DataFrame`, combining with `versioned_tx`.
    fn decode_transaction_metadata(
        &self,
        slot: u64,
        versioned_tx: VersionedTransaction,
        metadata_df: &IpldDataFrame,
    ) -> Result<TransactionWithStatusMeta, DecoderError> {
        let meta_bytes = self.reassemble_dataframe(metadata_df)?;
        match decode_transaction_status_meta_frame(slot, &meta_bytes)? {
            Some(meta) => Ok(TransactionWithStatusMeta::Complete(
                VersionedTransactionWithStatusMeta {
                    transaction: versioned_tx,
                    meta,
                },
            )),
            None => match versioned_tx.clone().into_legacy_transaction() {
                Some(legacy) => Ok(TransactionWithStatusMeta::MissingMetadata(legacy)),
                None => Ok(TransactionWithStatusMeta::Complete(
                    VersionedTransactionWithStatusMeta {
                        transaction: versioned_tx,
                        meta: Default::default(),
                    },
                )),
            },
        }
    }

    /// Decode a transaction node into [`TransactionWithStatusMeta`].
    fn decode_transaction_node(
        &self,
        slot: u64,
        tx_cid: &Cid,
        decode_metadata: bool,
    ) -> Result<TransactionWithStatusMeta, DecoderError> {
        let tx_cbor = self
            .get_cbor(tx_cid)
            .ok_or_else(|| DecoderError::MissingCid {
                cid: tx_cid.to_string(),
            })?;
        let tx_node = parse_transaction_cbor(tx_cbor)?;
        let tx_bytes = self.reassemble_dataframe(&tx_node.data)?;
        let versioned_tx: VersionedTransaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| DecoderError::TransactionDeserialize(e.to_string()))?;

        if !decode_metadata {
            return Ok(TransactionWithStatusMeta::Complete(
                VersionedTransactionWithStatusMeta {
                    transaction: versioned_tx,
                    meta: Default::default(),
                },
            ));
        }

        self.decode_transaction_metadata(slot, versioned_tx, &tx_node.metadata)
    }

    /// Decode block rewards (if referenced by `block.rewards`).
    fn decode_block_rewards(&self, block: &IpldBlock) -> Result<DecodedRewards, DecoderError> {
        let Some(rewards_cid) = block.rewards.as_ref() else {
            return Ok(DecodedRewards::default());
        };
        let Some(rewards_cbor) = self.get_cbor(rewards_cid) else {
            return Ok(DecodedRewards::default());
        };
        let rewards_node = parse_rewards_cbor(rewards_cbor)?;
        let reassembled = self.reassemble_dataframe(&rewards_node.data)?;
        Ok(decode_rewards_frame(block.slot, &reassembled)?)
    }
}

fn verify_dataframe_hash(data: &[u8], expected: u64) -> Result<(), DecoderError> {
    let crc = Crc::<u64>::new(&CRC_64_GO_ISO);
    let mut digest = crc.digest();
    digest.update(data);
    let crc64 = digest.finalize();
    if crc64 == expected {
        return Ok(());
    }

    let mut fnv_hasher = FnvHasher::default();
    fnv_hasher.write(data);
    let fnv = fnv_hasher.finish();
    if fnv == expected {
        return Ok(());
    }

    Err(DecoderError::DataFrameHashMismatch {
        expected,
        crc64,
        fnv,
    })
}

// ---------------------------------------------------------------------------
// Public high-level decoding & encoding API (reusable by M2 and M3)
// ---------------------------------------------------------------------------

/// Lightweight header metadata decoded from a slot CAR slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub slot: u64,
    pub parent_slot: u64,
    pub blockhash: Hash,
    pub block_time: Option<i64>,
    pub block_height: Option<u64>,
}

/// Controls which parts of a slot CAR slice are decoded so unnecessary work is avoided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOptions {
    /// Whether to deserialize transactions from entries (`false` for `transactionDetails: "none"`).
    pub include_transactions: bool,
    /// Whether to decompress & decode per-transaction status metadata (`false` for `"signatures"`/`"none"`).
    pub include_transaction_metadata: bool,
    /// Whether to reassemble, decompress & decode block rewards (`false` when `rewards: false`).
    pub include_rewards: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self::full()
    }
}

impl DecodeOptions {
    /// Decode everything (transactions, transaction metadata, and block rewards).
    pub const fn full() -> Self {
        Self {
            include_transactions: true,
            include_transaction_metadata: true,
            include_rewards: true,
        }
    }

    /// Derive optimal decode options from Solana `BlockEncodingOptions`.
    pub const fn from_encoding_options(opts: &BlockEncodingOptions) -> Self {
        use solana_transaction_status::TransactionDetails;
        match opts.transaction_details {
            TransactionDetails::Full | TransactionDetails::Accounts => Self {
                include_transactions: true,
                include_transaction_metadata: true,
                include_rewards: opts.show_rewards,
            },
            TransactionDetails::Signatures => Self {
                include_transactions: true,
                include_transaction_metadata: false,
                include_rewards: opts.show_rewards,
            },
            TransactionDetails::None => Self {
                include_transactions: false,
                include_transaction_metadata: false,
                include_rewards: opts.show_rewards,
            },
        }
    }
}

/// A decoded Solana block ready for JSON-RPC encoding.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedBlock {
    pub slot: u64,
    pub block: ConfirmedBlock,
}

impl DecodedBlock {
    /// Encode this block into a Solana RPC [`UiConfirmedBlock`] using `solana-transaction-status`.
    pub fn encode(
        self,
        encoding: UiTransactionEncoding,
        options: BlockEncodingOptions,
    ) -> Result<UiConfirmedBlock, EncodeError> {
        encode_block(self.block, encoding, options)
    }
}

/// Extract only the `blockhash` (last entry hash) from a raw slot CAR slice.
pub fn extract_blockhash_from_car(car_bytes: &[u8]) -> Result<Hash, DecoderError> {
    let index = CarIndex::parse(car_bytes)?;
    index.extract_blockhash()
}

/// Decode a block from an already-indexed [`CarIndex`] with a known `previous_blockhash`.
pub fn decode_block_from_index(
    slot: u64,
    index: &CarIndex<'_>,
    previous_blockhash: String,
    options: DecodeOptions,
) -> Result<DecodedBlock, DecoderError> {
    let block = index.block(Some(slot))?;
    let blockhash = index.extract_blockhash_for_block(&block)?.to_string();

    let mut transactions = Vec::new();
    if options.include_transactions {
        for entry_cid in &block.entries {
            let entry_cbor = index
                .get_cbor(entry_cid)
                .ok_or_else(|| DecoderError::MissingCid {
                    cid: entry_cid.to_string(),
                })?;
            let entry = parse_entry_cbor(entry_cbor)?;
            transactions.reserve(entry.transactions.len());
            for tx_cid in &entry.transactions {
                let tx = index.decode_transaction_node(
                    slot,
                    tx_cid,
                    options.include_transaction_metadata,
                )?;
                transactions.push(tx);
            }
        }
    }

    let DecodedRewards {
        rewards,
        num_partitions,
    } = if options.include_rewards {
        index.decode_block_rewards(&block)?
    } else {
        DecodedRewards::default()
    };

    Ok(DecodedBlock {
        slot,
        block: ConfirmedBlock {
            previous_blockhash,
            blockhash,
            parent_slot: block.meta.parent_slot,
            transactions,
            rewards,
            num_partitions,
            block_time: block.meta.blocktime,
            block_height: block.meta.block_height,
        },
    })
}

/// Decode a slot's raw CAR byte slice into a [`DecodedBlock`].
pub fn decode_block_from_car(
    slot: u64,
    car_bytes: &[u8],
    previous_blockhash: String,
    options: DecodeOptions,
) -> Result<DecodedBlock, DecoderError> {
    let index = CarIndex::parse(car_bytes)?;
    decode_block_from_index(slot, &index, previous_blockhash, options)
}

/// Encode a [`ConfirmedBlock`] into a Solana JSON-RPC [`UiConfirmedBlock`].
pub fn encode_block(
    block: ConfirmedBlock,
    encoding: UiTransactionEncoding,
    options: BlockEncodingOptions,
) -> Result<UiConfirmedBlock, EncodeError> {
    block.encode_with_options(encoding, options)
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use prost::Message;
    use sha2::{Digest, Sha256};
    use solana_message::compiled_instruction::CompiledInstruction;
    use solana_message::{v0, Message as LegacyMessage, MessageHeader, VersionedMessage};
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;

    use crate::proto::{
        ProtoNumPartitions, ProtoReward, ProtoRewards, ProtoTransactionStatusMeta,
        StoredExtendedReward, StoredTransactionStatusMeta,
    };

    fn append_varint(mut value: usize, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    pub fn cbor_link(cid: &Cid) -> CborValue {
        let mut bytes = vec![0u8];
        bytes.extend_from_slice(&cid.to_bytes());
        CborValue::Bytes(bytes)
    }

    pub fn push_cbor_section(car: &mut Vec<u8>, val: &CborValue) -> Cid {
        let data = serde_cbor::to_vec(val).expect("cbor encode");
        let digest = Sha256::digest(&data);
        let mh = multihash::Multihash::wrap(0x12, &digest).expect("multihash");
        let cid = Cid::new_v1(0x71, mh);
        let cid_bytes = cid.to_bytes();
        append_varint(cid_bytes.len() + data.len(), car);
        car.extend_from_slice(&cid_bytes);
        car.extend_from_slice(&data);
        cid
    }

    pub fn sample_legacy_tx(sig_byte: u8) -> VersionedTransaction {
        let payer = Pubkey::new_from_array([1u8; 32]);
        let recipient = Pubkey::new_from_array([2u8; 32]);
        let system_program = Pubkey::new_from_array([0u8; 32]);
        // SystemProgram::Transfer instruction (discriminant 2, lamports 1000).
        let mut ix_data = Vec::with_capacity(12);
        ix_data.extend_from_slice(&2u32.to_le_bytes());
        ix_data.extend_from_slice(&1_000u64.to_le_bytes());
        let msg = LegacyMessage {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![payer, recipient, system_program],
            recent_blockhash: Hash::new_from_array([9u8; 32]),
            instructions: vec![CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: ix_data,
            }],
        };
        VersionedTransaction {
            signatures: vec![Signature::from([sig_byte; 64])],
            message: VersionedMessage::Legacy(msg),
        }
    }

    pub fn sample_v0_tx(sig_byte: u8) -> VersionedTransaction {
        let payer = Pubkey::new_from_array([3u8; 32]);
        let recipient = Pubkey::new_from_array([4u8; 32]);
        let system_program = Pubkey::new_from_array([0u8; 32]);
        let mut ix_data = Vec::with_capacity(12);
        ix_data.extend_from_slice(&2u32.to_le_bytes());
        ix_data.extend_from_slice(&500u64.to_le_bytes());
        let msg = v0::Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![payer, recipient, system_program],
            recent_blockhash: Hash::new_from_array([8u8; 32]),
            instructions: vec![CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: ix_data,
            }],
            address_table_lookups: vec![],
        };
        VersionedTransaction {
            signatures: vec![Signature::from([sig_byte; 64])],
            message: VersionedMessage::V0(msg),
        }
    }

    fn make_dataframe_cbor(car: &mut Vec<u8>, payload: Vec<u8>, split_frames: bool) -> CborValue {
        if split_frames && payload.len() >= 9 {
            let third = payload.len() / 3;
            let two_thirds = third * 2;
            let crc = Crc::<u64>::new(&CRC_64_GO_ISO);
            let mut digest = crc.digest();
            digest.update(&payload);
            let checksum = digest.finalize();

            let df2 = CborValue::Array(vec![
                CborValue::Integer(NodeKind::DataFrame as i128),
                CborValue::Integer(checksum as i128),
                CborValue::Integer(2),
                CborValue::Integer(3),
                CborValue::Bytes(payload[two_thirds..].to_vec()),
                CborValue::Array(vec![]),
            ]);
            let cid2 = push_cbor_section(car, &df2);

            let df1 = CborValue::Array(vec![
                CborValue::Integer(NodeKind::DataFrame as i128),
                CborValue::Integer(checksum as i128),
                CborValue::Integer(1),
                CborValue::Integer(3),
                CborValue::Bytes(payload[third..two_thirds].to_vec()),
                CborValue::Array(vec![cbor_link(&cid2)]),
            ]);
            let cid1 = push_cbor_section(car, &df1);

            CborValue::Array(vec![
                CborValue::Integer(NodeKind::DataFrame as i128),
                CborValue::Integer(checksum as i128),
                CborValue::Integer(0),
                CborValue::Integer(3),
                CborValue::Bytes(payload[..third].to_vec()),
                CborValue::Array(vec![cbor_link(&cid1)]),
            ])
        } else {
            CborValue::Array(vec![
                CborValue::Integer(NodeKind::DataFrame as i128),
                CborValue::Null,
                CborValue::Null,
                CborValue::Null,
                CborValue::Bytes(payload),
                CborValue::Null,
            ])
        }
    }

    /// Build a synthetic CARv1 slot slice with transactions (modern protobuf or pre-157 bincode)
    /// and optional multi-frame rewards.
    pub fn build_synthetic_slot_car(
        slot: u64,
        parent_slot: u64,
        blockhash_byte: u8,
        txs: &[VersionedTransaction],
        split_rewards_frames: bool,
    ) -> Vec<u8> {
        build_synthetic_slot_car_with_options(
            slot,
            parent_slot,
            blockhash_byte,
            txs,
            split_rewards_frames,
            false,
        )
    }

    /// Build a synthetic CARv1 slot slice with optional multi-frame `DataFrame` splitting for
    /// both rewards and transaction data/metadata payloads.
    pub fn build_synthetic_slot_car_with_options(
        slot: u64,
        parent_slot: u64,
        blockhash_byte: u8,
        txs: &[VersionedTransaction],
        split_rewards_frames: bool,
        split_tx_frames: bool,
    ) -> Vec<u8> {
        let mut car = Vec::new();
        let is_pre_157 = slot < crate::proto::BINCODE_SLOT_CUTOFF;

        let mut tx_cids = Vec::new();
        for (idx, tx) in txs.iter().enumerate() {
            let tx_bytes = bincode::serialize(tx).expect("serialize tx");
            let meta_bytes = if is_pre_157 {
                let stored = StoredTransactionStatusMeta {
                    status: Ok(()),
                    fee: 5_000,
                    pre_balances: vec![10_000, 1_000, 1],
                    post_balances: vec![4_000, 2_000, 1],
                    inner_instructions: None,
                    log_messages: Some(vec![
                        "Program 11111111111111111111111111111111 success".into()
                    ]),
                    pre_token_balances: Some(vec![]),
                    post_token_balances: Some(vec![]),
                    rewards: Some(vec![]),
                    return_data: None,
                    compute_units_consumed: Some(150),
                    cost_units: None,
                };
                zstd::encode_all(bincode::serialize(&stored).unwrap().as_slice(), 1).unwrap()
            } else {
                let proto = ProtoTransactionStatusMeta {
                    err: None,
                    fee: 5_000,
                    pre_balances: vec![10_000, 1_000, 1],
                    post_balances: vec![4_000, 2_000, 1],
                    inner_instructions: vec![],
                    inner_instructions_none: false,
                    log_messages: vec!["Program 11111111111111111111111111111111 success".into()],
                    log_messages_none: false,
                    pre_token_balances: vec![],
                    post_token_balances: vec![],
                    rewards: vec![],
                    loaded_writable_addresses: vec![],
                    loaded_readonly_addresses: vec![],
                    return_data: None,
                    return_data_none: true,
                    compute_units_consumed: Some(150),
                    cost_units: Some(300),
                };
                zstd::encode_all(proto.encode_to_vec().as_slice(), 1).unwrap()
            };

            let data_df = make_dataframe_cbor(&mut car, tx_bytes, split_tx_frames);
            let meta_df = make_dataframe_cbor(&mut car, meta_bytes, split_tx_frames);

            let tx_node = CborValue::Array(vec![
                CborValue::Integer(NodeKind::Transaction as i128),
                data_df,
                meta_df,
                CborValue::Integer(slot as i128),
                CborValue::Integer(idx as i128),
            ]);
            tx_cids.push(push_cbor_section(&mut car, &tx_node));
        }

        let entry_node = CborValue::Array(vec![
            CborValue::Integer(NodeKind::Entry as i128),
            CborValue::Integer(10),
            CborValue::Bytes(vec![blockhash_byte; 32]),
            CborValue::Array(tx_cids.iter().map(cbor_link).collect()),
        ]);
        let entry_cid = push_cbor_section(&mut car, &entry_node);

        let rewards_payload = if is_pre_157 {
            let stored = vec![StoredExtendedReward {
                pubkey: Pubkey::new_from_array([7u8; 32]).to_string(),
                lamports: 2_500,
                post_balance: 50_000,
                reward_type: Some(solana_reward_info::RewardType::Fee),
                commission: None,
            }];
            zstd::encode_all(bincode::serialize(&stored).unwrap().as_slice(), 1).unwrap()
        } else {
            let proto = ProtoRewards {
                rewards: vec![ProtoReward {
                    pubkey: Pubkey::new_from_array([7u8; 32]).to_string(),
                    lamports: 2_500,
                    post_balance: 50_000,
                    reward_type: 1, // Fee
                    commission: String::new(),
                    commission_bps: String::new(),
                }],
                num_partitions: Some(ProtoNumPartitions { num_partitions: 1 }),
            };
            zstd::encode_all(proto.encode_to_vec().as_slice(), 1).unwrap()
        };

        let rewards_df = make_dataframe_cbor(&mut car, rewards_payload, split_rewards_frames);

        let rewards_node = CborValue::Array(vec![
            CborValue::Integer(NodeKind::Rewards as i128),
            CborValue::Integer(slot as i128),
            rewards_df,
        ]);
        let rewards_cid = push_cbor_section(&mut car, &rewards_node);

        let block_node = CborValue::Array(vec![
            CborValue::Integer(NodeKind::Block as i128),
            CborValue::Integer(slot as i128),
            CborValue::Array(vec![]),
            CborValue::Array(vec![cbor_link(&entry_cid)]),
            CborValue::Array(vec![
                CborValue::Integer(parent_slot as i128),
                CborValue::Integer(1_730_000_000),
                CborValue::Integer(slot.saturating_sub(100) as i128),
            ]),
            cbor_link(&rewards_cid),
        ]);
        push_cbor_section(&mut car, &block_node);

        car
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use solana_transaction_status::{
        EncodedTransaction, TransactionBinaryEncoding, TransactionDetails, UiMessage,
    };

    #[test]
    fn decodes_synthetic_block_all_four_encodings_and_multiframe_rewards() {
        let slot = 302_400_001;
        let tx_legacy = sample_legacy_tx(11);
        let tx_v0 = sample_v0_tx(22);
        let car = build_synthetic_slot_car(
            slot,
            slot - 1,
            0xAA,
            &[tx_legacy.clone(), tx_v0.clone()],
            true,
        );

        assert_eq!(
            extract_blockhash_from_car(&car).expect("blockhash"),
            Hash::new_from_array([0xAA; 32])
        );

        let prev_bh = Hash::new_from_array([0x55; 32]).to_string();

        // 1. json
        let decoded = decode_block_from_car(slot, &car, prev_bh.clone(), DecodeOptions::full())
            .expect("decode");
        assert_eq!(decoded.block.rewards.len(), 1);
        assert_eq!(decoded.block.num_partitions, Some(1));
        assert_eq!(decoded.block.transactions.len(), 2);

        let ui_json = decoded
            .clone()
            .encode(
                UiTransactionEncoding::Json,
                BlockEncodingOptions {
                    transaction_details: TransactionDetails::Full,
                    show_rewards: true,
                    max_supported_transaction_version: Some(0),
                },
            )
            .expect("encode json");
        let txs_json = ui_json.transactions.as_ref().expect("txs");
        assert_eq!(txs_json.len(), 2);
        assert!(matches!(
            txs_json[0].transaction,
            EncodedTransaction::Json(ref ui_tx) if matches!(ui_tx.message, UiMessage::Raw(_))
        ));

        // 2. jsonParsed
        let ui_parsed = decoded
            .clone()
            .encode(
                UiTransactionEncoding::JsonParsed,
                BlockEncodingOptions {
                    transaction_details: TransactionDetails::Full,
                    show_rewards: true,
                    max_supported_transaction_version: Some(0),
                },
            )
            .expect("encode jsonParsed");
        let txs_parsed = ui_parsed.transactions.as_ref().expect("txs");
        assert!(matches!(
            txs_parsed[0].transaction,
            EncodedTransaction::Json(ref ui_tx) if matches!(ui_tx.message, UiMessage::Parsed(_))
        ));

        // 3. base64
        let ui_b64 = decoded
            .clone()
            .encode(
                UiTransactionEncoding::Base64,
                BlockEncodingOptions {
                    transaction_details: TransactionDetails::Full,
                    show_rewards: false,
                    max_supported_transaction_version: Some(0),
                },
            )
            .expect("encode base64");
        assert!(ui_b64.rewards.is_none());
        let txs_b64 = ui_b64.transactions.as_ref().expect("txs");
        assert!(matches!(
            txs_b64[0].transaction,
            EncodedTransaction::Binary(_, TransactionBinaryEncoding::Base64)
        ));

        // 4. base58
        let ui_b58 = decoded
            .clone()
            .encode(
                UiTransactionEncoding::Base58,
                BlockEncodingOptions {
                    transaction_details: TransactionDetails::Full,
                    show_rewards: true,
                    max_supported_transaction_version: Some(0),
                },
            )
            .expect("encode base58");
        let txs_b58 = ui_b58.transactions.as_ref().expect("txs");
        assert!(matches!(
            txs_b58[0].transaction,
            EncodedTransaction::Binary(_, TransactionBinaryEncoding::Base58)
        ));

        // Omitting maxSupportedTransactionVersion on a block with v0 tx must return UnsupportedTransactionVersion(0).
        let err = decoded
            .encode(
                UiTransactionEncoding::Json,
                BlockEncodingOptions {
                    transaction_details: TransactionDetails::Full,
                    show_rewards: true,
                    max_supported_transaction_version: None,
                },
            )
            .expect_err("expected version error");
        assert_eq!(err, EncodeError::UnsupportedTransactionVersion(0));
    }

    #[test]
    fn decodes_pre_epoch_157_bincode_block() {
        let slot = 43_200_000;
        let tx = sample_legacy_tx(77);
        let car = build_synthetic_slot_car(slot, slot - 1, 0x12, &[tx], false);

        let decoded = decode_block_from_car(
            slot,
            &car,
            Hash::default().to_string(),
            DecodeOptions::full(),
        )
        .expect("decode pre-157");
        assert_eq!(decoded.block.transactions.len(), 1);
        assert_eq!(decoded.block.rewards.len(), 1);
    }

    #[test]
    fn decodes_multiframe_dataframe_transaction_and_metadata() {
        for (slot, tx) in [
            (302_400_001u64, sample_v0_tx(88)),
            (43_200_000u64, sample_legacy_tx(89)),
        ] {
            let other_tx = sample_legacy_tx(10);
            let target_sig = tx.signatures[0];
            let car = build_synthetic_slot_car_with_options(
                slot,
                slot - 1,
                0x33,
                &[other_tx, tx],
                true,
                true, // split both transaction data and metadata into 3 CRC64-verified DataFrames
            );

            let decoded = decode_block_from_car(
                slot,
                &car,
                Hash::default().to_string(),
                DecodeOptions::full(),
            )
            .expect("decode block with multi-frame transaction");
            assert_eq!(decoded.block.transactions.len(), 2);
            assert_eq!(decoded.block.block_time, Some(1_730_000_000));
            let TransactionWithStatusMeta::Complete(tx) = &decoded.block.transactions[1] else {
                panic!("expected complete metadata for the multi-frame transaction");
            };
            assert_eq!(tx.transaction.signatures[0], target_sig);
            assert_eq!(tx.meta.fee, 5_000);
            assert_eq!(tx.meta.compute_units_consumed, Some(150));
        }
    }

    #[test]
    fn reassemble_rejects_cyclic_dataframe() {
        let mut car = Vec::new();
        // Self-referential CID won't match SHA-256 of itself, so build a 2-node cycle using synthetic CIDs.
        let cid_a = Cid::try_from(
            [
                1u8, 113, 18, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            ]
            .as_slice(),
        )
        .unwrap();
        let df_bytes = serde_cbor::to_vec(&CborValue::Array(vec![
            CborValue::Integer(NodeKind::DataFrame as i128),
            CborValue::Null,
            CborValue::Null,
            CborValue::Null,
            CborValue::Bytes(vec![1, 2, 3]),
            CborValue::Array(vec![cbor_link(&cid_a)]),
        ]))
        .unwrap();

        let cid_bytes = cid_a.to_bytes();
        let total = cid_bytes.len() + df_bytes.len();
        car.push(total as u8);
        car.extend_from_slice(&cid_bytes);
        car.extend_from_slice(&df_bytes);

        let index = CarIndex::parse(&car).expect("parse");
        let first = IpldDataFrame {
            hash: None,
            data: vec![0],
            next: Some(vec![cid_a]),
        };
        let err = index
            .reassemble_dataframe(&first)
            .expect_err("expected cycle");
        assert!(matches!(err, DecoderError::CyclicDataFrame { .. }));
    }
}
