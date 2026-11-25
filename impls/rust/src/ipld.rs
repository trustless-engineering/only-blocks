//! Old Faithful IPLD node schemas and DataFrame reassembly (WIRE_FORMATS.md §5–§6).

use std::borrow::Cow;
use std::collections::HashSet;

use crate::bail;
use crate::car::{link_cid, CarIndex};
use crate::cbor::{self, Cbor};
use crate::error::DResult;
use crate::hash::dataframe_hash_matches;

pub const KIND_TRANSACTION: u64 = 0;
pub const KIND_ENTRY: u64 = 1;
pub const KIND_BLOCK: u64 = 2;
pub const KIND_REWARDS: u64 = 5;
pub const KIND_DATAFRAME: u64 = 6;

pub type CidBytes = Vec<u8>;

#[derive(Debug, Clone, Default)]
pub struct DataFrame<'a> {
    pub hash: Option<u64>,
    pub data: Cow<'a, [u8]>,
    pub next: Option<Vec<CidBytes>>,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub slot: u64,
    pub entries: Vec<CidBytes>,
    pub parent_slot: u64,
    pub block_time: Option<i64>,
    pub block_height: Option<u64>,
    /// `None` when absent or the empty identity CID.
    pub rewards: Option<CidBytes>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub hash: [u8; 32],
    pub transactions: Vec<CidBytes>,
}

#[derive(Debug, Clone)]
pub struct Transaction<'a> {
    pub data: DataFrame<'a>,
    pub metadata: DataFrame<'a>,
}

fn node_array<'a, 'b>(node: &'b mut Cbor<'a>, kind: u64, name: &str) -> DResult<&'b mut Vec<Cbor<'a>>> {
    let Cbor::Array(items) = node else { bail!("{name} node is not a CBOR array") };
    match items.first().and_then(Cbor::as_u64) {
        Some(k) if k == kind => Ok(items),
        other => bail!("expected {name} ({kind}) node, got kind {other:?}"),
    }
}

/// Every element of a link list must be a valid link.
fn links(v: &Cbor<'_>) -> DResult<Vec<CidBytes>> {
    let Some(items) = v.as_array() else { return Ok(Vec::new()) };
    items.iter().map(|item| link_cid(item).map(|(cid, _)| cid.to_vec())).collect()
}

pub fn dataframe_from_cbor(v: Cbor<'_>) -> DResult<DataFrame<'_>> {
    let mut v = v;
    let items = node_array(&mut v, KIND_DATAFRAME, "DataFrame")?;
    let hash = items.get(1).and_then(Cbor::as_u64);
    let data = items.get_mut(4).and_then(Cbor::take_bytes).unwrap_or(Cow::Borrowed(&[]));
    let next = match items.get(5) {
        Some(Cbor::Array(list)) if !list.is_empty() => Some(links(&items[5])?),
        _ => None,
    };
    Ok(DataFrame { hash, data, next })
}

pub fn parse_block(node: &[u8]) -> DResult<Block> {
    let mut v = cbor::parse(node)?;
    let items = node_array(&mut v, KIND_BLOCK, "Block")?;
    let Some(slot) = items.get(1).and_then(Cbor::as_u64) else { bail!("Block has no slot") };
    let entries = match items.get(3) {
        Some(list @ Cbor::Array(_)) => links(list)?,
        _ => Vec::new(),
    };
    let (mut parent_slot, mut block_time, mut block_height) = (0, None, None);
    if let Some(Cbor::Array(meta)) = items.get(4) {
        parent_slot = meta.first().and_then(Cbor::as_u64).unwrap_or(0);
        block_time = meta.get(1).and_then(Cbor::as_i64).filter(|&t| t != 0);
        block_height = meta.get(2).and_then(Cbor::as_u64);
    }
    let rewards = match items.get(5) {
        Some(link @ Cbor::Bytes(_)) => {
            let (cid, parsed) = link_cid(link)?;
            if parsed.is_empty_identity() {
                None
            } else {
                Some(cid.to_vec())
            }
        }
        _ => None,
    };
    Ok(Block { slot, entries, parent_slot, block_time, block_height, rewards })
}

pub fn parse_entry(node: &[u8]) -> DResult<Entry> {
    let mut v = cbor::parse(node)?;
    let items = node_array(&mut v, KIND_ENTRY, "Entry")?;
    let hash: [u8; 32] = match items.get(2).and_then(Cbor::as_bytes) {
        Some(b) if b.len() == 32 => b.try_into().unwrap_or([0; 32]),
        _ => bail!("Entry hash is not a 32-byte string"),
    };
    let transactions = match items.get(3) {
        Some(list @ Cbor::Array(_)) => links(list)?,
        _ => Vec::new(),
    };
    Ok(Entry { hash, transactions })
}

pub fn parse_transaction(node: &[u8]) -> DResult<Transaction<'_>> {
    let mut v = cbor::parse(node)?;
    let items = node_array(&mut v, KIND_TRANSACTION, "Transaction")?;
    if items.len() < 2 {
        bail!("Transaction has no data DataFrame");
    }
    let data = dataframe_from_cbor(std::mem::replace(&mut items[1], Cbor::Null))?;
    let metadata = match items.get_mut(2) {
        Some(slot @ Cbor::Array(_)) => dataframe_from_cbor(std::mem::replace(slot, Cbor::Null))?,
        _ => DataFrame::default(),
    };
    Ok(Transaction { data, metadata })
}

pub fn parse_rewards(node: &[u8]) -> DResult<DataFrame<'_>> {
    let mut v = cbor::parse(node)?;
    let items = node_array(&mut v, KIND_REWARDS, "Rewards")?;
    match items.get_mut(2) {
        Some(slot) => dataframe_from_cbor(std::mem::replace(slot, Cbor::Null)),
        None => Ok(DataFrame::default()),
    }
}

/// Reassemble a (possibly multi-frame) DataFrame with an iterative DFS and verify the first
/// frame's hash (CRC-64/GO-ISO or FNV-1a) against the whole payload.
pub fn reassemble<'a>(index: &CarIndex<'a>, first: DataFrame<'a>) -> DResult<Cow<'a, [u8]>> {
    let Some(next) = first.next else {
        if let Some(expected) = first.hash {
            if !dataframe_hash_matches(&first.data, expected) {
                bail!("DataFrame hash mismatch (expected {expected:#018x})");
            }
        }
        return Ok(first.data);
    };
    let mut out = first.data.into_owned();
    let mut visited: HashSet<CidBytes> = HashSet::new();
    let mut stack: Vec<CidBytes> = next.into_iter().rev().collect();
    while let Some(cid) = stack.pop() {
        if !visited.insert(cid.clone()) {
            bail!("cyclic DataFrame chain");
        }
        let Some(node) = index.get(&cid) else { bail!("missing DataFrame continuation CID") };
        let frame = dataframe_from_cbor(cbor::parse(node)?)?;
        out.extend_from_slice(&frame.data);
        if let Some(more) = frame.next {
            stack.extend(more.into_iter().rev());
        }
    }
    if let Some(expected) = first.hash {
        if !dataframe_hash_matches(&out, expected) {
            bail!("DataFrame hash mismatch (expected {expected:#018x})");
        }
    }
    Ok(Cow::Owned(out))
}
