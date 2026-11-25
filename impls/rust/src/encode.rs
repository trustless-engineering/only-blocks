//! JSON serialization of a `getBlock` result (WIRE_FORMATS.md §13–§14), streamed straight into
//! one output buffer with no intermediate value tree.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::block::TxWithMeta;
use crate::codec::{b58_decode, b58_encode, b64_encode};
use crate::error::RpcError;
use crate::json::Writer;
use crate::model::*;
use crate::tx::VersionedTransaction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Json,
    JsonParsed,
    Base64,
    Base58,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Details {
    Full,
    Accounts,
    Signatures,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockOptions {
    pub encoding: Encoding,
    pub details: Details,
    pub rewards: bool,
    pub max_supported_transaction_version: Option<u8>,
}

pub struct BlockHeader {
    pub previous_blockhash: String,
    pub blockhash: String,
    pub parent_slot: u64,
    pub block_time: Option<i64>,
    pub block_height: Option<u64>,
}

const RESERVED_KEYS: [&str; 31] = [
    "AddressLookupTab1e1111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "Config1111111111111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "Feature111111111111111111111111111111111111",
    "LoaderV411111111111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111",
    "StakeConfig11111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "11111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "ZkE1Gama1Proof11111111111111111111111111111",
    "ZkTokenProof1111111111111111111111111111111",
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarEpochRewards1111111111111111111111111",
    "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111",
    "Sysvar1nstructions1111111111111111111111111",
    "SysvarLastRestartS1ot1111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarRent111111111111111111111111111111111",
    "SysvarRewards111111111111111111111111111111",
    "SysvarS1otHashes111111111111111111111111111",
    "SysvarS1otHistory11111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
    "Sysvar1111111111111111111111111111111111111",
];

const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

fn decode_key(s: &str) -> Pubkey {
    let mut key = [0u8; 32];
    if let Some(bytes) = b58_decode(s) {
        if bytes.len() == 32 {
            key.copy_from_slice(&bytes);
        }
    }
    key
}

fn reserved() -> &'static HashSet<Pubkey> {
    static SET: OnceLock<HashSet<Pubkey>> = OnceLock::new();
    SET.get_or_init(|| RESERVED_KEYS.iter().map(|s| decode_key(s)).collect())
}

fn upgradeable_loader() -> &'static Pubkey {
    static KEY: OnceLock<Pubkey> = OnceLock::new();
    KEY.get_or_init(|| decode_key(BPF_LOADER_UPGRADEABLE))
}

/// One entry of the combined account list with its §14 flags.
struct AccountInfo {
    pubkey: String,
    writable: bool,
    signer: bool,
    lookup: bool,
}

/// Combined key list: static keys, then (for v0 with metadata) loaded writable, loaded readonly.
fn combined_keys<'k>(tx: &'k VersionedTransaction, loaded: Option<&'k Meta>) -> Vec<&'k Pubkey> {
    let mut keys: Vec<&Pubkey> = tx.account_keys.iter().collect();
    if let Some(meta) = loaded {
        keys.extend(meta.loaded_writable.iter());
        keys.extend(meta.loaded_readonly.iter());
    }
    keys
}

/// `parse_legacy_message_accounts` / `parse_v0_message_accounts` (§14).
fn account_infos(tx: &VersionedTransaction, loaded: Option<&Meta>) -> Vec<AccountInfo> {
    let keys = combined_keys(tx, loaded);
    let [nrs, nros, nrou] = tx.header.map(|b| b as usize);
    let s = tx.account_keys.len();
    let w = loaded.map_or(0, |m| m.loaded_writable.len());
    let upgradeable_present = keys.iter().any(|k| *k == upgradeable_loader());
    let reserved = reserved();
    keys.iter()
        .enumerate()
        .map(|(i, key)| {
            let writable_index = if i >= s {
                i - s < w
            } else if i >= nrs {
                i - nrs < s.saturating_sub(nrs).saturating_sub(nrou)
            } else {
                i < nrs.saturating_sub(nros)
            };
            let called_as_program = i <= 255 && tx.instructions.iter().any(|ix| ix.program_id_index as usize == i);
            let demoted = called_as_program && !upgradeable_present;
            AccountInfo {
                pubkey: b58_encode(*key),
                writable: writable_index && !reserved.contains(*key) && !demoted,
                signer: i < nrs,
                lookup: i >= s,
            }
        })
        .collect()
}

fn write_account_infos(w: &mut Writer, infos: &[AccountInfo]) {
    w.begin_arr();
    for a in infos {
        w.item();
        w.begin_obj();
        w.kv_str("pubkey", &a.pubkey);
        w.kv_bool("writable", a.writable);
        w.kv_bool("signer", a.signer);
        w.kv_str("source", if a.lookup { "lookupTable" } else { "transaction" });
        w.end_obj();
    }
    w.end_arr();
}

fn write_u8_array(w: &mut Writer, bytes: &[u8]) {
    w.begin_arr();
    for &b in bytes {
        w.item_u64(b as u64);
    }
    w.end_arr();
}

fn write_signatures(w: &mut Writer, tx: &VersionedTransaction) {
    w.begin_arr();
    for sig in &tx.signatures {
        w.item_str(&b58_encode(sig));
    }
    w.end_arr();
}

fn key_at<'k>(keys: &[&'k Pubkey], index: u8) -> Result<&'k Pubkey, RpcError> {
    keys.get(index as usize)
        .copied()
        .ok_or_else(|| RpcError::internal(format!("account index {index} out of range ({} keys)", keys.len())))
}

/// `{"programId","accounts","data","stackHeight"}` (OnlyBlocks partially decoded form).
fn write_partially_decoded(
    w: &mut Writer,
    keys: &[&Pubkey],
    program_id_index: u8,
    accounts: &[u8],
    data: &[u8],
    stack_height: Option<u32>,
) -> Result<(), RpcError> {
    w.begin_obj();
    w.kv_str("programId", &b58_encode(key_at(keys, program_id_index)?));
    w.key("accounts");
    w.begin_arr();
    for &a in accounts {
        w.item_str(&b58_encode(key_at(keys, a)?));
    }
    w.end_arr();
    w.kv_str("data", &b58_encode(data));
    w.key("stackHeight");
    match stack_height {
        Some(h) => w.u64(h as u64),
        None => w.null(),
    }
    w.end_obj();
    Ok(())
}

fn write_compiled(w: &mut Writer, program_id_index: u8, accounts: &[u8], data: &[u8], stack_height: Option<u32>) {
    w.begin_obj();
    w.kv_u64("programIdIndex", program_id_index as u64);
    w.key("accounts");
    write_u8_array(w, accounts);
    w.kv_str("data", &b58_encode(data));
    w.key("stackHeight");
    match stack_height {
        Some(h) => w.u64(h as u64),
        None => w.null(),
    }
    w.end_obj();
}

fn write_lookups(w: &mut Writer, tx: &VersionedTransaction) {
    w.key("addressTableLookups");
    w.begin_arr();
    for l in &tx.address_table_lookups {
        w.item();
        w.begin_obj();
        w.kv_str("accountKey", &b58_encode(&l.account_key));
        w.key("writableIndexes");
        write_u8_array(w, &l.writable_indexes);
        w.key("readonlyIndexes");
        write_u8_array(w, &l.readonly_indexes);
        w.end_obj();
    }
    w.end_arr();
}

/// `encoding: "json"` transaction object (§13.3).
fn write_json_transaction(w: &mut Writer, tx: &VersionedTransaction) {
    w.begin_obj();
    w.key("signatures");
    write_signatures(w, tx);
    w.key("message");
    w.begin_obj();
    w.key("header");
    w.begin_obj();
    w.kv_u64("numRequiredSignatures", tx.header[0] as u64);
    w.kv_u64("numReadonlySignedAccounts", tx.header[1] as u64);
    w.kv_u64("numReadonlyUnsignedAccounts", tx.header[2] as u64);
    w.end_obj();
    w.key("accountKeys");
    w.begin_arr();
    for k in &tx.account_keys {
        w.item_str(&b58_encode(k));
    }
    w.end_arr();
    w.kv_str("recentBlockhash", &b58_encode(&tx.recent_blockhash));
    w.key("instructions");
    w.begin_arr();
    for ix in &tx.instructions {
        w.item();
        write_compiled(w, ix.program_id_index, &ix.accounts, &ix.data, Some(1));
    }
    w.end_arr();
    if tx.version.is_some() {
        write_lookups(w, tx);
    }
    w.end_obj();
    w.end_obj();
}

/// `encoding: "jsonParsed"` transaction object (§13.5). `meta` is the metadata of a v0
/// `Complete` transaction (its loaded addresses extend the key list).
fn write_parsed_transaction(w: &mut Writer, tx: &VersionedTransaction, meta: Option<&Meta>) -> Result<(), RpcError> {
    let loaded = if tx.version.is_some() { meta } else { None };
    let keys = combined_keys(tx, loaded);
    w.begin_obj();
    w.key("signatures");
    write_signatures(w, tx);
    w.key("message");
    w.begin_obj();
    w.key("accountKeys");
    write_account_infos(w, &account_infos(tx, loaded));
    w.kv_str("recentBlockhash", &b58_encode(&tx.recent_blockhash));
    w.key("instructions");
    w.begin_arr();
    for ix in &tx.instructions {
        w.item();
        write_partially_decoded(w, &keys, ix.program_id_index, &ix.accounts, &ix.data, Some(1))?;
    }
    w.end_arr();
    if tx.version.is_some() {
        write_lookups(w, tx);
    }
    w.end_obj();
    w.end_obj();
    Ok(())
}

fn write_binary_transaction(w: &mut Writer, tx: &VersionedTransaction, raw: &[u8], base64: bool) {
    let bytes = &raw[..tx.wire_len.min(raw.len())];
    w.begin_arr();
    if base64 {
        w.item_str(&b64_encode(bytes));
        w.item_str("base64");
    } else {
        w.item_str(&b58_encode(bytes));
        w.item_str("base58");
    }
    w.end_arr();
}

fn write_instruction_error(w: &mut Writer, e: &InstructionError) {
    match e {
        InstructionError::Custom(n) => {
            w.begin_obj();
            w.kv_u64("Custom", *n as u64);
            w.end_obj();
        }
        InstructionError::Unit(v) => w.str(INSTRUCTION_ERROR_NAMES.get(*v as usize).copied().unwrap_or("InvalidError")),
    }
}

fn write_transaction_error(w: &mut Writer, e: &TransactionError) {
    let account_index = |w: &mut Writer, name: &str, i: u8| {
        w.begin_obj();
        w.key(name);
        w.begin_obj();
        w.kv_u64("account_index", i as u64);
        w.end_obj();
        w.end_obj();
    };
    match e {
        TransactionError::Unit(v) => w.str(TRANSACTION_ERROR_NAMES.get(*v as usize).copied().unwrap_or("SanitizeFailure")),
        TransactionError::InstructionError(i, ie) => {
            w.begin_obj();
            w.key("InstructionError");
            w.begin_arr();
            w.item_u64(*i as u64);
            w.item();
            write_instruction_error(w, ie);
            w.end_arr();
            w.end_obj();
        }
        TransactionError::DuplicateInstruction(i) => {
            w.begin_obj();
            w.kv_u64("DuplicateInstruction", *i as u64);
            w.end_obj();
        }
        TransactionError::InsufficientFundsForRent(i) => account_index(w, "InsufficientFundsForRent", *i),
        TransactionError::ProgramExecutionTemporarilyRestricted(i) => {
            account_index(w, "ProgramExecutionTemporarilyRestricted", *i)
        }
    }
}

pub fn write_reward(w: &mut Writer, r: &Reward) {
    w.begin_obj();
    w.kv_str("pubkey", &r.pubkey);
    w.key("lamports");
    w.i64(r.lamports);
    w.kv_u64("postBalance", r.post_balance);
    w.key("rewardType");
    match r.reward_type.and_then(reward_type_name) {
        Some(name) => w.str(name),
        None => w.null(),
    }
    w.key("commission");
    match r.commission {
        Some(c) => w.u64(c as u64),
        None => w.null(),
    }
    w.end_obj();
}

fn write_rewards(w: &mut Writer, rewards: &[Reward]) {
    w.begin_arr();
    for r in rewards {
        w.item();
        write_reward(w, r);
    }
    w.end_arr();
}

fn write_token_balances(w: &mut Writer, key: &str, balances: &Option<Vec<TokenBalance>>) {
    w.key(key);
    let Some(list) = balances else { return w.null() };
    w.begin_arr();
    for tb in list {
        w.item();
        w.begin_obj();
        w.kv_u64("accountIndex", tb.account_index as u64);
        w.kv_str("mint", &tb.mint);
        w.key("uiTokenAmount");
        w.begin_obj();
        w.key("uiAmount");
        match tb.ui_amount {
            Some(v) => w.f64(v),
            None => w.null(),
        }
        w.kv_u64("decimals", tb.decimals as u64);
        w.kv_str("amount", &tb.amount);
        w.kv_str("uiAmountString", &tb.ui_amount_string);
        w.end_obj();
        if !tb.owner.is_empty() {
            w.kv_str("owner", &tb.owner);
        }
        if !tb.program_id.is_empty() {
            w.kv_str("programId", &tb.program_id);
        }
        w.end_obj();
    }
    w.end_arr();
}

fn write_status(w: &mut Writer, meta: &Meta) {
    w.key("err");
    match &meta.status {
        Some(e) => write_transaction_error(w, e),
        None => w.null(),
    }
    w.key("status");
    w.begin_obj();
    match &meta.status {
        Some(e) => {
            w.key("Err");
            write_transaction_error(w, e);
        }
        None => w.kv_null("Ok"),
    }
    w.end_obj();
    w.kv_u64("fee", meta.fee);
    for (key, list) in [("preBalances", &meta.pre_balances), ("postBalances", &meta.post_balances)] {
        w.key(key);
        w.begin_arr();
        for &v in list {
            w.item_u64(v);
        }
        w.end_arr();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MetaForm {
    Json,
    Parsed,
    Accounts,
}

/// Metadata object (§13.8). `keys` is only used by the `Parsed` form for inner instructions.
fn write_meta(w: &mut Writer, meta: &Meta, form: MetaForm, show_rewards: bool, keys: &[&Pubkey]) -> Result<(), RpcError> {
    w.begin_obj();
    write_status(w, meta);
    if form != MetaForm::Accounts {
        w.key("innerInstructions");
        match &meta.inner_instructions {
            None => w.null(),
            Some(list) => {
                w.begin_arr();
                for ii in list {
                    w.item();
                    w.begin_obj();
                    w.kv_u64("index", ii.index as u64);
                    w.key("instructions");
                    w.begin_arr();
                    for ix in &ii.instructions {
                        w.item();
                        if form == MetaForm::Parsed {
                            write_partially_decoded(w, keys, ix.program_id_index, &ix.accounts, &ix.data, ix.stack_height)?;
                        } else {
                            write_compiled(w, ix.program_id_index, &ix.accounts, &ix.data, ix.stack_height);
                        }
                    }
                    w.end_arr();
                    w.end_obj();
                }
                w.end_arr();
            }
        }
        w.key("logMessages");
        match &meta.log_messages {
            None => w.null(),
            Some(list) => {
                w.begin_arr();
                for m in list {
                    w.item_str(m);
                }
                w.end_arr();
            }
        }
    }
    write_token_balances(w, "preTokenBalances", &meta.pre_token_balances);
    write_token_balances(w, "postTokenBalances", &meta.post_token_balances);
    if show_rewards || form != MetaForm::Accounts {
        w.key("rewards");
        match (&meta.rewards, show_rewards) {
            (Some(list), true) => write_rewards(w, list),
            _ => w.null(),
        }
    }
    if form == MetaForm::Json {
        w.key("loadedAddresses");
        w.begin_obj();
        for (key, list) in [("writable", &meta.loaded_writable), ("readonly", &meta.loaded_readonly)] {
            w.key(key);
            w.begin_arr();
            for k in list {
                w.item_str(&b58_encode(k));
            }
            w.end_arr();
        }
        w.end_obj();
    }
    if form != MetaForm::Accounts {
        if let Some(rd) = &meta.return_data {
            w.key("returnData");
            w.begin_obj();
            w.kv_str("programId", &b58_encode(&rd.program_id));
            w.key("data");
            w.begin_arr();
            w.item_str(&b64_encode(&rd.data));
            w.item_str("base64");
            w.end_arr();
            w.end_obj();
        }
        if let Some(v) = meta.compute_units_consumed {
            w.kv_u64("computeUnitsConsumed", v);
        }
        if let Some(v) = meta.cost_units {
            w.kv_u64("costUnits", v);
        }
    }
    w.end_obj();
    Ok(())
}

fn write_version(w: &mut Writer, tx: &VersionedTransaction) {
    w.key("version");
    match tx.version {
        None => w.str("legacy"),
        Some(v) => w.u64(v as u64),
    }
}

fn write_transaction(w: &mut Writer, item: &TxWithMeta, raw: &[u8], opts: &BlockOptions) -> Result<(), RpcError> {
    w.begin_obj();
    match item {
        TxWithMeta::MissingMetadata(tx) => {
            w.key("transaction");
            match (opts.details, opts.encoding) {
                (Details::Accounts, _) => {
                    w.begin_obj();
                    w.key("signatures");
                    write_signatures(w, tx);
                    w.key("accountKeys");
                    write_account_infos(w, &account_infos(tx, None));
                    w.end_obj();
                }
                (_, Encoding::Json) => write_json_transaction(w, tx),
                (_, Encoding::JsonParsed) => write_parsed_transaction(w, tx, None)?,
                (_, Encoding::Base64) => write_binary_transaction(w, tx, raw, true),
                (_, Encoding::Base58) => write_binary_transaction(w, tx, raw, false),
            }
            w.kv_null("meta");
        }
        TxWithMeta::Complete(tx, meta) => {
            let loaded = if tx.version.is_some() { Some(meta) } else { None };
            w.key("transaction");
            if opts.details == Details::Accounts {
                w.begin_obj();
                w.key("signatures");
                write_signatures(w, tx);
                w.key("accountKeys");
                write_account_infos(w, &account_infos(tx, loaded));
                w.end_obj();
                w.key("meta");
                write_meta(w, meta, MetaForm::Accounts, opts.rewards, &[])?;
            } else {
                match opts.encoding {
                    Encoding::Json => write_json_transaction(w, tx),
                    Encoding::JsonParsed => write_parsed_transaction(w, tx, Some(meta))?,
                    Encoding::Base64 => write_binary_transaction(w, tx, raw, true),
                    Encoding::Base58 => write_binary_transaction(w, tx, raw, false),
                }
                w.key("meta");
                if opts.encoding == Encoding::JsonParsed {
                    // Inner instructions resolve against static + loaded keys, even for legacy.
                    let keys = combined_keys(tx, Some(meta));
                    write_meta(w, meta, MetaForm::Parsed, opts.rewards, &keys)?;
                } else {
                    write_meta(w, meta, MetaForm::Json, opts.rewards, &[])?;
                }
            }
            if opts.max_supported_transaction_version.is_some() {
                write_version(w, tx);
            }
        }
    }
    w.end_obj();
    Ok(())
}

/// The `-32015` gate (§13.2): any v0 `Complete` transaction without a max version fails.
pub fn check_versions(txs: &[TxWithMeta], opts: &BlockOptions) -> Result<(), RpcError> {
    if !matches!(opts.details, Details::Full | Details::Accounts) {
        return Ok(());
    }
    for item in txs {
        if let TxWithMeta::Complete(tx, _) = item {
            if let Some(v) = tx.version {
                match opts.max_supported_transaction_version {
                    None => return Err(RpcError::unsupported_version(v)),
                    Some(max) if v > max => return Err(RpcError::unsupported_version(v)),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Serialize the block object. `raw_txs[i]` is the reassembled wire bytes of `txs[i]`.
pub fn write_block(
    w: &mut Writer,
    header: &BlockHeader,
    txs: &[TxWithMeta],
    raw_txs: &[Vec<u8>],
    rewards: Option<&BlockRewards>,
    opts: &BlockOptions,
) -> Result<(), RpcError> {
    check_versions(txs, opts)?;
    w.begin_obj();
    w.kv_str("previousBlockhash", &header.previous_blockhash);
    w.kv_str("blockhash", &header.blockhash);
    w.kv_u64("parentSlot", header.parent_slot);
    match opts.details {
        Details::Full | Details::Accounts => {
            w.key("transactions");
            w.begin_arr();
            for (i, item) in txs.iter().enumerate() {
                w.item();
                write_transaction(w, item, raw_txs.get(i).map_or(&[][..], Vec::as_slice), opts)?;
            }
            w.end_arr();
        }
        Details::Signatures => {
            w.key("signatures");
            w.begin_arr();
            for item in txs {
                let Some(sig) = item.tx().signatures.first() else {
                    return Err(RpcError::internal("transaction has no signatures"));
                };
                w.item_str(&b58_encode(sig));
            }
            w.end_arr();
        }
        Details::None => {}
    }
    if opts.rewards {
        let empty = BlockRewards::default();
        let rewards = rewards.unwrap_or(&empty);
        w.key("rewards");
        write_rewards(w, &rewards.rewards);
        if let Some(n) = rewards.num_partitions {
            w.kv_u64("numRewardPartitions", n);
        }
    }
    w.key("blockTime");
    match header.block_time {
        Some(t) => w.i64(t),
        None => w.null(),
    }
    w.key("blockHeight");
    match header.block_height {
        Some(h) => w.u64(h),
        None => w.null(),
    }
    w.end_obj();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_keys_decode_to_32_bytes() {
        for k in RESERVED_KEYS {
            assert_eq!(b58_decode(k).map(|b| b.len()), Some(32), "{k}");
        }
        assert_eq!(reserved().len(), 31);
        assert!(reserved().contains(&[0u8; 32]));
    }
}
