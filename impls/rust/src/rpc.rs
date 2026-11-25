//! JSON-RPC 2.0 envelope handling, `getBlock` parameter validation and the `getBlock`
//! pipeline (SPEC.md §4.5 and §5).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

use crate::block::{block_header, decode_block_rewards, decode_transactions};
use crate::car::CarIndex;
use crate::codec::b58_encode;
use crate::encode::{write_block, BlockHeader, BlockOptions, Details, Encoding};
use crate::error::{codes, RpcError};
use crate::json::{self, Json, Writer};
use crate::lru::Lru;
use crate::old_faithful::{FetchError, OldFaithful, SLOTS_PER_EPOCH};

pub const MAX_BATCH: usize = 100;
const DEFAULT_HASH: &str = "11111111111111111111111111111111";

pub struct Service {
    pub client: OldFaithful,
    blockhash_cache: Mutex<Lru<u64, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlockParams {
    pub slot: u64,
    pub options: BlockOptions,
}

impl Service {
    pub fn new(client: OldFaithful, blockhash_cache_capacity: usize) -> Self {
        Service { client, blockhash_cache: Mutex::new(Lru::new(blockhash_cache_capacity)) }
    }

    /// Handle one HTTP request body and return the JSON response text.
    pub fn handle_body(&self, body: &[u8]) -> String {
        let value = match json::parse(body) {
            Ok(v) => v,
            Err(e) => return error_response(&Json::Null, &RpcError::new(codes::PARSE_ERROR, format!("Parse error: {e}"))),
        };
        match &value {
            Json::Object(_) => self.dispatch(&value),
            Json::Array(items) if items.is_empty() => {
                error_response(&Json::Null, &RpcError::invalid_request("Invalid Request: empty batch"))
            }
            Json::Array(items) if items.len() > MAX_BATCH => error_response(
                &Json::Null,
                &RpcError::invalid_request(format!("Invalid Request: batch size {} exceeds maximum {MAX_BATCH}", items.len())),
            ),
            Json::Array(items) => {
                // Sequential, in order, one response per item.
                let mut out = String::from("[");
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if matches!(item, Json::Object(_)) {
                        out.push_str(&self.dispatch(item));
                    } else {
                        out.push_str(&error_response(
                            &Json::Null,
                            &RpcError::invalid_request("Invalid Request: batch item is not an object"),
                        ));
                    }
                }
                out.push(']');
                out
            }
            _ => error_response(&Json::Null, &RpcError::invalid_request("Invalid Request: expected JSON object or array")),
        }
    }

    /// Dispatch one request object; a panic anywhere below becomes `-32603`.
    fn dispatch(&self, req: &Json) -> String {
        match catch_unwind(AssertUnwindSafe(|| self.dispatch_inner(req))) {
            Ok(s) => s,
            Err(_) => {
                let id = req.get("id").filter(|id| valid_id(id)).cloned().unwrap_or(Json::Null);
                error_response(&id, &RpcError::internal("Internal error: request handler panicked"))
            }
        }
    }

    fn dispatch_inner(&self, req: &Json) -> String {
        // serde-style envelope typing: `jsonrpc`/`method` must be strings when present.
        for key in ["jsonrpc", "method"] {
            if let Some(v) = req.get(key) {
                if !matches!(v, Json::Str(_) | Json::Null) {
                    return error_response(&Json::Null, &RpcError::invalid_request(format!("Invalid Request: `{key}` must be a string")));
                }
            }
        }
        let id = req.get("id").cloned().unwrap_or(Json::Null);
        if !valid_id(&id) {
            return error_response(&Json::Null, &RpcError::invalid_request("Invalid Request: id must be a string, number, or null"));
        }
        if req.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
            return error_response(&id, &RpcError::invalid_request("Invalid Request: jsonrpc must be \"2.0\""));
        }
        let Some(method) = req.get("method").and_then(Json::as_str) else {
            return error_response(&id, &RpcError::invalid_request("Invalid Request: missing method"));
        };
        let params = req.get("params").filter(|p| !p.is_null());
        match method {
            "getHealth" => match params {
                None => ok_response(&id, "\"ok\""),
                Some(Json::Array(a)) if a.is_empty() => ok_response(&id, "\"ok\""),
                Some(_) => error_response(&id, &RpcError::invalid_params("Invalid params: getHealth expects no parameters")),
            },
            "getBlock" => match parse_get_block_params(params).and_then(|p| self.get_block_response(&p, &id)) {
                Ok(response) => response,
                Err(e) => {
                    if e.code == codes::INTERNAL_ERROR {
                        eprintln!("onlyblocks: getBlock failed: {}", e.message);
                    }
                    error_response(&id, &e)
                }
            },
            // Everything else, getTransaction included: no params parsing, no network.
            other => error_response(&id, &RpcError::method_not_found(other)),
        }
    }

    fn cached_blockhash(&self, slot: u64) -> Option<String> {
        self.blockhash_cache.lock().unwrap_or_else(|e| e.into_inner()).get(&slot)
    }

    fn cache_blockhash(&self, slot: u64, hash: String) {
        self.blockhash_cache.lock().unwrap_or_else(|e| e.into_inner()).put(slot, hash);
    }

    fn previous_blockhash(&self, slot: u64, parent_slot: u64) -> Result<String, RpcError> {
        if slot == 0 {
            return Ok(DEFAULT_HASH.to_string());
        }
        if let Some(hash) = self.cached_blockhash(parent_slot) {
            return Ok(hash);
        }
        let parent = self.client.fetch_slot_car(parent_slot).map_err(fetch_error)?;
        let index = CarIndex::parse(&parent)?;
        // The parent's own `Block.slot` is deliberately not checked.
        let (_, hash) = block_header(&index, None)?;
        let hash = b58_encode(&hash);
        self.cache_blockhash(parent_slot, hash.clone());
        Ok(hash)
    }

    /// The full JSON-RPC success response, with the block streamed straight into it (no copy
    /// of a possibly 100+ MB result).
    fn get_block_response(&self, p: &GetBlockParams, id: &Json) -> Result<String, RpcError> {
        let mut w = Writer::new();
        w.raw("{\"jsonrpc\":\"2.0\",\"result\":");
        self.write_get_block(p, &mut w)?;
        w.raw(",\"id\":");
        id.write_to(&mut w.out);
        w.raw("}");
        Ok(w.out)
    }

    /// The bare `getBlock` result object.
    pub fn get_block(&self, p: &GetBlockParams) -> Result<String, RpcError> {
        let mut w = Writer::new();
        self.write_get_block(p, &mut w)?;
        Ok(w.out)
    }

    fn write_get_block(&self, p: &GetBlockParams, w: &mut Writer) -> Result<(), RpcError> {
        let opts = &p.options;
        let car = self.client.fetch_slot_car(p.slot).map_err(fetch_error)?;
        let index = CarIndex::parse(&car)?;
        let (block, hash) = block_header(&index, Some(p.slot))?;
        let blockhash = b58_encode(&hash);
        self.cache_blockhash(p.slot, blockhash.clone());
        let previous_blockhash = self.previous_blockhash(p.slot, block.parent_slot)?;

        let (txs, raw) = if opts.details == Details::None {
            (Vec::new(), Vec::new())
        } else {
            let with_meta = matches!(opts.details, Details::Full | Details::Accounts);
            let keep_raw = opts.details == Details::Full && matches!(opts.encoding, Encoding::Base64 | Encoding::Base58);
            decode_transactions(p.slot, &index, &block, with_meta, keep_raw)?
        };
        let rewards = if opts.rewards { Some(decode_block_rewards(p.slot, &index, &block)?) } else { None };
        let header = BlockHeader {
            previous_blockhash,
            blockhash,
            parent_slot: block.parent_slot,
            block_time: block.block_time,
            block_height: block.block_height,
        };
        let hint = match opts.details {
            Details::Full | Details::Accounts => (car.len() * 2).min(64 << 20),
            Details::Signatures => txs.len() * 92,
            Details::None => 0,
        };
        w.out.reserve(4096 + hint + rewards.as_ref().map_or(0, |r| r.rewards.len() * 140));
        drop(car);
        write_block(w, &header, &txs, &raw, rewards.as_ref(), opts)
    }
}

fn valid_id(id: &Json) -> bool {
    matches!(id, Json::Null | Json::Str(_) | Json::Number(_))
}

fn fetch_error(e: FetchError) -> RpcError {
    match e {
        FetchError::Skipped { slot } => {
            RpcError::new(codes::SLOT_SKIPPED, format!("Slot {slot} was skipped, or missing in long-term storage"))
        }
        FetchError::Unarchived { slot, epoch } => RpcError::new(
            codes::BLOCK_NOT_AVAILABLE,
            format!(
                "Block not available for slot {slot}: epoch {epoch} is not archived in Old Faithful (historical-only server)"
            ),
        ),
        FetchError::Internal(m) => RpcError::internal(m),
    }
}

fn ok_response(id: &Json, result: &str) -> String {
    let mut out = String::with_capacity(result.len() + 48);
    out.push_str("{\"jsonrpc\":\"2.0\",\"result\":");
    out.push_str(result);
    out.push_str(",\"id\":");
    id.write_to(&mut out);
    out.push('}');
    out
}

pub fn error_response(id: &Json, e: &RpcError) -> String {
    let mut w = Writer::new();
    w.begin_obj();
    w.kv_str("jsonrpc", "2.0");
    w.key("error");
    w.begin_obj();
    w.key("code");
    w.i64(e.code);
    w.kv_str("message", if e.message.is_empty() { "error" } else { &e.message });
    w.end_obj();
    w.key("id");
    id.write_to(&mut w.out);
    w.end_obj();
    w.out
}

fn invalid(msg: impl Into<String>) -> RpcError {
    RpcError::invalid_params(format!("Invalid params: {}", msg.into()))
}

fn parse_encoding(v: &str) -> Result<Encoding, RpcError> {
    match v {
        "json" => Ok(Encoding::Json),
        "jsonParsed" => Ok(Encoding::JsonParsed),
        "base64" => Ok(Encoding::Base64),
        "base58" => Ok(Encoding::Base58),
        other => Err(invalid(format!(
            "unsupported encoding '{other}' (expected json, jsonParsed, base64, or base58)"
        ))),
    }
}

/// SPEC.md §5.4.
pub fn parse_get_block_params(params: Option<&Json>) -> Result<GetBlockParams, RpcError> {
    let Some(Json::Array(arr)) = params else { return Err(invalid("expected array [slot] or [slot, config]")) };
    if arr.is_empty() || arr.len() > 2 {
        return Err(invalid(format!("expected 1 or 2 parameters, got {}", arr.len())));
    }
    let Some(slot) = arr[0].as_u64() else { return Err(invalid("slot must be a non-negative integer")) };
    let mut options = BlockOptions {
        encoding: Encoding::Json,
        details: Details::Full,
        rewards: true,
        max_supported_transaction_version: None,
    };
    match arr.get(1) {
        None | Some(Json::Null) => {}
        Some(Json::Str(s)) => options.encoding = parse_encoding(s)?,
        Some(cfg @ Json::Object(_)) => {
            let field = |k: &str| cfg.get(k).filter(|v| !v.is_null());
            if let Some(v) = field("encoding") {
                options.encoding = parse_encoding(v.as_str().ok_or_else(|| invalid("encoding must be a string"))?)?;
            }
            if let Some(v) = field("transactionDetails") {
                options.details = match v.as_str().ok_or_else(|| invalid("transactionDetails must be a string"))? {
                    "full" => Details::Full,
                    "accounts" => Details::Accounts,
                    "signatures" => Details::Signatures,
                    "none" => Details::None,
                    other => return Err(invalid(format!("unsupported transactionDetails '{other}'"))),
                };
            }
            if let Some(v) = field("rewards") {
                options.rewards = v.as_bool().ok_or_else(|| invalid("rewards must be a boolean"))?;
            }
            if let Some(v) = field("maxSupportedTransactionVersion") {
                let n = v.as_u64().ok_or_else(|| invalid("maxSupportedTransactionVersion must be a non-negative integer"))?;
                let n = u8::try_from(n).map_err(|_| invalid("maxSupportedTransactionVersion must fit in u8 (0..=255)"))?;
                options.max_supported_transaction_version = Some(n);
            }
            if let Some(v) = field("commitment") {
                match v.as_str().ok_or_else(|| invalid("commitment must be a string"))? {
                    "finalized" | "confirmed" => {}
                    "processed" => return Err(invalid("commitment 'processed' is not supported for getBlock")),
                    other => return Err(invalid(format!("unknown commitment '{other}'"))),
                }
            }
        }
        Some(_) => return Err(invalid("second parameter must be a config object or encoding string")),
    }
    if options.encoding == Encoding::Base58
        && options.max_supported_transaction_version.is_some_and(|v| v >= 1)
    {
        return Err(RpcError::invalid_params(
            "base58 encoding is not supported with maxSupportedTransactionVersion >= 1",
        ));
    }
    if options.details == Details::Accounts && options.encoding != Encoding::Json {
        return Err(invalid("transactionDetails 'accounts' requires encoding 'json'"));
    }
    Ok(GetBlockParams { slot, options })
}

/// Convenience for tools/tests: the epoch a slot lives in.
pub fn epoch_of(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(s: &str) -> Result<GetBlockParams, RpcError> {
        parse_get_block_params(Some(&json::parse(s.as_bytes()).unwrap()))
    }

    #[test]
    fn get_block_params() {
        let p = params("[302400001]").unwrap();
        assert_eq!(p.slot, 302_400_001);
        assert_eq!(p.options.encoding, Encoding::Json);
        assert!(p.options.rewards);
        assert_eq!(params("[42, \"jsonParsed\"]").unwrap().options.encoding, Encoding::JsonParsed);
        let p = params(r#"[1, {"encoding":"base64","transactionDetails":"signatures","rewards":false,"maxSupportedTransactionVersion":0,"commitment":"finalized","unknown":7}]"#).unwrap();
        assert_eq!(p.options.details, Details::Signatures);
        assert_eq!(p.options.max_supported_transaction_version, Some(0));
        assert!(!p.options.rewards);
        assert_eq!(params("[1, null]").unwrap().options.details, Details::Full);
        assert_eq!(params(r#"[1, {"maxSupportedTransactionVersion":255}]"#).unwrap().options.max_supported_transaction_version, Some(255));
        for bad in [
            "[]", "[\"1\"]", "[-1]", "[1.0]", "[1e3]", "[true]", "[18446744073709551616]", "[1, 2, 3]", "{\"slot\":1}",
            "[1, \"binary\"]", "[1, \"base64+zstd\"]", "[1, 5]", "[1, {\"encoding\":5}]",
            "[1, {\"transactionDetails\":\"bogus\"}]", "[1, {\"rewards\":\"yes\"}]",
            "[1, {\"maxSupportedTransactionVersion\":-1}]", "[1, {\"maxSupportedTransactionVersion\":256}]",
            "[1, {\"maxSupportedTransactionVersion\":0.5}]", "[1, {\"commitment\":\"processed\"}]",
            "[1, {\"commitment\":\"recent\"}]", "[1, {\"commitment\":1}]",
            "[1, {\"encoding\":\"base64\",\"transactionDetails\":\"accounts\"}]",
        ] {
            assert_eq!(params(bad).map_err(|e| e.code), Err(codes::INVALID_PARAMS), "{bad}");
        }
        assert_eq!(parse_get_block_params(None).map_err(|e| e.code), Err(codes::INVALID_PARAMS));
    }
}
