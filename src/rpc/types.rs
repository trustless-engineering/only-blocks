//! JSON-RPC 2.0 request/response types, parameter parsers, and Solana RPC error codes.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use solana_signature::Signature;
use solana_transaction_status::{
    BlockEncodingOptions, EncodeError, TransactionDetails, UiTransactionEncoding,
};

use crate::decoder::DecoderError;
use crate::error::OldFaithfulError;

/// Standard JSON-RPC 2.0 & Solana RPC error codes.
pub mod error_codes {
    /// Invalid JSON was received by the server.
    pub const PARSE_ERROR: i64 = -32700;
    /// The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// The method does not exist / is not available.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Invalid method parameter(s).
    pub const INVALID_PARAMS: i64 = -32602;
    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i64 = -32603;

    /// Solana RPC: Block not available for slot (used here for unarchived slots / historical-only).
    pub const BLOCK_NOT_AVAILABLE: i64 = -32004;
    /// Solana RPC: Slot was skipped, or missing due to ledger jump to recent snapshot.
    pub const SLOT_SKIPPED: i64 = -32007;
    /// Solana RPC: Transaction version is not supported by the requesting client.
    pub const UNSUPPORTED_TRANSACTION_VERSION: i64 = -32015;
}

/// Incoming JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    #[serde(default)]
    pub id: Value,
    pub method: Option<String>,
    #[serde(default)]
    pub params: Option<Value>,
}

/// Outgoing JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self::new(error_codes::PARSE_ERROR, msg)
    }

    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(error_codes::INVALID_REQUEST, msg)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            error_codes::METHOD_NOT_FOUND,
            format!("Method not found: {method}"),
        )
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(error_codes::INVALID_PARAMS, msg)
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::new(error_codes::INTERNAL_ERROR, msg)
    }

    pub fn from_old_faithful_error(err: &OldFaithfulError) -> Self {
        match err {
            OldFaithfulError::SkippedSlot { slot } => Self::new(
                error_codes::SLOT_SKIPPED,
                format!("Slot {slot} was skipped, or missing in long-term storage"),
            ),
            OldFaithfulError::UnarchivedSlot { slot, epoch } => Self::new(
                error_codes::BLOCK_NOT_AVAILABLE,
                format!(
                    "Block not available for slot {slot}: epoch {epoch} is not archived in Old Faithful (historical-only server)"
                ),
            ),
            other => Self::internal_error(other.to_string()),
        }
    }

    pub fn from_encode_error(err: &EncodeError) -> Self {
        match err {
            EncodeError::UnsupportedTransactionVersion(v) => Self::new(
                error_codes::UNSUPPORTED_TRANSACTION_VERSION,
                format!(
                    "Transaction version ({v}) is not supported by the requesting client. Please try the request again with the following configuration parameter: \"maxSupportedTransactionVersion\": 0"
                ),
            ),
        }
    }

    pub fn from_decoder_error(err: &DecoderError) -> Self {
        Self::internal_error(format!(
            "Failed to decode block from Old Faithful CAR: {err}"
        ))
    }
}

/// Outgoing JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

impl JsonRpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn err(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// Parsed and validated parameters for Solana `getBlock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlockParams {
    pub slot: u64,
    pub encoding: UiTransactionEncoding,
    pub transaction_details: TransactionDetails,
    pub show_rewards: bool,
    pub max_supported_transaction_version: Option<u8>,
}

impl GetBlockParams {
    pub fn block_encoding_options(&self) -> BlockEncodingOptions {
        BlockEncodingOptions {
            transaction_details: self.transaction_details,
            show_rewards: self.show_rewards,
            max_supported_transaction_version: self.max_supported_transaction_version,
        }
    }

    /// Parse and validate JSON-RPC `params` for `getBlock`.
    ///
    /// Supports:
    /// - `[slot]`
    /// - `[slot, "json" | "jsonParsed" | "base64" | "base58"]`
    /// - `[slot, { encoding?, transactionDetails?, rewards?, maxSupportedTransactionVersion?, commitment? }]`
    pub fn from_rpc_params(params: Option<&Value>) -> Result<Self, JsonRpcError> {
        let arr = match params {
            Some(Value::Array(arr)) => arr,
            _ => {
                return Err(JsonRpcError::invalid_params(
                    "Invalid params: expected array [slot] or [slot, config]",
                ));
            }
        };

        if arr.is_empty() || arr.len() > 2 {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid params: expected 1 or 2 parameters, got {}",
                arr.len()
            )));
        }

        let slot = arr[0].as_u64().ok_or_else(|| {
            JsonRpcError::invalid_params("Invalid params: slot must be a non-negative integer")
        })?;

        let mut encoding = UiTransactionEncoding::Json;
        let mut transaction_details = TransactionDetails::Full;
        let mut show_rewards = true;
        let mut max_supported_transaction_version = None;

        if let Some(cfg_val) = arr.get(1) {
            match cfg_val {
                Value::Null => {}
                Value::String(enc_str) => {
                    encoding = parse_block_encoding(enc_str)?;
                }
                Value::Object(map) => {
                    if let Some(v) = map.get("encoding") {
                        if let Some(enc) = parse_encoding_value(v)? {
                            encoding = enc;
                        }
                    }

                    if let Some(v) = map.get("transactionDetails") {
                        if !v.is_null() {
                            let s = v.as_str().ok_or_else(|| {
                                JsonRpcError::invalid_params(
                                    "Invalid params: transactionDetails must be a string",
                                )
                            })?;
                            transaction_details = parse_transaction_details(s)?;
                        }
                    }

                    if let Some(v) = map.get("rewards") {
                        if !v.is_null() {
                            show_rewards = v.as_bool().ok_or_else(|| {
                                JsonRpcError::invalid_params(
                                    "Invalid params: rewards must be a boolean",
                                )
                            })?;
                        }
                    }

                    if let Some(v) = map.get("maxSupportedTransactionVersion") {
                        max_supported_transaction_version =
                            parse_max_supported_transaction_version(v)?;
                    }

                    if let Some(v) = map.get("commitment") {
                        parse_commitment(v, "getBlock")?;
                    }
                }
                _ => {
                    return Err(JsonRpcError::invalid_params(
                        "Invalid params: second parameter must be a config object or encoding string",
                    ));
                }
            }
        }

        // Match Solana RPC behavior: `transactionDetails: "accounts"` is only valid with `json`.
        if transaction_details == TransactionDetails::Accounts
            && !matches!(encoding, UiTransactionEncoding::Json)
        {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid params: encoding '{encoding}' is not supported with transactionDetails 'accounts'"
            )));
        }

        Ok(Self {
            slot,
            encoding,
            transaction_details,
            show_rewards,
            max_supported_transaction_version,
        })
    }
}

/// Parsed and validated parameters for slot-hinted Solana `getTransaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetTransactionParams {
    pub signature: Signature,
    pub slot: u64,
    pub encoding: UiTransactionEncoding,
    pub max_supported_transaction_version: Option<u8>,
}

impl GetTransactionParams {
    /// Parse and validate JSON-RPC `params` for slot-hinted `getTransaction`.
    ///
    /// Requires:
    /// `["<base58-signature>", { "slot": <u64>, "encoding"?: "...", "maxSupportedTransactionVersion"?: <u8>, "commitment"?: "..." }]`
    pub fn from_rpc_params(params: Option<&Value>) -> Result<Self, JsonRpcError> {
        let arr = match params {
            Some(Value::Array(arr)) => arr,
            _ => {
                return Err(JsonRpcError::invalid_params(
                    "Invalid params: expected array [signature, { \"slot\": <u64>, ... }]",
                ));
            }
        };

        if arr.is_empty() || arr.len() > 2 {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid params: expected 2 parameters [signature, config] for getTransaction, got {}",
                arr.len()
            )));
        }

        let sig_str = arr[0].as_str().ok_or_else(|| {
            JsonRpcError::invalid_params(
                "Invalid params: transaction signature must be a base58-encoded string",
            )
        })?;
        let signature = parse_signature(sig_str)?;

        let Some(cfg_val) = arr.get(1) else {
            return Err(JsonRpcError::invalid_params(
                "Invalid params: instant-rpc requires a 'slot' hint in the getTransaction config object (params: [signature, { \"slot\": <u64>, ... }])",
            ));
        };

        let Value::Object(map) = cfg_val else {
            return Err(JsonRpcError::invalid_params(
                "Invalid params: instant-rpc requires a config object with a 'slot' hint for getTransaction (params: [signature, { \"slot\": <u64>, ... }])",
            ));
        };

        let slot = match map.get("slot") {
            Some(v) if !v.is_null() => v.as_u64().ok_or_else(|| {
                JsonRpcError::invalid_params(
                    "Invalid params: instant-rpc requires a 'slot' hint (non-negative integer) for getTransaction",
                )
            })?,
            _ => {
                return Err(JsonRpcError::invalid_params(
                    "Invalid params: instant-rpc requires a 'slot' hint for getTransaction (provide { \"slot\": <u64> })",
                ));
            }
        };

        let mut encoding = UiTransactionEncoding::Json;
        if let Some(v) = map.get("encoding") {
            if let Some(enc) = parse_encoding_value(v)? {
                encoding = enc;
            }
        }

        let max_supported_transaction_version = match map.get("maxSupportedTransactionVersion") {
            Some(v) => parse_max_supported_transaction_version(v)?,
            None => None,
        };

        if let Some(v) = map.get("commitment") {
            parse_commitment(v, "getTransaction")?;
        }

        Ok(Self {
            signature,
            slot,
            encoding,
            max_supported_transaction_version,
        })
    }
}

/// Parse and validate a base58-encoded 64-byte Solana transaction [`Signature`].
pub fn parse_signature(s: &str) -> Result<Signature, JsonRpcError> {
    let mut buf = [0u8; 64];
    match bs58::decode(s).onto(&mut buf) {
        Ok(64) => Ok(Signature::from(buf)),
        Ok(len) => Err(JsonRpcError::invalid_params(format!(
            "Invalid params: invalid transaction signature length (expected 64 bytes, got {len})"
        ))),
        Err(bs58::decode::Error::BufferTooSmall) => Err(JsonRpcError::invalid_params(
            "Invalid params: invalid transaction signature (decoded length exceeds 64 bytes)",
        )),
        Err(e) => Err(JsonRpcError::invalid_params(format!(
            "Invalid params: invalid base58 transaction signature: {e}"
        ))),
    }
}

/// Parse one of the 4 supported Solana transaction encodings (`json`, `jsonParsed`, `base64`, `base58`).
pub fn parse_transaction_encoding(s: &str) -> Result<UiTransactionEncoding, JsonRpcError> {
    match s {
        "json" => Ok(UiTransactionEncoding::Json),
        "jsonParsed" => Ok(UiTransactionEncoding::JsonParsed),
        "base64" => Ok(UiTransactionEncoding::Base64),
        "base58" => Ok(UiTransactionEncoding::Base58),
        other => Err(JsonRpcError::invalid_params(format!(
            "Invalid params: unsupported encoding '{other}' (expected json, jsonParsed, base64, or base58)"
        ))),
    }
}

/// Alias for [`parse_transaction_encoding`] preserved for `getBlock` callers.
pub fn parse_block_encoding(s: &str) -> Result<UiTransactionEncoding, JsonRpcError> {
    parse_transaction_encoding(s)
}

fn parse_encoding_value(v: &Value) -> Result<Option<UiTransactionEncoding>, JsonRpcError> {
    if v.is_null() {
        return Ok(None);
    }
    let s = v
        .as_str()
        .ok_or_else(|| JsonRpcError::invalid_params("Invalid params: encoding must be a string"))?;
    parse_transaction_encoding(s).map(Some)
}

fn parse_max_supported_transaction_version(v: &Value) -> Result<Option<u8>, JsonRpcError> {
    if v.is_null() {
        return Ok(None);
    }
    let n = v.as_u64().ok_or_else(|| {
        JsonRpcError::invalid_params(
            "Invalid params: maxSupportedTransactionVersion must be a non-negative integer",
        )
    })?;
    let ver = u8::try_from(n).map_err(|_| {
        JsonRpcError::invalid_params(
            "Invalid params: maxSupportedTransactionVersion must fit in u8 (0..=255)",
        )
    })?;
    Ok(Some(ver))
}

fn parse_commitment(v: &Value, method: &str) -> Result<(), JsonRpcError> {
    if v.is_null() {
        return Ok(());
    }
    let s = v.as_str().ok_or_else(|| {
        JsonRpcError::invalid_params("Invalid params: commitment must be a string")
    })?;
    match s {
        "finalized" | "confirmed" => Ok(()),
        "processed" => Err(JsonRpcError::invalid_params(format!(
            "Invalid params: commitment 'processed' is not supported for {method}"
        ))),
        other => Err(JsonRpcError::invalid_params(format!(
            "Invalid params: unknown commitment '{other}'"
        ))),
    }
}

fn parse_transaction_details(s: &str) -> Result<TransactionDetails, JsonRpcError> {
    match s {
        "full" => Ok(TransactionDetails::Full),
        "accounts" => Ok(TransactionDetails::Accounts),
        "signatures" => Ok(TransactionDetails::Signatures),
        "none" => Ok(TransactionDetails::None),
        other => Err(JsonRpcError::invalid_params(format!(
            "Invalid params: unsupported transactionDetails '{other}' (expected full, accounts, signatures, or none)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_get_block_defaults_and_shorthand_and_full_config() {
        let p = GetBlockParams::from_rpc_params(Some(&json!([302400001]))).expect("defaults");
        assert_eq!(p.slot, 302_400_001);
        assert_eq!(p.encoding, UiTransactionEncoding::Json);
        assert_eq!(p.transaction_details, TransactionDetails::Full);
        assert!(p.show_rewards);
        assert_eq!(p.max_supported_transaction_version, None);

        let p2 =
            GetBlockParams::from_rpc_params(Some(&json!([42, "jsonParsed"]))).expect("shorthand");
        assert_eq!(p2.encoding, UiTransactionEncoding::JsonParsed);

        let p3 = GetBlockParams::from_rpc_params(Some(&json!([
            302400000,
            {
                "encoding": "base64",
                "transactionDetails": "signatures",
                "rewards": false,
                "maxSupportedTransactionVersion": 0,
                "commitment": "finalized"
            }
        ])))
        .expect("full config");
        assert_eq!(p3.encoding, UiTransactionEncoding::Base64);
        assert_eq!(p3.transaction_details, TransactionDetails::Signatures);
        assert!(!p3.show_rewards);
        assert_eq!(p3.max_supported_transaction_version, Some(0));

        let p4 = GetBlockParams::from_rpc_params(Some(&json!([
            10,
            { "encoding": "base58", "transactionDetails": "none" }
        ])))
        .expect("base58");
        assert_eq!(p4.encoding, UiTransactionEncoding::Base58);
        assert_eq!(p4.transaction_details, TransactionDetails::None);
    }

    #[test]
    fn rejects_invalid_get_block_params() {
        for bad in [
            json!([]),
            json!(["not-a-slot"]),
            json!([-1]),
            json!([1, "invalidEncoding"]),
            json!([1, { "encoding": "base64+zstd" }]),
            json!([1, { "transactionDetails": "bogus" }]),
            json!([1, { "rewards": "yes" }]),
            json!([1, { "maxSupportedTransactionVersion": -1 }]),
            json!([1, { "maxSupportedTransactionVersion": 300 }]),
            json!([1, { "commitment": "processed" }]),
            json!([1, { "encoding": "base64", "transactionDetails": "accounts" }]),
            json!([1, {}, "extra"]),
            json!({ "slot": 1 }),
        ] {
            let err = GetBlockParams::from_rpc_params(Some(&bad))
                .expect_err(&format!("expected invalid params for {bad}"));
            assert_eq!(err.code, error_codes::INVALID_PARAMS);
        }
    }

    #[test]
    fn maps_errors_to_expected_solana_jsonrpc_codes() {
        let skipped = JsonRpcError::from_old_faithful_error(&OldFaithfulError::SkippedSlot {
            slot: 302_400_004,
        });
        assert_eq!(skipped.code, error_codes::SLOT_SKIPPED);
        assert!(skipped.message.contains("302400004"));

        let unarchived = JsonRpcError::from_old_faithful_error(&OldFaithfulError::UnarchivedSlot {
            slot: 4_319_568_000,
            epoch: 9999,
        });
        assert_eq!(unarchived.code, error_codes::BLOCK_NOT_AVAILABLE);
        assert!(unarchived.message.contains("historical-only"));

        let ver = JsonRpcError::from_encode_error(&EncodeError::UnsupportedTransactionVersion(0));
        assert_eq!(ver.code, error_codes::UNSUPPORTED_TRANSACTION_VERSION);
        assert!(ver.message.contains("maxSupportedTransactionVersion"));
    }

    #[test]
    fn parses_get_transaction_defaults_and_full_config() {
        let sig = Signature::from([42u8; 64]);
        let sig_str = sig.to_string();

        let p = GetTransactionParams::from_rpc_params(Some(&json!([
            sig_str,
            { "slot": 302_400_001 }
        ])))
        .expect("defaults");
        assert_eq!(p.signature, sig);
        assert_eq!(p.slot, 302_400_001);
        assert_eq!(p.encoding, UiTransactionEncoding::Json);
        assert_eq!(p.max_supported_transaction_version, None);

        for (enc_str, expected_enc) in [
            ("json", UiTransactionEncoding::Json),
            ("jsonParsed", UiTransactionEncoding::JsonParsed),
            ("base64", UiTransactionEncoding::Base64),
            ("base58", UiTransactionEncoding::Base58),
        ] {
            let p = GetTransactionParams::from_rpc_params(Some(&json!([
                sig_str,
                {
                    "slot": 43_200_000,
                    "encoding": enc_str,
                    "maxSupportedTransactionVersion": 0,
                    "commitment": "confirmed"
                }
            ])))
            .expect(enc_str);
            assert_eq!(p.slot, 43_200_000);
            assert_eq!(p.encoding, expected_enc);
            assert_eq!(p.max_supported_transaction_version, Some(0));
        }

        // Explicit null optional fields fall back to defaults.
        let p_nulls = GetTransactionParams::from_rpc_params(Some(&json!([
            sig_str,
            {
                "slot": 0,
                "encoding": null,
                "maxSupportedTransactionVersion": null,
                "commitment": null
            }
        ])))
        .expect("null optionals");
        assert_eq!(p_nulls.slot, 0);
        assert_eq!(p_nulls.encoding, UiTransactionEncoding::Json);
        assert_eq!(p_nulls.max_supported_transaction_version, None);
    }

    #[test]
    fn rejects_missing_or_invalid_slot_hint_and_invalid_get_transaction_params() {
        let sig_str = Signature::from([7u8; 64]).to_string();

        // Missing or invalid `slot` hint must return -32602 with a clear message mentioning `slot`.
        for bad_slot in [
            json!([sig_str]),
            json!([sig_str, null]),
            json!([sig_str, "json"]),
            json!([sig_str, {}]),
            json!([sig_str, { "slot": null }]),
            json!([sig_str, { "slot": -1 }]),
            json!([sig_str, { "slot": 1.5 }]),
            json!([sig_str, { "slot": "302400001" }]),
            json!([sig_str, { "slot": true }]),
        ] {
            let err = GetTransactionParams::from_rpc_params(Some(&bad_slot)).expect_err(&format!(
                "expected missing/invalid slot error for {bad_slot}"
            ));
            assert_eq!(err.code, error_codes::INVALID_PARAMS);
            assert!(
                err.message.contains("slot"),
                "expected 'slot' hint in error message, got: {}",
                err.message
            );
        }

        // Invalid signature / encoding / commitment / version / arity -> -32602.
        let too_short_base58 = bs58::encode([1u8; 32]).into_string();
        let too_long_base58 = bs58::encode([1u8; 65]).into_string();
        for bad in [
            json!([]),
            json!({ "signature": sig_str, "slot": 1 }),
            json!([12345, { "slot": 1 }]),
            json!(["", { "slot": 1 }]),
            json!(["not-valid-base58-0OIl", { "slot": 1 }]),
            json!([too_short_base58, { "slot": 1 }]),
            json!([too_long_base58, { "slot": 1 }]),
            json!([sig_str, { "slot": 1, "encoding": "base64+zstd" }]),
            json!([sig_str, { "slot": 1, "encoding": 42 }]),
            json!([sig_str, { "slot": 1, "commitment": "processed" }]),
            json!([sig_str, { "slot": 1, "commitment": "bogus" }]),
            json!([sig_str, { "slot": 1, "commitment": 123 }]),
            json!([sig_str, { "slot": 1, "maxSupportedTransactionVersion": -1 }]),
            json!([sig_str, { "slot": 1, "maxSupportedTransactionVersion": 256 }]),
            json!([sig_str, { "slot": 1, "maxSupportedTransactionVersion": "0" }]),
            json!([sig_str, { "slot": 1 }, "extra"]),
        ] {
            let err = GetTransactionParams::from_rpc_params(Some(&bad))
                .expect_err(&format!("expected invalid params for {bad}"));
            assert_eq!(err.code, error_codes::INVALID_PARAMS);
        }

        assert!(GetTransactionParams::from_rpc_params(None).is_err());
    }
}
