//! Error types shared by the decoders and the RPC layer.

use std::fmt;

/// A decoding failure. Every one of these becomes JSON-RPC `-32603`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl DecodeError {
    pub fn new(msg: impl Into<String>) -> Self {
        DecodeError(msg.into())
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Shorthand for `Err(DecodeError(format!(...)))`.
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error::DecodeError(format!($($arg)*)))
    };
}

pub type DResult<T> = Result<T, DecodeError>;

/// JSON-RPC error codes (SPEC.md §6).
pub mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    pub const BLOCK_NOT_AVAILABLE: i64 = -32004;
    pub const SLOT_SKIPPED: i64 = -32007;
    pub const UNSUPPORTED_TX_VERSION: i64 = -32015;
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError { code, message: message.into() }
    }
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(codes::INVALID_REQUEST, msg)
    }
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(codes::INVALID_PARAMS, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(codes::INTERNAL_ERROR, msg)
    }
    pub fn method_not_found(method: &str) -> Self {
        Self::new(codes::METHOD_NOT_FOUND, format!("Method not found: {method}"))
    }
    pub fn unsupported_version(version: u8) -> Self {
        Self::new(
            codes::UNSUPPORTED_TX_VERSION,
            format!(
                "Transaction version ({version}) is not supported by the requesting client. \
                 Please try the request again with the following configuration parameter: \
                 \"maxSupportedTransactionVersion\": {version}"
            ),
        )
    }
}

impl From<DecodeError> for RpcError {
    fn from(e: DecodeError) -> Self {
        RpcError::internal(format!("Failed to decode block from Old Faithful CAR: {e}"))
    }
}
