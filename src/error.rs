use thiserror::Error;

/// Errors returned by the Old Faithful Range transport.
#[derive(Debug, Error)]
pub enum OldFaithfulError {
    /// Client configuration is invalid or the HTTP client could not be constructed.
    #[error("invalid Old Faithful client configuration: {0}")]
    InvalidConfig(String),

    /// The slot exists in an archived epoch, but was skipped (`length == 0` in `slot-ranges.raw`).
    #[error("slot {slot} was skipped (no block produced)")]
    SkippedSlot { slot: u64 },

    /// The epoch/slot is not present in Old Faithful (HTTP 404; historical-only archive).
    #[error("slot {slot} (epoch {epoch}) is not archived in Old Faithful (historical-only)")]
    UnarchivedSlot { slot: u64, epoch: u64 },

    /// The CAR slice exceeds the configured maximum byte limit.
    #[error(
        "slot {slot} CAR slice size {length} bytes exceeds max_slice_bytes ({max_bytes} bytes)"
    )]
    SliceTooLarge {
        slot: u64,
        length: u64,
        max_bytes: u64,
    },

    /// A `slot-ranges.raw` entry did not contain exactly 12 bytes.
    #[error("invalid slot-ranges.raw entry for slot {slot}: expected 12 bytes, got {actual_len}")]
    InvalidSlotRangeEntry { slot: u64, actual_len: usize },

    /// Byte range calculation overflowed `u64`.
    #[error("byte range arithmetic overflow for slot {slot} (offset={offset}, length={length})")]
    ArithmeticOverflow { slot: u64, offset: u64, length: u32 },

    /// Upstream returned a non-retryable unexpected HTTP status (for example `200` instead of `206`).
    #[error("unexpected HTTP status {status} from {url} (expected {expected})")]
    UnexpectedStatus {
        url: String,
        status: u16,
        expected: u16,
    },

    /// The response body length did not match the requested byte range length.
    #[error("byte length mismatch from {url}: expected {expected} bytes, got {actual} bytes")]
    LengthMismatch {
        url: String,
        expected: u64,
        actual: u64,
    },

    /// Retries were exhausted after repeated `429` or `5xx` responses.
    #[error("HTTP {status} from {url} after {attempts} attempt(s)")]
    HttpRetryExhausted {
        url: String,
        status: u16,
        attempts: usize,
    },

    /// A transport/network error persisted after all retry attempts.
    #[error("HTTP transport error for {url}: {source}")]
    Transport {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    /// Internal concurrency semaphore was closed unexpectedly.
    #[error("Old Faithful client concurrency semaphore closed")]
    SemaphoreClosed,
}

impl OldFaithfulError {
    /// Returns `true` if the error indicates a skipped slot (`length == 0`).
    pub fn is_skipped_slot(&self) -> bool {
        matches!(self, Self::SkippedSlot { .. })
    }

    /// Returns `true` if the error indicates an unarchived/future slot (`404`).
    pub fn is_unarchived_slot(&self) -> bool {
        matches!(self, Self::UnarchivedSlot { .. })
    }
}
