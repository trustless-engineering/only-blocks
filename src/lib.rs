//! Instant RPC — Historical-only Solana RPC backed by Old Faithful HTTP/2 Range transport.
//!
//! All data is fetched on demand over HTTP/2 Range requests with bounded RAM-only
//! caching and zero local disk downloads.

pub mod config;
pub mod error;
pub mod old_faithful;

pub use config::{
    OldFaithfulConfig, RetryConfig, DEFAULT_BASE_URL, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_MAX_CONCURRENT_REQUESTS, DEFAULT_MAX_SLICE_BYTES, DEFAULT_POOL_IDLE_TIMEOUT,
    DEFAULT_POOL_MAX_IDLE_PER_HOST, DEFAULT_REQUEST_TIMEOUT, DEFAULT_SLOT_RANGE_CACHE_CAPACITY,
};
pub use error::OldFaithfulError;
pub use old_faithful::{
    parse_slot_range_entry, slot_range_byte_offset, slot_to_epoch, slot_to_index,
    OldFaithfulClient, SlotAddress, SlotCarSlice, SlotFetchMeta, SlotRange, SlotRangeLookup,
    SLOTS_PER_EPOCH, SLOT_RANGE_ENTRY_BYTES,
};
