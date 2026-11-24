//! Instant RPC — Historical-only Solana JSON-RPC server backed by Old Faithful HTTP/2 Range
//! transport.
//!
//! All data is fetched on demand over HTTP/2 Range requests, decoded strictly in RAM, and
//! cached only in bounded RAM-only LRU caches with zero local disk downloads.

pub mod config;
pub mod decoder;
pub mod error;
pub mod old_faithful;
pub mod proto;
pub mod rpc;

pub use config::{
    OldFaithfulConfig, RetryConfig, DEFAULT_BASE_URL, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_MAX_CONCURRENT_REQUESTS, DEFAULT_MAX_SLICE_BYTES, DEFAULT_POOL_IDLE_TIMEOUT,
    DEFAULT_POOL_MAX_IDLE_PER_HOST, DEFAULT_REQUEST_TIMEOUT, DEFAULT_SLOT_RANGE_CACHE_CAPACITY,
};
pub use decoder::{
    decode_block_from_car, decode_block_from_index, decode_transaction_by_signature, encode_block,
    encode_transaction, extract_blockhash_from_car, BlockHeader, CarIndex, DecodeOptions,
    DecodedBlock, DecoderError, NodeKind, MAX_CAR_SECTION_SIZE,
};
pub use error::OldFaithfulError;
pub use old_faithful::{
    parse_slot_range_entry, slot_range_byte_offset, slot_to_epoch, slot_to_index,
    OldFaithfulClient, SlotAddress, SlotCarSlice, SlotFetchMeta, SlotRange, SlotRangeLookup,
    SLOTS_PER_EPOCH, SLOT_RANGE_ENTRY_BYTES,
};
pub use proto::{
    decode_rewards_bytes, decode_rewards_frame, decode_transaction_status_meta_bytes,
    decode_transaction_status_meta_frame, decompress_zstd, DecodedRewards, ProtoDecodeError,
    BINCODE_EPOCH_CUTOFF, BINCODE_SLOT_CUTOFF, MAX_DECOMPRESSED_BYTES,
};
pub use rpc::{
    build_router, build_router_with_limits, error_codes, parse_block_encoding, parse_signature,
    parse_transaction_encoding, GetBlockParams, GetTransactionParams, JsonRpcError, JsonRpcRequest,
    JsonRpcResponse, RpcState, DEFAULT_BLOCKHASH_CACHE_CAPACITY, DEFAULT_MAX_BATCH_SIZE,
    DEFAULT_MAX_REQUEST_BODY_BYTES,
};
