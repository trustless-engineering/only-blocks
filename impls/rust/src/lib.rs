//! OnlyBlocks — a zero-crate, pure-`std` historical Solana `getBlock` JSON-RPC 2.0 server that
//! reads blocks straight out of the Old Faithful archive with two HTTP Range requests.
//!
//! Every codec is hand-written on top of the standard library:
//!
//! | Module | What it implements |
//! |---|---|
//! | [`http_server`] | HTTP/1.1 server over `TcpListener` with an elastic worker pool |
//! | [`http_client`] | keep-alive HTTP/1.1 Range client over `TcpStream`; OS `curl` for `https://` |
//! | [`old_faithful`] | the 2-range-read protocol, retries with jitter, semaphore, slot-range LRU |
//! | [`json`] | strict RFC 8259 parser and streaming writer |
//! | [`car`], [`cbor`], [`ipld`] | CARv1 sections, CIDs, DAG-CBOR, Old Faithful nodes, DataFrames |
//! | [`hash`] | CRC-64/GO-ISO and FNV-1a |
//! | [`zstd`] | RFC 8878 Zstandard decoder with XXH64 |
//! | [`proto`], [`bincode`] | transaction metadata and rewards codecs |
//! | [`tx`] | Solana `VersionedTransaction` wire format |
//! | [`codec`] | Base58, Base64, `uiAmountString` formatting |
//! | [`encode`] | the `getBlock` JSON result |
//! | [`rpc`] | JSON-RPC envelope, params, and the `getBlock` pipeline |

pub mod bincode;
pub mod block;
pub mod car;
pub mod cbor;
pub mod codec;
pub mod config;
pub mod encode;
pub mod error;
pub mod hash;
pub mod http_client;
pub mod http_server;
pub mod ipld;
pub mod json;
pub mod lru;
pub mod model;
pub mod old_faithful;
pub mod proto;
pub mod rpc;
pub mod signal;
pub mod tx;
pub mod zstd;
