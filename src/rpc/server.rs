//! `axum` JSON-RPC 2.0 server and block-fetching service backed exclusively by Old Faithful.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use lru::LruCache;
use serde_json::Value;
use solana_hash::Hash;
use tracing::{debug, warn};

use crate::decoder::{
    decode_block_from_index, decode_transaction_by_signature, encode_block, encode_transaction,
    extract_blockhash_from_car, CarIndex, DecodeOptions,
};
use crate::error::OldFaithfulError;
use crate::old_faithful::OldFaithfulClient;
use crate::rpc::types::{
    GetBlockParams, GetTransactionParams, JsonRpcError, JsonRpcRequest, JsonRpcResponse,
};

/// Default capacity for the bounded RAM-only `slot -> blockhash` LRU cache.
///
/// 100,000 entries (~64 bytes each) take ~6–8 MiB of RAM with zero disk writes.
pub const DEFAULT_BLOCKHASH_CACHE_CAPACITY: usize = 100_000;

/// Default maximum HTTP request body size accepted by the JSON-RPC server (1 MiB).
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// Default maximum number of requests allowed in a single JSON-RPC batch array.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 100;

/// Shared state for the JSON-RPC server.
#[derive(Clone)]
pub struct RpcState {
    client: OldFaithfulClient,
    blockhash_cache: Option<Arc<Mutex<LruCache<u64, String>>>>,
    max_batch_size: usize,
}

impl RpcState {
    /// Construct [`RpcState`] using [`DEFAULT_BLOCKHASH_CACHE_CAPACITY`].
    pub fn new(client: OldFaithfulClient) -> Self {
        Self::with_blockhash_cache_capacity(client, DEFAULT_BLOCKHASH_CACHE_CAPACITY)
    }

    /// Construct [`RpcState`] with an explicit RAM-only `slot -> blockhash` LRU cache capacity
    /// (`0` disables blockhash caching).
    pub fn with_blockhash_cache_capacity(
        client: OldFaithfulClient,
        blockhash_cache_capacity: usize,
    ) -> Self {
        let blockhash_cache = NonZeroUsize::new(blockhash_cache_capacity)
            .map(|cap| Arc::new(Mutex::new(LruCache::new(cap))));
        Self {
            client,
            blockhash_cache,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
        }
    }

    /// Return a copy of [`RpcState`] with an explicit JSON-RPC batch size limit (clamped to `>= 1`).
    pub fn with_max_batch_size(mut self, max_batch_size: usize) -> Self {
        self.max_batch_size = max_batch_size.max(1);
        self
    }

    /// Configured maximum number of items accepted in a single JSON-RPC batch array.
    pub fn max_batch_size(&self) -> usize {
        self.max_batch_size
    }

    /// Access the underlying [`OldFaithfulClient`].
    pub fn client(&self) -> &OldFaithfulClient {
        &self.client
    }

    /// Current number of cached `slot -> blockhash` entries in RAM.
    pub fn blockhash_cache_len(&self) -> usize {
        self.blockhash_cache
            .as_ref()
            .map(|c| c.lock().unwrap_or_else(|e| e.into_inner()).len())
            .unwrap_or(0)
    }

    fn get_cached_blockhash(&self, slot: u64) -> Option<String> {
        self.blockhash_cache.as_ref().and_then(|cache| {
            cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&slot)
                .cloned()
        })
    }

    fn put_cached_blockhash(&self, slot: u64, blockhash: String) {
        if let Some(cache) = &self.blockhash_cache {
            cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .put(slot, blockhash);
        }
    }

    /// Resolve `previousBlockhash` for a block with `slot` and `parent_slot`.
    async fn resolve_previous_blockhash(
        &self,
        slot: u64,
        parent_slot: u64,
    ) -> Result<String, JsonRpcError> {
        if slot == 0 {
            return Ok(Hash::default().to_string());
        }

        if let Some(cached) = self.get_cached_blockhash(parent_slot) {
            return Ok(cached);
        }

        let parent_car = self
            .client
            .fetch_slot_car(parent_slot)
            .await
            .map_err(|err| JsonRpcError::from_old_faithful_error(&err))?;

        let parent_hash =
            tokio::task::spawn_blocking(move || extract_blockhash_from_car(&parent_car.bytes))
                .await
                .map_err(|e| JsonRpcError::internal_error(format!("decode task panicked: {e}")))?
                .map_err(|e| JsonRpcError::from_decoder_error(&e))?
                .to_string();

        self.put_cached_blockhash(parent_slot, parent_hash.clone());
        Ok(parent_hash)
    }

    /// Execute a `getBlock` RPC call end-to-end (historical-only, strictly in RAM).
    pub async fn handle_get_block(&self, params: GetBlockParams) -> Result<Value, JsonRpcError> {
        let slot = params.slot;
        let car_slice = self
            .client
            .fetch_slot_car(slot)
            .await
            .map_err(|err| JsonRpcError::from_old_faithful_error(&err))?;

        let encoding = params.encoding;
        let enc_opts = params.block_encoding_options();
        let decode_opts = DecodeOptions::from_encoding_options(&enc_opts);

        // First extract lightweight header (parent_slot + own blockhash) so we can resolve
        // previousBlockhash cleanly without copying CAR bytes.
        let car_bytes_for_header = car_slice.bytes.clone();
        let header = tokio::task::spawn_blocking(move || {
            let index = CarIndex::parse(&car_bytes_for_header)?;
            index.decode_header(Some(slot))
        })
        .await
        .map_err(|e| JsonRpcError::internal_error(format!("decode task panicked: {e}")))?
        .map_err(|e| JsonRpcError::from_decoder_error(&e))?;

        self.put_cached_blockhash(slot, header.blockhash.to_string());

        let previous_blockhash = self
            .resolve_previous_blockhash(slot, header.parent_slot)
            .await?;

        let ui_block = tokio::task::spawn_blocking(move || {
            let index = CarIndex::parse(&car_slice.bytes)
                .map_err(|e| JsonRpcError::from_decoder_error(&e))?;
            let decoded = decode_block_from_index(slot, &index, previous_blockhash, decode_opts)
                .map_err(|e| JsonRpcError::from_decoder_error(&e))?;
            encode_block(decoded.block, encoding, enc_opts)
                .map_err(|e| JsonRpcError::from_encode_error(&e))
        })
        .await
        .map_err(|e| JsonRpcError::internal_error(format!("decode task panicked: {e}")))??;

        serde_json::to_value(ui_block)
            .map_err(|e| JsonRpcError::internal_error(format!("JSON serialization failed: {e}")))
    }

    /// Execute a slot-hinted `getTransaction` RPC call end-to-end (historical-only, strictly in RAM).
    pub async fn handle_get_transaction(
        &self,
        params: GetTransactionParams,
    ) -> Result<Value, JsonRpcError> {
        let slot = params.slot;
        let car_slice = match self.client.fetch_slot_car(slot).await {
            Ok(slice) => slice,
            // Standard Solana `getTransaction` behavior for a skipped slot: return `result: null`.
            Err(OldFaithfulError::SkippedSlot { .. }) => return Ok(Value::Null),
            Err(err) => return Err(JsonRpcError::from_old_faithful_error(&err)),
        };

        let signature = params.signature;
        let encoding = params.encoding;
        let max_ver = params.max_supported_transaction_version;

        let encoded_opt = tokio::task::spawn_blocking(move || {
            let found = decode_transaction_by_signature(slot, &car_slice.bytes, &signature)
                .map_err(|e| JsonRpcError::from_decoder_error(&e))?;
            match found {
                Some(tx) => encode_transaction(tx, encoding, max_ver)
                    .map(Some)
                    .map_err(|e| JsonRpcError::from_encode_error(&e)),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| JsonRpcError::internal_error(format!("decode task panicked: {e}")))??;

        match encoded_opt {
            Some(encoded) => serde_json::to_value(encoded).map_err(|e| {
                JsonRpcError::internal_error(format!("JSON serialization failed: {e}"))
            }),
            None => Ok(Value::Null),
        }
    }

    /// Dispatch a single parsed JSON-RPC 2.0 request.
    pub async fn dispatch_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        if !matches!(req.id, Value::Null | Value::String(_) | Value::Number(_)) {
            return JsonRpcResponse::err(
                Value::Null,
                JsonRpcError::invalid_request(
                    "Invalid Request: id must be a string, number, or null",
                ),
            );
        }
        let id = req.id;

        if req.jsonrpc.as_deref() != Some("2.0") {
            return JsonRpcResponse::err(
                id,
                JsonRpcError::invalid_request("Invalid Request: jsonrpc must be \"2.0\""),
            );
        }

        let Some(method) = req.method else {
            return JsonRpcResponse::err(
                id,
                JsonRpcError::invalid_request("Invalid Request: missing method"),
            );
        };

        debug!(method = %method, "dispatching JSON-RPC request");

        match method.as_str() {
            "getHealth" => match req.params.as_ref() {
                None | Some(Value::Null) => {
                    JsonRpcResponse::ok(id, Value::String("ok".to_string()))
                }
                Some(Value::Array(arr)) if arr.is_empty() => {
                    JsonRpcResponse::ok(id, Value::String("ok".to_string()))
                }
                _ => JsonRpcResponse::err(
                    id,
                    JsonRpcError::invalid_params("Invalid params: getHealth expects no parameters"),
                ),
            },
            "getBlock" => match GetBlockParams::from_rpc_params(req.params.as_ref()) {
                Ok(params) => match self.handle_get_block(params).await {
                    Ok(result) => JsonRpcResponse::ok(id, result),
                    Err(err) => {
                        warn!(code = err.code, message = %err.message, "getBlock failed");
                        JsonRpcResponse::err(id, err)
                    }
                },
                Err(err) => JsonRpcResponse::err(id, err),
            },
            "getTransaction" => match GetTransactionParams::from_rpc_params(req.params.as_ref()) {
                Ok(params) => match self.handle_get_transaction(params).await {
                    Ok(result) => JsonRpcResponse::ok(id, result),
                    Err(err) => {
                        warn!(code = err.code, message = %err.message, "getTransaction failed");
                        JsonRpcResponse::err(id, err)
                    }
                },
                Err(err) => JsonRpcResponse::err(id, err),
            },
            other => JsonRpcResponse::err(id, JsonRpcError::method_not_found(other)),
        }
    }
}

/// Build the `axum` [`Router`] serving JSON-RPC 2.0 on `POST /` with default request limits
/// ([`DEFAULT_MAX_REQUEST_BODY_BYTES`] and [`DEFAULT_MAX_BATCH_SIZE`]).
pub fn build_router(state: RpcState) -> Router {
    let max_batch_size = state.max_batch_size();
    build_router_with_limits(state, DEFAULT_MAX_REQUEST_BODY_BYTES, max_batch_size)
}

/// Build the `axum` [`Router`] serving JSON-RPC 2.0 on `POST /` with explicit HTTP request
/// body byte limit and JSON-RPC batch size limit.
pub fn build_router_with_limits(
    state: RpcState,
    max_request_body_bytes: usize,
    max_batch_size: usize,
) -> Router {
    let state = state.with_max_batch_size(max_batch_size);
    Router::new()
        .route("/", post(handle_rpc))
        .layer(DefaultBodyLimit::max(max_request_body_bytes))
        .with_state(state)
}

async fn handle_rpc(State(state): State<RpcState>, body: Bytes) -> Response {
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let resp = JsonRpcResponse::err(
                Value::Null,
                JsonRpcError::parse_error(format!("Parse error: {e}")),
            );
            return json_response(&resp);
        }
    };

    match raw {
        Value::Object(_) => match serde_json::from_value::<JsonRpcRequest>(raw) {
            Ok(req) => json_response(&state.dispatch_request(req).await),
            Err(e) => {
                let resp = JsonRpcResponse::err(
                    Value::Null,
                    JsonRpcError::invalid_request(format!("Invalid Request: {e}")),
                );
                json_response(&resp)
            }
        },
        Value::Array(items) => {
            if items.is_empty() {
                let resp = JsonRpcResponse::err(
                    Value::Null,
                    JsonRpcError::invalid_request("Invalid Request: empty batch"),
                );
                return json_response(&resp);
            }
            if items.len() > state.max_batch_size() {
                let resp = JsonRpcResponse::err(
                    Value::Null,
                    JsonRpcError::invalid_request(format!(
                        "Invalid Request: batch size {} exceeds maximum {}",
                        items.len(),
                        state.max_batch_size()
                    )),
                );
                return json_response(&resp);
            }
            let mut responses = Vec::with_capacity(items.len());
            for item in items {
                match serde_json::from_value::<JsonRpcRequest>(item) {
                    Ok(req) => responses.push(state.dispatch_request(req).await),
                    Err(e) => responses.push(JsonRpcResponse::err(
                        Value::Null,
                        JsonRpcError::invalid_request(format!("Invalid Request: {e}")),
                    )),
                }
            }
            json_response(&responses)
        }
        _ => {
            let resp = JsonRpcResponse::err(
                Value::Null,
                JsonRpcError::invalid_request("Invalid Request: expected JSON object or array"),
            );
            json_response(&resp)
        }
    }
}

fn json_response<T: serde::Serialize>(payload: &T) -> Response {
    match serde_json::to_vec(payload) {
        Ok(bytes) => (
            StatusCode::OK,
            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            bytes,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize JSON-RPC response: {e}"),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use solana_signature::Signature;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use crate::config::OldFaithfulConfig;
    use crate::decoder::test_helpers::{
        build_synthetic_slot_car, build_synthetic_slot_car_with_options, sample_legacy_tx,
        sample_v0_tx,
    };
    use crate::old_faithful::{OldFaithfulClient, SLOTS_PER_EPOCH, SLOT_RANGE_ENTRY_BYTES};
    use crate::rpc::server::{build_router, RpcState};
    use crate::rpc::types::error_codes;

    struct MockOldFaithful {
        base_url: String,
        request_count: Arc<AtomicUsize>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockOldFaithful {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    impl MockOldFaithful {
        fn request_count(&self) -> usize {
            self.request_count.load(Ordering::SeqCst)
        }

        /// Serve synthetic slot-ranges and CAR slices for a map of `slot -> Option<car_bytes>`
        /// (`None` = skipped slot, absent epoch = 404).
        async fn start(archived_epochs: Vec<u64>, slots: HashMap<u64, Option<Vec<u8>>>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let request_count = Arc::new(AtomicUsize::new(0));
            let request_count_bg = Arc::clone(&request_count);

            // Pack each epoch's CAR slices contiguously and build a map of `(epoch, slot_idx) -> (offset, len)`.
            let mut epoch_cars: HashMap<u64, Vec<u8>> = HashMap::new();
            let mut slot_entries: HashMap<u64, (u64, u32)> = HashMap::new();

            for &epoch in &archived_epochs {
                epoch_cars.entry(epoch).or_default();
            }

            let mut sorted_slots: Vec<u64> = slots.keys().copied().collect();
            sorted_slots.sort_unstable();
            for slot in sorted_slots {
                let epoch = slot / SLOTS_PER_EPOCH;
                let car_buf = epoch_cars.entry(epoch).or_default();
                match &slots[&slot] {
                    Some(slice) => {
                        let offset = car_buf.len() as u64;
                        let length = slice.len() as u32;
                        car_buf.extend_from_slice(slice);
                        slot_entries.insert(slot, (offset, length));
                    }
                    None => {
                        slot_entries.insert(slot, (0, 0));
                    }
                }
            }

            let epoch_cars = Arc::new(epoch_cars);
            let slot_entries = Arc::new(slot_entries);

            let handle = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    let epoch_cars = Arc::clone(&epoch_cars);
                    let slot_entries = Arc::clone(&slot_entries);
                    let request_count = Arc::clone(&request_count_bg);

                    tokio::spawn(async move {
                        request_count.fetch_add(1, Ordering::SeqCst);
                        let mut buf = vec![0u8; 8192];
                        let mut filled = 0usize;
                        loop {
                            let Ok(n) = stream.read(&mut buf[filled..]).await else {
                                return;
                            };
                            if n == 0 {
                                return;
                            }
                            filled += n;
                            if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n")
                                || filled == buf.len()
                            {
                                break;
                            }
                        }

                        let req_text = String::from_utf8_lossy(&buf[..filled]);
                        let mut lines = req_text.lines();
                        let first_line = lines.next().unwrap_or_default();
                        let path = first_line
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or_default()
                            .to_string();
                        let mut range = None;
                        for line in lines {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.eq_ignore_ascii_case("range") {
                                    range = Some(v.trim().to_string());
                                }
                            }
                        }

                        let parse_range = |r: Option<String>| -> Option<(u64, u64)> {
                            let s = r?.strip_prefix("bytes=")?.to_string();
                            let (a, b) = s.split_once('-')?;
                            Some((a.parse().ok()?, b.parse().ok()?))
                        };

                        let epoch: Option<u64> = path
                            .trim_start_matches('/')
                            .split('/')
                            .next()
                            .and_then(|s| s.parse().ok());

                        let (status, reason, body) = match (epoch, parse_range(range)) {
                            (Some(ep), Some((start, end))) if epoch_cars.contains_key(&ep) => {
                                if path.ends_with("-slot-ranges.raw") {
                                    let slot_idx = start / SLOT_RANGE_ENTRY_BYTES;
                                    let slot = ep * SLOTS_PER_EPOCH + slot_idx;
                                    let (off, len) =
                                        slot_entries.get(&slot).copied().unwrap_or((0, 0));
                                    let mut entry = Vec::with_capacity(12);
                                    entry.extend_from_slice(&off.to_le_bytes());
                                    entry.extend_from_slice(&len.to_le_bytes());
                                    (206, "Partial Content", entry)
                                } else if path.ends_with(".car") {
                                    let car = &epoch_cars[&ep];
                                    let s = start as usize;
                                    let e = (end as usize).min(car.len().saturating_sub(1));
                                    (206, "Partial Content", car[s..=e].to_vec())
                                } else {
                                    (404, "Not Found", Vec::new())
                                }
                            }
                            _ => (404, "Not Found", Vec::new()),
                        };

                        let head = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes()).await;
                        let _ = stream.write_all(&body).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });

            Self {
                base_url: format!("http://{addr}"),
                request_count,
                handle,
            }
        }
    }

    async fn rpc_post(app: &axum::Router, payload: &str) -> Value {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).expect("valid JSON response")
    }

    #[tokio::test]
    async fn rpc_server_handles_health_errors_all_encodings_and_options() {
        let parent_slot = 302_400_000;
        let slot = 302_400_001;
        let skipped_slot = 302_400_004;
        let unarchived_slot = 9999 * SLOTS_PER_EPOCH;

        let mut slots = HashMap::new();
        slots.insert(
            parent_slot,
            Some(build_synthetic_slot_car(
                parent_slot,
                parent_slot - 1,
                0x11,
                &[sample_legacy_tx(1)],
                false,
            )),
        );
        slots.insert(
            slot,
            Some(build_synthetic_slot_car(
                slot,
                parent_slot,
                0x22,
                &[sample_legacy_tx(2), sample_v0_tx(3)],
                true,
            )),
        );
        slots.insert(skipped_slot, None);

        let mock = MockOldFaithful::start(vec![700], slots).await;
        let client = OldFaithfulClient::new(OldFaithfulConfig::with_base_url(&mock.base_url))
            .expect("client");
        let app = build_router(RpcState::new(client));

        // 1. getHealth
        let health = rpc_post(
            &app,
            &json!({"jsonrpc":"2.0","id":1,"method":"getHealth"}).to_string(),
        )
        .await;
        assert_eq!(health["result"], "ok");
        assert_eq!(health["id"], 1);

        // 2. Unknown method -> -32601
        let unknown = rpc_post(
            &app,
            &json!({"jsonrpc":"2.0","id":2,"method":"getSlot"}).to_string(),
        )
        .await;
        assert_eq!(unknown["error"]["code"], error_codes::METHOD_NOT_FOUND);

        // 3. Invalid params -> -32602
        let bad_params = rpc_post(
            &app,
            &json!({"jsonrpc":"2.0","id":3,"method":"getBlock","params":["oops"]}).to_string(),
        )
        .await;
        assert_eq!(bad_params["error"]["code"], error_codes::INVALID_PARAMS);

        // 4. Parse error -> -32700
        let bad_json = rpc_post(&app, "{not valid json").await;
        assert_eq!(bad_json["error"]["code"], error_codes::PARSE_ERROR);

        // 5. Skipped slot -> -32007
        let skipped = rpc_post(
            &app,
            &json!({"jsonrpc":"2.0","id":4,"method":"getBlock","params":[skipped_slot]})
                .to_string(),
        )
        .await;
        assert_eq!(skipped["error"]["code"], error_codes::SLOT_SKIPPED);

        // 6. Unarchived slot -> -32004 (historical-only)
        let unarchived = rpc_post(
            &app,
            &json!({"jsonrpc":"2.0","id":5,"method":"getBlock","params":[unarchived_slot]})
                .to_string(),
        )
        .await;
        assert_eq!(
            unarchived["error"]["code"],
            error_codes::BLOCK_NOT_AVAILABLE
        );
        assert!(unarchived["error"]["message"]
            .as_str()
            .unwrap()
            .contains("historical-only"));

        // 7. Unsupported tx version when maxSupportedTransactionVersion omitted -> -32015
        let ver_err = rpc_post(
            &app,
            &json!({"jsonrpc":"2.0","id":6,"method":"getBlock","params":[slot]}).to_string(),
        )
        .await;
        assert_eq!(
            ver_err["error"]["code"],
            error_codes::UNSUPPORTED_TRANSACTION_VERSION
        );

        // 8. All 4 encodings with maxSupportedTransactionVersion: 0
        for encoding in ["json", "jsonParsed", "base64", "base58"] {
            let resp = rpc_post(
                &app,
                &json!({
                    "jsonrpc": "2.0",
                    "id": encoding,
                    "method": "getBlock",
                    "params": [slot, { "encoding": encoding, "maxSupportedTransactionVersion": 0 }]
                })
                .to_string(),
            )
            .await;
            assert!(
                resp.get("error").is_none(),
                "unexpected error for {encoding}: {resp}"
            );
            let res = &resp["result"];
            assert_eq!(res["parentSlot"], parent_slot);
            assert_eq!(res["blockTime"], 1_730_000_000);
            assert_eq!(
                res["previousBlockhash"],
                solana_hash::Hash::new_from_array([0x11; 32]).to_string()
            );
            assert_eq!(
                res["blockhash"],
                solana_hash::Hash::new_from_array([0x22; 32]).to_string()
            );
            assert_eq!(res["transactions"].as_array().unwrap().len(), 2);
            assert_eq!(res["rewards"].as_array().unwrap().len(), 1);
        }

        // 9. transactionDetails: accounts, signatures, none & rewards: false
        let accounts_resp = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "getBlock",
                "params": [slot, {
                    "transactionDetails": "accounts",
                    "rewards": false,
                    "maxSupportedTransactionVersion": 0
                }]
            })
            .to_string(),
        )
        .await;
        assert!(accounts_resp["result"].get("rewards").is_none());
        assert!(
            accounts_resp["result"]["transactions"][0]["transaction"]["accountKeys"].is_array()
        );

        let sigs_resp = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "getBlock",
                "params": [slot, { "transactionDetails": "signatures", "rewards": false }]
            })
            .to_string(),
        )
        .await;
        assert_eq!(
            sigs_resp["result"]["signatures"].as_array().unwrap().len(),
            2
        );
        assert!(sigs_resp["result"].get("transactions").is_none());

        let none_resp = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "getBlock",
                "params": [slot, { "transactionDetails": "none", "rewards": false }]
            })
            .to_string(),
        )
        .await;
        assert!(none_resp["result"].get("transactions").is_none());
        assert!(none_resp["result"].get("signatures").is_none());
        assert!(none_resp["result"].get("rewards").is_none());
    }

    #[tokio::test]
    async fn rpc_server_handles_get_transaction_slot_hint_encodings_versions_and_errors() {
        let slot = 302_400_001u64;
        let pre_157_slot = 43_200_000u64;
        let skipped_slot = 302_400_004u64;
        let unarchived_slot = 9999 * SLOTS_PER_EPOCH;

        let legacy_tx = sample_legacy_tx(12);
        let v0_tx = sample_v0_tx(34);
        let pre_157_tx = sample_legacy_tx(56);
        let legacy_sig = legacy_tx.signatures[0].to_string();
        let v0_sig = v0_tx.signatures[0].to_string();
        let pre_157_sig = pre_157_tx.signatures[0].to_string();
        let absent_sig = Signature::from([99u8; 64]).to_string();

        let mut slots = HashMap::new();
        // Use multi-frame DataFrames for the modern slot's transactions and metadata.
        slots.insert(
            slot,
            Some(build_synthetic_slot_car_with_options(
                slot,
                slot - 1,
                0x22,
                &[legacy_tx, v0_tx],
                true,
                true,
            )),
        );
        slots.insert(
            pre_157_slot,
            Some(build_synthetic_slot_car_with_options(
                pre_157_slot,
                pre_157_slot - 1,
                0x11,
                &[pre_157_tx],
                false,
                true,
            )),
        );
        slots.insert(skipped_slot, None);

        let mock = MockOldFaithful::start(vec![100, 700], slots).await;
        let client = OldFaithfulClient::new(OldFaithfulConfig::with_base_url(&mock.base_url))
            .expect("client");
        let app = build_router(RpcState::new(client));

        // 1. Missing/invalid slot hint, invalid sig/encoding/commitment -> -32602 with ZERO HTTP calls.
        for bad_params in [
            json!([legacy_sig]),
            json!([legacy_sig, {}]),
            json!([legacy_sig, { "slot": null }]),
            json!([legacy_sig, { "slot": -5 }]),
            json!([legacy_sig, { "slot": 1.5 }]),
            json!([legacy_sig, { "slot": "302400001" }]),
            json!(["not-a-valid-sig-0OIl", { "slot": slot }]),
            json!([legacy_sig, { "slot": slot, "encoding": "base64+zstd" }]),
            json!([legacy_sig, { "slot": slot, "commitment": "processed" }]),
            json!([legacy_sig, { "slot": slot, "commitment": "unknown" }]),
        ] {
            let resp = rpc_post(
                &app,
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getTransaction",
                    "params": bad_params
                })
                .to_string(),
            )
            .await;
            assert_eq!(
                resp["error"]["code"],
                error_codes::INVALID_PARAMS,
                "expected -32602 for {bad_params}, got {resp}"
            );
        }
        assert_eq!(
            mock.request_count(),
            0,
            "invalid getTransaction params must never make outbound HTTP requests"
        );

        // 2. v0 tx without maxSupportedTransactionVersion -> -32015
        let ver_err = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "getTransaction",
                "params": [v0_sig, { "slot": slot }]
            })
            .to_string(),
        )
        .await;
        assert_eq!(
            ver_err["error"]["code"],
            error_codes::UNSUPPORTED_TRANSACTION_VERSION
        );

        // 3. v0 tx with maxSupportedTransactionVersion: 0 across all 4 encodings
        for encoding in ["json", "jsonParsed", "base64", "base58"] {
            let resp = rpc_post(
                &app,
                &json!({
                    "jsonrpc": "2.0",
                    "id": encoding,
                    "method": "getTransaction",
                    "params": [v0_sig, {
                        "slot": slot,
                        "encoding": encoding,
                        "maxSupportedTransactionVersion": 0,
                        "commitment": "finalized"
                    }]
                })
                .to_string(),
            )
            .await;
            assert!(
                resp.get("error").is_none(),
                "unexpected error for {encoding}: {resp}"
            );
            let res = &resp["result"];
            assert_eq!(res["slot"], slot);
            assert_eq!(res["blockTime"], 1_730_000_000);
            assert_eq!(res["version"], 0);
            assert_eq!(res["meta"]["fee"], 5_000);
            match encoding {
                "json" => {
                    assert_eq!(res["transaction"]["signatures"][0], v0_sig);
                    assert!(res["transaction"]["message"]["accountKeys"][0].is_string());
                }
                "jsonParsed" => {
                    assert_eq!(res["transaction"]["signatures"][0], v0_sig);
                    assert!(res["transaction"]["message"]["accountKeys"][0]["pubkey"].is_string());
                }
                "base64" => {
                    assert!(res["transaction"][0].is_string());
                    assert_eq!(res["transaction"][1], "base64");
                }
                "base58" => {
                    assert!(res["transaction"][0].is_string());
                    assert_eq!(res["transaction"][1], "base58");
                }
                _ => unreachable!(),
            }
        }

        // 4. Legacy tx without maxSupportedTransactionVersion succeeds and omits `version`;
        //    with `maxSupportedTransactionVersion: 0` includes `version: "legacy"`.
        let legacy_no_ver = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "getTransaction",
                "params": [legacy_sig, { "slot": slot, "commitment": "confirmed" }]
            })
            .to_string(),
        )
        .await;
        assert!(legacy_no_ver.get("error").is_none());
        assert_eq!(legacy_no_ver["result"]["slot"], slot);
        assert!(legacy_no_ver["result"].get("version").is_none());

        let legacy_with_ver = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "getTransaction",
                "params": [legacy_sig, { "slot": slot, "maxSupportedTransactionVersion": 0 }]
            })
            .to_string(),
        )
        .await;
        assert!(legacy_with_ver.get("error").is_none());
        assert_eq!(legacy_with_ver["result"]["version"], "legacy");

        // 5. Pre-Epoch 157 legacy bincode transaction decodes cleanly
        let pre_157_resp = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "getTransaction",
                "params": [pre_157_sig, {
                    "slot": pre_157_slot,
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0
                }]
            })
            .to_string(),
        )
        .await;
        assert!(pre_157_resp.get("error").is_none());
        assert_eq!(pre_157_resp["result"]["slot"], pre_157_slot);
        assert_eq!(pre_157_resp["result"]["meta"]["fee"], 5_000);
        assert_eq!(pre_157_resp["result"]["blockTime"], 1_730_000_000);
        assert_eq!(pre_157_resp["result"]["version"], "legacy");

        // 6. Skipped slot -> result: null
        let skipped = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "getTransaction",
                "params": [legacy_sig, { "slot": skipped_slot }]
            })
            .to_string(),
        )
        .await;
        assert!(
            skipped.get("error").is_none(),
            "unexpected error: {skipped}"
        );
        assert!(skipped.as_object().unwrap().contains_key("result"));
        assert!(skipped["result"].is_null());

        // 7. Absent signature in existing slot -> result: null
        let absent = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "getTransaction",
                "params": [absent_sig, { "slot": slot }]
            })
            .to_string(),
        )
        .await;
        assert!(absent.get("error").is_none(), "unexpected error: {absent}");
        assert!(absent.as_object().unwrap().contains_key("result"));
        assert!(absent["result"].is_null());

        // 8. Unarchived slot -> -32004 (historical-only)
        let unarchived = rpc_post(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "getTransaction",
                "params": [legacy_sig, { "slot": unarchived_slot }]
            })
            .to_string(),
        )
        .await;
        assert_eq!(
            unarchived["error"]["code"],
            error_codes::BLOCK_NOT_AVAILABLE
        );
        assert!(unarchived["error"]["message"]
            .as_str()
            .unwrap()
            .contains("historical-only"));
    }

    #[tokio::test]
    async fn rpc_server_hardening_jsonrpc_edge_cases_body_limit_and_batch_limit() {
        let mock = MockOldFaithful::start(vec![], HashMap::new()).await;
        let client = OldFaithfulClient::new(OldFaithfulConfig::with_base_url(&mock.base_url))
            .expect("client");
        let state = RpcState::with_blockhash_cache_capacity(client, 4);
        let app = crate::rpc::server::build_router_with_limits(state, 512, 3);

        // 1. Oversized HTTP body (> 512 bytes) rejected with 413 Payload Too Large.
        let oversized = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\",\"pad\":\"{}\"}}",
            "x".repeat(600)
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(oversized))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);

        // 2. Non-object / non-array JSON primitives -> -32600 Invalid Request.
        for primitive in ["42", "\"hello\"", "true", "null"] {
            let resp = rpc_post(&app, primitive).await;
            assert_eq!(
                resp["error"]["code"],
                error_codes::INVALID_REQUEST,
                "expected -32600 for {primitive}, got {resp}"
            );
            assert!(resp["id"].is_null());
        }

        // 3. Invalid jsonrpc version, missing method, invalid id types -> -32600.
        for bad_req in [
            json!({"jsonrpc": "1.0", "id": 1, "method": "getHealth"}),
            json!({"id": 1, "method": "getHealth"}),
            json!({"jsonrpc": 2.0, "id": 1, "method": "getHealth"}),
            json!({"jsonrpc": "2.0", "id": 1}),
            json!({"jsonrpc": "2.0", "id": true, "method": "getHealth"}),
            json!({"jsonrpc": "2.0", "id": {"nested": 1}, "method": "getHealth"}),
            json!({"jsonrpc": "2.0", "id": [1, 2], "method": "getHealth"}),
        ] {
            let resp = rpc_post(&app, &bad_req.to_string()).await;
            assert_eq!(
                resp["error"]["code"],
                error_codes::INVALID_REQUEST,
                "expected -32600 for {bad_req}, got {resp}"
            );
        }

        // 4. getHealth accepts empty array / null params and rejects non-empty params with -32602.
        let health_empty = rpc_post(
            &app,
            &json!({"jsonrpc": "2.0", "id": "h1", "method": "getHealth", "params": []}).to_string(),
        )
        .await;
        assert_eq!(health_empty["result"], "ok");
        assert_eq!(health_empty["id"], "h1");

        let health_null = rpc_post(
            &app,
            &json!({"jsonrpc": "2.0", "id": "h2", "method": "getHealth", "params": null})
                .to_string(),
        )
        .await;
        assert_eq!(health_null["result"], "ok");

        let health_bad = rpc_post(
            &app,
            &json!({"jsonrpc": "2.0", "id": "h3", "method": "getHealth", "params": [1]})
                .to_string(),
        )
        .await;
        assert_eq!(health_bad["error"]["code"], error_codes::INVALID_PARAMS);

        // 5. Empty batch and oversized batch (> max_batch_size = 3) -> -32600.
        let empty_batch = rpc_post(&app, "[]").await;
        assert_eq!(empty_batch["error"]["code"], error_codes::INVALID_REQUEST);

        let big_batch = rpc_post(
            &app,
            &json!([
                {"jsonrpc": "2.0", "id": 1, "method": "getHealth"},
                {"jsonrpc": "2.0", "id": 2, "method": "getHealth"},
                {"jsonrpc": "2.0", "id": 3, "method": "getHealth"},
                {"jsonrpc": "2.0", "id": 4, "method": "getHealth"}
            ])
            .to_string(),
        )
        .await;
        assert_eq!(big_batch["error"]["code"], error_codes::INVALID_REQUEST);

        // 6. Valid mixed batch (<= 3 items) returns matching array of responses.
        let mixed_batch = rpc_post(
            &app,
            &json!([
                {"jsonrpc": "2.0", "id": 1, "method": "getHealth"},
                123,
                {"jsonrpc": "2.0", "id": 3, "method": "unknownMethod"}
            ])
            .to_string(),
        )
        .await;
        let arr = mixed_batch.as_array().expect("batch array response");
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["result"], "ok");
        assert_eq!(arr[1]["error"]["code"], error_codes::INVALID_REQUEST);
        assert_eq!(arr[2]["error"]["code"], error_codes::METHOD_NOT_FOUND);

        // None of these malformed/health requests may hit Old Faithful.
        assert_eq!(mock.request_count(), 0);
    }

    #[tokio::test]
    async fn concurrency_soak_429_burst_bounds_inflight_and_lru_eviction() {
        use crate::config::RetryConfig;
        use std::time::Duration;

        // Build 25 distinct slots across Epoch 700 (plus parent slot 302_400_000).
        const BASE_SLOT: u64 = 302_400_000;
        const SLOT_COUNT: u64 = 25;
        let mut slots_data: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut slot_sigs: HashMap<u64, String> = HashMap::new();

        for i in 0..=SLOT_COUNT {
            let slot = BASE_SLOT + i;
            let parent = if i == 0 { slot } else { slot - 1 };
            let tx = sample_legacy_tx((i as u8).wrapping_add(1));
            let sig = tx.signatures[0].to_string();
            let car = build_synthetic_slot_car_with_options(
                slot,
                parent,
                (i as u8).wrapping_add(10),
                &[tx],
                false,
                false,
            );
            slots_data.insert(slot, car);
            slot_sigs.insert(slot, sig);
        }

        // Pack Epoch 700 CAR and slot-ranges table.
        let mut car_buf = Vec::new();
        let mut slot_entries: HashMap<u64, (u64, u32)> = HashMap::new();
        for i in 0..=SLOT_COUNT {
            let slot = BASE_SLOT + i;
            let slice = &slots_data[&slot];
            let offset = car_buf.len() as u64;
            let length = slice.len() as u32;
            car_buf.extend_from_slice(slice);
            slot_entries.insert(slot, (offset, length));
        }

        let car_buf = Arc::new(car_buf);
        let slot_entries = Arc::new(slot_entries);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak_in_flight = Arc::new(AtomicUsize::new(0));
        let total_reqs = Arc::new(AtomicUsize::new(0));
        let throttled_429 = Arc::new(AtomicUsize::new(0));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let car_bg = Arc::clone(&car_buf);
        let entries_bg = Arc::clone(&slot_entries);
        let in_flight_bg = Arc::clone(&in_flight);
        let peak_bg = Arc::clone(&peak_in_flight);
        let total_bg = Arc::clone(&total_reqs);
        let throttled_bg = Arc::clone(&throttled_429);

        let server_handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let car = Arc::clone(&car_bg);
                let entries = Arc::clone(&entries_bg);
                let in_flight = Arc::clone(&in_flight_bg);
                let peak = Arc::clone(&peak_bg);
                let total = Arc::clone(&total_bg);
                let throttled = Arc::clone(&throttled_bg);

                tokio::spawn(async move {
                    let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(cur, Ordering::SeqCst);
                    let req_idx = total.fetch_add(1, Ordering::SeqCst);

                    let mut buf = vec![0u8; 4096];
                    let mut filled = 0usize;
                    loop {
                        let Ok(n) = stream.read(&mut buf[filled..]).await else {
                            in_flight.fetch_sub(1, Ordering::SeqCst);
                            return;
                        };
                        if n == 0 {
                            in_flight.fetch_sub(1, Ordering::SeqCst);
                            return;
                        }
                        filled += n;
                        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") || filled == buf.len()
                        {
                            break;
                        }
                    }

                    // Artificial latency so concurrent tasks contend on the semaphore.
                    tokio::time::sleep(Duration::from_millis(8)).await;

                    // Deterministic 429 burst: reject every 5th request with 429 + Retry-After: 0,
                    // and every 13th with 503 Service Unavailable.
                    let (status, reason, extra_header, body) = if req_idx.is_multiple_of(5) {
                        throttled.fetch_add(1, Ordering::SeqCst);
                        (429, "Too Many Requests", "Retry-After: 0\r\n", Vec::new())
                    } else if req_idx % 13 == 1 {
                        (503, "Service Unavailable", "", Vec::new())
                    } else {
                        let req_text = String::from_utf8_lossy(&buf[..filled]);
                        let mut lines = req_text.lines();
                        let first_line = lines.next().unwrap_or_default();
                        let path = first_line
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or_default()
                            .to_string();
                        let mut range = None;
                        for line in lines {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.eq_ignore_ascii_case("range") {
                                    range = Some(v.trim().to_string());
                                }
                            }
                        }
                        let parsed = range.and_then(|r| {
                            let s = r.strip_prefix("bytes=")?;
                            let (a, b) = s.split_once('-')?;
                            Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?))
                        });
                        match parsed {
                            Some((start, _end)) if path.ends_with("-slot-ranges.raw") => {
                                let slot_idx = start / SLOT_RANGE_ENTRY_BYTES;
                                let slot = 700 * SLOTS_PER_EPOCH + slot_idx;
                                let (off, len) = entries.get(&slot).copied().unwrap_or((0, 0));
                                let mut entry = Vec::with_capacity(12);
                                entry.extend_from_slice(&off.to_le_bytes());
                                entry.extend_from_slice(&len.to_le_bytes());
                                (206, "Partial Content", "", entry)
                            }
                            Some((start, end)) if path.ends_with(".car") => {
                                let s = start as usize;
                                let e = (end as usize).min(car.len().saturating_sub(1));
                                (206, "Partial Content", "", car[s..=e].to_vec())
                            }
                            _ => (404, "Not Found", "", Vec::new()),
                        }
                    };

                    let head = format!(
                        "HTTP/1.1 {status} {reason}\r\n{extra_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;

                    in_flight.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        const MAX_CONCURRENCY: usize = 4;
        const RANGE_CACHE_CAP: usize = 8;
        const BLOCKHASH_CACHE_CAP: usize = 6;

        let cfg = OldFaithfulConfig {
            base_url: format!("http://{addr}"),
            max_concurrent_requests: MAX_CONCURRENCY,
            slot_range_cache_capacity: RANGE_CACHE_CAP,
            retry: RetryConfig {
                max_retries: 6,
                initial_backoff: Duration::from_millis(5),
                max_backoff: Duration::from_millis(50),
                jitter_ratio: 0.2,
            },
            ..OldFaithfulConfig::default()
        };
        let client = OldFaithfulClient::new(cfg).expect("client");
        let state = RpcState::with_blockhash_cache_capacity(client.clone(), BLOCKHASH_CACHE_CAP);
        let app = build_router(state.clone());

        // Launch 50 concurrent RPC requests: 25 getBlock + 25 getTransaction across 25 distinct slots.
        let mut tasks = Vec::new();
        for i in 1..=SLOT_COUNT {
            let slot = BASE_SLOT + i;
            let app_blk = app.clone();
            tasks.push(tokio::spawn(async move {
                let resp = rpc_post(
                    &app_blk,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": slot,
                        "method": "getBlock",
                        "params": [slot, { "encoding": "json", "maxSupportedTransactionVersion": 0 }]
                    })
                    .to_string(),
                )
                .await;
                assert!(
                    resp.get("error").is_none(),
                    "getBlock({slot}) failed under 429 burst: {resp}"
                );
                assert_eq!(resp["result"]["parentSlot"], slot - 1);
            }));

            let sig = slot_sigs[&slot].clone();
            let app_tx = app.clone();
            tasks.push(tokio::spawn(async move {
                let resp = rpc_post(
                    &app_tx,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": format!("tx-{slot}"),
                        "method": "getTransaction",
                        "params": [sig, { "slot": slot, "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }]
                    })
                    .to_string(),
                )
                .await;
                assert!(
                    resp.get("error").is_none(),
                    "getTransaction({slot}) failed under 429 burst: {resp}"
                );
                assert_eq!(resp["result"]["slot"], slot);
                assert_eq!(resp["result"]["transaction"]["signatures"][0], sig);
            }));
        }

        for t in tasks {
            t.await.expect("task completed without panic");
        }

        server_handle.abort();

        let observed_peak = peak_in_flight.load(Ordering::SeqCst);
        let observed_429 = throttled_429.load(Ordering::SeqCst);
        assert!(
            observed_429 >= 5,
            "expected >= 5 injected 429 responses to exercise throttling recovery, got {observed_429}"
        );
        assert!(
            observed_peak <= MAX_CONCURRENCY,
            "expected peak in-flight concurrency <= {MAX_CONCURRENCY}, observed {observed_peak}"
        );
        assert!(
            client.cache_len() <= RANGE_CACHE_CAP,
            "slot-range RAM LRU exceeded cap {RANGE_CACHE_CAP}: {}",
            client.cache_len()
        );
        assert_eq!(client.cache_len(), RANGE_CACHE_CAP);
        assert!(
            state.blockhash_cache_len() <= BLOCKHASH_CACHE_CAP,
            "blockhash RAM LRU exceeded cap {BLOCKHASH_CACHE_CAP}: {}",
            state.blockhash_cache_len()
        );
        assert_eq!(state.blockhash_cache_len(), BLOCKHASH_CACHE_CAP);
    }
}
