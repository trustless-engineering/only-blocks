//! `axum` JSON-RPC 2.0 server and block-fetching service backed exclusively by Old Faithful.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
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
    decode_block_from_index, encode_block, extract_blockhash_from_car, CarIndex, DecodeOptions,
};
use crate::old_faithful::OldFaithfulClient;
use crate::rpc::types::{GetBlockParams, JsonRpcError, JsonRpcRequest, JsonRpcResponse};

/// Default capacity for the bounded RAM-only `slot -> blockhash` LRU cache.
///
/// 100,000 entries (~64 bytes each) take ~6–8 MiB of RAM with zero disk writes.
pub const DEFAULT_BLOCKHASH_CACHE_CAPACITY: usize = 100_000;

/// Shared state for the JSON-RPC server.
#[derive(Clone)]
pub struct RpcState {
    client: OldFaithfulClient,
    blockhash_cache: Option<Arc<Mutex<LruCache<u64, String>>>>,
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
        }
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

    /// Dispatch a single parsed JSON-RPC 2.0 request.
    pub async fn dispatch_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
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
            "getHealth" => JsonRpcResponse::ok(id, Value::String("ok".to_string())),
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
            other => JsonRpcResponse::err(id, JsonRpcError::method_not_found(other)),
        }
    }
}

/// Build the `axum` [`Router`] serving JSON-RPC 2.0 on `POST /`.
pub fn build_router(state: RpcState) -> Router {
    Router::new().route("/", post(handle_rpc)).with_state(state)
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
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use crate::config::OldFaithfulConfig;
    use crate::decoder::test_helpers::{build_synthetic_slot_car, sample_legacy_tx, sample_v0_tx};
    use crate::old_faithful::{OldFaithfulClient, SLOTS_PER_EPOCH, SLOT_RANGE_ENTRY_BYTES};
    use crate::rpc::server::{build_router, RpcState};
    use crate::rpc::types::error_codes;

    struct MockOldFaithful {
        base_url: String,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockOldFaithful {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    impl MockOldFaithful {
        /// Serve synthetic slot-ranges and CAR slices for a map of `slot -> Option<car_bytes>`
        /// (`None` = skipped slot, absent epoch = 404).
        async fn start(archived_epochs: Vec<u64>, slots: HashMap<u64, Option<Vec<u8>>>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");

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

                    tokio::spawn(async move {
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
}
