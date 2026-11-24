//! Live integration tests for the full `axum` JSON-RPC 2.0 slot-hinted `getTransaction` handler
//! against `https://files.old-faithful.net`.
//!
//! Marked `#[ignore]` so default `cargo test` remains fast and offline.
//! Run explicitly with:
//! ```sh
//! cargo test -- --ignored --nocapture
//! ```

use std::time::Instant;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use instant_rpc::{build_router, error_codes, OldFaithfulClient, RpcState, SLOTS_PER_EPOCH};
use serde_json::{json, Value};
use solana_signature::Signature;
use tower::ServiceExt;

async fn rpc_post(app: &axum::Router, body: Value) -> Value {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("parse JSON-RPC response")
}

/// Discover a real transaction signature from `slot` using an independent `OldFaithfulClient`
/// so the router under test starts genuinely cold.
///
/// When `prefer_v0` is true, picks a version-0 transaction if one exists in the slot.
async fn discover_slot_signature(slot: u64, prefer_v0: bool) -> (String, Value, i64) {
    let setup_client = OldFaithfulClient::with_defaults().expect("setup client");
    let setup_app = build_router(RpcState::new(setup_client));
    let block_resp = rpc_post(
        &setup_app,
        json!({
            "jsonrpc": "2.0",
            "id": "setup",
            "method": "getBlock",
            "params": [slot, {
                "encoding": "json",
                "transactionDetails": "full",
                "rewards": false,
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    assert!(
        block_resp.get("error").is_none(),
        "setup getBlock({slot}) failed: {block_resp}"
    );
    let result = &block_resp["result"];
    let block_time = result["blockTime"].as_i64().expect("blockTime");
    let txs = result["transactions"].as_array().expect("transactions");
    assert!(!txs.is_empty(), "expected non-empty slot {slot}");

    let chosen = if prefer_v0 {
        txs.iter()
            .find(|tx| tx["version"] == json!(0))
            .unwrap_or(&txs[0])
    } else {
        &txs[0]
    };

    let sig = chosen["transaction"]["signatures"][0]
        .as_str()
        .expect("signature string")
        .to_string();
    let version = chosen["version"].clone();
    (sig, version, block_time)
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_transaction_modern_slot_all_four_encodings_and_latency() {
    let slot = 302_400_001u64; // Epoch 700, modern archived slot with v0 txs
    let (sig, expected_version, expected_block_time) = discover_slot_signature(slot, true).await;

    // Fresh client & router so the first getTransaction request measures true cold latency.
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));

    // 1. Cold request (`json`, maxSupportedTransactionVersion: 0)
    let t_cold = Instant::now();
    let resp_json_cold = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [sig, {
                "slot": slot,
                "encoding": "json",
                "maxSupportedTransactionVersion": 0,
                "commitment": "finalized"
            }]
        }),
    )
    .await;
    let cold_ms = t_cold.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        resp_json_cold.get("error").is_none(),
        "unexpected json error: {resp_json_cold}"
    );
    let res_json = &resp_json_cold["result"];
    assert_eq!(res_json["slot"], slot);
    assert_eq!(res_json["blockTime"], expected_block_time);
    assert_eq!(res_json["version"], expected_version);
    assert!(res_json["meta"].is_object());
    assert!(res_json["meta"]["fee"].is_u64());
    assert!(res_json["meta"]["preBalances"].is_array());
    assert!(res_json["meta"]["postBalances"].is_array());
    assert_eq!(res_json["transaction"]["signatures"][0], sig);
    assert!(res_json["transaction"]["message"]["accountKeys"][0].is_string());

    // 2. Warm request (`json`, slot-ranges.raw entry cached in RAM)
    let t_warm = Instant::now();
    let resp_json_warm = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getTransaction",
            "params": [sig, {
                "slot": slot,
                "encoding": "json",
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let warm_ms = t_warm.elapsed().as_secs_f64() * 1_000.0;
    assert!(resp_json_warm.get("error").is_none());
    assert_eq!(resp_json_warm["result"]["slot"], slot);
    assert_eq!(
        resp_json_warm["result"]["transaction"]["signatures"][0],
        sig
    );

    // 3. `jsonParsed` encoding
    let t_parsed = Instant::now();
    let resp_parsed = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "getTransaction",
            "params": [sig, {
                "slot": slot,
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let parsed_ms = t_parsed.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        resp_parsed.get("error").is_none(),
        "unexpected jsonParsed error: {resp_parsed}"
    );
    let res_parsed = &resp_parsed["result"];
    assert_eq!(res_parsed["slot"], slot);
    assert_eq!(res_parsed["blockTime"], expected_block_time);
    assert_eq!(res_parsed["version"], expected_version);
    assert!(res_parsed["meta"]["fee"].is_u64());
    assert_eq!(res_parsed["transaction"]["signatures"][0], sig);
    assert!(res_parsed["transaction"]["message"]["accountKeys"][0]["pubkey"].is_string());
    assert!(res_parsed["transaction"]["message"]["accountKeys"][0]["signer"].is_boolean());

    // 4. `base64` encoding
    let t_b64 = Instant::now();
    let resp_b64 = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "getTransaction",
            "params": [sig, {
                "slot": slot,
                "encoding": "base64",
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let b64_ms = t_b64.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        resp_b64.get("error").is_none(),
        "unexpected base64 error: {resp_b64}"
    );
    let res_b64 = &resp_b64["result"];
    assert_eq!(res_b64["slot"], slot);
    assert_eq!(res_b64["blockTime"], expected_block_time);
    assert_eq!(res_b64["version"], expected_version);
    assert!(res_b64["meta"]["fee"].is_u64());
    assert!(res_b64["transaction"][0].is_string());
    assert_eq!(res_b64["transaction"][1], "base64");

    // 5. `base58` encoding
    let t_b58 = Instant::now();
    let resp_b58 = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "getTransaction",
            "params": [sig, {
                "slot": slot,
                "encoding": "base58",
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let b58_ms = t_b58.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        resp_b58.get("error").is_none(),
        "unexpected base58 error: {resp_b58}"
    );
    let res_b58 = &resp_b58["result"];
    assert_eq!(res_b58["slot"], slot);
    assert_eq!(res_b58["blockTime"], expected_block_time);
    assert_eq!(res_b58["version"], expected_version);
    assert!(res_b58["meta"]["fee"].is_u64());
    assert!(res_b58["transaction"][0].is_string());
    assert_eq!(res_b58["transaction"][1], "base58");

    // 6. If the matched transaction is v0, omitting maxSupportedTransactionVersion must return -32015
    if expected_version == json!(0) {
        let resp_no_ver = rpc_post(
            &app,
            json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "getTransaction",
                "params": [sig, { "slot": slot }]
            }),
        )
        .await;
        assert_eq!(
            resp_no_ver["error"]["code"],
            error_codes::UNSUPPORTED_TRANSACTION_VERSION,
            "expected -32015 for v0 tx without maxSupportedTransactionVersion, got: {resp_no_ver}"
        );
    }

    println!(
        "[live_get_transaction_modern_slot] slot={slot} sig={sig} version={expected_version} cold_json={cold_ms:.1}ms warm_json={warm_ms:.1}ms jsonParsed={parsed_ms:.1}ms base64={b64_ms:.1}ms base58={b58_ms:.1}ms"
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_transaction_pre_epoch_157_bincode() {
    let slot = 43_200_000u64; // Epoch 100, pre-Epoch 157 legacy bincode meta
    let (sig, _expected_version, expected_block_time) = discover_slot_signature(slot, false).await;

    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));

    let t0 = Instant::now();
    let resp = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [sig, {
                "slot": slot,
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert!(
        resp.get("error").is_none(),
        "unexpected pre-157 getTransaction error: {resp}"
    );
    let res = &resp["result"];
    assert_eq!(res["slot"], slot);
    assert_eq!(res["blockTime"], expected_block_time);
    assert!(res["meta"].is_object());
    assert!(res["meta"]["fee"].is_u64());
    assert!(res["meta"]["preBalances"].is_array());
    assert!(res["meta"]["postBalances"].is_array());
    assert_eq!(res["transaction"]["signatures"][0], sig);
    assert_eq!(res["version"], "legacy");

    println!(
        "[live_get_transaction_pre_epoch_157] slot={slot} sig={sig} blockTime={expected_block_time} fee={} elapsed={elapsed_ms:.1}ms",
        res["meta"]["fee"]
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_transaction_absent_signature_returns_null() {
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));
    let slot = 302_400_001u64;
    let fake_sig = Signature::from([0x5au8; 64]).to_string();

    let t0 = Instant::now();
    let resp = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [fake_sig, { "slot": slot, "maxSupportedTransactionVersion": 0 }]
        }),
    )
    .await;
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert!(resp.get("error").is_none(), "unexpected error: {resp}");
    assert!(resp.as_object().unwrap().contains_key("result"));
    assert!(resp["result"].is_null());

    println!(
        "[live_get_transaction_absent_signature] slot={slot} sig={fake_sig} result=null elapsed={elapsed_ms:.1}ms"
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_transaction_skipped_slot_returns_null() {
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));
    let skipped_slot = 302_400_004u64;
    let valid_sig = Signature::from([0x33u8; 64]).to_string();

    let t0 = Instant::now();
    let resp = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [valid_sig, { "slot": skipped_slot }]
        }),
    )
    .await;
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert!(resp.get("error").is_none(), "unexpected error: {resp}");
    assert!(resp.as_object().unwrap().contains_key("result"));
    assert!(resp["result"].is_null());

    println!(
        "[live_get_transaction_skipped_slot] slot={skipped_slot} result=null elapsed={elapsed_ms:.1}ms"
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_transaction_omitted_slot_hint_returns_invalid_params() {
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));
    let valid_sig = Signature::from([0x44u8; 64]).to_string();

    let t0 = Instant::now();
    let resp_no_cfg = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [valid_sig]
        }),
    )
    .await;
    let resp_empty_cfg = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getTransaction",
            "params": [valid_sig, {}]
        }),
    )
    .await;
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert_eq!(resp_no_cfg["error"]["code"], error_codes::INVALID_PARAMS);
    assert!(resp_no_cfg["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("slot"));
    assert_eq!(resp_empty_cfg["error"]["code"], error_codes::INVALID_PARAMS);
    assert!(resp_empty_cfg["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("slot"));

    println!(
        "[live_get_transaction_omitted_slot_hint] code={} elapsed={elapsed_ms:.3}ms (immediate, zero network)",
        resp_no_cfg["error"]["code"]
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_transaction_unarchived_slot_returns_block_not_available() {
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));
    let unarchived_slot = 9999 * SLOTS_PER_EPOCH;
    let valid_sig = Signature::from([0x55u8; 64]).to_string();

    let t0 = Instant::now();
    let resp = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [valid_sig, { "slot": unarchived_slot }]
        }),
    )
    .await;
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert_eq!(resp["error"]["code"], error_codes::BLOCK_NOT_AVAILABLE);
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("historical-only"));

    println!(
        "[live_get_transaction_unarchived_slot] slot={unarchived_slot} code={} msg='{}' elapsed={elapsed_ms:.1}ms",
        resp["error"]["code"], resp["error"]["message"]
    );
}
