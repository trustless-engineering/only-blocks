//! Live integration tests for the full `axum` JSON-RPC 2.0 `getBlock` handler against
//! `https://files.old-faithful.net`.
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
use instant_rpc::{
    build_router, decode_transaction_by_signature, encode_transaction, error_codes,
    OldFaithfulClient, RpcState, SLOTS_PER_EPOCH,
};
use serde_json::{json, Value};
use solana_signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
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

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_block_modern_slot_all_four_encodings_and_latency() {
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client.clone()));
    let slot = 302_400_001u64; // Epoch 700, normal modern slot (contains v0 txs)

    // 0. getHealth sanity check on live router
    let health = rpc_post(
        &app,
        json!({"jsonrpc": "2.0", "id": "health", "method": "getHealth"}),
    )
    .await;
    assert_eq!(health["result"], "ok");

    // 1. Cold request (json) — also warms slot-range cache + parent blockhash cache
    let t_cold = Instant::now();
    let resp_json = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBlock",
            "params": [slot, {
                "encoding": "json",
                "transactionDetails": "full",
                "rewards": true,
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let cold_ms = t_cold.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        resp_json.get("error").is_none(),
        "unexpected json error: {resp_json}"
    );
    let res_json = &resp_json["result"];
    let blockhash = res_json["blockhash"].as_str().expect("blockhash");
    let prev_blockhash = res_json["previousBlockhash"]
        .as_str()
        .expect("previousBlockhash");
    let parent_slot = res_json["parentSlot"].as_u64().expect("parentSlot");
    let block_time = res_json["blockTime"].as_i64().expect("blockTime");
    let block_height = res_json["blockHeight"].as_u64().expect("blockHeight");
    let txs_json = res_json["transactions"]
        .as_array()
        .expect("transactions array");
    assert!(!blockhash.is_empty());
    assert!(!prev_blockhash.is_empty());
    assert_ne!(blockhash, prev_blockhash);
    assert_eq!(parent_slot, 302_400_000);
    assert!(block_time > 1_700_000_000);
    assert!(block_height > 0);
    assert!(!txs_json.is_empty());
    // `json` encoding has `transaction.message.accountKeys` as array of strings (raw message).
    assert!(txs_json[0]["transaction"]["message"]["accountKeys"][0].is_string());
    assert!(txs_json[0]["meta"]["fee"].is_u64());

    // 2. Warm request (json) — slot range & parent blockhash cached in RAM
    let t_warm = Instant::now();
    let resp_json_warm = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getBlock",
            "params": [slot, {
                "encoding": "json",
                "transactionDetails": "full",
                "rewards": true,
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let warm_ms = t_warm.elapsed().as_secs_f64() * 1_000.0;
    assert!(resp_json_warm.get("error").is_none());
    assert_eq!(resp_json_warm["result"]["blockhash"], blockhash);

    // 3. `jsonParsed` encoding
    let t_parsed = Instant::now();
    let resp_parsed = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "getBlock",
            "params": [slot, {
                "encoding": "jsonParsed",
                "transactionDetails": "full",
                "rewards": true,
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
    let txs_parsed = resp_parsed["result"]["transactions"]
        .as_array()
        .expect("jsonParsed txs");
    assert_eq!(txs_parsed.len(), txs_json.len());
    // `jsonParsed` accountKeys are objects `{ pubkey, signer, writable, source }`.
    assert!(txs_parsed[0]["transaction"]["message"]["accountKeys"][0]["pubkey"].is_string());
    assert!(txs_parsed[0]["transaction"]["message"]["accountKeys"][0]["signer"].is_boolean());

    // 4. `base64` encoding
    let t_b64 = Instant::now();
    let resp_b64 = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "getBlock",
            "params": [slot, {
                "encoding": "base64",
                "transactionDetails": "full",
                "rewards": true,
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
    let txs_b64 = resp_b64["result"]["transactions"]
        .as_array()
        .expect("base64 txs");
    assert_eq!(txs_b64.len(), txs_json.len());
    assert_eq!(txs_b64[0]["transaction"][1], "base64");
    assert!(txs_b64[0]["transaction"][0].is_string());

    // 5. `base58` encoding
    let t_b58 = Instant::now();
    let resp_b58 = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "getBlock",
            "params": [slot, {
                "encoding": "base58",
                "transactionDetails": "full",
                "rewards": true,
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
    let txs_b58 = resp_b58["result"]["transactions"]
        .as_array()
        .expect("base58 txs");
    assert_eq!(txs_b58.len(), txs_json.len());
    assert_eq!(txs_b58[0]["transaction"][1], "base58");
    assert!(txs_b58[0]["transaction"][0].is_string());

    // 6. Omitting maxSupportedTransactionVersion on a modern slot containing v0 txs -> -32015
    let resp_no_ver = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "getBlock",
            "params": [slot]
        }),
    )
    .await;
    assert_eq!(
        resp_no_ver["error"]["code"],
        error_codes::UNSUPPORTED_TRANSACTION_VERSION,
        "expected -32015 when maxSupportedTransactionVersion omitted, got: {resp_no_ver}"
    );

    // 7. M3 reuse check: decode a single transaction by signature directly from CAR slice
    let first_sig_str = txs_json[0]["transaction"]["signatures"][0]
        .as_str()
        .expect("first signature");
    let first_sig: Signature = first_sig_str.parse().expect("parse sig");
    let car = client.fetch_slot_car(slot).await.expect("fetch car");
    let found = decode_transaction_by_signature(slot, &car.bytes, &first_sig)
        .expect("decode single tx")
        .expect("tx present");
    assert_eq!(found.block_time, Some(block_time));
    let encoded_tx =
        encode_transaction(found, UiTransactionEncoding::JsonParsed, Some(0)).expect("encode tx");
    assert_eq!(encoded_tx.slot, slot);

    println!(
        "[live_get_block_modern_slot] slot={slot} parent={parent_slot} txs={} blockhash={blockhash} prev={prev_blockhash} cold={cold_ms:.1}ms warm_json={warm_ms:.1}ms jsonParsed={parsed_ms:.1}ms base64={b64_ms:.1}ms base58={b58_ms:.1}ms",
        txs_json.len()
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_block_skipped_slot() {
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));
    let slot = 302_400_004u64;

    let t0 = Instant::now();
    let resp = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBlock",
            "params": [slot, { "maxSupportedTransactionVersion": 0 }]
        }),
    )
    .await;
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert_eq!(resp["error"]["code"], error_codes::SLOT_SKIPPED);
    println!(
        "[live_get_block_skipped_slot] slot={slot} code={} msg='{}' elapsed={elapsed_ms:.1}ms",
        resp["error"]["code"], resp["error"]["message"]
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_block_pre_epoch_157_bincode_slot() {
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));
    let slot = 43_200_000u64; // Epoch 100, pre-Epoch 157 (bincode meta & rewards)

    let t0 = Instant::now();
    let resp = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBlock",
            "params": [slot, {
                "encoding": "jsonParsed",
                "transactionDetails": "full",
                "rewards": true,
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert!(
        resp.get("error").is_none(),
        "unexpected pre-157 error: {resp}"
    );
    let res = &resp["result"];
    let txs = res["transactions"].as_array().expect("txs array");
    assert!(!txs.is_empty(), "expected non-empty pre-157 transactions");
    assert!(
        txs[0]["meta"].is_object(),
        "expected decoded bincode meta on pre-157 tx"
    );
    assert!(txs[0]["meta"]["fee"].is_u64());
    assert!(res["blockhash"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(res["previousBlockhash"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));

    println!(
        "[live_get_block_pre_epoch_157] slot={slot} parent={} txs={} rewards={} blockhash={} elapsed={elapsed_ms:.1}ms",
        res["parentSlot"],
        txs.len(),
        res["rewards"].as_array().map(|r| r.len()).unwrap_or(0),
        res["blockhash"].as_str().unwrap_or(""),
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_block_epoch_boundary_reward_block() {
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));
    let slot = 302_400_000u64; // Epoch 700 boundary reward block (~53.8 MiB)

    // With rewards: true
    let t_with = Instant::now();
    let resp_with = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBlock",
            "params": [slot, {
                "encoding": "json",
                "transactionDetails": "signatures",
                "rewards": true,
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let with_ms = t_with.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        resp_with.get("error").is_none(),
        "unexpected reward-block error: {resp_with}"
    );
    let rewards_arr = resp_with["result"]["rewards"]
        .as_array()
        .expect("rewards array when rewards: true");
    assert!(
        rewards_arr.len() > 10_000,
        "expected large epoch-boundary reward list, got {}",
        rewards_arr.len()
    );

    // With rewards: false (omits rewards field)
    let t_without = Instant::now();
    let resp_without = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getBlock",
            "params": [slot, {
                "encoding": "json",
                "transactionDetails": "signatures",
                "rewards": false,
                "maxSupportedTransactionVersion": 0
            }]
        }),
    )
    .await;
    let without_ms = t_without.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        resp_without.get("error").is_none(),
        "unexpected rewards=false error: {resp_without}"
    );
    assert!(
        resp_without["result"].get("rewards").is_none(),
        "expected rewards omitted when rewards: false"
    );

    println!(
        "[live_get_block_epoch_boundary_reward_block] slot={slot} rewards_count={} with_rewards={with_ms:.1}ms without_rewards={without_ms:.1}ms",
        rewards_arr.len()
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_get_block_unarchived_future_slot() {
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client));
    let slot = 9999 * SLOTS_PER_EPOCH;

    let t0 = Instant::now();
    let resp = rpc_post(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBlock",
            "params": [slot, { "maxSupportedTransactionVersion": 0 }]
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
        "[live_get_block_unarchived_future_slot] slot={slot} code={} msg='{}' elapsed={elapsed_ms:.1}ms",
        resp["error"]["code"], resp["error"]["message"]
    );
}
