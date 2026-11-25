//! Live concurrent smoke test running parallel `getBlock` calls against
//! `https://files.old-faithful.net` and reporting p50/p95 latencies.
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
use onlyblocks::{build_router, OldFaithfulClient, RpcState};
use serde_json::{json, Value};
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

fn percentile_ms(sorted_ms: &[f64], pct: f64) -> f64 {
    assert!(!sorted_ms.is_empty());
    let rank = ((pct / 100.0) * (sorted_ms.len() as f64)).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted_ms.len() - 1);
    sorted_ms[idx]
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_concurrent_get_block_p50_p95() {
    // Discover six archived blocks with a separate client so the benchmark starts cold.
    let setup_client = OldFaithfulClient::with_defaults().expect("setup client");
    let setup_app = build_router(RpcState::new(setup_client));

    let mut targets = Vec::new();
    for candidate in 302_400_001u64..302_400_020u64 {
        if targets.len() >= 6 {
            break;
        }
        let resp = rpc_post(
            &setup_app,
            json!({
                "jsonrpc": "2.0",
                "id": candidate,
                "method": "getBlock",
                "params": [candidate, {
                    "transactionDetails": "none",
                    "rewards": false
                }]
            }),
        )
        .await;
        if resp["result"]["blockhash"].is_string() {
            targets.push(candidate);
        }
    }
    assert_eq!(
        targets.len(),
        6,
        "expected to discover 6 non-skipped slots in Epoch 700"
    );

    // Fresh client & router under test.
    let client = OldFaithfulClient::with_defaults().expect("client");
    let app = build_router(RpcState::new(client.clone()));

    // Issue six concurrent requests with cold caches, then repeat with warm caches.
    for (wave_name, wave_idx) in [("cold", 0usize), ("warm", 1usize)] {
        let mut block_tasks = Vec::with_capacity(targets.len());

        let wave_start = Instant::now();
        for (i, &slot) in targets.iter().enumerate() {
            let app_blk = app.clone();
            block_tasks.push(tokio::spawn(async move {
                let t0 = Instant::now();
                let resp = rpc_post(
                    &app_blk,
                    json!({
                        "jsonrpc": "2.0",
                        "id": format!("blk-{wave_idx}-{i}"),
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
                let ms = t0.elapsed().as_secs_f64() * 1_000.0;
                assert!(
                    resp.get("error").is_none(),
                    "parallel getBlock({slot}) failed: {resp}"
                );
                assert!(resp["result"]["blockhash"].is_string());
                ms
            }));
        }

        let mut block_ms = Vec::with_capacity(block_tasks.len());
        for t in block_tasks {
            block_ms.push(t.await.expect("block task"));
        }
        let wave_wall_ms = wave_start.elapsed().as_secs_f64() * 1_000.0;

        block_ms.sort_by(|a, b| a.total_cmp(b));

        println!(
            "[live_concurrent_smoke:{wave_name}] n={} wall={wave_wall_ms:.1}ms | getBlock p50={:.1}ms p95={:.1}ms | range_cache_len={}",
            block_ms.len(),
            percentile_ms(&block_ms, 50.0),
            percentile_ms(&block_ms, 95.0),
            client.cache_len(),
        );
    }
}
