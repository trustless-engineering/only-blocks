//! Live integration tests against `https://files.old-faithful.net`.
//!
//! Marked `#[ignore]` so default `cargo test` remains fast and offline.
//! Run explicitly with:
//! ```sh
//! cargo test -- --ignored --nocapture
//! ```

use std::time::Instant;

use onlyblocks::{OldFaithfulClient, OldFaithfulError, SLOTS_PER_EPOCH};

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_normal_archived_slot() {
    let client = OldFaithfulClient::with_defaults().expect("build default client");
    let slot = 302_400_001; // Epoch 700, slot_idx 1

    let t0 = Instant::now();
    let cold = client
        .fetch_slot_car(slot)
        .await
        .expect("cold fetch normal slot");
    let cold_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert_eq!(cold.meta.slot, slot);
    assert_eq!(cold.meta.epoch, 700);
    assert!(!cold.meta.range_cache_hit);
    assert!(!cold.bytes.is_empty());
    assert_eq!(cold.bytes.len(), cold.meta.length as usize);

    let t1 = Instant::now();
    let warm = client
        .fetch_slot_car(slot)
        .await
        .expect("warm fetch normal slot");
    let warm_ms = t1.elapsed().as_secs_f64() * 1_000.0;

    assert!(warm.meta.range_cache_hit);
    assert_eq!(warm.bytes.len(), cold.bytes.len());
    assert_eq!(warm.bytes, cold.bytes);

    println!(
        "[live_normal_archived_slot] slot={slot} epoch={} offset={} bytes={} cold={cold_ms:.1}ms warm={warm_ms:.1}ms",
        cold.meta.epoch,
        cold.meta.offset,
        cold.meta.length
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_skipped_slot() {
    let client = OldFaithfulClient::with_defaults().expect("build default client");
    let slot = 302_400_004; // Epoch 700, slot_idx 4 (length == 0)

    let t0 = Instant::now();
    let err_cold = client
        .fetch_slot_car(slot)
        .await
        .expect_err("expected SkippedSlot");
    let cold_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert!(
        matches!(err_cold, OldFaithfulError::SkippedSlot { slot: s } if s == slot),
        "unexpected error: {err_cold:?}"
    );

    let t1 = Instant::now();
    let err_warm = client
        .fetch_slot_car(slot)
        .await
        .expect_err("expected cached SkippedSlot");
    let warm_ms = t1.elapsed().as_secs_f64() * 1_000.0;

    assert!(matches!(
        err_warm,
        OldFaithfulError::SkippedSlot { slot: s } if s == slot
    ));

    println!(
        "[live_skipped_slot] slot={slot} epoch={} SkippedSlot cold={cold_ms:.1}ms warm_cache={warm_ms:.3}ms",
        slot / SLOTS_PER_EPOCH
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_pre_epoch_157_slot() {
    let client = OldFaithfulClient::with_defaults().expect("build default client");
    let slot = 43_200_000; // Epoch 100, slot_idx 0 (< 67_824_000)
    assert!(slot < 67_824_000);

    let t0 = Instant::now();
    let cold = client
        .fetch_slot_car(slot)
        .await
        .expect("cold fetch pre-epoch-157 slot");
    let cold_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert_eq!(cold.meta.slot, slot);
    assert_eq!(cold.meta.epoch, 100);
    assert!(!cold.meta.range_cache_hit);
    assert!(!cold.bytes.is_empty());
    assert_eq!(cold.bytes.len(), cold.meta.length as usize);

    let t1 = Instant::now();
    let warm = client
        .fetch_slot_car(slot)
        .await
        .expect("warm fetch pre-epoch-157 slot");
    let warm_ms = t1.elapsed().as_secs_f64() * 1_000.0;

    assert!(warm.meta.range_cache_hit);
    assert_eq!(warm.bytes.len(), cold.meta.length as usize);

    println!(
        "[live_pre_epoch_157_slot] slot={slot} epoch={} offset={} bytes={} cold={cold_ms:.1}ms warm={warm_ms:.1}ms",
        cold.meta.epoch,
        cold.meta.offset,
        cold.meta.length
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_epoch_boundary_reward_block() {
    let client = OldFaithfulClient::with_defaults().expect("build default client");
    let slot = 302_400_000; // Epoch 700 boundary reward block (~56 MB)

    let t0 = Instant::now();
    let cold = client
        .fetch_slot_car(slot)
        .await
        .expect("cold fetch epoch-boundary reward block");
    let cold_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert_eq!(cold.meta.slot, slot);
    assert_eq!(cold.meta.epoch, 700);
    assert!(!cold.meta.range_cache_hit);
    assert!(
        cold.meta.length > 40 * 1024 * 1024,
        "expected large epoch-boundary reward block, got {} bytes",
        cold.meta.length
    );
    assert_eq!(cold.bytes.len(), cold.meta.length as usize);

    let t1 = Instant::now();
    let warm = client
        .fetch_slot_car(slot)
        .await
        .expect("warm fetch epoch-boundary reward block");
    let warm_ms = t1.elapsed().as_secs_f64() * 1_000.0;

    assert!(warm.meta.range_cache_hit);
    assert_eq!(warm.bytes.len(), cold.meta.length as usize);

    println!(
        "[live_epoch_boundary_reward_block] slot={slot} epoch={} offset={} bytes={} ({:.2} MiB) cold={cold_ms:.1}ms warm={warm_ms:.1}ms",
        cold.meta.epoch,
        cold.meta.offset,
        cold.meta.length,
        cold.meta.length as f64 / (1024.0 * 1024.0)
    );
}

#[tokio::test]
#[ignore = "hits live https://files.old-faithful.net"]
async fn live_unarchived_future_slot() {
    let client = OldFaithfulClient::with_defaults().expect("build default client");
    let epoch = 9999;
    let slot = epoch * SLOTS_PER_EPOCH;

    let t0 = Instant::now();
    let err = client
        .fetch_slot_car(slot)
        .await
        .expect_err("expected UnarchivedSlot");
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    assert!(
        matches!(err, OldFaithfulError::UnarchivedSlot { slot: s, epoch: e } if s == slot && e == epoch),
        "unexpected error: {err:?}"
    );
    assert!(err.is_unarchived_slot());

    println!(
        "[live_unarchived_future_slot] slot={slot} epoch={epoch} UnarchivedSlot elapsed={elapsed_ms:.1}ms (no retries)"
    );
}
