use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use instant_rpc::{
    build_router, OldFaithfulClient, OldFaithfulConfig, RetryConfig, RpcState, DEFAULT_BASE_URL,
    DEFAULT_BLOCKHASH_CACHE_CAPACITY, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_CONCURRENT_REQUESTS,
    DEFAULT_MAX_SLICE_BYTES, DEFAULT_REQUEST_TIMEOUT, DEFAULT_SLOT_RANGE_CACHE_CAPACITY,
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Instant RPC — Historical-only Solana JSON-RPC server backed by Old Faithful.
#[derive(Debug, Parser)]
#[command(name = "instant-rpc", version, about)]
struct Cli {
    /// Socket address to bind the JSON-RPC HTTP server to.
    #[arg(long, default_value = "127.0.0.1:8899", env = "INSTANT_RPC_BIND")]
    bind: SocketAddr,

    /// Base URL for the Old Faithful archive.
    #[arg(long, default_value = DEFAULT_BASE_URL, env = "OLD_FAITHFUL_BASE_URL")]
    base_url: String,

    /// Maximum allowed CAR slice size in bytes (default: 128 MiB).
    #[arg(long, default_value_t = DEFAULT_MAX_SLICE_BYTES)]
    max_slice_bytes: u64,

    /// Maximum concurrent in-flight HTTP/2 Range requests to Old Faithful.
    #[arg(long, default_value_t = DEFAULT_MAX_CONCURRENT_REQUESTS)]
    max_concurrent_requests: usize,

    /// Capacity of the RAM-only slot-range LRU cache (`0` disables).
    #[arg(long, default_value_t = DEFAULT_SLOT_RANGE_CACHE_CAPACITY)]
    slot_range_cache_capacity: usize,

    /// Capacity of the RAM-only slot -> blockhash LRU cache (`0` disables).
    #[arg(long, default_value_t = DEFAULT_BLOCKHASH_CACHE_CAPACITY)]
    blockhash_cache_capacity: usize,

    /// HTTP connect timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_CONNECT_TIMEOUT.as_secs())]
    connect_timeout_secs: u64,

    /// Per-request HTTP timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_REQUEST_TIMEOUT.as_secs())]
    request_timeout_secs: u64,

    /// Maximum retry attempts on transient 429/5xx/transport errors.
    #[arg(long, default_value_t = RetryConfig::default().max_retries)]
    max_retries: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let config = OldFaithfulConfig {
        base_url: cli.base_url,
        connect_timeout: Duration::from_secs(cli.connect_timeout_secs),
        request_timeout: Duration::from_secs(cli.request_timeout_secs),
        max_slice_bytes: cli.max_slice_bytes,
        max_concurrent_requests: cli.max_concurrent_requests,
        slot_range_cache_capacity: cli.slot_range_cache_capacity,
        retry: RetryConfig {
            max_retries: cli.max_retries,
            ..RetryConfig::default()
        },
        ..OldFaithfulConfig::default()
    };

    let client = OldFaithfulClient::new(config)?;
    let state =
        RpcState::with_blockhash_cache_capacity(client.clone(), cli.blockhash_cache_capacity);
    let app = build_router(state);

    let listener = TcpListener::bind(cli.bind).await?;
    let local_addr = listener.local_addr()?;

    info!(
        bind = %local_addr,
        base_url = %client.base_url(),
        max_slice_bytes = client.config().max_slice_bytes,
        max_concurrent_requests = client.config().max_concurrent_requests,
        slot_range_cache_capacity = client.cache_capacity(),
        blockhash_cache_capacity = cli.blockhash_cache_capacity,
        "instant-rpc JSON-RPC server listening (historical-only, zero disk downloads)"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("received shutdown signal; stopping instant-rpc server");
}
