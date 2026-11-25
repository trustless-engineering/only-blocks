use std::time::Duration;

use url::Url;

use crate::error::OldFaithfulError;

/// Default base URL for the Old Faithful public archive.
pub const DEFAULT_BASE_URL: &str = "https://files.old-faithful.net";

/// Default maximum CAR slice size (128 MiB), safely above ~55 MB epoch-boundary reward blocks.
pub const DEFAULT_MAX_SLICE_BYTES: u64 = 128 * 1024 * 1024;

/// Default TCP/TLS connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default per-request timeout (generous enough for ~55 MB epoch-boundary reward blocks).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Default idle connection timeout in the HTTP pool.
pub const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Default maximum idle connections retained per host.
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 16;

/// Default maximum number of concurrent in-flight HTTP requests.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 32;

/// Default maximum number of entries in the RAM-only slot-range LRU cache.
///
/// Each cached entry holds a `u64` slot key plus a small enum (16 bytes) and LRU metadata,
/// keeping 100,000 entries under ~8 MiB of RAM with zero disk usage.
pub const DEFAULT_SLOT_RANGE_CACHE_CAPACITY: usize = 100_000;

/// Retry and exponential backoff configuration for transient Old Faithful failures.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retries after the initial attempt (`0` disables retries).
    pub max_retries: usize,
    /// Initial backoff delay before the first retry.
    pub initial_backoff: Duration,
    /// Maximum backoff delay (also bounds `Retry-After` delays).
    pub max_backoff: Duration,
    /// Jitter ratio in `[0.0, 1.0]`. A value of `0.5` picks uniformly in `[0.5 * delay, delay]`.
    pub jitter_ratio: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 4,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(10),
            jitter_ratio: 0.5,
        }
    }
}

impl RetryConfig {
    /// Validate retry parameters.
    pub fn validate(&self) -> Result<(), OldFaithfulError> {
        if self.max_backoff < self.initial_backoff {
            return Err(OldFaithfulError::InvalidConfig(
                "retry.max_backoff must be >= retry.initial_backoff".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&self.jitter_ratio) || self.jitter_ratio.is_nan() {
            return Err(OldFaithfulError::InvalidConfig(
                "retry.jitter_ratio must be in [0.0, 1.0]".to_string(),
            ));
        }
        Ok(())
    }
}

/// Configuration for [`crate::OldFaithfulClient`].
#[derive(Debug, Clone)]
pub struct OldFaithfulConfig {
    /// Base URL for Old Faithful (e.g. `https://files.old-faithful.net`).
    pub base_url: String,
    /// HTTP `User-Agent` header sent on every request.
    pub user_agent: String,
    /// Connect timeout for HTTP requests.
    pub connect_timeout: Duration,
    /// Total timeout for a single HTTP request attempt (including body streaming).
    pub request_timeout: Duration,
    /// Idle timeout for pooled HTTP connections.
    pub pool_idle_timeout: Duration,
    /// Maximum number of idle pooled connections per host.
    pub pool_max_idle_per_host: usize,
    /// Maximum allowed CAR slice size in bytes (enforced before and while buffering).
    pub max_slice_bytes: u64,
    /// Maximum concurrent in-flight HTTP requests enforced by a Tokio semaphore.
    pub max_concurrent_requests: usize,
    /// Maximum entries in the bounded RAM-only slot-range LRU cache (`0` disables caching).
    pub slot_range_cache_capacity: usize,
    /// Retry/backoff settings for `429`, `5xx`, and transient transport errors.
    pub retry: RetryConfig,
}

impl Default for OldFaithfulConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            user_agent: format!("onlyblocks/{}", env!("CARGO_PKG_VERSION")),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            pool_idle_timeout: DEFAULT_POOL_IDLE_TIMEOUT,
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE_PER_HOST,
            max_slice_bytes: DEFAULT_MAX_SLICE_BYTES,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            slot_range_cache_capacity: DEFAULT_SLOT_RANGE_CACHE_CAPACITY,
            retry: RetryConfig::default(),
        }
    }
}

impl OldFaithfulConfig {
    /// Create a configuration targeting a custom base URL (useful for testing or mirrors).
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            ..Self::default()
        }
    }

    /// Validate all configuration fields and return the normalized base URL (without trailing `/`).
    pub fn validate(&self) -> Result<String, OldFaithfulError> {
        let trimmed = self.base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(OldFaithfulError::InvalidConfig(
                "base_url must not be empty".to_string(),
            ));
        }
        let parsed = Url::parse(trimmed).map_err(|e| {
            OldFaithfulError::InvalidConfig(format!("invalid base_url '{}': {e}", self.base_url))
        })?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(OldFaithfulError::InvalidConfig(format!(
                    "unsupported base_url scheme '{other}' (expected http or https)"
                )));
            }
        }
        if self.user_agent.trim().is_empty() {
            return Err(OldFaithfulError::InvalidConfig(
                "user_agent must not be empty".to_string(),
            ));
        }
        if self.max_slice_bytes == 0 {
            return Err(OldFaithfulError::InvalidConfig(
                "max_slice_bytes must be > 0".to_string(),
            ));
        }
        if self.max_concurrent_requests == 0 {
            return Err(OldFaithfulError::InvalidConfig(
                "max_concurrent_requests must be > 0".to_string(),
            ));
        }
        if self.connect_timeout.is_zero() {
            return Err(OldFaithfulError::InvalidConfig(
                "connect_timeout must be > 0".to_string(),
            ));
        }
        if self.request_timeout.is_zero() {
            return Err(OldFaithfulError::InvalidConfig(
                "request_timeout must be > 0".to_string(),
            ));
        }
        self.retry.validate()?;
        Ok(trimmed.to_string())
    }
}
