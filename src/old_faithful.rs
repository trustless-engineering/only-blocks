use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use lru::LruCache;
use reqwest::header::{HeaderMap, RANGE, RETRY_AFTER};
use reqwest::StatusCode;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::config::OldFaithfulConfig;
use crate::error::OldFaithfulError;

/// Number of Solana slots in a single mainnet epoch.
pub const SLOTS_PER_EPOCH: u64 = 432_000;

/// Size in bytes of each entry in `epoch-{epoch}-slot-ranges.raw`:
/// `offset: u64` (8 bytes LE) + `length: u32` (4 bytes LE).
pub const SLOT_RANGE_ENTRY_BYTES: u64 = 12;

/// Compute the epoch number for a given Solana slot.
#[inline]
pub const fn slot_to_epoch(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

/// Compute the 0-based slot index within its epoch (`0..432_000`).
#[inline]
pub const fn slot_to_index(slot: u64) -> u64 {
    slot % SLOTS_PER_EPOCH
}

/// Compute the starting byte offset of a slot's 12-byte record in `slot-ranges.raw`.
#[inline]
pub const fn slot_range_byte_offset(slot: u64) -> u64 {
    slot_to_index(slot) * SLOT_RANGE_ENTRY_BYTES
}

/// Epoch and within-epoch addressing derived from a Solana slot number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotAddress {
    /// Absolute Solana slot number.
    pub slot: u64,
    /// Epoch containing this slot (`slot / 432_000`).
    pub epoch: u64,
    /// Index of this slot within `epoch` (`slot % 432_000`).
    pub slot_idx: u64,
}

impl SlotAddress {
    /// Derive [`SlotAddress`] from an absolute slot number.
    #[inline]
    pub const fn from_slot(slot: u64) -> Self {
        Self {
            slot,
            epoch: slot_to_epoch(slot),
            slot_idx: slot_to_index(slot),
        }
    }

    /// Starting byte offset of this slot's entry in `epoch-{epoch}-slot-ranges.raw`.
    #[inline]
    pub const fn range_file_offset(&self) -> u64 {
        self.slot_idx * SLOT_RANGE_ENTRY_BYTES
    }

    /// Inclusive `(start, end)` byte range of this slot's 12-byte entry in `slot-ranges.raw`.
    #[inline]
    pub const fn range_file_byte_range(&self) -> (u64, u64) {
        let start = self.range_file_offset();
        (start, start + SLOT_RANGE_ENTRY_BYTES - 1)
    }

    /// Relative path to this epoch's `slot-ranges.raw` file on Old Faithful.
    pub fn slot_ranges_path(&self) -> String {
        format!("/{0}/epoch-{0}-slot-ranges.raw", self.epoch)
    }

    /// Relative path to this epoch's `.car` archive on Old Faithful.
    pub fn car_path(&self) -> String {
        format!("/{0}/epoch-{0}.car", self.epoch)
    }
}

/// Parsed byte range of a non-skipped slot within `epoch-{epoch}.car`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotRange {
    /// Starting byte offset inside `epoch-{epoch}.car`.
    pub offset: u64,
    /// Exact byte length of the slot's CAR slice (`> 0`).
    pub length: u32,
}

impl SlotRange {
    /// Inclusive `(start, end)` byte range inside `epoch-{epoch}.car`.
    pub fn inclusive_byte_range(&self, slot: u64) -> Result<(u64, u64), OldFaithfulError> {
        let span = u64::from(self.length)
            .checked_sub(1)
            .ok_or(OldFaithfulError::SkippedSlot { slot })?;
        let end = self
            .offset
            .checked_add(span)
            .ok_or(OldFaithfulError::ArithmeticOverflow {
                slot,
                offset: self.offset,
                length: self.length,
            })?;
        Ok((self.offset, end))
    }
}

/// Parse a 12-byte little-endian `slot-ranges.raw` entry into `Option<SlotRange>`.
///
/// Returns `Ok(None)` when `length == 0` (skipped slot) and `Ok(Some(SlotRange))` otherwise.
pub fn parse_slot_range_entry(
    slot: u64,
    raw: &[u8],
) -> Result<Option<SlotRange>, OldFaithfulError> {
    if raw.len() != SLOT_RANGE_ENTRY_BYTES as usize {
        return Err(OldFaithfulError::InvalidSlotRangeEntry {
            slot,
            actual_len: raw.len(),
        });
    }
    let offset = u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]);
    let length = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    if length == 0 {
        Ok(None)
    } else {
        Ok(Some(SlotRange { offset, length }))
    }
}

/// Result of Range read 1 (`slot-ranges.raw`) for a non-skipped slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotRangeLookup {
    pub slot: u64,
    pub epoch: u64,
    pub range: SlotRange,
    pub range_cache_hit: bool,
}

/// Lightweight metadata accompanying a fetched raw CAR slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotFetchMeta {
    pub slot: u64,
    pub epoch: u64,
    pub offset: u64,
    pub length: u32,
    pub range_cache_hit: bool,
}

/// Raw CAR bytes for a single slot along with fetch metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotCarSlice {
    pub meta: SlotFetchMeta,
    pub bytes: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedSlotRange {
    Present(SlotRange),
    Skipped,
}

/// Pooled HTTP/2 Range client for Old Faithful with bounded concurrency,
/// retry + exponential backoff + jitter, and a bounded RAM-only LRU cache
/// for `slot-ranges.raw` lookups.
#[derive(Clone)]
pub struct OldFaithfulClient {
    http: reqwest::Client,
    base_url: String,
    config: OldFaithfulConfig,
    semaphore: Arc<Semaphore>,
    range_cache: Option<Arc<Mutex<LruCache<u64, CachedSlotRange>>>>,
}

impl std::fmt::Debug for OldFaithfulClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OldFaithfulClient")
            .field("base_url", &self.base_url)
            .field("max_slice_bytes", &self.config.max_slice_bytes)
            .field(
                "max_concurrent_requests",
                &self.config.max_concurrent_requests,
            )
            .field("cache_len", &self.cache_len())
            .field("cache_capacity", &self.cache_capacity())
            .finish()
    }
}

impl OldFaithfulClient {
    /// Build a new client with default configuration targeting `https://files.old-faithful.net`.
    pub fn with_defaults() -> Result<Self, OldFaithfulError> {
        Self::new(OldFaithfulConfig::default())
    }

    /// Build a new client from the provided [`OldFaithfulConfig`].
    pub fn new(config: OldFaithfulConfig) -> Result<Self, OldFaithfulError> {
        let base_url = config.validate()?;

        let http = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Some(Duration::from_secs(30)))
            .http2_keep_alive_while_idle(true)
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| {
                OldFaithfulError::InvalidConfig(format!("failed to build HTTP client: {e}"))
            })?;

        let range_cache = NonZeroUsize::new(config.slot_range_cache_capacity)
            .map(|cap| Arc::new(Mutex::new(LruCache::new(cap))));

        Ok(Self {
            http,
            base_url,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            config,
            range_cache,
        })
    }

    /// Return a reference to the client's configuration.
    pub fn config(&self) -> &OldFaithfulConfig {
        &self.config
    }

    /// Return the normalized base URL (without trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Current number of entries in the RAM-only slot-range LRU cache.
    pub fn cache_len(&self) -> usize {
        self.range_cache
            .as_ref()
            .map(|cache| cache.lock().unwrap_or_else(|e| e.into_inner()).len())
            .unwrap_or(0)
    }

    /// Configured maximum capacity of the RAM-only slot-range LRU cache.
    pub fn cache_capacity(&self) -> usize {
        self.config.slot_range_cache_capacity
    }

    /// Clear all entries from the RAM-only slot-range LRU cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = &self.range_cache {
            cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
    }

    /// Range read 1: resolve `(offset, length)` for `slot` from `slot-ranges.raw`
    /// (served from the bounded RAM LRU cache when available).
    ///
    /// - Returns `Err(OldFaithfulError::SkippedSlot { slot })` if `length == 0`.
    /// - Returns `Err(OldFaithfulError::UnarchivedSlot { slot, epoch })` on HTTP `404`.
    pub async fn fetch_slot_range(&self, slot: u64) -> Result<SlotRangeLookup, OldFaithfulError> {
        let addr = SlotAddress::from_slot(slot);

        if let Some(cached) = self.cache_get(slot) {
            return match cached {
                CachedSlotRange::Present(range) => Ok(SlotRangeLookup {
                    slot,
                    epoch: addr.epoch,
                    range,
                    range_cache_hit: true,
                }),
                CachedSlotRange::Skipped => Err(OldFaithfulError::SkippedSlot { slot }),
            };
        }

        let url = format!("{}{}", self.base_url, addr.slot_ranges_path());
        let (start, end) = addr.range_file_byte_range();
        let bytes = self
            .get_exact_range(
                slot,
                addr.epoch,
                &url,
                start,
                end,
                SLOT_RANGE_ENTRY_BYTES,
                SLOT_RANGE_ENTRY_BYTES,
            )
            .await?;

        match parse_slot_range_entry(slot, &bytes)? {
            Some(range) => {
                self.cache_put(slot, CachedSlotRange::Present(range));
                Ok(SlotRangeLookup {
                    slot,
                    epoch: addr.epoch,
                    range,
                    range_cache_hit: false,
                })
            }
            None => {
                self.cache_put(slot, CachedSlotRange::Skipped);
                Err(OldFaithfulError::SkippedSlot { slot })
            }
        }
    }

    /// Range read 2: fetch the exact CAR byte slice for a known [`SlotRange`].
    ///
    /// Enforces `max_slice_bytes` both before issuing the request and while streaming chunks,
    /// validates HTTP `206 Partial Content`, and verifies the exact byte length matches `range.length`.
    pub async fn fetch_car_range(
        &self,
        slot: u64,
        epoch: u64,
        range: SlotRange,
        range_cache_hit: bool,
    ) -> Result<SlotCarSlice, OldFaithfulError> {
        let expected_len = u64::from(range.length);
        if expected_len > self.config.max_slice_bytes {
            return Err(OldFaithfulError::SliceTooLarge {
                slot,
                length: expected_len,
                max_bytes: self.config.max_slice_bytes,
            });
        }

        let (start, end) = range.inclusive_byte_range(slot)?;
        let addr = SlotAddress {
            slot,
            epoch,
            slot_idx: slot_to_index(slot),
        };
        let url = format!("{}{}", self.base_url, addr.car_path());

        let bytes = self
            .get_exact_range(
                slot,
                epoch,
                &url,
                start,
                end,
                expected_len,
                self.config.max_slice_bytes,
            )
            .await?;

        Ok(SlotCarSlice {
            meta: SlotFetchMeta {
                slot,
                epoch,
                offset: range.offset,
                length: range.length,
                range_cache_hit,
            },
            bytes,
        })
    }

    /// Full 2-request Old Faithful fetch for a slot:
    /// 1. Resolve `(offset, length)` from `slot-ranges.raw` (or RAM LRU cache).
    /// 2. Fetch the exact raw CAR slice from `epoch-{epoch}.car`.
    pub async fn fetch_slot_car(&self, slot: u64) -> Result<SlotCarSlice, OldFaithfulError> {
        let lookup = self.fetch_slot_range(slot).await?;
        self.fetch_car_range(
            lookup.slot,
            lookup.epoch,
            lookup.range,
            lookup.range_cache_hit,
        )
        .await
    }

    fn cache_get(&self, slot: u64) -> Option<CachedSlotRange> {
        self.range_cache.as_ref().and_then(|cache| {
            cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&slot)
                .copied()
        })
    }

    fn cache_put(&self, slot: u64, entry: CachedSlotRange) {
        if let Some(cache) = &self.range_cache {
            cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .put(slot, entry);
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn get_exact_range(
        &self,
        slot: u64,
        epoch: u64,
        url: &str,
        start: u64,
        end: u64,
        expected_len: u64,
        max_bytes: u64,
    ) -> Result<Bytes, OldFaithfulError> {
        let range_header = format!("bytes={start}-{end}");
        let max_retries = self.config.retry.max_retries;
        let total_attempts = max_retries + 1;

        for attempt in 0..total_attempts {
            let attempt_result = self
                .single_range_attempt(slot, epoch, url, &range_header, expected_len, max_bytes)
                .await;

            match attempt_result {
                Ok(bytes) => return Ok(bytes),
                Err(AttemptFailure::Fatal(err)) => return Err(err),
                Err(AttemptFailure::RetryableHttp {
                    status,
                    retry_after,
                }) => {
                    if attempt >= max_retries {
                        return Err(OldFaithfulError::HttpRetryExhausted {
                            url: url.to_string(),
                            status: status.as_u16(),
                            attempts: total_attempts,
                        });
                    }
                    let delay = self.compute_retry_delay(attempt, retry_after);
                    warn!(
                        slot,
                        epoch,
                        url,
                        status = status.as_u16(),
                        attempt = attempt + 1,
                        max_attempts = total_attempts,
                        delay_ms = delay.as_millis() as u64,
                        "retryable HTTP status from Old Faithful; backing off"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(AttemptFailure::RetryableTransport(source)) => {
                    if attempt >= max_retries {
                        return Err(OldFaithfulError::Transport {
                            url: url.to_string(),
                            source,
                        });
                    }
                    let delay = self.compute_retry_delay(attempt, None);
                    warn!(
                        slot,
                        epoch,
                        url,
                        attempt = attempt + 1,
                        max_attempts = total_attempts,
                        delay_ms = delay.as_millis() as u64,
                        error = %source,
                        "transient transport error from Old Faithful; backing off"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }

        unreachable!("retry loop always returns on final attempt")
    }

    async fn single_range_attempt(
        &self,
        slot: u64,
        epoch: u64,
        url: &str,
        range_header: &str,
        expected_len: u64,
        max_bytes: u64,
    ) -> Result<Bytes, AttemptFailure> {
        // Hold the concurrency permit only while the HTTP attempt is actively in flight,
        // releasing it before any retry backoff sleep.
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| AttemptFailure::Fatal(OldFaithfulError::SemaphoreClosed))?;

        debug!(
            slot,
            epoch,
            url,
            range = range_header,
            "issuing Old Faithful range request"
        );

        let mut resp = self
            .http
            .get(url)
            .header(RANGE, range_header)
            .send()
            .await
            .map_err(AttemptFailure::RetryableTransport)?;

        let status = resp.status();

        if status == StatusCode::NOT_FOUND {
            return Err(AttemptFailure::Fatal(OldFaithfulError::UnarchivedSlot {
                slot,
                epoch,
            }));
        }

        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            let retry_after = parse_retry_after(resp.headers());
            return Err(AttemptFailure::RetryableHttp {
                status,
                retry_after,
            });
        }

        if status != StatusCode::PARTIAL_CONTENT {
            return Err(AttemptFailure::Fatal(OldFaithfulError::UnexpectedStatus {
                url: url.to_string(),
                status: status.as_u16(),
                expected: StatusCode::PARTIAL_CONTENT.as_u16(),
            }));
        }

        // Enforce slice cap before buffering if Content-Length is provided.
        if let Some(content_len) = resp.content_length() {
            if content_len > max_bytes {
                return Err(AttemptFailure::Fatal(OldFaithfulError::SliceTooLarge {
                    slot,
                    length: content_len,
                    max_bytes,
                }));
            }
        }

        let initial_cap = expected_len.min(max_bytes) as usize;
        let mut buf = BytesMut::with_capacity(initial_cap);

        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(AttemptFailure::RetryableTransport)?
        {
            let new_len = (buf.len() as u64).saturating_add(chunk.len() as u64);
            if new_len > max_bytes {
                return Err(AttemptFailure::Fatal(OldFaithfulError::SliceTooLarge {
                    slot,
                    length: new_len,
                    max_bytes,
                }));
            }
            buf.extend_from_slice(&chunk);
        }

        let actual_len = buf.len() as u64;
        if actual_len != expected_len {
            return Err(AttemptFailure::Fatal(OldFaithfulError::LengthMismatch {
                url: url.to_string(),
                expected: expected_len,
                actual: actual_len,
            }));
        }

        Ok(buf.freeze())
    }

    fn compute_retry_delay(&self, attempt: usize, retry_after: Option<Duration>) -> Duration {
        let retry = &self.config.retry;

        if let Some(ra) = retry_after {
            return ra.min(retry.max_backoff);
        }

        let shift = u32::try_from(attempt).unwrap_or(u32::MAX).min(30);
        let multiplier = 1u32 << shift;
        let base = retry
            .initial_backoff
            .saturating_mul(multiplier)
            .min(retry.max_backoff);

        if retry.jitter_ratio <= 0.0 || base.is_zero() {
            return base;
        }

        let base_secs = base.as_secs_f64();
        let min_factor = 1.0 - retry.jitter_ratio;
        let jitter_factor = min_factor + fastrand::f64() * retry.jitter_ratio;
        let jittered = Duration::from_secs_f64((base_secs * jitter_factor).max(0.0));
        jittered.min(retry.max_backoff)
    }
}

enum AttemptFailure {
    Fatal(OldFaithfulError),
    RetryableHttp {
        status: StatusCode,
        retry_after: Option<Duration>,
    },
    RetryableTransport(reqwest::Error),
}

/// Parse an HTTP `Retry-After` header (either integer delta-seconds or HTTP-date).
pub(crate) fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    if let Ok(target) = httpdate::parse_http_date(raw) {
        return Some(
            target
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::config::{OldFaithfulConfig, RetryConfig};
    use crate::error::OldFaithfulError;
    use crate::old_faithful::{
        parse_retry_after, parse_slot_range_entry, slot_range_byte_offset, slot_to_epoch,
        slot_to_index, OldFaithfulClient, SlotAddress, SlotRange, SLOTS_PER_EPOCH,
    };

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        path: String,
        range: Option<String>,
    }

    enum MockAction {
        Response {
            status: u16,
            reason: &'static str,
            headers: Vec<(String, String)>,
            body: Vec<u8>,
            delay: Duration,
        },
        ChunkedResponse {
            status: u16,
            reason: &'static str,
            chunks: Vec<Vec<u8>>,
        },
        DropConnection,
    }

    type HandlerFn = Arc<dyn Fn(&RecordedRequest, usize) -> MockAction + Send + Sync>;

    struct MockServer {
        base_url: String,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        peak_in_flight: Arc<AtomicUsize>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    impl MockServer {
        async fn start(handler: HandlerFn) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let req_counter = Arc::new(AtomicUsize::new(0));
            let in_flight = Arc::new(AtomicUsize::new(0));
            let peak_in_flight = Arc::new(AtomicUsize::new(0));

            let requests_clone = Arc::clone(&requests);
            let peak_clone = Arc::clone(&peak_in_flight);

            let handle = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    let handler = Arc::clone(&handler);
                    let requests = Arc::clone(&requests_clone);
                    let counter = Arc::clone(&req_counter);
                    let in_flight = Arc::clone(&in_flight);
                    let peak = Arc::clone(&peak_clone);

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

                        let recorded = RecordedRequest { path, range };
                        let idx = counter.fetch_add(1, Ordering::SeqCst);
                        requests.lock().unwrap().push(recorded.clone());

                        let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);

                        let action = handler(&recorded, idx);
                        match action {
                            MockAction::DropConnection => {
                                drop(stream);
                            }
                            MockAction::ChunkedResponse {
                                status,
                                reason,
                                chunks,
                            } => {
                                let head = format!(
                                    "HTTP/1.1 {status} {reason}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                                );
                                let _ = stream.write_all(head.as_bytes()).await;
                                for chunk in chunks {
                                    let len_line = format!("{:x}\r\n", chunk.len());
                                    if stream.write_all(len_line.as_bytes()).await.is_err() {
                                        break;
                                    }
                                    if stream.write_all(&chunk).await.is_err() {
                                        break;
                                    }
                                    if stream.write_all(b"\r\n").await.is_err() {
                                        break;
                                    }
                                }
                                let _ = stream.write_all(b"0\r\n\r\n").await;
                                let _ = stream.shutdown().await;
                            }
                            MockAction::Response {
                                status,
                                reason,
                                headers,
                                body,
                                delay,
                            } => {
                                if !delay.is_zero() {
                                    tokio::time::sleep(delay).await;
                                }
                                let mut head = format!(
                                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                    body.len()
                                );
                                for (k, v) in headers {
                                    head.push_str(&format!("{k}: {v}\r\n"));
                                }
                                head.push_str("\r\n");
                                let _ = stream.write_all(head.as_bytes()).await;
                                let _ = stream.write_all(&body).await;
                                let _ = stream.shutdown().await;
                            }
                        }

                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });

            Self {
                base_url: format!("http://{addr}"),
                requests,
                peak_in_flight,
                handle,
            }
        }

        fn recorded_requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().unwrap().clone()
        }

        fn peak_in_flight(&self) -> usize {
            self.peak_in_flight.load(Ordering::SeqCst)
        }
    }

    fn encode_slot_range(offset: u64, length: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
        out
    }

    fn fast_test_config(base_url: &str) -> OldFaithfulConfig {
        OldFaithfulConfig {
            base_url: base_url.to_string(),
            retry: RetryConfig {
                max_retries: 3,
                initial_backoff: Duration::from_millis(10),
                max_backoff: Duration::from_millis(250),
                jitter_ratio: 0.25,
            },
            ..OldFaithfulConfig::default()
        }
    }

    #[test]
    fn epoch_and_slot_math() {
        assert_eq!(SLOTS_PER_EPOCH, 432_000);

        let a0 = SlotAddress::from_slot(0);
        assert_eq!(a0.epoch, 0);
        assert_eq!(a0.slot_idx, 0);
        assert_eq!(a0.range_file_offset(), 0);
        assert_eq!(a0.range_file_byte_range(), (0, 11));
        assert_eq!(a0.slot_ranges_path(), "/0/epoch-0-slot-ranges.raw");
        assert_eq!(a0.car_path(), "/0/epoch-0.car");

        let a_end = SlotAddress::from_slot(431_999);
        assert_eq!(a_end.epoch, 0);
        assert_eq!(a_end.slot_idx, 431_999);
        assert_eq!(a_end.range_file_offset(), 431_999 * 12);
        assert_eq!(
            a_end.range_file_byte_range(),
            (431_999 * 12, 431_999 * 12 + 11)
        );

        let a700 = SlotAddress::from_slot(302_400_000);
        assert_eq!(slot_to_epoch(302_400_000), 700);
        assert_eq!(slot_to_index(302_400_000), 0);
        assert_eq!(slot_range_byte_offset(302_400_000), 0);
        assert_eq!(a700.epoch, 700);
        assert_eq!(a700.slot_idx, 0);
        assert_eq!(a700.slot_ranges_path(), "/700/epoch-700-slot-ranges.raw");
        assert_eq!(a700.car_path(), "/700/epoch-700.car");

        let a700_next = SlotAddress::from_slot(302_400_001);
        assert_eq!(a700_next.epoch, 700);
        assert_eq!(a700_next.slot_idx, 1);
        assert_eq!(a700_next.range_file_byte_range(), (12, 23));

        // Pre-Epoch 157 boundary (157 * 432_000 = 67_824_000)
        assert_eq!(slot_to_epoch(67_823_999), 156);
        assert_eq!(slot_to_epoch(67_824_000), 157);
    }

    #[test]
    fn parse_slot_range_entry_little_endian() {
        let offset = 0x0102_0304_0506_0708u64;
        let length = 56_383_108u32;
        let raw = encode_slot_range(offset, length);

        let parsed = parse_slot_range_entry(302_400_000, &raw)
            .expect("valid entry")
            .expect("non-skipped");
        assert_eq!(parsed, SlotRange { offset, length });

        let skipped = encode_slot_range(0, 0);
        assert_eq!(
            parse_slot_range_entry(302_400_004, &skipped).expect("valid skipped"),
            None
        );

        let short = [0u8; 11];
        let err = parse_slot_range_entry(1, &short).unwrap_err();
        assert!(matches!(
            err,
            OldFaithfulError::InvalidSlotRangeEntry {
                slot: 1,
                actual_len: 11
            }
        ));
    }

    #[test]
    fn retry_after_header_parsing() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(3)));

        headers.insert(RETRY_AFTER, HeaderValue::from_static("invalid-value"));
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[tokio::test]
    async fn skipped_slot_returns_typed_error_and_is_cached() {
        let server = MockServer::start(Arc::new(|req, _| {
            assert_eq!(req.path, "/700/epoch-700-slot-ranges.raw");
            assert_eq!(req.range.as_deref(), Some("bytes=48-59"));
            MockAction::Response {
                status: 206,
                reason: "Partial Content",
                headers: vec![],
                body: encode_slot_range(0, 0),
                delay: Duration::ZERO,
            }
        }))
        .await;

        let client = OldFaithfulClient::new(fast_test_config(&server.base_url)).unwrap();
        let err = client.fetch_slot_car(302_400_004).await.unwrap_err();
        assert!(matches!(
            err,
            OldFaithfulError::SkippedSlot { slot: 302_400_004 }
        ));
        assert!(err.is_skipped_slot());
        assert_eq!(server.recorded_requests().len(), 1);

        // Second lookup should hit the RAM LRU cache without touching the server.
        let err2 = client.fetch_slot_car(302_400_004).await.unwrap_err();
        assert!(matches!(
            err2,
            OldFaithfulError::SkippedSlot { slot: 302_400_004 }
        ));
        assert_eq!(server.recorded_requests().len(), 1);
    }

    #[tokio::test]
    async fn unarchived_404_never_retries_and_is_not_cached() {
        let server = MockServer::start(Arc::new(|_, _| MockAction::Response {
            status: 404,
            reason: "Not Found",
            headers: vec![],
            body: b"not found".to_vec(),
            delay: Duration::ZERO,
        }))
        .await;

        let client = OldFaithfulClient::new(fast_test_config(&server.base_url)).unwrap();
        let slot = 9999 * SLOTS_PER_EPOCH;
        let err = client.fetch_slot_car(slot).await.unwrap_err();
        assert!(matches!(
            err,
            OldFaithfulError::UnarchivedSlot { slot: s, epoch: 9999 } if s == slot
        ));
        assert!(err.is_unarchived_slot());
        assert_eq!(server.recorded_requests().len(), 1);
        assert_eq!(client.cache_len(), 0);
    }

    #[tokio::test]
    async fn retries_on_429_with_retry_after_and_5xx_and_transport_drop() {
        let car_payload = b"hello-old-faithful-car-slice".to_vec();
        let range_entry = encode_slot_range(128, car_payload.len() as u32);

        let queue = Arc::new(Mutex::new(VecDeque::from([
            MockAction::Response {
                status: 429,
                reason: "Too Many Requests",
                headers: vec![("Retry-After".to_string(), "1".to_string())],
                body: vec![],
                delay: Duration::ZERO,
            },
            MockAction::Response {
                status: 503,
                reason: "Service Unavailable",
                headers: vec![],
                body: vec![],
                delay: Duration::ZERO,
            },
            MockAction::Response {
                status: 206,
                reason: "Partial Content",
                headers: vec![],
                body: range_entry,
                delay: Duration::ZERO,
            },
            MockAction::DropConnection,
            MockAction::Response {
                status: 500,
                reason: "Internal Server Error",
                headers: vec![],
                body: vec![],
                delay: Duration::ZERO,
            },
            MockAction::Response {
                status: 206,
                reason: "Partial Content",
                headers: vec![],
                body: car_payload.clone(),
                delay: Duration::ZERO,
            },
        ])));

        let server = MockServer::start(Arc::new(move |_, _| {
            queue
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra request")
        }))
        .await;

        let mut cfg = fast_test_config(&server.base_url);
        cfg.retry.max_backoff = Duration::from_secs(2);
        let client = OldFaithfulClient::new(cfg).unwrap();

        let started = Instant::now();
        let slice = client.fetch_slot_car(302_400_001).await.unwrap();
        let elapsed = started.elapsed();

        // Retry-After: 1 must be honored.
        assert!(
            elapsed >= Duration::from_millis(900),
            "expected Retry-After delay >= 900ms, got {elapsed:?}"
        );
        assert_eq!(slice.bytes.as_ref(), car_payload.as_slice());
        assert_eq!(slice.meta.slot, 302_400_001);
        assert_eq!(slice.meta.epoch, 700);
        assert_eq!(slice.meta.offset, 128);
        assert_eq!(slice.meta.length, car_payload.len() as u32);
        assert!(!slice.meta.range_cache_hit);
        assert_eq!(server.recorded_requests().len(), 6);
    }

    #[tokio::test]
    async fn retries_exhausted_returns_http_retry_exhausted() {
        let server = MockServer::start(Arc::new(|_, _| MockAction::Response {
            status: 503,
            reason: "Service Unavailable",
            headers: vec![],
            body: vec![],
            delay: Duration::ZERO,
        }))
        .await;

        let mut cfg = fast_test_config(&server.base_url);
        cfg.retry.max_retries = 2;
        let client = OldFaithfulClient::new(cfg).unwrap();

        let err = client.fetch_slot_car(42).await.unwrap_err();
        assert!(matches!(
            err,
            OldFaithfulError::HttpRetryExhausted {
                status: 503,
                attempts: 3,
                ..
            }
        ));
        assert_eq!(server.recorded_requests().len(), 3);
    }

    #[tokio::test]
    async fn non_206_and_length_mismatch_are_rejected() {
        // 200 OK instead of 206 Partial Content
        let server_200 = MockServer::start(Arc::new(|_, _| MockAction::Response {
            status: 200,
            reason: "OK",
            headers: vec![],
            body: encode_slot_range(59, 10),
            delay: Duration::ZERO,
        }))
        .await;

        let client = OldFaithfulClient::new(fast_test_config(&server_200.base_url)).unwrap();
        let err = client.fetch_slot_car(10).await.unwrap_err();
        assert!(matches!(
            err,
            OldFaithfulError::UnexpectedStatus {
                status: 200,
                expected: 206,
                ..
            }
        ));
        assert_eq!(server_200.recorded_requests().len(), 1);

        // Truncated CAR payload (length mismatch)
        let server_short = MockServer::start(Arc::new(|req, _| {
            if req.path.ends_with("slot-ranges.raw") {
                MockAction::Response {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![],
                    body: encode_slot_range(59, 16),
                    delay: Duration::ZERO,
                }
            } else {
                MockAction::Response {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![],
                    body: vec![0xAB; 10], // declared 16, returned 10
                    delay: Duration::ZERO,
                }
            }
        }))
        .await;

        let client = OldFaithfulClient::new(fast_test_config(&server_short.base_url)).unwrap();
        let err = client.fetch_slot_car(10).await.unwrap_err();
        assert!(matches!(
            err,
            OldFaithfulError::LengthMismatch {
                expected: 16,
                actual: 10,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn max_slice_guard_enforced_before_and_during_transfer() {
        // Case 1: slot-ranges.raw declares length > max_slice_bytes -> .car is never requested.
        let server_pre = MockServer::start(Arc::new(|req, _| {
            assert!(req.path.ends_with("slot-ranges.raw"));
            MockAction::Response {
                status: 206,
                reason: "Partial Content",
                headers: vec![],
                body: encode_slot_range(59, 2048),
                delay: Duration::ZERO,
            }
        }))
        .await;

        let mut cfg = fast_test_config(&server_pre.base_url);
        cfg.max_slice_bytes = 1024;
        let client = OldFaithfulClient::new(cfg).unwrap();

        let err = client.fetch_slot_car(7).await.unwrap_err();
        assert!(matches!(
            err,
            OldFaithfulError::SliceTooLarge {
                slot: 7,
                length: 2048,
                max_bytes: 1024
            }
        ));
        assert_eq!(server_pre.recorded_requests().len(), 1);

        // Case 2: slot-ranges.raw declares length <= max_slice_bytes,
        // but server returns oversized body -> rejected by response guard.
        let server_resp = MockServer::start(Arc::new(|req, _| {
            if req.path.ends_with("slot-ranges.raw") {
                MockAction::Response {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![],
                    body: encode_slot_range(59, 512),
                    delay: Duration::ZERO,
                }
            } else {
                MockAction::Response {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![],
                    body: vec![0xCD; 2048],
                    delay: Duration::ZERO,
                }
            }
        }))
        .await;

        let mut cfg = fast_test_config(&server_resp.base_url);
        cfg.max_slice_bytes = 1024;
        let client = OldFaithfulClient::new(cfg).unwrap();

        let err = client.fetch_slot_car(8).await.unwrap_err();
        assert!(matches!(
            err,
            OldFaithfulError::SliceTooLarge {
                slot: 8,
                length: 2048,
                max_bytes: 1024
            }
        ));

        // Case 3: chunked response (no Content-Length) exceeds max_slice_bytes while streaming.
        let server_chunked = MockServer::start(Arc::new(|req, _| {
            if req.path.ends_with("slot-ranges.raw") {
                MockAction::Response {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![],
                    body: encode_slot_range(59, 512),
                    delay: Duration::ZERO,
                }
            } else {
                MockAction::ChunkedResponse {
                    status: 206,
                    reason: "Partial Content",
                    chunks: vec![vec![0xEF; 600], vec![0xEF; 600]],
                }
            }
        }))
        .await;

        let mut cfg = fast_test_config(&server_chunked.base_url);
        cfg.max_slice_bytes = 1024;
        let client = OldFaithfulClient::new(cfg).unwrap();

        let err = client.fetch_slot_car(9).await.unwrap_err();
        assert!(matches!(
            err,
            OldFaithfulError::SliceTooLarge {
                slot: 9,
                length: 1200,
                max_bytes: 1024
            }
        ));
    }

    #[test]
    fn config_validation_rejects_invalid_values() {
        let cfg = OldFaithfulConfig {
            base_url: "ftp://example.com".to_string(),
            ..OldFaithfulConfig::default()
        };
        assert!(matches!(
            OldFaithfulClient::new(cfg),
            Err(OldFaithfulError::InvalidConfig(_))
        ));

        let cfg = OldFaithfulConfig {
            max_slice_bytes: 0,
            ..OldFaithfulConfig::default()
        };
        assert!(matches!(
            OldFaithfulClient::new(cfg),
            Err(OldFaithfulError::InvalidConfig(_))
        ));

        let cfg = OldFaithfulConfig {
            max_concurrent_requests: 0,
            ..OldFaithfulConfig::default()
        };
        assert!(matches!(
            OldFaithfulClient::new(cfg),
            Err(OldFaithfulError::InvalidConfig(_))
        ));

        let cfg = OldFaithfulConfig {
            retry: RetryConfig {
                jitter_ratio: 1.5,
                ..RetryConfig::default()
            },
            ..OldFaithfulConfig::default()
        };
        assert!(matches!(
            OldFaithfulClient::new(cfg),
            Err(OldFaithfulError::InvalidConfig(_))
        ));
    }

    #[tokio::test]
    async fn ram_lru_cache_hit_and_eviction() {
        let server = MockServer::start(Arc::new(|req, _| {
            if req.path.ends_with("slot-ranges.raw") {
                MockAction::Response {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![],
                    body: encode_slot_range(100, 8),
                    delay: Duration::ZERO,
                }
            } else {
                MockAction::Response {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![],
                    body: vec![1, 2, 3, 4, 5, 6, 7, 8],
                    delay: Duration::ZERO,
                }
            }
        }))
        .await;

        let mut cfg = fast_test_config(&server.base_url);
        cfg.slot_range_cache_capacity = 2;
        let client = OldFaithfulClient::new(cfg).unwrap();

        // Cold miss for slot 1
        let s1 = client.fetch_slot_car(1).await.unwrap();
        assert!(!s1.meta.range_cache_hit);
        assert_eq!(client.cache_len(), 1);

        // Warm hit for slot 1 (no slot-ranges.raw request issued)
        let s1_warm = client.fetch_slot_car(1).await.unwrap();
        assert!(s1_warm.meta.range_cache_hit);
        assert_eq!(client.cache_len(), 1);

        // Insert slots 2 and 3 -> capacity 2 evicts slot 1 (LRU)
        let s2 = client.fetch_slot_car(2).await.unwrap();
        assert!(!s2.meta.range_cache_hit);
        let s3 = client.fetch_slot_car(3).await.unwrap();
        assert!(!s3.meta.range_cache_hit);
        assert_eq!(client.cache_len(), 2);

        // Slot 2 is still cached, slot 1 was evicted
        let s2_warm = client.fetch_slot_car(2).await.unwrap();
        assert!(s2_warm.meta.range_cache_hit);

        let s1_after_evict = client.fetch_slot_car(1).await.unwrap();
        assert!(!s1_after_evict.meta.range_cache_hit);

        let range_reqs = server
            .recorded_requests()
            .into_iter()
            .filter(|r| r.path.ends_with("slot-ranges.raw"))
            .count();
        // 1 (cold) + 2 (cold) + 3 (cold) + 1 (after eviction) = 4
        assert_eq!(range_reqs, 4);
    }

    #[tokio::test]
    async fn concurrency_is_bounded_by_semaphore() {
        let server = MockServer::start(Arc::new(|req, _| {
            if req.path.ends_with("slot-ranges.raw") {
                MockAction::Response {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![],
                    body: encode_slot_range(59, 4),
                    delay: Duration::from_millis(30),
                }
            } else {
                MockAction::Response {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![],
                    body: vec![9, 8, 7, 6],
                    delay: Duration::from_millis(30),
                }
            }
        }))
        .await;

        let mut cfg = fast_test_config(&server.base_url);
        cfg.max_concurrent_requests = 2;
        let client = OldFaithfulClient::new(cfg).unwrap();

        let mut tasks = Vec::new();
        for slot in 100..108u64 {
            let c = client.clone();
            tasks.push(tokio::spawn(async move { c.fetch_slot_car(slot).await }));
        }

        for t in tasks {
            let slice = t.await.unwrap().unwrap();
            assert_eq!(slice.bytes.as_ref(), &[9, 8, 7, 6]);
        }

        assert!(
            server.peak_in_flight() <= 2,
            "expected peak concurrency <= 2, observed {}",
            server.peak_in_flight()
        );
    }
}
