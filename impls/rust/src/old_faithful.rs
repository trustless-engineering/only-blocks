//! The Old Faithful 2-range-read protocol (SPEC.md §4): slot index lookup, CAR slice fetch,
//! retry/backoff with jitter, a concurrency semaphore and the RAM-only slot-range LRU.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::http_client::{AttemptError, BaseUrl, RangeRequest, Transport};
use crate::lru::Lru;

pub const SLOTS_PER_EPOCH: u64 = 432_000;
pub const SLOT_RANGE_ENTRY_BYTES: u64 = 12;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub max_slice_bytes: u64,
    pub max_concurrent_requests: usize,
    pub slot_range_cache_capacity: usize,
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub jitter_ratio: f64,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            max_slice_bytes: 128 * 1024 * 1024,
            max_concurrent_requests: 32,
            slot_range_cache_capacity: 100_000,
            max_retries: 4,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(10),
            jitter_ratio: 0.5,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
        }
    }
}

/// Why a slot could not be fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// `length == 0` in `slot-ranges.raw` (`-32007`).
    Skipped { slot: u64 },
    /// HTTP 404 on either read (`-32004`).
    Unarchived { slot: u64, epoch: u64 },
    /// Everything else (`-32603`).
    Internal(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotRange {
    Present { offset: u64, length: u32 },
    Skipped,
}

/// A counting semaphore built from `Mutex` + `Condvar`.
struct Semaphore {
    permits: Mutex<usize>,
    cv: Condvar,
}

struct Permit<'a>(&'a Semaphore);

impl Semaphore {
    fn new(n: usize) -> Self {
        Semaphore { permits: Mutex::new(n.max(1)), cv: Condvar::new() }
    }
    fn acquire(&self) -> Permit<'_> {
        let mut p = self.permits.lock().unwrap_or_else(|e| e.into_inner());
        while *p == 0 {
            p = self.cv.wait(p).unwrap_or_else(|e| e.into_inner());
        }
        *p -= 1;
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.permits.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.0.cv.notify_one();
    }
}

pub struct OldFaithful {
    transport: Transport,
    config: ClientConfig,
    semaphore: Semaphore,
    slot_cache: Mutex<Lru<u64, SlotRange>>,
    rng: AtomicU64,
}

impl OldFaithful {
    pub fn new(base: BaseUrl, config: ClientConfig) -> Self {
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0x9E37_79B9, |d| d.as_nanos() as u64) | 1;
        OldFaithful {
            transport: Transport::new(base, "onlyblocks/rust".into(), config.connect_timeout, config.request_timeout),
            semaphore: Semaphore::new(config.max_concurrent_requests),
            slot_cache: Mutex::new(Lru::new(config.slot_range_cache_capacity)),
            rng: AtomicU64::new(seed),
            config,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.transport.base.url
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Uniform `[0, 1)` from a shared xorshift64* generator (jitter only, not crypto).
    fn uniform(&self) -> f64 {
        let mut x = self.rng.load(Ordering::Relaxed);
        loop {
            let mut next = x;
            next ^= next >> 12;
            next ^= next << 25;
            next ^= next >> 27;
            match self.rng.compare_exchange_weak(x, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return (next.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64,
                Err(actual) => x = actual,
            }
        }
    }

    /// SPEC.md §4.3: honour `Retry-After`, else exponential backoff with jitter.
    fn retry_delay(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let c = &self.config;
        if let Some(ra) = retry_after {
            return ra.min(c.max_backoff);
        }
        let factor = 2f64.powi(attempt.min(30) as i32);
        let base = (c.initial_backoff.as_secs_f64() * factor).min(c.max_backoff.as_secs_f64());
        let jitter = (1.0 - c.jitter_ratio) + self.uniform() * c.jitter_ratio;
        Duration::from_secs_f64((base * jitter).max(0.0)).min(c.max_backoff)
    }

    fn get_exact_range(&self, req: &RangeRequest<'_>) -> Result<Vec<u8>, AttemptError> {
        let mut attempt = 0u32;
        loop {
            let result = {
                let _permit = self.semaphore.acquire();
                self.transport.fetch(req)
            };
            match result {
                Ok(body) => return Ok(body),
                Err(AttemptError::Retry { retry_after, message }) => {
                    if attempt >= self.config.max_retries {
                        return Err(AttemptError::Fatal(format!(
                            "{message} from {}{} after {} attempt(s)",
                            self.transport.base.url,
                            req.path,
                            attempt + 1
                        )));
                    }
                    let delay = self.retry_delay(attempt, retry_after);
                    eprintln!(
                        "onlyblocks: retrying {} bytes={}-{} in {:?} ({message})",
                        req.path, req.start, req.end, delay
                    );
                    std::thread::sleep(delay);
                    attempt += 1;
                }
                Err(other) => return Err(other),
            }
        }
    }

    fn slot_range(&self, slot: u64) -> Result<(u64, u32), FetchError> {
        let cached = self.slot_cache.lock().unwrap_or_else(|e| e.into_inner()).get(&slot);
        let range = match cached {
            Some(r) => r,
            None => {
                let epoch = slot / SLOTS_PER_EPOCH;
                let start = (slot % SLOTS_PER_EPOCH) * SLOT_RANGE_ENTRY_BYTES;
                let path = format!("/{epoch}/epoch-{epoch}-slot-ranges.raw");
                let req = RangeRequest { path: &path, start, end: start + 11, expected: 12, cap: 12 };
                let body = match self.get_exact_range(&req) {
                    Ok(b) => b,
                    Err(AttemptError::NotFound) => return Err(FetchError::Unarchived { slot, epoch }),
                    Err(AttemptError::Fatal(m)) | Err(AttemptError::Retry { message: m, .. }) => {
                        return Err(FetchError::Internal(m))
                    }
                };
                let offset = u64::from_le_bytes(body[0..8].try_into().unwrap_or([0; 8]));
                let length = u32::from_le_bytes(body[8..12].try_into().unwrap_or([0; 4]));
                let r = if length == 0 { SlotRange::Skipped } else { SlotRange::Present { offset, length } };
                self.slot_cache.lock().unwrap_or_else(|e| e.into_inner()).put(slot, r);
                r
            }
        };
        match range {
            SlotRange::Present { offset, length } => Ok((offset, length)),
            SlotRange::Skipped => Err(FetchError::Skipped { slot }),
        }
    }

    /// Both range reads for `slot`: its 12-byte index record, then its CAR slice.
    pub fn fetch_slot_car(&self, slot: u64) -> Result<Vec<u8>, FetchError> {
        let (offset, length) = self.slot_range(slot)?;
        let epoch = slot / SLOTS_PER_EPOCH;
        let length = length as u64;
        if length > self.config.max_slice_bytes {
            return Err(FetchError::Internal(format!(
                "slot {slot} CAR slice size {length} bytes exceeds max_slice_bytes ({} bytes)",
                self.config.max_slice_bytes
            )));
        }
        let Some(end) = offset.checked_add(length - 1) else {
            return Err(FetchError::Internal(format!("byte range overflow for slot {slot} (offset {offset}, length {length})")));
        };
        let path = format!("/{epoch}/epoch-{epoch}.car");
        let req = RangeRequest { path: &path, start: offset, end, expected: length, cap: self.config.max_slice_bytes };
        match self.get_exact_range(&req) {
            Ok(b) => Ok(b),
            Err(AttemptError::NotFound) => Err(FetchError::Unarchived { slot, epoch }),
            Err(AttemptError::Fatal(m)) | Err(AttemptError::Retry { message: m, .. }) => Err(FetchError::Internal(m)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::parse_base_url;

    #[test]
    fn backoff_schedule() {
        let of = OldFaithful::new(parse_base_url("http://127.0.0.1:1").unwrap(), ClientConfig::default());
        assert_eq!(of.retry_delay(0, Some(Duration::ZERO)), Duration::ZERO);
        assert_eq!(of.retry_delay(3, Some(Duration::from_secs(99))), Duration::from_secs(10));
        for attempt in 0..40 {
            let base = (0.2 * 2f64.powi(attempt.min(30) as i32)).min(10.0);
            let d = of.retry_delay(attempt, None).as_secs_f64();
            assert!(d >= base * 0.5 - 1e-9 && d <= base + 1e-9, "attempt {attempt}: {d}");
        }
    }
}
