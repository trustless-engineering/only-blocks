//! SIGINT/SIGTERM handling with nothing but libc's `signal(2)` (no crates).
//!
//! The handler only stores to an atomic (async-signal-safe). A watcher thread notices, lets
//! in-flight requests finish for a short grace period, then exits the process with status 0.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::http_server::IN_FLIGHT;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
}

extern "C" fn on_signal(_signum: i32) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Install the handlers and start the watcher thread.
pub fn install(grace: Duration) {
    let handler = on_signal as extern "C" fn(i32) as usize;
    // SAFETY: `on_signal` is an `extern "C" fn(i32)` that only touches an atomic.
    unsafe {
        signal(SIGINT, handler);
        signal(SIGTERM, handler);
    }
    std::thread::Builder::new()
        .name("onlyblocks-signals".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_millis(10));
            if shutdown_requested() {
                eprintln!("onlyblocks: shutdown signal received, draining in-flight requests");
                let deadline = Instant::now() + grace;
                while IN_FLIGHT.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                eprintln!("onlyblocks: bye");
                std::process::exit(0);
            }
        })
        .expect("spawn signal watcher");
}
