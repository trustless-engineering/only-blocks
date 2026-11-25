//! Inbound HTTP/1.1 server: `std::net::TcpListener` feeding an elastic worker-thread pool.
//!
//! Each connection carries one request (`Connection: close`). The pool keeps a few warm
//! workers and grows on demand, so a slow `getBlock` never starves `getHealth`.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::rpc::Service;

pub const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_HEAD_BYTES: usize = 64 * 1024;
const MIN_IDLE_WORKERS: usize = 4;
const MAX_WORKERS: usize = 512;
const IDLE_WORKER_TIMEOUT: Duration = Duration::from_secs(30);

/// Number of requests currently being served (used for graceful shutdown).
pub static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

struct InFlight;

impl InFlight {
    fn enter() -> Self {
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        InFlight
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

struct PoolState {
    queue: VecDeque<TcpStream>,
    idle: usize,
    total: usize,
}

struct Pool {
    state: Mutex<PoolState>,
    cv: Condvar,
    service: Arc<Service>,
}

impl Pool {
    fn submit(self: &Arc<Self>, stream: TcpStream) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.queue.push_back(stream);
        if st.queue.len() > st.idle && st.total < MAX_WORKERS {
            st.total += 1;
            let pool = Arc::clone(self);
            let spawned = std::thread::Builder::new()
                .name("onlyblocks-worker".into())
                .stack_size(8 << 20)
                .spawn(move || pool.worker());
            if spawned.is_err() {
                st.total -= 1;
            }
        }
        drop(st);
        self.cv.notify_one();
    }

    fn worker(self: Arc<Self>) {
        loop {
            let stream = {
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if let Some(s) = st.queue.pop_front() {
                        break s;
                    }
                    st.idle += 1;
                    let (guard, timeout) = self.cv.wait_timeout(st, IDLE_WORKER_TIMEOUT).unwrap_or_else(|e| e.into_inner());
                    st = guard;
                    st.idle -= 1;
                    if timeout.timed_out() && st.queue.is_empty() && st.total > MIN_IDLE_WORKERS {
                        st.total -= 1;
                        return;
                    }
                }
            };
            // A panic here must not shrink the pool or kill the process.
            let service = &self.service;
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_connection(stream, service)));
        }
    }
}

/// Accept connections forever.
pub fn serve(listener: TcpListener, service: Arc<Service>) {
    let pool = Arc::new(Pool {
        state: Mutex::new(PoolState { queue: VecDeque::new(), idle: 0, total: 0 }),
        cv: Condvar::new(),
        service,
    });
    for conn in listener.incoming() {
        if crate::signal::shutdown_requested() {
            break; // stop accepting; the shutdown watcher drains in-flight work
        }
        match conn {
            Ok(stream) => pool.submit(stream),
            Err(e) => {
                eprintln!("onlyblocks: accept failed: {e}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

enum RequestError {
    /// Peer went away or timed out: just close.
    Gone,
    BadRequest(&'static str),
    TooLarge,
    HeadTooLarge,
}

struct Request {
    method: String,
    target: String,
    body: Vec<u8>,
}

struct Inbound {
    stream: TcpStream,
    buf: Vec<u8>,
    pos: usize,
}

impl Inbound {
    fn fill(&mut self) -> Result<usize, RequestError> {
        let mut tmp = [0u8; 16 * 1024];
        loop {
            match self.stream.read(&mut tmp) {
                Ok(n) => {
                    self.buf.extend_from_slice(&tmp[..n]);
                    return Ok(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(RequestError::Gone),
            }
        }
    }

    fn need(&mut self, n: usize) -> Result<(), RequestError> {
        while self.buf.len() - self.pos < n {
            if self.fill()? == 0 {
                return Err(RequestError::Gone);
            }
        }
        Ok(())
    }

    fn line(&mut self) -> Result<String, RequestError> {
        loop {
            if let Some(i) = self.buf[self.pos..].windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[self.pos..self.pos + i]).into_owned();
                self.pos += i + 2;
                return Ok(line);
            }
            if self.buf.len() - self.pos > MAX_HEAD_BYTES {
                return Err(RequestError::BadRequest("chunk line too long"));
            }
            if self.fill()? == 0 {
                return Err(RequestError::Gone);
            }
        }
    }

    fn read_request(&mut self) -> Result<Request, RequestError> {
        let head_end = loop {
            if let Some(i) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err(RequestError::HeadTooLarge);
            }
            if self.fill()? == 0 {
                return Err(RequestError::Gone);
            }
        };
        let head = String::from_utf8_lossy(&self.buf[..head_end]).into_owned();
        self.pos = head_end + 4;
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_ascii_whitespace();
        let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(RequestError::BadRequest("malformed request line"));
        };
        if !version.starts_with("HTTP/1.") {
            return Err(RequestError::BadRequest("unsupported HTTP version"));
        }
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut expect_continue = false;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else { continue };
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => {
                    let n: u64 = value.parse().map_err(|_| RequestError::BadRequest("invalid Content-Length"))?;
                    if content_length.is_some_and(|old| old as u64 != n) {
                        return Err(RequestError::BadRequest("conflicting Content-Length"));
                    }
                    if n > MAX_BODY_BYTES as u64 {
                        return Err(RequestError::TooLarge);
                    }
                    content_length = Some(n as usize);
                }
                "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
                "expect" => expect_continue = value.eq_ignore_ascii_case("100-continue"),
                _ => {}
            }
        }
        if expect_continue && (chunked || content_length.unwrap_or(0) > 0) {
            let _ = self.stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        let body = if chunked {
            let mut body = Vec::new();
            loop {
                let line = self.line()?;
                let size_str = line.split(';').next().unwrap_or("").trim();
                let size = usize::from_str_radix(size_str, 16).map_err(|_| RequestError::BadRequest("invalid chunk size"))?;
                if size == 0 {
                    while !self.line()?.is_empty() {}
                    break body;
                }
                if body.len() + size > MAX_BODY_BYTES {
                    return Err(RequestError::TooLarge);
                }
                self.need(size + 2)?;
                body.extend_from_slice(&self.buf[self.pos..self.pos + size]);
                self.pos += size;
                if &self.buf[self.pos..self.pos + 2] != b"\r\n" {
                    return Err(RequestError::BadRequest("malformed chunk"));
                }
                self.pos += 2;
            }
        } else {
            let n = content_length.unwrap_or(0);
            self.need(n)?;
            self.buf[self.pos..self.pos + n].to_vec()
        };
        Ok(Request { method: method.to_string(), target: target.to_string(), body })
    }
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8], extra: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        body.len()
    );
    if body.len() <= 64 * 1024 {
        // One buffer, one write: avoids Nagle/delayed-ACK stalls on small responses.
        let mut out = Vec::with_capacity(head.len() + body.len());
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(body);
        let _ = stream.write_all(&out);
    } else {
        // Large blocks: skip the extra copy of a possibly 100+ MB body.
        let _ = stream.write_all(head.as_bytes()).and_then(|_| stream.write_all(body));
    }
    let _ = stream.flush();
}

/// Reject without reading the rest of the request: half-close, then briefly drain so the
/// client sees our status instead of a reset.
fn reject(stream: &mut TcpStream, status: &str) {
    respond(stream, status, "text/plain", status.as_bytes(), "");
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 16 * 1024];
    let mut drained = 0usize;
    while drained < 4 * MAX_BODY_BYTES {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

fn handle_connection(stream: TcpStream, service: &Service) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
    let mut inbound = Inbound { stream, buf: Vec::with_capacity(4096), pos: 0 };
    let request = inbound.read_request();
    let stream = &mut inbound.stream;
    match request {
        Ok(req) => {
            let path = req.target.split(['?', '#']).next().unwrap_or("");
            if path != "/" {
                respond(stream, "404 Not Found", "text/plain", b"not found", "");
            } else if req.method != "POST" {
                respond(stream, "405 Method Not Allowed", "text/plain", b"method not allowed", "Allow: POST\r\n");
            } else {
                let _guard = InFlight::enter();
                let body = service.handle_body(&req.body);
                respond(stream, "200 OK", "application/json", body.as_bytes(), "");
            }
        }
        Err(RequestError::TooLarge) => reject(stream, "413 Payload Too Large"),
        Err(RequestError::HeadTooLarge) => reject(stream, "431 Request Header Fields Too Large"),
        Err(RequestError::BadRequest(why)) => {
            eprintln!("onlyblocks: rejecting malformed request: {why}");
            reject(stream, "400 Bad Request")
        }
        Err(RequestError::Gone) => {}
    }
}
