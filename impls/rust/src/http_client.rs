//! Outbound HTTP Range transport.
//!
//! * `http://`: HTTP/1.1 over `std::net::TcpStream` with a small keep-alive pool.
//! * `https://`: the OS-shipped `curl` binary (SPEC.md §3.3), body streamed over a pipe.
//!
//! One call performs exactly one attempt; retries live in [`crate::old_faithful`].

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseUrl {
    /// Normalized (trimmed, no trailing `/`) URL used to build request URLs.
    pub url: String,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// Value for the `Host` header.
    pub authority: String,
    /// Path prefix (may be empty), no trailing `/`.
    pub path: String,
}

/// Parse and normalize a base URL (SPEC.md §2.3): trim, strip trailing `/`, http(s) only.
pub fn parse_base_url(input: &str) -> Result<BaseUrl, String> {
    let url = input.trim().trim_end_matches('/').to_string();
    let (scheme_str, rest) = url.split_once("://").ok_or_else(|| format!("invalid base URL {input:?}: missing scheme"))?;
    let scheme = match scheme_str.to_ascii_lowercase().as_str() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        other => return Err(format!("unsupported base URL scheme {other:?} (expected http or https)")),
    };
    let (authority_full, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let authority = authority_full.rsplit_once('@').map_or(authority_full, |(_, a)| a);
    let default_port = if scheme == Scheme::Http { 80 } else { 443 };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or("invalid IPv6 host in base URL")?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| format!("invalid port in base URL {input:?}"))?,
            None if after.is_empty() => default_port,
            None => return Err(format!("invalid base URL {input:?}")),
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| format!("invalid port in base URL {input:?}"))?),
            None => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return Err(format!("invalid base URL {input:?}: empty host"));
    }
    Ok(BaseUrl { scheme, host, port, authority: authority.to_string(), path: path.to_string(), url })
}

/// The outcome of a single attempt that did not produce a valid body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError {
    /// HTTP 404: unarchived. Never retried, never cached.
    NotFound,
    /// Non-retryable failure (unexpected status, oversize body, length mismatch).
    Fatal(String),
    /// 429, 5xx or a transport error; `retry_after` comes from the response, if any.
    Retry { retry_after: Option<Duration>, message: String },
}

fn retry(message: impl Into<String>) -> AttemptError {
    AttemptError::Retry { retry_after: None, message: message.into() }
}

pub struct RangeRequest<'a> {
    pub path: &'a str,
    pub start: u64,
    pub end: u64,
    /// Exact body length the caller requires.
    pub expected: u64,
    /// Hard cap while streaming (`12` or `max_slice_bytes`).
    pub cap: u64,
}

pub struct Transport {
    pub base: BaseUrl,
    pub user_agent: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pool: Mutex<Vec<(TcpStream, Instant)>>,
    curl: String,
}

const POOL_MAX_IDLE: usize = 16;
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_HEAD_BYTES: usize = 64 * 1024;

impl Transport {
    pub fn new(base: BaseUrl, user_agent: String, connect_timeout: Duration, request_timeout: Duration) -> Self {
        let curl = if std::path::Path::new("/usr/bin/curl").exists() { "/usr/bin/curl" } else { "curl" };
        Transport { base, user_agent, connect_timeout, request_timeout, pool: Mutex::new(Vec::new()), curl: curl.to_string() }
    }

    pub fn fetch(&self, req: &RangeRequest<'_>) -> Result<Vec<u8>, AttemptError> {
        match self.base.scheme {
            Scheme::Http => self.fetch_http(req),
            Scheme::Https => self.fetch_curl(req),
        }
    }

    // ----------------------------------------------------------------------------------
    // http:// over TcpStream
    // ----------------------------------------------------------------------------------

    fn checkout(&self) -> Option<TcpStream> {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        while let Some((stream, since)) = pool.pop() {
            if since.elapsed() < POOL_IDLE_TIMEOUT {
                return Some(stream);
            }
        }
        None
    }

    fn checkin(&self, stream: TcpStream) {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        if pool.len() < POOL_MAX_IDLE {
            pool.push((stream, Instant::now()));
        }
    }

    fn connect(&self) -> Result<TcpStream, AttemptError> {
        let addrs = (self.base.host.as_str(), self.base.port)
            .to_socket_addrs()
            .map_err(|e| retry(format!("resolve {}: {e}", self.base.host)))?;
        let mut last = String::from("no addresses");
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last = format!("connect {addr}: {e}"),
            }
        }
        Err(retry(last))
    }

    fn fetch_http(&self, req: &RangeRequest<'_>) -> Result<Vec<u8>, AttemptError> {
        if let Some(stream) = self.checkout() {
            match self.exchange(stream, req) {
                // A stale keep-alive socket: one free redial on a fresh connection.
                Err(Exchange::Stale) => {}
                other => return other.map_err(Exchange::into_attempt),
            }
        }
        let stream = self.connect()?;
        self.exchange(stream, req).map_err(Exchange::into_attempt)
    }

    fn exchange(&self, stream: TcpStream, req: &RangeRequest<'_>) -> Result<Vec<u8>, Exchange> {
        let deadline = Instant::now() + self.request_timeout;
        let head = format!(
            "GET {}{} HTTP/1.1\r\nHost: {}\r\nRange: bytes={}-{}\r\nUser-Agent: {}\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n",
            self.base.path, req.path, self.base.authority, req.start, req.end, self.user_agent
        );
        let _ = stream.set_write_timeout(Some(self.request_timeout));
        let mut conn = Conn { stream, buf: Vec::with_capacity(8192), pos: 0, deadline };
        if conn.stream.write_all(head.as_bytes()).is_err() {
            return Err(Exchange::Stale);
        }
        let head = match conn.read_head() {
            Ok(h) => h,
            Err(ReadErr::Closed) if conn.buf.is_empty() => return Err(Exchange::Stale),
            Err(e) => return Err(Exchange::Attempt(retry(e.message("reading response head")))),
        };
        let resp = parse_response_head(&head).map_err(|e| Exchange::Attempt(retry(e)))?;
        let reusable = resp.keep_alive;
        if let Some(err) = classify_status(&resp) {
            return Err(Exchange::Attempt(err));
        }
        let (body, framed) = if resp.chunked {
            (conn.read_chunked(req.cap)?, true)
        } else if let Some(len) = resp.content_length {
            if len > req.cap {
                return Err(Exchange::Attempt(AttemptError::Fatal(format!(
                    "Content-Length {len} exceeds the {} byte cap",
                    req.cap
                ))));
            }
            (conn.read_exact_body(len)?, true)
        } else {
            (conn.read_to_close(req.cap)?, false)
        };
        let body = check_length(body, req.expected).map_err(Exchange::Attempt)?;
        // Only a fully framed 206 with nothing left over goes back to the pool.
        if reusable && framed && conn.pos == conn.buf.len() {
            self.checkin(conn.stream);
        }
        Ok(body)
    }

    // ----------------------------------------------------------------------------------
    // https:// via the OS `curl` binary
    // ----------------------------------------------------------------------------------

    fn fetch_curl(&self, req: &RangeRequest<'_>) -> Result<Vec<u8>, AttemptError> {
        let url = format!("{}{}", self.base.url, req.path);
        let mut child = Command::new(&self.curl)
            .arg("-q") // never read ~/.curlrc (it could redirect output to a file)
            .arg("-sS")
            .arg("-i")
            .arg("--connect-timeout")
            .arg(self.connect_timeout.as_secs().max(1).to_string())
            .arg("--max-time")
            .arg(self.request_timeout.as_secs().max(1).to_string())
            .arg("-H")
            .arg(format!("Range: bytes={}-{}", req.start, req.end))
            .arg("-A")
            .arg(&self.user_agent)
            .arg(&url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| retry(format!("spawn {}: {e}", self.curl)))?;
        let result = self.read_curl_output(&mut child, req);
        if result.is_err() {
            // Early exits (404, 429, caps) leave curl mid-transfer: stop it before reaping.
            let _ = child.kill();
        }
        let mut stderr = String::new();
        if let Some(s) = child.stderr.take() {
            let _ = s.take(4096).read_to_string(&mut stderr);
        }
        let status = child.wait().map_err(|e| retry(format!("curl wait: {e}")))?;
        match result {
            Ok(body) if status.success() => check_length(body, req.expected),
            Ok(_) => Err(retry(format!("curl failed ({status}): {}", stderr.trim()))),
            Err(AttemptError::Retry { retry_after, message }) if !status.success() && retry_after.is_none() => {
                Err(retry(format!("curl failed ({status}): {} {message}", stderr.trim())))
            }
            Err(e) => Err(e),
        }
    }

    fn read_curl_output(&self, child: &mut std::process::Child, req: &RangeRequest<'_>) -> Result<Vec<u8>, AttemptError> {
        let Some(stdout) = child.stdout.take() else { return Err(retry("curl stdout unavailable")) };
        let mut conn = PipeConn { stdout, buf: Vec::with_capacity(8192), pos: 0 };
        // Skip informational (1xx) and proxy CONNECT header blocks.
        let resp = loop {
            let head = conn.read_head().map_err(|e| retry(e.message("reading curl output")))?;
            let resp = parse_response_head(&head).map_err(retry)?;
            let proxy = resp.status == 200 && resp.reason.to_ascii_lowercase().contains("connection established");
            if !(100..200).contains(&resp.status) && !proxy {
                break resp;
            }
        };
        if let Some(err) = classify_status(&resp) {
            return Err(err);
        }
        if let Some(len) = resp.content_length {
            if len > req.cap {
                return Err(AttemptError::Fatal(format!("Content-Length {len} exceeds the {} byte cap", req.cap)));
            }
        }
        // curl removes chunked framing; the body runs to EOF.
        let hint = resp.content_length.unwrap_or(0).min(req.cap);
        conn.read_to_close_with_hint(req.cap, hint as usize).map_err(Exchange::into_attempt)
    }
}

fn check_length(body: Vec<u8>, expected: u64) -> Result<Vec<u8>, AttemptError> {
    if body.len() as u64 != expected {
        return Err(AttemptError::Fatal(format!("byte length mismatch: expected {expected} bytes, got {}", body.len())));
    }
    Ok(body)
}

fn classify_status(resp: &ResponseHead) -> Option<AttemptError> {
    match resp.status {
        206 => None,
        404 => Some(AttemptError::NotFound),
        429 => Some(AttemptError::Retry { retry_after: resp.retry_after, message: "HTTP 429 Too Many Requests".into() }),
        500..=599 => Some(AttemptError::Retry { retry_after: resp.retry_after, message: format!("HTTP {}", resp.status) }),
        s => Some(AttemptError::Fatal(format!("unexpected HTTP status {s} (expected 206)"))),
    }
}

enum Exchange {
    /// The pooled socket was dead before any response byte arrived.
    Stale,
    Attempt(AttemptError),
}

impl Exchange {
    fn into_attempt(self) -> AttemptError {
        match self {
            Exchange::Stale => retry("connection closed before the response"),
            Exchange::Attempt(a) => a,
        }
    }
}

enum ReadErr {
    Closed,
    TimedOut,
    Io(String),
    TooLarge,
}

impl ReadErr {
    fn message(&self, ctx: &str) -> String {
        match self {
            ReadErr::Closed => format!("{ctx}: connection closed"),
            ReadErr::TimedOut => format!("{ctx}: timed out"),
            ReadErr::Io(e) => format!("{ctx}: {e}"),
            ReadErr::TooLarge => format!("{ctx}: response head too large"),
        }
    }
}

/// A buffered reader over a socket, bounded by an absolute per-attempt deadline.
struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
    pos: usize,
    deadline: Instant,
}

/// Shared buffered-reading logic for both sources.
trait Buffered {
    fn buf(&mut self) -> &mut Vec<u8>;
    fn pos(&mut self) -> &mut usize;
    /// Read more bytes into the buffer; `Ok(0)` is EOF.
    fn fill(&mut self) -> Result<usize, ReadErr>;
    /// Read directly into `out` (bypassing the buffer); `Ok(0)` is EOF.
    fn read_into(&mut self, out: &mut [u8]) -> Result<usize, ReadErr>;

    fn read_head(&mut self) -> Result<Vec<u8>, ReadErr> {
        loop {
            let pos = *self.pos();
            let buf = self.buf();
            if let Some(i) = find_head_end(&buf[pos..]) {
                let head = buf[pos..pos + i].to_vec();
                *self.pos() = pos + i + 4;
                return Ok(head);
            }
            if buf.len() - pos > MAX_HEAD_BYTES {
                return Err(ReadErr::TooLarge);
            }
            if self.fill()? == 0 {
                return Err(ReadErr::Closed);
            }
        }
    }

    fn take_buffered(&mut self, max: usize) -> Vec<u8> {
        let pos = *self.pos();
        let buf = self.buf();
        let n = (buf.len() - pos).min(max);
        let out = buf[pos..pos + n].to_vec();
        *self.pos() = pos + n;
        out
    }

    fn read_line(&mut self) -> Result<Vec<u8>, ReadErr> {
        loop {
            let pos = *self.pos();
            let buf = self.buf();
            if let Some(i) = buf[pos..].windows(2).position(|w| w == b"\r\n") {
                let line = buf[pos..pos + i].to_vec();
                *self.pos() = pos + i + 2;
                return Ok(line);
            }
            if buf.len() - pos > MAX_HEAD_BYTES {
                return Err(ReadErr::TooLarge);
            }
            if self.fill()? == 0 {
                return Err(ReadErr::Closed);
            }
        }
    }

    /// Read exactly `len` body bytes; EOF first is a transport error (retryable).
    fn read_exact_body(&mut self, len: u64) -> Result<Vec<u8>, Exchange> {
        let len = len as usize;
        let mut body = self.take_buffered(len);
        if body.len() == len {
            return Ok(body);
        }
        body.reserve_exact(len - body.len());
        let mut chunk = vec![0u8; (len - body.len()).min(1 << 20)];
        while body.len() < len {
            let want = (len - body.len()).min(chunk.len());
            match self.read_into(&mut chunk[..want]) {
                Ok(0) => return Err(Exchange::Attempt(retry(format!("connection closed after {} of {len} body bytes", body.len())))),
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(Exchange::Attempt(retry(e.message("reading body")))),
            }
        }
        Ok(body)
    }

    fn read_to_close_with_hint(&mut self, cap: u64, hint: usize) -> Result<Vec<u8>, Exchange> {
        let mut body = self.take_buffered(usize::MAX);
        body.reserve(hint.saturating_sub(body.len()));
        let mut chunk = vec![0u8; 1 << 20];
        loop {
            if body.len() as u64 > cap {
                return Err(Exchange::Attempt(AttemptError::Fatal(format!("body exceeds the {cap} byte cap"))));
            }
            match self.read_into(&mut chunk) {
                Ok(0) => return Ok(body),
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(Exchange::Attempt(retry(e.message("reading body")))),
            }
        }
    }

    fn read_to_close(&mut self, cap: u64) -> Result<Vec<u8>, Exchange> {
        self.read_to_close_with_hint(cap, 0)
    }

    fn read_chunked(&mut self, cap: u64) -> Result<Vec<u8>, Exchange> {
        let transport = |e: ReadErr| Exchange::Attempt(retry(e.message("reading chunked body")));
        let mut body = Vec::new();
        loop {
            let line = self.read_line().map_err(transport)?;
            let text = String::from_utf8_lossy(&line);
            let size_str = text.split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size_str, 16)
                .map_err(|_| Exchange::Attempt(AttemptError::Fatal(format!("invalid chunk size {size_str:?}"))))?;
            if size == 0 {
                // Trailers until the empty line.
                loop {
                    if self.read_line().map_err(transport)?.is_empty() {
                        return Ok(body);
                    }
                }
            }
            if body.len() as u64 + size > cap {
                return Err(Exchange::Attempt(AttemptError::Fatal(format!("chunked body exceeds the {cap} byte cap"))));
            }
            let chunk = self.read_exact_body(size)?;
            body.extend_from_slice(&chunk);
            if !self.read_line().map_err(transport)?.is_empty() {
                return Err(Exchange::Attempt(retry("malformed chunk terminator")));
            }
        }
    }
}

impl Buffered for Conn {
    fn buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
    fn pos(&mut self) -> &mut usize {
        &mut self.pos
    }
    fn fill(&mut self) -> Result<usize, ReadErr> {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = self.read_into(&mut tmp)?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }
    fn read_into(&mut self, out: &mut [u8]) -> Result<usize, ReadErr> {
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ReadErr::TimedOut);
            }
            let _ = self.stream.set_read_timeout(Some(left.max(Duration::from_millis(1))));
            match self.stream.read(out) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                    return Err(ReadErr::TimedOut)
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => {
                    return Err(ReadErr::Closed)
                }
                Err(e) => return Err(ReadErr::Io(e.to_string())),
            }
        }
    }
}

/// A buffered reader over curl's stdout pipe (curl enforces its own `--max-time`).
struct PipeConn {
    stdout: std::process::ChildStdout,
    buf: Vec<u8>,
    pos: usize,
}

impl Buffered for PipeConn {
    fn buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
    fn pos(&mut self) -> &mut usize {
        &mut self.pos
    }
    fn fill(&mut self) -> Result<usize, ReadErr> {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = self.read_into(&mut tmp)?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }
    fn read_into(&mut self, out: &mut [u8]) -> Result<usize, ReadErr> {
        loop {
            match self.stdout.read(out) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(ReadErr::Io(e.to_string())),
            }
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub keep_alive: bool,
    pub retry_after: Option<Duration>,
}

pub fn parse_response_head(head: &[u8]) -> Result<ResponseHead, String> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(format!("malformed status line {status_line:?}"));
    }
    let status = parts
        .next()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .ok_or_else(|| format!("malformed status line {status_line:?}"))?;
    let reason = parts.next().unwrap_or("").trim().to_string();
    let mut resp = ResponseHead {
        status,
        reason,
        content_length: None,
        chunked: false,
        keep_alive: version == "HTTP/1.1",
        retry_after: None,
    };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                let n = value.parse::<u64>().map_err(|_| format!("invalid Content-Length {value:?}"))?;
                if resp.content_length.is_some_and(|old| old != n) {
                    return Err("conflicting Content-Length headers".into());
                }
                resp.content_length = Some(n);
            }
            "transfer-encoding" => {
                if value.to_ascii_lowercase().split(',').any(|t| t.trim() == "chunked") {
                    resp.chunked = true;
                }
            }
            "connection" => {
                let v = value.to_ascii_lowercase();
                if v.split(',').any(|t| t.trim() == "close") {
                    resp.keep_alive = false;
                } else if v.split(',').any(|t| t.trim() == "keep-alive") {
                    resp.keep_alive = true;
                }
            }
            "retry-after" => resp.retry_after = parse_retry_after(value, SystemTime::now()),
            _ => {}
        }
    }
    Ok(resp)
}

/// `Retry-After`: delta-seconds or an HTTP-date (a past date means "now").
pub fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let v = value.trim();
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
        return Some(Duration::from_secs(v.parse::<u64>().unwrap_or(u64::MAX)));
    }
    let when = parse_http_date(v)?;
    let now = now.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(Duration::from_secs((when - now).max(0) as u64))
}

/// Parse IMF-fixdate, RFC 850 and asctime dates into Unix seconds.
pub fn parse_http_date(s: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let month = |m: &str| MONTHS.iter().position(|x| x.eq_ignore_ascii_case(m)).map(|i| i as i64 + 1);
    let hms = |t: &str| -> Option<(i64, i64, i64)> {
        let mut it = t.split(':').map(|p| p.parse::<i64>().ok());
        let (h, m, s) = (it.next()??, it.next()??, it.next()??);
        (h < 24 && m < 60 && s <= 60).then_some((h, m, s))
    };
    let tokens: Vec<&str> = s.split([' ', ',']).filter(|t| !t.is_empty()).collect();
    let (year, mon, day, (h, mi, se)) = match tokens.as_slice() {
        // Sun, 06 Nov 1994 08:49:37 GMT
        [_, d, m, y, t, "GMT"] if y.len() == 4 => (y.parse().ok()?, month(m)?, d.parse().ok()?, hms(t)?),
        // Sunday, 06-Nov-94 08:49:37 GMT
        [_, dmy, t, "GMT"] => {
            let mut p = dmy.split('-');
            let (d, m, y) = (p.next()?, p.next()?, p.next()?);
            let y: i64 = y.parse().ok()?;
            let y = if y < 70 { 2000 + y } else if y < 100 { 1900 + y } else { y };
            (y, month(m)?, d.parse().ok()?, hms(t)?)
        }
        // Sun Nov  6 08:49:37 1994
        [_, m, d, t, y] => (y.parse().ok()?, month(m)?, d.parse().ok()?, hms(t)?),
        _ => return None,
    };
    if !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, mon, day) * 86_400 + h * 3600 + mi * 60 + se)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls() {
        let b = parse_base_url("  http://127.0.0.1:8080/// ").unwrap();
        assert_eq!((b.scheme, b.host.as_str(), b.port, b.path.as_str()), (Scheme::Http, "127.0.0.1", 8080, ""));
        assert_eq!(b.url, "http://127.0.0.1:8080");
        let b = parse_base_url("https://files.old-faithful.net").unwrap();
        assert_eq!((b.scheme, b.port, b.authority.as_str()), (Scheme::Https, 443, "files.old-faithful.net"));
        let b = parse_base_url("http://[::1]:9/mirror/").unwrap();
        assert_eq!((b.host.as_str(), b.port, b.path.as_str()), ("::1", 9, "/mirror"));
        assert!(parse_base_url("ftp://x").is_err());
        assert!(parse_base_url("files.old-faithful.net").is_err());
        assert!(parse_base_url("http://").is_err());
    }

    #[test]
    fn retry_after_values() {
        let now = UNIX_EPOCH + Duration::from_secs(784_111_777); // Sun, 06 Nov 1994 08:49:37 GMT
        assert_eq!(parse_retry_after("0", now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("3", now), Some(Duration::from_secs(3)));
        assert_eq!(parse_retry_after("Sun, 06 Nov 1994 08:49:40 GMT", now), Some(Duration::from_secs(3)));
        assert_eq!(parse_retry_after("Sunday, 06-Nov-94 08:49:47 GMT", now), Some(Duration::from_secs(10)));
        assert_eq!(parse_retry_after("Sun Nov  6 08:49:38 1994", now), Some(Duration::from_secs(1)));
        assert_eq!(parse_retry_after("Sat, 05 Nov 1994 08:49:37 GMT", now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("soon", now), None);
        assert_eq!(parse_retry_after("-1", now), None);
    }

    #[test]
    fn response_heads() {
        let h = parse_response_head(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 12\r\nRetry-After: 0").unwrap();
        assert_eq!((h.status, h.content_length, h.keep_alive), (206, Some(12), true));
        let h = parse_response_head(b"HTTP/2 429 \r\nretry-after: 1\r\nconnection: close").unwrap();
        assert_eq!((h.status, h.retry_after, h.keep_alive), (429, Some(Duration::from_secs(1)), false));
        assert!(parse_response_head(b"garbage").is_err());
    }
}
