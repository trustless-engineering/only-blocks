//! End-to-end golden tests with zero crates: an in-process std-only Old Faithful mock serves
//! `conformance/fixtures`, and every manifest case runs through the real HTTP client, cache,
//! decoders and JSON encoder.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use onlyblocks::http_client::parse_base_url;
use onlyblocks::json::{self, Json};
use onlyblocks::old_faithful::{ClientConfig, OldFaithful};
use onlyblocks::rpc::Service;

const SLOTS_PER_EPOCH: u64 = 432_000;

struct Epoch {
    car: Vec<u8>,
    ranges: HashMap<u64, (u64, u32)>,
}

#[derive(Default)]
struct Counters {
    slot_ranges: AtomicUsize,
    cars: AtomicUsize,
    pending_429: AtomicUsize,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fixtures")
}

fn load_manifest() -> Json {
    let bytes = std::fs::read(fixtures_dir().join("manifest.json")).expect("read manifest");
    json::parse(&bytes).expect("parse manifest")
}

fn load_epochs(manifest: &Json) -> HashMap<u64, Epoch> {
    let mut epochs = HashMap::new();
    let Some(Json::Object(list)) = manifest.get("epochs") else { panic!("no epochs") };
    for (epoch, fixture) in list {
        let car = std::fs::read(fixtures_dir().join(fixture.get("car_file").and_then(Json::as_str).unwrap())).unwrap();
        let mut ranges = HashMap::new();
        if let Some(Json::Object(r)) = fixture.get("slot_ranges") {
            for (slot, rec) in r {
                let offset = rec.get("offset").and_then(Json::as_u64).unwrap();
                let length = rec.get("length").and_then(Json::as_u64).unwrap() as u32;
                ranges.insert(slot.parse().unwrap(), (offset, length));
            }
        }
        epochs.insert(epoch.parse().unwrap(), Epoch { car, ranges });
    }
    epochs
}

/// Serve `GET /{epoch}/epoch-{epoch}-slot-ranges.raw` and `/{epoch}/epoch-{epoch}.car` ranges.
fn start_mock(epochs: HashMap<u64, Epoch>, counters: Arc<Counters>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let epochs = Arc::new(epochs);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let epochs = Arc::clone(&epochs);
            let counters = Arc::clone(&counters);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut out = stream;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    let mut range = None;
                    loop {
                        let mut h = String::new();
                        if reader.read_line(&mut h).unwrap_or(0) == 0 {
                            return;
                        }
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        if let Some(v) = h.strip_prefix("Range: bytes=") {
                            let (a, b) = v.split_once('-').unwrap();
                            range = Some((a.parse::<u64>().unwrap(), b.parse::<u64>().unwrap()));
                        }
                    }
                    let reply = |out: &mut std::net::TcpStream, status: &str, body: &[u8], extra: &str| {
                        let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n{extra}\r\n", body.len());
                        out.write_all(head.as_bytes()).and_then(|_| out.write_all(body))
                    };
                    let parts: Vec<&str> = path.trim_start_matches('/').splitn(2, '/').collect();
                    let epoch: Option<u64> = parts.first().and_then(|e| e.parse().ok());
                    let is_ranges = path.ends_with("-slot-ranges.raw");
                    let (Some(epoch), Some((start, end))) = (epoch, range) else {
                        let _ = reply(&mut out, "400 Bad Request", b"", "");
                        continue;
                    };
                    if is_ranges {
                        counters.slot_ranges.fetch_add(1, Ordering::SeqCst);
                    } else {
                        counters.cars.fetch_add(1, Ordering::SeqCst);
                    }
                    let Some(fixture) = epochs.get(&epoch) else {
                        let _ = reply(&mut out, "404 Not Found", b"", "");
                        continue;
                    };
                    if counters.pending_429.load(Ordering::SeqCst) > 0 {
                        counters.pending_429.fetch_sub(1, Ordering::SeqCst);
                        let _ = reply(&mut out, "429 Too Many Requests", b"", "Retry-After: 0\r\n");
                        continue;
                    }
                    let body = if is_ranges {
                        let mut table = vec![0u8; ((end - start + 12) as usize).max(24)];
                        let first = start / 12;
                        for idx in first..=end / 12 {
                            if let Some(&(o, l)) = fixture.ranges.get(&(epoch * SLOTS_PER_EPOCH + idx)) {
                                let at = ((idx - first) * 12) as usize;
                                table[at..at + 8].copy_from_slice(&o.to_le_bytes());
                                table[at + 8..at + 12].copy_from_slice(&l.to_le_bytes());
                            }
                        }
                        let cut = (start % 12) as usize;
                        table[cut..cut + (end - start + 1) as usize].to_vec()
                    } else {
                        fixture.car[start as usize..=end as usize].to_vec()
                    };
                    let _ = reply(&mut out, "206 Partial Content", &body, "");
                }
            });
        }
    });
    base
}

fn service(base: &str) -> Service {
    let cfg = ClientConfig { initial_backoff: std::time::Duration::from_millis(1), ..ClientConfig::default() };
    Service::new(OldFaithful::new(parse_base_url(base).unwrap(), cfg), 1000)
}

const OPTIONAL_META: [&str; 9] = [
    "innerInstructions",
    "logMessages",
    "preTokenBalances",
    "postTokenBalances",
    "loadedAddresses",
    "returnData",
    "computeUnitsConsumed",
    "costUnits",
    "rewards",
];

/// The harness comparator, minus the jsonParsed well-known-program allowance (fixtures use
/// custom programs): null == missing only for optional metadata/instruction/token fields.
fn compare(want: &Json, got: &Json, path: &str) -> Result<(), String> {
    match (want, got) {
        (Json::Object(_), Json::Object(_)) => {
            let mut keys: Vec<&String> = Vec::new();
            for obj in [want, got] {
                if let Json::Object(m) = obj {
                    for (k, _) in m {
                        if !keys.contains(&k) {
                            keys.push(k);
                        }
                    }
                }
            }
            for k in keys {
                let (w, g) = (want.get(k), got.get(k));
                let optional = (path.ends_with(".meta") && OPTIONAL_META.contains(&k.as_str()))
                    || k == "stackHeight"
                    || ((k == "owner" || k == "programId") && path.contains("TokenBalances"));
                match (w, g) {
                    (Some(w), Some(g)) => compare(w, g, &format!("{path}.{k}"))?,
                    (None, Some(Json::Null)) | (Some(Json::Null), None) if optional => {}
                    _ => return Err(format!("{path}.{k}: expected {w:?}, got {g:?}")),
                }
            }
            Ok(())
        }
        (Json::Array(a), Json::Array(b)) => {
            if a.len() != b.len() {
                return Err(format!("{path}.length: expected {}, got {}", a.len(), b.len()));
            }
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                compare(x, y, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        (Json::Number(x), Json::Number(y)) => {
            let is_int = |s: &str| !s.contains(['.', 'e', 'E']);
            let same = if is_int(x) && is_int(y) {
                x == y
            } else {
                let (fx, fy): (f64, f64) = (x.parse().unwrap(), y.parse().unwrap());
                let tol = if path.ends_with(".uiAmount") { 1e-9 } else { 0.0 };
                (fx - fy).abs() <= tol
            };
            if same {
                Ok(())
            } else {
                Err(format!("{path}: expected {x}, got {y}"))
            }
        }
        _ if want == got => Ok(()),
        _ => Err(format!("{path}: expected {want:?}, got {got:?}")),
    }
}

fn validate(case: &Json, resp: &Json) -> Result<(), String> {
    match case.get("expect_kind").and_then(Json::as_str) {
        Some("batch") => {
            let Json::Array(items) = resp else { return Err("expected batch array".into()) };
            let Some(Json::Array(expected)) = case.get("expected_batch") else { return Err("bad fixture".into()) };
            if items.len() != expected.len() {
                return Err(format!("batch length {} != {}", items.len(), expected.len()));
            }
            // Batches are answered in order, so match positionally.
            for (e, r) in expected.iter().zip(items) {
                validate(e, r)?;
            }
            Ok(())
        }
        Some(kind) => {
            if resp.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
                return Err("missing jsonrpc 2.0".into());
            }
            compare(case.get("expected_id").unwrap_or(&Json::Null), resp.get("id").unwrap_or(&Json::Null), "$.id")?;
            if kind == "result" {
                let result = resp.get("result").ok_or_else(|| format!("expected result, got {resp:?}"))?;
                compare(case.get("expected_result").unwrap(), result, "$")
            } else {
                let err = resp.get("error").ok_or("expected error")?;
                let code = err.get("code").cloned().unwrap_or(Json::Null);
                let want = case.get("expected_error_code").unwrap();
                if &code != want {
                    return Err(format!("error code {code:?}, expected {want:?}"));
                }
                match err.get("message").and_then(Json::as_str) {
                    Some(m) if !m.is_empty() => Ok(()),
                    _ => Err("empty error message".into()),
                }
            }
        }
        None => Err("bad fixture".into()),
    }
}

#[test]
fn golden_manifest_cases() {
    let manifest = load_manifest();
    let counters = Arc::new(Counters::default());
    let base = start_mock(load_epochs(&manifest), Arc::clone(&counters));
    let svc = service(&base);
    let Some(Json::Array(cases)) = manifest.get("cases") else { panic!("no cases") };
    let mut failures = Vec::new();
    for case in cases {
        let id = case.get("id").and_then(Json::as_str).unwrap_or("?");
        let body = case.get("raw_body").and_then(Json::as_str).unwrap();
        let resp = json::parse(svc.handle_body(body.as_bytes()).as_bytes()).expect("response is JSON");
        if let Err(e) = validate(case, &resp) {
            failures.push(format!("{id}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{} golden failures:\n{}", failures.len(), failures.join("\n"));
    assert!(cases.len() >= 30);
}

#[test]
fn removed_method_cache_and_retry() {
    let manifest = load_manifest();
    let counters = Arc::new(Counters::default());
    let base = start_mock(load_epochs(&manifest), Arc::clone(&counters));
    let svc = service(&base);

    // getTransaction is gone: -32601 and zero upstream requests.
    let r = svc.handle_body(br#"{"jsonrpc":"2.0","id":7,"method":"getTransaction","params":["x",{"slot":302400011}]}"#);
    assert!(r.contains("-32601") && r.contains("\"id\":7"), "{r}");
    assert_eq!(counters.slot_ranges.load(Ordering::SeqCst) + counters.cars.load(Ordering::SeqCst), 0);

    // An injected 429 (Retry-After: 0) is absorbed; the warm repeat makes no slot-range read.
    counters.pending_429.store(1, Ordering::SeqCst);
    let req = br#"{"jsonrpc":"2.0","id":1,"method":"getBlock","params":[302400011,{"transactionDetails":"none"}]}"#;
    let cold = svc.handle_body(req);
    assert!(cold.contains("3qbR1eZRqXUWroWKKYhbDmR3FfqTHfqSU8zZSxtANzYh"), "{cold}");
    let ranges_after_cold = counters.slot_ranges.load(Ordering::SeqCst);
    assert!(ranges_after_cold >= 2, "cold read plus one retry");
    assert_eq!(svc.handle_body(req), cold);
    assert_eq!(counters.slot_ranges.load(Ordering::SeqCst), ranges_after_cold, "warm repeat hit the RAM cache");

    // Unarchived epoch -> -32004, skipped slot -> -32007.
    let r = svc.handle_body(br#"{"jsonrpc":"2.0","id":2,"method":"getBlock","params":[4319568000]}"#);
    assert!(r.contains("-32004"), "{r}");
    let r = svc.handle_body(br#"{"jsonrpc":"2.0","id":3,"method":"getBlock","params":[302400004]}"#);
    assert!(r.contains("-32007"), "{r}");
}

#[test]
fn oversized_and_odd_http_requests() {
    use std::net::TcpStream;
    let manifest = load_manifest();
    let base = start_mock(load_epochs(&manifest), Arc::new(Counters::default()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = Arc::new(service(&base));
    std::thread::spawn(move || onlyblocks::http_server::serve(listener, svc));

    let roundtrip = |raw: &[u8]| -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(raw).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    };
    let health = br#"{"jsonrpc":"2.0","id":1,"method":"getHealth"}"#;
    let ok = roundtrip(&[format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", health.len()).as_bytes(), health].concat());
    assert!(ok.starts_with("HTTP/1.1 200 OK") && ok.ends_with(r#"{"jsonrpc":"2.0","result":"ok","id":1}"#), "{ok}");
    let chunked = roundtrip(
        &[&b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..], format!("{:x}\r\n", health.len()).as_bytes(), health, b"\r\n0\r\n\r\n"]
            .concat(),
    );
    assert!(chunked.contains("\"result\":\"ok\""), "{chunked}");
    let big = roundtrip(b"POST / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n");
    assert!(big.starts_with("HTTP/1.1 413"), "{big}");
    assert!(roundtrip(b"GET / HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 405"));
    assert!(roundtrip(b"POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n").starts_with("HTTP/1.1 404"));
    let parse_err = roundtrip(b"POST / HTTP/1.0\r\nContent-Length: 4\r\n\r\n{bad");
    assert!(parse_err.contains("-32700") && parse_err.contains("\"id\":null"), "{parse_err}");
}

#[test]
fn hostile_bytes_never_panic() {
    // Feed truncated/bit-flipped fixture CAR slices straight through the decoder.
    let manifest = load_manifest();
    let epochs = load_epochs(&manifest);
    let epoch = &epochs[&700];
    let (offset, length) = epoch.ranges[&302400011];
    let slice = &epoch.car[offset as usize..(offset + length as u64) as usize];
    for i in (0..slice.len()).step_by(7) {
        let mut m = slice.to_vec();
        m[i] ^= 0x5a;
        if let Ok(index) = onlyblocks::car::CarIndex::parse(&m) {
            if let Ok((block, _)) = onlyblocks::block::block_header(&index, None) {
                let _ = onlyblocks::block::decode_transactions(302400011, &index, &block, true, true);
                let _ = onlyblocks::block::decode_block_rewards(302400011, &index, &block);
            }
        }
        let _ = onlyblocks::car::CarIndex::parse(&slice[..i]);
    }
}
