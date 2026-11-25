# OnlyBlocks — Rust (0 crates, pure `std`)

A historical Solana `getBlock` JSON-RPC 2.0 server that reads blocks straight out of
[Old Faithful](https://files.old-faithful.net) with two HTTP Range requests. It uses **zero
third-party crates**:

```console
$ cargo tree
onlyblocks v0.1.0
```

`Cargo.toml` has empty `[dependencies]` and `[dev-dependencies]`, and `build.sh` runs
`cargo build --offline`, so nothing is downloaded. Everything from the TCP socket up to the
JSON bytes is implemented in `src/` on top of the Rust standard library. Earlier this
directory held the crate-based reference oracle (axum, tokio, reqwest, prost, zstd,
`solana-transaction-status`, …). This port reproduces its output field for field under the
conformance comparator.

```sh
./build.sh                                   # cargo build --release --offline
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
cargo test                                   # unit vectors + golden fixtures, std-only
python3 ../../conformance/runner.py --impl rust --live
```

Flags take precedence over environment variables (`ONLYBLOCKS_BIND`, `OLD_FAITHFUL_BASE_URL`),
which take precedence over defaults. `--help` lists the tuning knobs: slice cap, upstream
concurrency, cache sizes, retries and timeouts.

## What replaces each crate

| Was | Now (`src/`) |
|---|---|
| axum + tokio | `http_server.rs`: `TcpListener` feeding an **elastic thread pool** (`Mutex<VecDeque>` + `Condvar`). It keeps 4 warm workers and grows on demand, so a 56 MB decode never starves `getHealth`. Bodies are capped at 1 MiB (`413`), and chunked bodies and `Expect: 100-continue` are supported. |
| tokio signals | `signal.rs`: `extern "C" { fn signal(..) }` straight to libc. The handler only stores an `AtomicBool`; a watcher thread drains in-flight requests and exits with status 0. |
| reqwest + rustls | `http_client.rs`: keep-alive HTTP/1.1 Range client over `TcpStream` with an idle pool. A socket goes back to the pool only after a fully framed `206`, and a stale pooled socket gets one free redial. For `https://`, `/usr/bin/curl -q -sS -i` (SPEC §3.3) streams the body over a pipe and never touches disk. |
| tokio `Semaphore`, `lru` | `old_faithful.rs`: a `Mutex`/`Condvar` semaphore (32 attempts in flight, never held while sleeping). `lru.rs`: an O(1) LRU, `HashMap` → slab nodes on an intrusive doubly linked list, with the `slot → range` and `slot → blockhash` caches bounded at 100 000 entries. |
| fastrand, httpdate | xorshift64* jitter on an `AtomicU64`. `Retry-After` takes delta-seconds and all three HTTP-date forms, via Hinnant's `days_from_civil`. |
| serde_json | `json.rs`: a strict RFC 8259 parser (depth-limited, surrogate-aware) that **keeps numbers as raw lexemes**, so ids echo byte for byte and `1.0`/`1e3`/`-0` are never mistaken for slots. A streaming `Writer` emits the result straight into the response buffer, with no value tree for 100 MB results. |
| cid, multihash, serde_cbor | `car.rs`, `cbor.rs`, `ipld.rs`: a zero-copy CARv1 index (`HashMap<&[u8], &[u8]>` borrowing the slice), CIDv0/v1, `bafkqaaa`, and DAG-CBOR with `Cow` byte strings. Tag-42 links drop out naturally because tags are discarded. DataFrames are reassembled by iterative DFS with cycle detection. |
| crc, fnv | `hash.rs`: CRC-64/GO-ISO with **slicing-by-8** tables built once in a `OnceLock`, plus FNV-1a. |
| zstd (C libzstd) | `zstd.rs`: the full RFC 8878 decoder. Raw/RLE/compressed blocks, 1- and 4-stream Huffman (direct and FSE weights, treeless), all four FSE modes, repeat offsets, XXH64, skippable and concatenated frames, and the 512 MiB bomb limit. It handles the 75 MB epoch-boundary rewards payload with end-to-end `getBlock` latency
matching the libzstd-based oracle. |
| prost | `proto.rs`: a protobuf wire reader with prost semantics. Packed and unpacked repeated fields mix, sub-messages are merged field by field, groups are skipped, and wrong wire types are rejected. |
| bincode | `bincode.rs`: fixint bincode that reproduces `SliceReader` + `default_on_eof` exactly (fixed-width EOF does not consume, and a truncated string never defaults), all four legacy metadata layouts, and the 39/54-variant `TransactionError`/`InstructionError` enums. |
| solana-* | `tx.rs`: the legacy, v0 and v1 `VersionedTransaction` parser. `encode.rs`: the full `getBlock` JSON (§13), with signer/writable/demotion flags against the 31 reserved keys. `codec.rs`: Base58 using base-58⁵ limbs and three input bytes per pass, Base64, `uiAmountString`. |

## Robustness

Every decode path returns `Result`. Allocations from untrusted lengths are clamped to the
bytes actually remaining. Each request is wrapped in `catch_unwind`, so hostile archive
bytes produce `-32603`, never a crash. `panic = "unwind"` is set explicitly. A debug-build
fuzz run of 35 800 bit-flipped mainnet CAR slices and zstd/protobuf/bincode frames produced
zero panics.

## Verification

* `cargo test`: 40 tests. Spec vectors for every codec, and `tests/golden.rs`, which serves
  `conformance/fixtures` from an in-process std-only mock origin and checks every manifest
  case, the `getTransaction` zero-network rule, the warm cache and `429` retries.
* `conformance/runner.py --impl rust --live`: PASS. With `--bench`: cold 0.9 ms, warm p50 0.28 ms, peak RSS ≈ 4 MB, ~950 KB binary.
* A differential run against the old crate-based oracle on real mainnet slices matched under
  the conformance comparator in every encoding and detail mode. It covered v0 slots
  302400001–302400004, pre-157 bincode slots 43199999–43200002 and genesis-era slots 0–5,
  9 and 10. The 56 MB epoch-boundary block 302400000 was checked in three configurations:
  `none`, `signatures`, and `json` with rewards. The only differences are the intentional
  `jsonParsed` "partially decoded only" instructions (SPEC §10.1).
