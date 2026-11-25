# OnlyBlocks — C11 (zero dependencies)

A historical Solana `getBlock` JSON-RPC 2.0 server in portable C11. It reads blocks straight
out of [Old Faithful](https://files.old-faithful.net) with two HTTP Range requests and keeps
everything in RAM. `getTransaction` (and every other method) answers `-32601` without
touching the network.

```sh
./build.sh      # clang -O3 -std=c11 -Wall -Wextra  →  build/onlyblocks (no warnings)
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
python3 ../../conformance/runner.py --impl c --live
```

## Zero dependencies

The only things linked are libc, pthreads and, **solely for `https://`**, the libcurl that
ships with macOS (SPEC §3.3). `http://` (the conformance mock) goes over raw POSIX sockets.
Everything else is in `src/`:

| File | What it implements |
|---|---|
| `server.c` | CLI and env, listener, one detached pthread per connection, HTTP/1.1 framing (`Content-Length`, chunked, `Expect: 100-continue`, 413/404/405), JSON-RPC 2.0 envelope and batches |
| `json.c` | strict RFC 8259 parser that keeps number and string **lexemes**, so ids echo byte for byte and `1.0`, `1e3` and `-0` are never mistaken for slots. Depth-limited to 128 levels |
| `upstream.c` | Range client with the §4.3 retry policy (`Retry-After` as delta-seconds or HTTP-date, jittered backoff), a 32-slot semaphore held only during an attempt, and two O(1) LRUs (`slot → range`, `slot → blockhash`, 100 000 entries each) |
| `ipld.c` | CARv1 sections, CIDv0/v1, DAG-CBOR (tags dropped, so tag-42 links are plain byte strings), Old Faithful nodes, DataFrame DFS reassembly with cycle detection, and the `VersionedTransaction` parser |
| `meta.c` | protobuf with prost semantics (packed and unpacked fields, message merging, groups, wire-type checks), bincode with the reference's `default_on_eof` quirks, and the §9 zstd/codec fallback |
| `zstd.c` | the full RFC 8878 decoder: Raw/RLE/Compressed blocks, 1- and 4-stream Huffman (FSE and direct weights, treeless), all four FSE modes, repeat offsets, XXH64 checksums, skippable and concatenated frames, and the 512 MiB limit |
| `block.c` | the getBlock pipeline (§4.5) and the exact §13 JSON, including signer/writable/demotion flags |
| `common.c` | arena, error traps, JSON writer, Base58 (base-58⁵ limbs), Base64, CRC-64/GO-ISO (slicing-by-8), FNV-1a, XXH64, UTF-8 validation |

## C idioms worth a look

* **Arena plus `longjmp` error traps.** Each batch item gets an arena. Every decoder calls
  `fail()` on bad bytes, which `longjmp`s to the nearest `attempt()` trap. That trap is either
  the request boundary (→ `-32603`) or a fallback point: CAR header sniffing, bincode→protobuf,
  raw→zstd. No hand-written cleanup paths are needed. The one rule is that nothing besides
  arena memory may be live across a jump, so sockets, locks and curl handles live in code that
  returns status codes instead.
* **Two error channels in bincode.** Bincode returns `B_EOF` and `B_OTHER` as codes, not
  traps. That is how `EOF_FIELD()` reproduces bincode's `default_on_eof`: a fixed-width read
  that runs out defaults the field, but a truncated string payload stays an error.
* **Zero-copy throughout.** CAR nodes, CIDs, signatures, keys, strings and raw literals all
  point into the slice or into one decompression buffer.
* **Constant-time backward bit reads.** Zstd reads its backward bitstreams through one 8-byte
  little-endian window load per peek, with the spec's "zero bits past the start" semantics.

## Verification

* `conformance/runner.py --impl c`: **PASS** (golden cases, zero-network `getTransaction`,
  RAM cache, 429 retry, hostile input, zero disk).
* `--live --bench` against mainnet over HTTPS: **PASS**. Cold 1.6 ms, warm p50 0.54 ms, peak RSS
  about 10 MB, 143 KB binary.
* An `-fsanitize=address,undefined` build passes the full runner.
* The zstd decoder is byte-identical to `zstd -d` on 97 frames (levels `--fast=5` to
  `--ultra -22`, `--long`, checksums, small blocks, concatenated and skippable frames) and
  survives 25 000 bit-flipped frames under ASan.
* An end-to-end differential fuzz served 1 800 randomly corrupted CAR archives through the
  mock origin. C, C++ and Rust returned the same JSON value (or the same error code) for every
  request.
