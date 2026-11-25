# OnlyBlocks in ARM64 assembly

Hand-written AArch64 assembly for macOS on Apple Silicon. The 11 `.s` files
contain 9,131 total lines, including 8,431 non-blank, non-comment lines.
The implementation is entirely assembly. `build.sh` assembles it with
`clang -arch arm64` and links the result against libSystem.

```sh
./build.sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

## Zero dependencies

The code calls only the OS:

* **libSystem**: sockets, `getaddrinfo`, `read`/`write`, `malloc`/`realloc`,
  `memcpy`/`memcmp`, `snprintf` (only for the `%.17g` of `uiAmount`),
  `strptime`/`timegm` (for `Retry-After` dates), `arc4random_uniform` and
  `usleep`.
* **The system libcurl** (`/usr/lib/libcurl.4.dylib`), for `https://` Range
  reads only. This is SPEC §3.3's OS-TLS exception. Plain `http://` (the
  conformance mock) goes over raw libSystem sockets with an HTTP/1.1 client
  written in assembly.

Every codec is assembly:

| File | What it implements |
|---|---|
| `main.s` | flags and environment, base-URL normalization, the HTTP/1.1 server (`Content-Length` and chunked bodies, 413/404/405) |
| `json.s`, `rpc.s` | an RFC 8259 parser with a 128-level depth limit, the JSON-RPC 2.0 envelope, batches, `getBlock` parameter rules |
| `fetch.s` | the Range client, the SPEC §4.3 retry/backoff policy, `Retry-After`, the two 100,000-entry LRU caches |
| `car.s` | LEB128, CIDs, a validating DAG-CBOR cursor, a hashed CARv1 index, DataFrame DFS reassembly, CRC-64/GO-ISO, FNV-1a |
| `block.s` | the getBlock pipeline, blockhash and `previousBlockhash` |
| `tx.s` | legacy, `v0` and `v1` (SIMD-0385: config mask, split instruction headers/payloads, tail signatures) transactions, every encoding and detail level, the version gate, signer/writable flags with the reserved-key list |
| `meta.s` | protobuf metadata and rewards, the five bincode layouts, `TransactionError`, the §9 zstd and codec fallbacks |
| `zstd.s` | RFC 8878: FSE, Huffman (1 and 4 streams), all sequence modes, repeat offsets, skippable frames, XXH64 |
| `util.s` | the arena, growable buffers, Base58 (base-58^9 limbs), Base64, JSON escaping, UTF-8 validation |

## Idioms

* **Exceptions in assembly.** `_ob_try` saves x19-x30 and sp into a frame on
  the caller's stack, like `setjmp`. `_ob_throw` unwinds to the innermost
  frame. Decoders simply throw on any bounds or format violation. The codec
  fallbacks, bincode's "try layout 1, 2, 3, 4, then lenient", and the
  per-request `-32603` boundary are all nested try frames.
* **The request arena.** Every per-request allocation is a zero-filled bump
  allocation, and the whole arena is freed after each response, so an
  unwinding throw cannot leak.
* **A tiny printf for JSON.** `out_fmt` understands `%K` (a Base58 pubkey),
  `%G` (a signature), `%S` (an escaped string), `%Y` (Base64) and more.
  Serializers read almost like templates.
* **The CBOR cursor never builds a tree.** `node_view` validates a node once
  and records where its first eight elements start. Accessors skip tags and
  read values in place.

## Process model

One process and one thread. Connections are served one at a time, each
closed after its response. SIGTERM and SIGINT call `_exit(0)`, and SIGPIPE is
ignored. Nothing touches the disk.
