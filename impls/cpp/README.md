# OnlyBlocks — C++20 (zero dependencies)

A historical Solana `getBlock` JSON-RPC 2.0 server in modern C++20, built only on the standard
library. It reads blocks straight out of [Old Faithful](https://files.old-faithful.net) with
two HTTP Range requests and keeps everything in RAM. `getTransaction` (and every other method)
answers `-32601` without touching the network.

```sh
./build.sh      # clang++ -O3 -std=c++20 -Wall -Wextra  →  build/onlyblocks (no warnings)
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
python3 ../../conformance/runner.py --impl cpp --live
```

## Zero dependencies

The only things linked are libc++ and, **solely for `https://`**, the libcurl that ships with
macOS (SPEC §3.3). `http://` (the conformance mock) goes over raw POSIX sockets. This is a
separate design, not the C implementation recompiled:

| File | What it implements |
|---|---|
| `main.cpp` | CLI and env, listener, one `std::thread` per connection, HTTP/1.1 framing (`Content-Length`, chunked, `Expect: 100-continue`, 413/404/405), JSON-RPC 2.0 envelope and batches |
| `json.cpp` | strict RFC 8259 parser that keeps **lexemes** (`Json::raw`), so ids echo byte for byte and slots are validated on their source text |
| `archive.cpp` | Range client, §4.3 retry policy, `std::counting_semaphore<32>` held only while an attempt is in flight, and `LruCache<K, V>` (`std::list::splice` + `unordered_map`) |
| `ipld.cpp` | DAG-CBOR, CIDs, a **zero-copy `CarIndex`** (`unordered_map<string_view, span<const uint8_t>>` straight over the slice), DataFrames, Block nodes |
| `solana.cpp` | the legacy, v0 and v1 `VersionedTransaction` parser, protobuf (a `Proto` field cursor with prost semantics), bincode, and the §9 zstd/codec fallback |
| `zstd.cpp` | the full RFC 8878 decoder as a `FrameDecoder` class: FSE/Huffman tables, 4-stream literals, repeat offsets, XXH64, skippable and concatenated frames, the 512 MiB limit |
| `block.cpp` | the getBlock pipeline and the exact §13 JSON |
| `core.cpp` | Base58, Base64, CRC-64/GO-ISO, FNV-1a, XXH64, UTF-8, `uiAmountString` |

## C++20 idioms worth a look

* **One checked cursor.** `std::span` doesn't bounds-check, so every binary decoder reads
  through one throwing `Reader`. Bad bytes become a `DecodeError` (→ `-32603`), and coded
  failures are `RpcError{code}`. Each connection thread ends in `catch (...)`, so nothing can
  escape and kill the process.
* **`default_on_eof` as a type.** Bincode's fixed-width EOF is its own exception,
  `BincodeEof`. `eof_default([&]{ ... })` catches only that and returns `{}`, which reproduces
  the reference's legacy-layout leniency exactly. Truncated strings stay `DecodeError`.
* **Compile-time tables and checks.** The CRC-64 slicing-by-8 tables are `constexpr` and
  `static_assert` their own check value (`0xB90956C775A41001`). The zstd default
  distributions are `static_assert`ed to sum to `2^accuracy_log`.
* **Lexically nested JSON.** `JsonWriter::object([&]{ ... })` and `array_of(range, fn)` handle
  commas automatically. `value()` dispatches with `if constexpr`: `std::optional` becomes
  `null`, integers go through `std::to_chars`, and doubles use the shortest round-trip form.
* **RAII everywhere.** `Socket` is a move-only fd owner. The curl handle is
  `std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>`. Decoded buffers live in a per-request
  `Arena`, so every `string_view` and `span` into them stays valid until the response is
  written.

## Verification

* `conformance/runner.py --impl cpp`: **PASS** (golden cases, zero-network `getTransaction`,
  RAM cache, 429 retry, hostile input, zero disk).
* `--live` against mainnet over HTTPS: **PASS**.
* An `-fsanitize=address,undefined` build passes the full runner.
* The zstd decoder is byte-identical to `zstd -d` on 97 frames and survives 25 000
  bit-flipped frames under ASan.
* An end-to-end differential fuzz served 1 800 randomly corrupted CAR archives. C, C++ and
  Rust returned the same JSON value (or the same error code) for every request.
