# OnlyBlocks in Fortran 2018

A historical Solana `getBlock` JSON-RPC 2.0 server written in modern Fortran.
It is one process, keeps everything in RAM, and has no dependencies. Every
byte of the protocol stack is Fortran, from the TCP accept loop down to the
Zstandard Huffman decoder. It builds with GNU Fortran 14 and
`-O3 -std=f2018 -ffree-line-length-none -fwrapv`.

```sh
bash build.sh                    # bin/onlyblocks, about 350 KB
bash run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
bash build.sh --test             # offline self-test: hashes, codecs, zstd vectors
python3 ../../conformance/runner.py --impl fortran
```

## Zero dependencies

* There is no C. `iso_c_binding` declares only libc calls: `socket`,
  `setsockopt`, `bind`, `listen`, `accept`, `connect`, `recv`, `send`,
  `close`, `getaddrinfo`, `signal`, `_exit`, `usleep`, `time`, and
  `popen`/`fread`/`pclose`. All of them are non-variadic. On Apple arm64 a
  variadic call such as `fcntl` would receive its arguments in the wrong place.
* `http://` Range reads use raw POSIX TCP from Fortran: the request line,
  `Content-Length`, chunked framing and per-read caps. The conformance mock
  origin uses this path.
* `https://` uses the transport exception in SPEC 3.3. The server runs the
  OS `/usr/bin/curl -i` through `popen`, and `exec` replaces the shell so curl
  is the only child. The response head and body come back over the pipe and
  pass through the same HTTP head parser and the same status and length checks.
* The implementation contains, in Fortran:
  * CARv1 varints and CIDs
  * a validating DAG-CBOR walker
  * CRC-64/GO-ISO, FNV-1a and XXH64
  * a full RFC 8878 Zstandard decoder (FSE, Huffman, all four sequence modes,
    repeat offsets, checksums, skippable and concatenated frames, the 512 MiB
    output limit)
  * protobuf with prost semantics, including packed and unpacked repeated
    fields, merged sub-messages and group skipping
  * the five pre-epoch-157 bincode `TransactionStatusMeta` layouts
  * Base58 and Base64, and `VersionedTransaction` decoding
  * the section 14 signer and writable flags
  * an RFC 8259 JSON parser with UTF-8 and surrogate-pair validation and a
    128-level depth cap
  * two bounded 100 000-entry LRU caches (`slot -> range` and
    `slot -> blockhash`)

## Fortran idioms worth a look

* **Unsigned 64-bit without unsigned types.** Slots, offsets, balances and
  hashes are `int64` bit patterns. Comparisons use the F2008 bitwise
  intrinsics `bge`/`bgt`/`blt`, which compare as unsigned. `udivmod` divides by
  halving first (`shiftl(shiftr(n,1)/d,1)` plus one correction), which is how
  `18446744073709551615` reaches epoch `42700796466920`.
* **Modular hashing.** With `-fwrapv`, `h = h * PRIME` is exact FNV-1a.
  XXH64 rounds use `ishftc` (circular shift), and the CRC-64 table uses
  logical `shiftr`.
* **0-based buffers.** Decoder dummies are declared `integer(int8),
  intent(in) :: d(0:)`, so offsets read exactly like the spec. Bytes are
  widened with `iand(int(b, int32), 255)`.
* **Spans, not copies.** Transactions, metadata strings, log lines and token
  mints are `(position, length)` views into the reassembled or decompressed
  buffer.
* **Deferred-length string builder.** `character(len=:), allocatable` plus
  `move_alloc` doubling builds responses of up to 167 MB, for example the
  1.2 M-reward epoch-boundary slot `302400000`. The result is written straight
  into the HTTP response and rolled back to a mark if decoding fails.
* **Signals in Fortran.** The SIGTERM/SIGINT handler is a
  `subroutine on_terminate(sig) bind(c)` that calls `_exit(0)`. `SIG_IGN` for
  SIGPIPE is `transfer(1_c_intptr_t, c_null_funptr)`, and `errno` is read with
  `c_f_pointer(__error())`.
* **Shortest round-trip doubles** for `uiAmount`: try `ESw.d` internal
  `write`s with 1 to 17 digits and keep the first one that `read`s back to
  the same value.

## Layout

| Module | Role |
|---|---|
| `ob_util` | byte buffer, string builder, u64 decimal, UTF-8, JSON escaping |
| `ob_hash` | CRC-64/GO-ISO, FNV-1a, XXH64 |
| `ob_zstd` | RFC 8878 decoder (port of `docs/ZSTD_MINI_SPEC.md`) |
| `ob_codec` | Base58/Base64, shortest doubles, `real_number_string_trimmed` |
| `ob_json` | request JSON parser |
| `ob_posix` | libc interfaces, sockaddr/addrinfo layouts, signals |
| `ob_http` | buffered socket/pipe readers, HTTP framing, Range client with retry/backoff |
| `ob_cache` | LRU maps |
| `ob_car` | CAR index, CIDs, CBOR, IPLD nodes, DataFrame reassembly |
| `ob_tx` | `VersionedTransaction` |
| `ob_meta` | protobuf and bincode metadata and rewards, epoch-157 split |
| `ob_render` | `getBlock` JSON for every encoding and detail level |
| `ob_rpc` | envelopes, parameter validation, the two-range-read pipeline |
| `ob_server`, `main` | accept loop, argument and environment handling |

## Verification

* `runner.py --impl fortran` passes, including with `--strict-parsed`,
  `--bench` and `--live`. It also passes with a bounds-checked
  `OB_DEBUG=1 bash build.sh` build (`-fcheck=all`).
* `bash build.sh --test` runs the hash check values, the Base58/Base64
  vectors and the six `ZSTD_MINI_SPEC.md` section 9 frames.
  `tests/zstd_corpus.f90` (`<frame> <expected>` pairs) and
  `tests/zstd_fuzz.f90` (mutation fuzzing) are drivers for frames you generate
  with the `zstd` CLI. The decoder matched `zstd -d` on every frame tried,
  from `--fast` to `--ultra -22 --long=27`.
* On live mainnet data (slots `302400001`, `43200000` and the 167 MB
  epoch-boundary `302400000`, in every encoding and detail mode), the parsed
  JSON is identical to `impls/javascript-node`.

## Limits

Connections are served one at a time, so a slow upstream fetch delays
`getHealth`. Parallel serving is RECOMMENDED by the spec, not required. Socket
constants and the `sockaddr`/`addrinfo` layouts are the Darwin ones (see
`ob_posix`). Inbound and `http://` upstream addresses are IPv4. `http://`
connects use the OS connect timeout, then a 60 s per-read timeout.
