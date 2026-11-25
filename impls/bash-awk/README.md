# OnlyBlocks in Bash + AWK

GNU Bash 5.3 plus macOS's own BWK `awk` (version 20200816). No Python, Perl,
Ruby, Node or `jq`.

```sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

## How it works

* `server.bash` listens with Bash's **`accept` loadable builtin**, which ships
  with bash in `lib/bash/`. It forks one subshell per connection, and that
  subshell frames the HTTP/1.1 request with `read -N` and `read -t`. The
  builtin closes its listening socket on every accept, so the hand-off happens
  at once. The port is listening again long before the handler replies.
* One long-lived **AWK coprocess** (`main.awk`) does everything else: JSON-RPC,
  CARv1, DAG-CBOR, CIDs, DataFrames, CRC-64/GO-ISO, FNV-1a, Base58 and Base64,
  `VersionedTransaction`, protobuf, all five bincode metadata layouts,
  `TransactionError`, and both bounded LRU caches (doubly linked lists
  threaded through awk arrays). Bash and AWK talk over anonymous pipes using
  length- and sequence-tagged messages.
* Plain `http://` Range reads use Bash's **`/dev/tcp`** sockets (`fetch.bash`).
  AWK parses the raw HTTP response itself: status, `Content-Length`, chunked
  framing and `Retry-After`. `https://` goes through the OS-shipped
  `/usr/bin/curl --raw -i` over a pipe, under the SPEC §3.3 transport
  exception.

## AWK idioms

BWK awk has no bitwise operators and only doubles. To cope:

* Bytes come in as `od -An -v -tx1` hex and land in one flat numeric array
  `M[]`.
* A `u64` is a pair of exact 32-bit halves. Decimal output uses long division.
* XOR is a 64 Ki-entry lookup table, built lazily.
* CRC-64 is table-driven over eight byte lanes. FNV-1a multiplies by
  `2^40 + 0x1b3` with byte-wise carries.
* Base58 runs on limbs of `58^5`, so every partial product stays exact.
* `substr()` costs a `strlen()` on every call. The JSON reader therefore walks
  request bodies 4 KiB at a time, with `split(s, a, "")`.

## The zstd exception

Zstandard frames are decompressed by piping them through the `zstd -d` CLI
(`/opt/homebrew/bin/zstd`). The spec permits this only for this `bash-awk`
entry. The CLI would also decode gzip or xz data, so `meta.awk` first walks
the RFC 8878 frame and block headers itself. Only well-formed zstd frames
reach it, with skippable frames already dropped. A non-zero exit counts as a
zstd failure, which falls back to the raw bytes (WIRE_FORMATS §9.1). The
compressed frame travels on the command line, so this entry rejects frames
over about 450 KB.

## Process model

The server is one Bash process plus its AWK coprocess. Each connection adds a
short-lived handler subshell, and each Range read or zstd call adds a few
short-lived tool processes (`od`, `xxd`, `zstd`, `curl`). No temporary files,
FIFOs, here-docs or here-strings are used. Every byte stays in pipes or RAM.
A blocking `accept(2)` restarts after a signal, so a SIGTERM or SIGINT trap
alone would wait for the next client. A sentinel subshell therefore answers
those signals by connecting to the server's own port. That returns `accept`,
so the trap can exit with status 0.
