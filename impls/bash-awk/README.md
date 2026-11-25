# OnlyBlocks in Bash + AWK

GNU Bash 5.3 plus macOS's own BWK `awk` (version 20200816). No Python, Perl,
Ruby, Node, `jq` or external Zstandard tool: every decoder, Zstandard
included, is AWK.

```sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

## How it works

* `server.bash` listens with Bash's **`accept` loadable builtin**, which ships
  with bash in `lib/bash/`. It forks one subshell per connection, and that
  subshell frames the HTTP/1.1 request with `read -t`. The body is read with
  `read -n` and NUL as the delimiter, so a raw NUL is caught, not skipped. The
  builtin closes its listening socket on every accept, so the hand-off happens
  at once. The port is listening again long before the handler replies.
* One long-lived **AWK coprocess** (`main.awk`) does everything else: JSON-RPC,
  CARv1, DAG-CBOR, CIDs, DataFrames, CRC-64/GO-ISO, FNV-1a, Base58 and Base64,
  RFC 8878 Zstandard (`zstd.awk`), `VersionedTransaction`, protobuf, all five
  bincode metadata layouts, `TransactionError`, and both bounded LRU caches
  (doubly linked lists threaded through awk arrays). Bash and AWK talk over
  anonymous pipes using length- and sequence-tagged messages.
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

## Zstandard in AWK

`zstd.awk` is a port of the `docs/ZSTD_MINI_SPEC.md` blueprint. It runs inside
the engine process on the bytes already in `M[]`, with no CLI, library or
pipe. It covers the following:

* frame headers, plus skippable and concatenated frames;
* Raw, RLE and Compressed blocks;
* Raw, RLE, Compressed and Treeless literals;
* 1- and 4-stream Huffman, with direct or FSE-coded weights;
* Predefined, RLE, FSE and Repeat sequence tables;
* the `[1, 4, 8]` repeat offsets;
* the XXH64 content checksum, which is verified.

Output is capped at 512 MiB across all frames, and the cap is checked before
the output grows. Window, block and content-size limits are checked the way
`impls/python/zstd.py` checks them. A failure leaves `ERR` alone, so
WIRE_FORMATS §9.1 falls back to the raw bytes.

* **Bitstreams.** A bitstream is read through one exact "bit container", a
  double that holds up to 53 unread bits. Taking the top `k` of `N` bits is
  `int(C / 2^(N-k))`, and dropping them is `C % 2^(N-k)`. The Huffman stream
  loop inlines that reader.
* **FSE tables.** Every FSE table (LL/OF/ML, Huffman weights, and the three
  predefined tables, built once) lives in flat arrays, with 512 cells per
  slot. `Repeat_Mode` just keeps the slot.
* **XXH64.** XXH64 runs on four exact 16-bit limbs, with XOR from the byte
  table.

## Process model

The server is one Bash process plus its AWK coprocess. The accept loop runs
in one more Bash child, and each connection adds a short-lived handler
subshell. All decoding, Zstandard included, happens in the AWK process. The
only other children are short-lived, OS-shipped stream tools for Range reads
and back-off:

* `sh`, from awk's pipes;
* `bash fetch.bash` for `http://` (its `/dev/tcp` socket), or
  `/usr/bin/curl` for `https://` (SPEC §3.3);
* `/usr/bin/od`, which turns the response bytes into hex for awk;
* `sleep`, for a retry wait.

No temporary files, FIFOs, here-docs or here-strings are used. Every byte
stays in pipes or RAM.

A blocking `accept(2)` restarts after a signal, so a SIGTERM or SIGINT trap
in the accepting process would wait for the next client. The accept loop
therefore runs in a child with default signal actions. The main shell only
`wait`s, which a trapped signal interrupts at once. It stops the loop and the
engine and exits 0, whether the signal went to its PID alone or to the whole
process group.
