# OnlyBlocks Specification: Protocol, Runtime and Conformance Contract

**OnlyBlocks** (`onlyblocks`) shows how to build the same tiny server in 20+
programming languages: a **single-process, zero-dependency, zero-disk,
historical Solana `getBlock` JSON-RPC 2.0 server** that reads blocks straight
out of the [Old Faithful](https://files.old-faithful.net) archive with two
HTTP Range requests.

This file is the contract. Together with
[`docs/WIRE_FORMATS.md`](docs/WIRE_FORMATS.md) (every byte format and the
exact JSON) and [`docs/ZSTD_MINI_SPEC.md`](docs/ZSTD_MINI_SPEC.md) (an
executable RFC 8878 decoder blueprint), it is everything an implementer needs.
You never need to read a Rust crate or a Solana repository.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY**
are used as in RFC 2119. The **reference behaviour** is that of the original
crate-based Rust server (axum, tokio, reqwest, `solana-transaction-status`, …),
the oracle that produced `conformance/fixtures/`. That oracle is no longer in
the tree: `impls/rust/` is now a zero-crate, pure-`std` port that reproduces
it, and `impls/javascript-node/` is a second, independent zero-dependency
implementation. Both are bound by every rule below, and either can be used
as a behavioural cross-check. Where OnlyBlocks intentionally
differs from the original oracle, §10 says so.

---

## 1. Core philosophy

| Property | Requirement |
|---|---|
| **Single OS process** | The server is one process. No sidecars, helper daemons or worker processes. The exceptions are the HTTPS transport exception in §3.3 and a runtime's own fixed plumbing: a VM's port helper (every BEAM forks `erl_child_setup`) and, for `bash-awk`, whose language is the shell, a `bash` `accept` listener with its handler subshells, one persistent `awk` engine coprocess, and the OS-shipped POSIX `sh`, `od` and `sleep` it pipes Range bytes and retry waits through. All decoding stays in the implementation's own code, and third-party binaries (`zstd`, `xxd`, `jq`, …) are forbidden. |
| **Zero disk** | After start-up the server MUST NOT create, write, append to, rename or delete any file or directory anywhere: not in `TMPDIR`, not in the implementation directory, not in a cache directory. Every cache lives in **bounded RAM**. Reading its own program/source files at start-up is fine. Logging goes to stdout/stderr only. |
| **Zero third-party dependencies** | Only the language's own standard library and the OS (§3). |
| **Historical only** | Data comes exclusively from Old Faithful (`https://files.old-faithful.net` by default). There is no ledger, validator, database or fallback RPC. |
| **Tiny surface** | Exactly two methods: `getBlock` and `getHealth`. Everything else, `getTransaction` included, returns `-32601` (§5.3). |

---

## 2. Repository layout and runner contract

### 2.1 Directory layout

```
impls/<slug>/              one directory per implementation
impls/<slug>/run.sh        REQUIRED, executable, starts the server in the foreground
impls/<slug>/build.sh      OPTIONAL, executable, compiles ahead of time
impls/<slug>/...           sources, a README, anything else
conformance/               offline harness, mock Old Faithful origin, golden fixtures
SPEC.md, docs/             this contract
```

`<slug>` is lowercase `[a-z0-9-]+` and names the language or variant (`rust`,
`c`, `go`, `zig`, `erlang`, `fortran`, `tcl`, `perl`, `bash-awk`,
`arm64-asm`, …).

### 2.2 `build.sh` (optional)

* Invoked as `bash build.sh` with the working directory `impls/<slug>/`. It
  must finish within **240 s** and exit `0` on success.
* `PATH` is prefixed with `~/.cargo/bin`, `~/.nix-profile/bin` and
  `/opt/homebrew/bin`.
* It MAY write build artefacts under `impls/<slug>/` (for example
  `impls/<slug>/target/`). Those must be git-ignored. It MUST NOT download
  anything (no package managers, no `curl | sh`). There are no exceptions:
  `impls/rust/build.sh` runs `cargo build --offline` with an empty
  `[dependencies]` table.
* It must be idempotent: running it twice is harmless.

### 2.3 `run.sh` (required)

* Invoked as
  `bash run.sh --bind <HOST:PORT> --base-url <URL>` with the working directory
  `impls/<slug>/`. It runs in its **own process group** with an **empty,
  private `TMPDIR`**.
* Arguments and their sources, in precedence order **flag > environment > default**:

  | Flag | Environment fallback | Default |
  |---|---|---|
  | `--bind <HOST:PORT>` | `ONLYBLOCKS_BIND` | `127.0.0.1:8899` |
  | `--base-url <URL>` | `OLD_FAITHFUL_BASE_URL` | `https://files.old-faithful.net` |

  Both flags may also be written `--bind=<v>` / `--base-url=<v>`.
  Implementations MAY accept additional flags. Unknown flags SHOULD be an
  error.
* It MUST stay in the **foreground** and SHOULD `exec` the server binary or
  runtime (`exec ./target/server "$@"`), so signals reach the server directly.
  If it cannot `exec`, it must forward `SIGTERM`/`SIGINT` and wait.
* `--base-url` normalization: trim surrounding whitespace, then strip all
  trailing `/` characters. The scheme MUST be `http` or `https`. Anything else
  is a start-up error (exit non-zero).
* **Readiness**: within **20 s** of launch, `getHealth` on `POST /` must
  answer `{"jsonrpc":"2.0","result":"ok","id":…}`. The harness polls it every
  50 ms, and **each probe has a 50 ms socket timeout** (connect plus
  response). Once listening, the server MUST answer `getHealth` in well under
  50 ms. Interpreted implementations (Bash+AWK, Tcl, …) must not do expensive
  per-connection start-up work.
* **Shutdown**: on `SIGINT` or `SIGTERM`, stop accepting connections, finish
  or abort in-flight requests, and exit (status `0` preferred) within **3 s**.
  After 3 s the harness sends `SIGKILL` to the whole process group.
* `run.sh` SHOULD NOT compile. It MAY call `build.sh` as a fallback when the
  build output is missing (the Rust implementation does).

### 2.4 Inbound HTTP server

* Listen on the given TCP `HOST:PORT`. IPv4 is required. `[v6]:port` MAY be
  supported.
* Speak **HTTP/1.1** (HTTP/1.0 requests SHOULD also work). Read the request
  line and headers, then exactly `Content-Length` body bytes. `Transfer-Encoding:
  chunked` request bodies SHOULD be supported.
* **`POST /`** is the only endpoint. Respond `200 OK` with
  `Content-Type: application/json` and an accurate `Content-Length` (or
  chunked encoding) for **every** JSON-RPC response, errors included. Other
  methods or paths SHOULD get `404`/`405`.
* Bodies larger than **1 MiB** (1 048 576 bytes) MUST be rejected with HTTP
  `413` (no JSON-RPC body required).
* Honour `Connection: close`. Keep-alive is optional, but if a connection is
  kept open it MUST be framed correctly. The harness opens one connection per
  request.
* Serving connections concurrently (threads or an in-process event loop) is
  RECOMMENDED but not required. A slow upstream fetch SHOULD NOT block
  `getHealth`.

---

## 3. Zero-dependency boundary

### 3.1 Allowed

* The language's **standard library** as shipped with its toolchain: sockets,
  threads, JSON (if built in), Base64 (if built in), TLS (if built in), and
  zstd (if built in, e.g. Python ≥ 3.14 `compression.zstd` or recent Node.js
  `zlib.zstdDecompressSync`). A stdlib zstd decoder MUST still enforce the
  512 MiB output limit and must accept concatenated and skippable frames.

  **Do not assume a one-shot stdlib call does that.** Node's
  `zstdDecompressSync` (observed on Node 25), for example, stops after the
  first frame (so
  concatenated frames lose data and a leading skippable frame yields empty
  output), silently ignores trailing garbage, and returns partial output for a
  truncated frame instead of failing. If your stdlib decoder behaves like
  that, walk the frame boundaries yourself (`ZSTD_MINI_SPEC.md` §7: magic,
  frame header, the 3-byte block headers up to `Last_Block`, the optional
  4-byte checksum, and skippable frames) and hand the decoder exactly one
  complete frame at a time, summing the outputs against the 512 MiB limit.
  Truncated or malformed input must be a zstd *failure* (`WIRE_FORMATS.md`
  §9.1 then falls back to the raw bytes), never a short success.
* The **compiler/interpreter and the OS**: syscalls, libc, POSIX shell
  utilities needed to launch (`bash`, `exec`).

### 3.2 Forbidden

* **Zero** third-party packages: no Cargo crates, no Go `require`s outside
  the standard library, no
  npm/pip/Maven/Gradle/NuGet/gem/CPAN/opam/hex/LuaRocks packages, no git
  submodules, no vendored or copy-pasted libraries, no generated protobuf code
  from external tools.
* Everything binary is implemented in the target language itself:

  | Component | Spec |
  |---|---|
  | HTTP/1.1 client + server | §2.4, §4 |
  | JSON parse/serialize (if not in stdlib) | RFC 8259, §5, `WIRE_FORMATS.md` §15.3 |
  | CARv1 + LEB128 varints + CIDs | `WIRE_FORMATS.md` §3 |
  | DAG-CBOR | `WIRE_FORMATS.md` §4–5 |
  | CRC-64/GO-ISO, FNV-1a 64 | `WIRE_FORMATS.md` §6 |
  | Solana `VersionedTransaction` | `WIRE_FORMATS.md` §8 |
  | Protobuf | `WIRE_FORMATS.md` §10 |
  | Bincode | `WIRE_FORMATS.md` §11 |
  | Base58, Base64 | `WIRE_FORMATS.md` §15 |
  | Zstandard decoder (unless in stdlib) | `docs/ZSTD_MINI_SPEC.md` |
  | Bounded LRU caches | §4.4 |

* **No exemptions.** The crate-based Rust oracle that generated the golden
  fixtures has been replaced by the zero-crate `impls/rust/` (`cargo tree`
  prints one line). Every implementation in `impls/`, Rust included, is fully
  bound by §3.

### 3.3 TLS / HTTPS transport exception

The offline conformance suite uses **`http://` only**, served by
`conformance/mock_old_faithful.py`. Every implementation MUST speak plain HTTP
over **native TCP sockets** in-process.

For `https://` (the real archive), languages whose standard library has no
TLS client (for example C, C++, 0-crate Rust, Fortran, Tcl, Perl, Bash+AWK,
ARM64 assembly) MAY use **TLS facilities that ship with the OS and need no
install**. Languages whose standard library does include a TLS client (Go,
Java, Python, Node.js, .NET, Zig's `std.crypto.tls`, Erlang's `ssl`, …)
SHOULD use it. The OS facilities are:

* macOS `Security.framework` / `Network.framework`;
* the system `libcurl` or `libssl`/`libcrypto` via the language's FFI;
* spawning the **OS-provided `curl` binary**, solely to perform the HTTPS Range
  GET. Apart from the runtime plumbing that §1 lists, this is the only
  permitted child process. Its body must be streamed
  over a pipe, never written to a file. The same status/length checks as §4.2
  apply.

The exception covers transport only. CAR/CBOR/protobuf/bincode/zstd decoding
MUST stay in the implementation's own code.

---

## 4. Old Faithful: the 2-range-read protocol

### 4.1 Addressing

```
SLOTS_PER_EPOCH        = 432_000
SLOT_RANGE_ENTRY_BYTES = 12
epoch    = slot / 432_000          (integer division)
slot_idx = slot % 432_000
```

**Range read 1** (slot index):

```
GET {base}/{epoch}/epoch-{epoch}-slot-ranges.raw
Range: bytes={slot_idx*12}-{slot_idx*12 + 11}
```

The 12-byte body is `offset: u64 LE` followed by `length: u32 LE`.

* `length == 0` means a **skipped slot**: error `-32007`, and the result is
  cached as `Skipped`.
* Otherwise the result is cached as `Present(offset, length)`.

**Range read 2** (the slot's CAR slice):

```
GET {base}/{epoch}/epoch-{epoch}.car
Range: bytes={offset}-{offset + length - 1}
```

* If `length > max_slice_bytes` (default **128 MiB** = `134_217_728`), fail
  **before** sending the request (`-32603`).
* `offset + length - 1` overflowing `u64` is `-32603`.

Examples:

* slot `302400001` is epoch `700`, `slot_idx 1`, giving
  `Range: bytes=12-23` on `/700/epoch-700-slot-ranges.raw`;
* slot `0` is `bytes=0-11` on `/0/epoch-0-slot-ranges.raw`;
* slot `431999` is `bytes=5183988-5183999` on `/0/...`.

### 4.2 Response handling (both reads)

Each attempt sends a single `Range` header. It SHOULD also send `Host`,
`User-Agent: onlyblocks/<slug>` and `Connection: close`.

| Upstream result | Action |
|---|---|
| `206 Partial Content` | accept, subject to the length checks below |
| `404 Not Found` | **unarchived**: `-32004`. **Never retried and never cached.** |
| `429 Too Many Requests` | retry (§4.3), honouring `Retry-After` |
| `5xx` | retry (§4.3) |
| any other status (`200`, `400`, `416`, …) | `-32603`, no retry |
| connect error, timeout, connection reset, or connection closed before the framed body (`Content-Length`/chunked) is complete | retry (§4.3) as a transport error |

Length checks on a `206`:

* If `Content-Length` exceeds the per-read cap (`12` for read 1,
  `max_slice_bytes` for read 2), fail immediately (`-32603`).
* While streaming the body (with or without `Content-Length`, including
  chunked), abort as soon as more than the cap has been received (`-32603`).
* The final (completely framed) body length MUST equal exactly `12` or
  `length` respectively. Otherwise `-32603` with no retry.

Clients MUST support `Content-Length` bodies and SHOULD support `chunked`
bodies. The mock origin always sends `Content-Length` and `Content-Range`.

### 4.3 Retry policy

Defaults: `max_retries = 4` (5 attempts total), `initial_backoff = 200 ms`,
`max_backoff = 10 s`, `jitter_ratio = 0.5`, connect timeout `10 s`,
per-attempt timeout `60 s`.

Before retry number `attempt` (0-based count of failures so far):

```
if the failure carried a parseable Retry-After:
    delay = min(retry_after, max_backoff)         # delta-seconds or HTTP-date (past date -> 0)
else:
    base  = min(initial_backoff * 2^min(attempt, 30), max_backoff)
    delay = base * uniform(1 - jitter_ratio, 1)   # i.e. uniformly in [0.5*base, base]
```

When retries are exhausted, the request fails with `-32603`.
`Retry-After: 0` means retry immediately (the harness injects exactly this).
Implementations SHOULD cap concurrent upstream requests (reference: 32
in flight) and SHOULD hold a concurrency slot only while an attempt is in
flight, not while sleeping.

### 4.4 Bounded RAM-only caches

| Cache | Key → value | Capacity (default) | Rules |
|---|---|---|---|
| slot-range cache | `slot → Present(offset,length) \| Skipped` | 100 000 entries | filled by every successful range read 1. `404`s and errors are **not** cached |
| blockhash cache | `slot → blockhash (Base58 string)` | 100 000 entries | filled for the requested slot after every successful header decode, and for each fetched parent |

Both caches MUST be bounded, and LRU eviction is RECOMMENDED. A cache hit
MUST NOT touch the network. A **warm** repeat of the same `getBlock` therefore
makes **zero** slot-range requests (the harness checks this). It still makes
one CAR request: CAR slices are not cached by default, and implementations
MAY add a bounded RAM slice cache.

### 4.5 `getBlock` pipeline and `previousBlockhash`

1. Validate params (§5.4). Invalid params produce **no network traffic**.
2. Range read 1 for `slot` (or a cache hit), then range read 2.
3. Index the CAR slice and parse the `Block` node (`WIRE_FORMATS.md` §7). No
   `Block` node, or `block.slot != slot`, is `-32603`. Compute this block's
   `blockhash` (the hash of the last `Entry`) and put it in the blockhash cache.
4. `previousBlockhash`:
   * if `slot == 0`: `"11111111111111111111111111111111"` (`Hash::default()`, 32 zero bytes);
   * else, if `blockhash_cache[parent_slot]` hits, use it;
   * else fetch `parent_slot` with both range reads (the same caches and the
     same error mapping apply, so a skipped parent yields `-32007` and an
     unarchived one `-32004`). Index it, take the hash of its last `Entry`
     (32 zero bytes if it has no entries), Base58-encode it, and cache it. The
     parent's `Block.slot` is **not** checked against `parent_slot`.

   This step runs for **every** `getBlock`, whatever `transactionDetails` and
   `rewards` say, and it runs **before** step 5. A parent error therefore wins
   over a `-32015` or a decode error in the block's own transactions or
   rewards. Golden cases pin
   it: fixture slot `43200000` has parent `43199999` in the unarchived epoch 99,
   so it answers `-32004` even with `transactionDetails:"none"`; fixture slot
   `302400009` has the skipped parent `302400008`, so it answers `-32007`.
5. Decode transactions, metadata and rewards as `transactionDetails` /
   `rewards` require, then serialize (`WIRE_FORMATS.md` §13). A versioned (`v0`
   or `v1`) transaction when `maxSupportedTransactionVersion` is absent/null or
   smaller than the transaction's version is `-32015`. Any decode failure is
   `-32603`.

---

## 5. JSON-RPC 2.0 surface

### 5.1 Envelope parsing

| Input | Response |
|---|---|
| body is not valid JSON | `-32700`, `id: null` |
| a JSON value other than an object or array | `-32600`, `id: null` |
| `[]` (empty batch) | single object `-32600`, `id: null` |
| array with more than **100** items | single object `-32600`, `id: null` |
| object with `jsonrpc`/`method` present but neither a string nor `null` | `-32600`, `id: null` |
| object whose `id` is present but is not a string, number or `null` | `-32600`, `id: null` |
| `jsonrpc` absent or not exactly `"2.0"` | `-32600`, echoing `id` |
| `method` absent | `-32600`, echoing `id` |
| unknown `method` | `-32601`, echoing `id` |

* An absent `id` is treated as `null`. Requests without `id`
  ("notifications") **still get a response** (with `"id": null`).
* The checks apply **in table order**: a wrongly typed `jsonrpc`/`method`,
  then a wrongly typed `id` (both answer with `id: null`), and only then the
  `jsonrpc` value and the presence of `method` (which echo the `id`).
* An explicit `null` for `jsonrpc` or `method` SHOULD be treated as *absent*
  (the reference does: `{"jsonrpc":null,"id":5,"method":"getHealth"}` is
  `-32600` echoing `"id": 5`). The harness does not test this.
* A valid `id` is echoed back unchanged. Numeric ids SHOULD be echoed with
  their original text (`7` stays `7`, not `7.0`), and a string id is never
  turned into a number or the reverse.
* Duplicate keys in one object: the last occurrence SHOULD win (the reference
  does this; not tested).
* **Nesting depth.** An implementation MAY answer `-32700` for a body nested
  deeper than 128 levels (the reference does). It MUST NOT crash or overflow
  its stack on a 1 MiB body of nested arrays: use an explicit depth limit or
  an iterative parser. The harness sends 524 288 `[` followed by 524 288 `]`
  and accepts `-32700`, or `-32600` (the body is a one-item batch whose item
  is not an object).
* **Batches** (1–100 items) are processed **sequentially in order**. The
  response is an array with one response per item, in the same order. A
  non-object item yields `-32600` with `id: null` in its slot.
* Response objects:
  `{"jsonrpc":"2.0","result":<value>,"id":<id>}` or
  `{"jsonrpc":"2.0","error":{"code":<int>,"message":<non-empty string>},"id":<id>}`.
  Never both `result` and `error`. The `error.data` member is optional.
* Method names are case-sensitive.

### 5.2 `getHealth`

`params` absent, `null` or `[]` gives `"result": "ok"`. Anything else is
`-32602`. It never touches the network.

### 5.3 Dropped methods

`getTransaction`, and every method other than `getBlock`/`getHealth`, MUST
return `-32601` (`"Method not found: <name>"`) **immediately, without parsing
params and with zero outbound HTTP requests**. The harness verifies the
upstream request counter stays at `0`.

### 5.4 `getBlock` parameters

`params` MUST be an array of length 1 or 2. Anything else (absent, `null`, an
object, `[]`, 3+ items) is `-32602`.

* `params[0]` (slot): a JSON **integer literal** in `0..2^64-1`. Strings,
  negatives, fractions, exponents (`1e3`, `1.0`), booleans and out-of-range
  values are `-32602`. Validate the **source text** of the number
  (`0|[1-9][0-9]*`), not a parsed double: `1.0` and `1e3` are rejected even
  though they are integral, and `18446744073709551615` (`2^64-1`) is a valid
  slot. It lies in epoch `42700796466920`, which the mock origin answers with
  `404`, so the result is `-32004`, while `18446744073709551616` is `-32602`. Languages whose
  JSON library yields doubles (JavaScript, Lua, AWK, …) or signed 64-bit
  integers (Java, Tcl, …) need care here.
* `params[1]`, optional:
  * `null`: all defaults;
  * a string: the encoding (shorthand `[slot, "base64"]`);
  * an object with the keys below; **unknown keys are ignored**;
  * anything else: `-32602`.

| Key | Accepted values (`null` = default) | Default | Invalid → |
|---|---|---|---|
| `encoding` | `"json"`, `"jsonParsed"`, `"base64"`, `"base58"` | `"json"` | `-32602` (incl. `"binary"`, `"base64+zstd"`, non-strings) |
| `transactionDetails` | `"full"`, `"accounts"`, `"signatures"`, `"none"` | `"full"` | `-32602` |
| `rewards` | `true` / `false` | `true` | `-32602` (non-boolean) |
| `maxSupportedTransactionVersion` | integer `0..255` | absent (*none*) | `-32602` (negative, > 255, non-integer) |
| `commitment` | `"finalized"`, `"confirmed"` (accepted and ignored: archive data is final) | — | `-32602` for `"processed"`, any other string, non-strings |

Cross-field rules:

* `transactionDetails: "accounts"` is only valid with `encoding: "json"`. With
  any other encoding it is `-32602`.
* `encoding: "base58"` is not supported when `maxSupportedTransactionVersion >= 1`
  (because `v1` transactions scale up to 4 096 bytes while Base58 RPC binary
  encoding is capped at legacy packet sizes). Combining `"base58"` with
  `maxSupportedTransactionVersion` in `1..255` MUST fail upfront with `-32602`
  and zero network traffic.

Semantics (full detail in `WIRE_FORMATS.md` §13):

* `rewards: false`: the block-level `rewards` and `numRewardPartitions`
  keys are **omitted**, and rewards are not decoded at all. Per-transaction
  `meta.rewards` becomes `null` for `full`, and is omitted for `accounts`.
* `transactionDetails: "signatures"`: `"signatures": [first signature of each
  tx]`, and `transactions` is omitted. Metadata is not decoded, and
  `maxSupportedTransactionVersion` is not checked (so `v0` and `v1` first
  signatures are returned even when `maxSupportedTransactionVersion` is absent
  or `0`; note that for `v1` transactions, signatures sit at the **tail** of the
  wire payload).
* `transactionDetails: "none"`: both `transactions` and `signatures` are
  omitted. Transactions are not decoded.
* Version gate in `full`/`accounts` mode: if a transaction has numeric version
  `v` (`0` or `1`) and `maxSupportedTransactionVersion` is *none* or `< v`, the
  **whole request** fails with `-32015`. When `maxSupportedTransactionVersion`
  is set and `>= v` for every transaction, each `Complete` transaction carries
  `"version": "legacy"`, `"version": 0`, or `"version": 1`.

### 5.5 Result shape (summary)

```json
{
  "previousBlockhash": "<b58>", "blockhash": "<b58>", "parentSlot": 302400010,
  "transactions": [ { "transaction": …, "meta": …, "version": 0 } ],
  "rewards": [ {"pubkey": "…", "lamports": 2500, "postBalance": 52500,
                "rewardType": "Fee", "commission": null} ],
  "numRewardPartitions": 4,
  "blockTime": 1902400011,
  "blockHeight": 302399911
}
```

`blockTime` and `blockHeight` are always present (possibly `null`).

---

## 6. Error codes

| Code | Name | When |
|---|---|---|
| `-32700` | Parse error | body is not JSON |
| `-32600` | Invalid Request | envelope violations (§5.1) |
| `-32601` | Method not found | anything but `getBlock`/`getHealth`, **including `getTransaction`** |
| `-32602` | Invalid params | §5.2, §5.4 |
| `-32603` | Internal error | upstream non-206/non-404 status, retries exhausted, transport failure, oversize slice, length mismatch, any CAR/CBOR/DataFrame/transaction/protobuf/bincode/zstd decode failure, slot mismatch, internal panics |
| `-32004` | Block not available | HTTP `404` on either range read, for the slot or its parent (epoch not archived) |
| `-32007` | Slot skipped | `length == 0` in `slot-ranges.raw`, for the slot or its parent |
| `-32015` | Unsupported transaction version | versioned (`v0` or `v1`) transaction while `maxSupportedTransactionVersion` is absent/null or `< version` (`full`/`accounts` only) |

Messages are free text but MUST be non-empty. Recommended (the reference's
wording):

* `-32004`: `Block not available for slot {slot}: epoch {epoch} is not archived in Old Faithful (historical-only server)`
* `-32007`: `Slot {slot} was skipped, or missing in long-term storage`
* `-32015`: `Transaction version ({v}) is not supported by the requesting client. Please try the request again with the following configuration parameter: "maxSupportedTransactionVersion": {v}`
* `-32601`: `Method not found: {method}`

An implementation MUST turn every internal failure (bad bytes, index out of
range, allocation limits) into `-32603` and keep serving. Crashing the process
on hostile archive bytes is a conformance failure.

---

## 7. Decoding overview

The full byte-level rules are in [`docs/WIRE_FORMATS.md`](docs/WIRE_FORMATS.md).
In short:

```
CAR slice ──► CARv1 sections (uvarint len | CID | DAG-CBOR)
   Block [2, slot, _, [entry links], [parent, blocktime, height], rewards link]
     └─► Entry [1, _, hash32, [tx links]]               (last entry hash = blockhash)
           └─► Transaction [0, DataFrame(tx bytes), DataFrame(metadata), …]
                  tx bytes  ──► Solana VersionedTransaction (compact-u16 wire format)
                  metadata  ──► zstd? ──► protobuf (slot ≥ 67_824_000) | bincode (slot < 67_824_000)
     └─► Rewards [5, slot, DataFrame] ──► zstd? ──► protobuf Rewards | bincode StoredExtendedRewards
DataFrame [6, hash, idx, total, bytes, [next links]] ──► DFS reassembly, CRC-64/GO-ISO or FNV-1a check
```

The epoch-157 boundary (slot `67_824_000`) switches the *preferred* metadata
and rewards codec from bincode to protobuf. Both directions fall back to the
other codec.

---

## 8. Conformance

`conformance/` contains a stdlib-only Python 3.11+ harness:

```sh
python3 conformance/runner.py                      # every impls/*/run.sh
python3 conformance/runner.py --impl go            # one implementation
python3 conformance/runner.py --impl c --strict-parsed --bench
```

It starts `conformance/mock_old_faithful.py`, which is a loopback HTTP/1.1
Range origin serving `conformance/fixtures/` (epochs 100, 700 and 1095). It then
launches `run.sh` per §2.3 and checks:

1. **Golden cases** (`conformance/fixtures/manifest.json`): `getHealth`
   variants, `getBlock` in every encoding and `transactionDetails` mode across
   `legacy`, `v0` and `v1` (SIMD-0385) transactions (including `> 1232`-byte
   `v1` payloads, inline `transactionConfig` bitmasks, separated instruction
   headers/payloads, trailing signature arrays and verbatim mainnet epoch-1095
   CAR slices), rewards on/off, both commitments, multi-frame DataFrames,
   pre-157 bincode, every envelope rule of §5.1 (oversize batches, non-object
   batch items, missing and wrongly typed `id`/`method`/`jsonrpc`), every
   parameter rule of §5.4 (non-literal, out-of-range and `2^64-1` slots, wrongly
   typed options, `base58` with `maxSupportedTransactionVersion >= 1`, null and
   unknown config keys), skipped/unarchived slots, skipped and unarchived
   **parents** (§4.5), the `-32015` gate for both `v0` and `v1`, corrupt `v1`
   wire slices, and mixed batches. Every response must be HTTP `200`. Results
   are compared field by field:
   * error cases are matched on `code` plus a non-empty `message`;
   * `uiAmount` allows a `1e-9` absolute tolerance;
   * `null` and omission are interchangeable **only** for optional metadata
     keys (`innerInstructions`, `logMessages`, `preTokenBalances`,
     `postTokenBalances`, `loadedAddresses`, `returnData`,
     `computeUnitsConsumed`, `costUnits`, `rewards`), for instruction
     `stackHeight`, and for token-balance `owner`/`programId`. Everything else
     is exact;
   * batch responses are matched by `id`.
2. **`getTransaction` is gone**: `-32601` with zero upstream requests.
3. **Cache**: a fresh process makes ≥ 1 slot-range read on a cold
   `getBlock` and **0** on the immediate warm repeat.
4. **Retry**: one injected `429` (`Retry-After: 0`) is absorbed transparently.
5. **Zero disk**: no file or symlink appears in the private `TMPDIR`, at
   start-up, between requests or after shutdown.
6. `--bench` also records cold/warm latency, p50/p95, peak RSS, build time,
   lines of code and artefact size.
7. **Hostile input**: a body of 1 MiB + 1 byte must not get an HTTP `200`
   (`413`, or the connection is dropped), a 1 MiB body of nested arrays must
   get `-32700` or `-32600`, and the server must still answer `getHealth`
   afterwards (§2.4, §5.1, §6).
8. `--live` probes the real archive: slot `302400001` (epoch 700, `v0`; `json`,
   `base64`, `base58` and `signatures`), epoch-1095 `v1` slot (SIMD-0385 `v1` +
   `v0` + `legacy`; `-32015` gate at `maxSupportedTransactionVersion: 0`, then
   `json`, `base64` and `signatures` at `maxSupportedTransactionVersion: 1`),
   skipped slot `302400004`, legacy pre-157 slot `43200000` and the removed
   method. Mainnet history is
   immutable, so the probe compares `blockhash`, `previousBlockhash`,
   `parentSlot`, `blockTime`, `blockHeight`, the transaction count, the fee
   total, the number of `v0`, `v1` and failed transactions, the first and last
   signatures and the block rewards against values pinned in `runner.py`, and
   checks that the binary and `json` encodings describe the same transactions.
   A cold live `getBlock` is four sequential
   HTTPS Range reads, so each live request is given 120 s.

An implementation is **conformant** when `runner.py --impl <slug>` exits `0`.

---

## 9. Implementation guidance (non-normative)

* Decode lazily. `"none"` never touches transactions, `"signatures"` never
  touches metadata, and `rewards:false` never touches the Rewards node. The
  reference does exactly this, so corrupt data in an untouched part MUST NOT
  cause an error.
* Epoch-boundary blocks are huge. Slot `302400000` is a 56 383 108-byte CAR
  slice whose rewards payload spans 4 DataFrames (56 369 821 bytes of zstd)
  and decompresses to 75 677 186 bytes of protobuf. Preallocated or growable
  buffers help. The 512 MiB zstd bomb limit
  (`ZSTD_MINI_SPEC.md` §1) and the 128 MiB slice limit must hold.
* Key the CAR index by raw CID bytes. You never need to compute SHA-256.
* Use 64-bit unsigned arithmetic for slots, offsets, balances and CRC/FNV.
  Languages with only signed 64-bit ints or doubles (Java, Erlang/BEAM bignums
  aside, Tcl, AWK, Fortran) must take care with `u64` values ≥ `2^63`, both in
  parsing and in JSON output.
* JSON key order does not matter, and whitespace does not matter.

---

## 10. Deviations and corrections (read this)

### 10.1 Intentional OnlyBlocks deviations from the Rust reference

1. **`getTransaction` is dropped.** The original Rust oracle implemented a
   slot-hinted `getTransaction`. OnlyBlocks returns `-32601` for it with no
   network traffic (§5.3). `impls/rust` and `impls/javascript-node` both do.
2. **`jsonParsed` is "partially decoded only".** The reference (via
   `solana-transaction-status`) parses instructions of well-known programs
   (System, Vote, Stake, SPL Token/Token-2022, ATA, Memo, BPF loaders, Address
   Lookup Table). OnlyBlocks implementations MUST emit every instruction, top
   level and inner, as `{"programId","accounts","data","stackHeight"}`
   (`WIRE_FORMATS.md` §13.5). The harness tolerates the difference for
   top-level instructions only, and golden fixtures use custom programs.
3. The bind environment variable is `ONLYBLOCKS_BIND`. The pre-rebrand name is
   not accepted.

### 10.2 Corrections to the original task brief (verified against the original oracle and the golden fixtures)

| The brief said | Actual reference behaviour (normative here) |
|---|---|
| top-level instructions have `"stackHeight": null` | **`"stackHeight": 1`** for every top-level instruction in `json` and `jsonParsed`. Inner instructions use the stored value, which may be `null` |
| block key `numPartitions` | the key is **`numRewardPartitions`** (omitted when there is no partition count or `rewards:false`) |
| `TransactionError` variants `0..36` | **`0..38`** (39 variants). `InstructionError` has **`0..53`** (54 variants, `25 = Custom(u32)`). See `WIRE_FORMATS.md` §11.2–11.3 |
| CRC-64-GO-ISO with init `0`, xorout `0` | **init `0xFFFF_FFFF_FFFF_FFFF`, xorout `0xFFFF_FFFF_FFFF_FFFF`** (reflected poly `0xD800000000000000`). Go's API passes `0` only because it inverts internally. Check value `0xB90956C775A41001` |
| "64-bit FNV-1" | the reference uses **FNV-1a** (`h = (h ^ b) * prime`). Either CRC or FNV-1a may match a DataFrame hash |
| `maxSupportedTransactionVersion` is `0` | any integer **`0..255`** is accepted (`0` admits `legacy` + `v0`; `1..255` admits `legacy` + `v0` + `v1`, and rejects `encoding: "base58"` with `-32602`) |
| `rewards:false` omits `rewards` | at **block** level, yes (together with `numRewardPartitions`). Per transaction, `meta.rewards` is **`null`** for `full` encodings and omitted for `accounts` |

### 10.3 Reference quirks OnlyBlocks keeps (for byte-for-byte parity)

* `blockTime` stored as `0` is reported as `null`.
* `previousBlockhash` for slot `0` is 32 × `1`. A block with no entries has
  `blockhash` 32 × `1`.
* A missing Rewards CID (absent from the slice) means empty rewards, not an error.
* Legacy transactions with an empty metadata frame serialize as `"meta": null`
  with no `version` key. Versioned (`v0` or `v1`) transactions with an empty
  metadata frame get default metadata.
* `loadedAddresses` is always present in `json`/`base64`/`base58` metadata,
  and absent in `jsonParsed` and `accounts`.
