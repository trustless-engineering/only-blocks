# OnlyBlocks conformance

Run with Python 3.11 or later on macOS or Linux. The harness has no third-party
Python dependencies.

```sh
python3 conformance/runner.py
python3 conformance/runner.py --impl rust --impl go --strict-parsed
python3 conformance/runner.py --impl rust --bench --json-out /tmp/onlyblocks-bench.json
python3 conformance/runner.py --self-test
```

Without `--impl`, the runner discovers `impls/*/run.sh` in sorted order.
`--fixtures` overrides the default `conformance/fixtures/manifest.json`. The
version 1 manifest names archived epochs, their CAR files relative to the
manifest, the slot-to-byte ranges, and raw JSON-RPC cases. Include a successful
single `getBlock` case for an archived slot with a nonempty CAR range so the
runner can select a golden response for the cache and retry checks.

The runner calls `build.sh` when present, with a 240-second timeout, and starts
`run.sh` from the implementation directory. The launcher receives `--bind`
and `--base-url` plus `ONLYBLOCKS_BIND` and `OLD_FAITHFUL_BASE_URL`. It should
stay in the foreground and use `exec` or wait for its server to terminate on
SIGTERM. Each launch gets an empty `TMPDIR` and a fresh loopback port.
The origin binds its ephemeral
port directly. The RPC launcher's port is reserved by the OS and released just
before launch.

The runner sends each raw case as written and requires HTTP 200. Batch
responses are matched by ID and expectation, with each response used once.
`getBlock` result diffs identify the first differing JSON path. The comparator
allows a `1e-9` absolute tolerance for numeric `uiAmount` and treats null
and omission as equivalent on the supported optional transaction metadata,
token-balance and instruction fields. It compares other fields exactly,
including `accountKeys`. On top-level `jsonParsed` message instructions, the
default comparator accepts an Agave-recognized program's parsed or partially
decoded representation when the program ID and any stack height reported by
both forms agree. Use `--strict-parsed` to require the golden instruction
representation. Inner instructions in metadata retain the golden shape.
[Solana JSON structures](https://solana.com/developers/docs/rpc/json-structures)
[Agave instruction parsers](https://github.com/anza-xyz/agave/blob/master/transaction-status/src/parse_instruction.rs)

The runner checks that `getTransaction` returns `-32601` with zero mock
requests. Separate fresh processes verify a cold slot-range read followed by
a warm hit with zero range-table reads, and recovery from an injected HTTP
429. CAR reads on warm requests are allowed. The cache check covers immediate
reuse. The disk check samples files and symlinks retained under `TMPDIR` at
startup, between requests and after shutdown. The process exits 0 when every
selected implementation passes and 1 when any check fails.

`--live` additionally runs sequential probes against
`https://files.old-faithful.net` with a one-second pause before each block
request. It checks the modern v0 slot 302400001, skipped slot 302400004, legacy
slot 43200000, and the removed RPC method. Omitting `--live` keeps the harness
on loopback.

## Benchmark output

`--bench` adds cold RPC latency, p50 and p95 over 20 measured warm RPCs, and
sampled peak process-group RSS in KiB using `ps`. Latency includes loopback
HTTP and JSON decoding. Build time is reported in seconds in the JSON output.
The source line count excludes blank and comment-only lines using common
language comment syntax and skips known generated directories and launchers.
Artifact size uses the largest detected binary or archive in the implementation
root or a common build output directory. When none is detected, it uses the
total bytes of the measured sources and reports `artifact_path: null`.

## Standalone mock origin

```sh
python3 conformance/mock_old_faithful.py --fixtures conformance/fixtures/manifest.json
```

The process prints its loopback base URL. Archive requests use a single
inclusive `Range: bytes=start-end` header. Slot-table records are 12 bytes
each, and unlisted slots within an archived epoch return zero-filled records.
Unarchived epochs return 404. Missing or malformed ranges return 400 for an
archived epoch. Out-of-bounds ranges return 416.

| Method and path | Behavior |
| --- | --- |
| `GET /__stats` | Return `slot_range_requests`, `car_requests`, `total_requests`, `injected_429`, and `pending_429`. |
| `POST /__reset` | Clear counters and queued faults. |
| `POST /__inject_429` | Queue faults for subsequent valid archive requests. The JSON body supports `count` and `retry_after`, defaulting to 1 and 0. |

Control requests are excluded from counters. Injected responses count as
archive requests and include the requested `Retry-After` header. Python
callers can use `MockOldFaithful` as a context manager and call `stats()`,
`reset()`, and `inject_429()` directly.
