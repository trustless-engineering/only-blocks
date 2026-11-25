# OnlyBlocks defensive security audit

**Observed result:** 24/24 implementations passed every probe.

This is a local, loopback-only adversarial audit. It proves only the implementations built and executed on this machine; it is not deployment or production-origin validation.

## Audit assumptions

- Build-time writes are excluded. Start-up, request-time, and shutdown mutations under the private `TMPDIR` and each `impls/<slug>/` tree are failures.
- Directory metadata and file size/mtime/content snapshots detect retained writes and ordinary create-then-delete behavior. Writes elsewhere on the host are outside this task's stated scope.
- An HTTP 413 or an immediate dropped connection safely rejects the 1.5 MiB + 1 byte POST, matching the existing hostile-input conformance check. The server must answer `getHealth` afterward.
- The zstd bomb is a valid roughly 16 KiB RLE frame declaring and encoding 512 MiB + 1 byte of output; the harness never materializes that output.

## Pass/fail matrix

| Implementation | Overall | Build / launch | CAR / CBOR / DataFrame | Memory caps / zstd | JSON-RPC / HTTP | Zero disk | Liveness |
|---|---|---|---|---|---|---|---|
| arm64-asm | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| bash-awk | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| bun | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| c | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| cpp | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| csharp | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| elixir | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| erlang | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| fortran | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| go | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| haskell | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| java | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| javascript-node | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| kotlin | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| ocaml | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| perl | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| php | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| python | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| ruby | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| rust | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| swift | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| tcl | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| typescript-deno | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| zig | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

## Exact failure reproductions

No builder rework was required by this run.

## Probe inventory

- Headerless CAR sections: valid control, cyclic DataFrame links, bad CRC64/FNV checksum, truncated uvarint, section length above 32 MiB, and truncated CBOR.
- Resource caps: a 200,000,000-byte advertised slice rejected before `.car` fetch, an oversized zstd content size, a valid high-ratio RLE frame, and invalid zstd bytes.
- RPC/HTTP: 1.5 MiB + 1 byte POST, 105-item batch, 1 MiB deeply nested JSON, malformed JSON, negative/fractional/u64-overflow slots, removed `getTransaction`, and `GET /`.
- Every archive/RPC failure is followed immediately by `getHealth`; final liveness and zero-disk checks run before shutdown, with disk snapshots compared again after shutdown.
