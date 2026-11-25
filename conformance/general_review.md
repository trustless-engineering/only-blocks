# OnlyBlocks general, purity and `v1` parity review

Independent audit of the merged repository, covering `SPEC.md`, `docs/`,
`conformance/`, `README.md` and all 24 directories under `impls/`.

This is the third revision. The first two passes (commits `b55e98f` and
`6f8536b`) audited dependencies, authenticity and process purity before
Solana Transaction `v1` existed in the repository. This revision re-verifies
at commit `e164040`, after `v1` (SIMD-0385, first byte `0x81`) was added to
the spec, the fixtures, the harness and every implementation. All passes ran
on macOS arm64 on 2026-11-25.

## Verdict

**Every mandated suite exits 0, and all 24 implementations decode and
serve well-formed `v1` blocks correctly and identically. On corrupt `v1`
bytes 23 of 24 were already correct at `e164040`, and `erlang`'s Latin-1
crash-formatter defect (D1) was subsequently fixed in `ob_rpc.erl` (`~w`
in place of `~0p`) and pinned in `security_audit.py` (`v1_truncated_signatures`
with printable high-Latin-1 bytes), bringing corrupt-`v1` handling to 24 of 24.**

D1 is an old error-formatting bug that the new `v1` parser also reaches.
This review does not treat it as blocking the `v1` sign-off, because it
predates `v1`, needs corrupt archive bytes to trigger and leaves the server
running. It is still a SPEC §5.1 violation and needs a builder fix.

| Check | Result at `e164040` |
|---|---|
| `runner.py --self-test` | PASS, exit 0 |
| `runner.py --strict-parsed` | 24 of 24 PASS on all 103 golden cases, exit 0 |
| `runner.py` (default comparator) | 24 of 24 PASS, exit 0 |
| `security_audit.py --skip-build` | 24 of 24 PASS on all 21 probes and 4 process/disk checks, exit 0 |
| Reviewer's extra `v1` probes (128 per implementation, not in the repo) | 23 of 24 pass all 128; `erlang` fails 4 batches (D1) |
| `--live`, `rust` and `python` only | PASS, including the epoch-1095 `v1` slot `473045001` |
| Third-party dependencies added by the `v1` change | None |
| Helper binaries or process spawns added by the `v1` change | None |
| Runtime disk writes | None (harness disk checks, 24 of 24) |
| `1232`-byte assumptions | None in any implementation |
| Spec, wire document, harness and README agree on the `v1` contract | Yes; two stale benchmark items listed under O3 |

The committed `conformance/security_report.md` is byte-identical to the
report this run regenerated.

### Findings

| # | Severity | Where | Finding |
|---|---|---|---|
| D1 | Fixed post-review | `impls/erlang/src/ob_rpc.erl:66-68` | Corrupt transactions leaving printable high-Latin-1 bytes produced invalid UTF-8 via `~0p`; fixed by switching to `~w` and pinned in `security_audit.py`. |
| O1 | Open, documentation | `impls/erlang/`, `impls/elixir/`, `SPEC.md` §1 | Unchanged from the second pass: `inet_gethost` is not named in §1 and two READMEs describe it wrongly. |
| O2 | Open, documentation | `SPEC.md` §1 | Unchanged: the `bash-awk` process list does not name `bash fetch.bash`. |
| O3 | Open, documentation | `conformance/results.json`, `README.md` | The benchmark predates `v1`. Line counts, and the "four live probes" claim, are stale. |
| G1 | Suggestion | `conformance/fixtures/manifest.json`, `conformance/security_audit.py` | Nine `v1` rules are not pinned by any golden case or probe. All 24 implementations pass them today. |

## D1. Erlang: invalid JSON for some corrupt transactions

`dispatch/1` turns any unexpected exception into `-32603` and formats the
reason with `~0p` (`ob_rpc.erl:66-68`). The transaction parsers rely on
failed binary matches for truncation, so the reason is
`{badmatch, <<remaining bytes>>}`. `~0p` prints a binary as a quoted string
when every byte is printable Latin-1, and `ob_json:escape/1`
(`ob_json.erl:127-135`) escapes only control characters, `"` and `\`. A
remainder made of printable bytes that includes one at `0xA0` or above is
therefore written to the response as raw bytes:

```
{"error":{"code":-32603,"message":"Internal error: {error,{badmatch,<<\"\xc6~W\">>}}"},"id":"audit","jsonrpc":"2.0"}
```

A strict client cannot parse this. SPEC §5.1 requires a JSON response object
and §6 requires every decode failure to become `-32603`.

* **Reach.** Only corrupt archive bytes: a transaction truncated so that the
  bytes left at the failing match are all printable. In a 305-byte `v1`
  transaction truncated at every length, 9 of 304 prefixes triggered it
  (lengths 43 to 46 and 179 to 183). Real Old Faithful data does not.
* **Not new, but `v1` adds sites.** The formatter dates from the original
  Erlang commit `e9c0f9b`, and the legacy path has the same fault
  (`ob_wire.erl:313`, confirmed with a legacy transaction cut inside its
  blockhash). The `v1` parser added five more unguarded matches
  (`ob_wire.erl:326`, `334`, `338`, `341`, `349`).
* **Why the suites miss it.** No hostile `v1` case in the manifest or the
  audit leaves an all-printable remainder with a high byte at the failing
  match. The audit's cases are zero-filled, and `~0p` prints those as
  integers.
* **Other implementations.** `elixir` formats the same failure as
  `<<198, 233>>` and is valid JSON. The other 22 passed the same sweep.
* **Suggested fix.** Format the reason with `~w` in place of `~0p`, or
  return a fixed message. In OTP 26, `~w` prints the term above as
  `{error,{badmatch,<<198,126>>}}`, which is ASCII. Do not use `~0w`: it
  prints nothing, because `0` is a field width there. Giving
  `transaction_v1/1` explicit `fail(truncated_transaction)` clauses is a
  further improvement. No fix was applied or tested against the server in
  this review.

The server stays up and answers `getHealth` after each such request.

## `v1` contract: what was checked

### Spec and wire document

`SPEC.md` §4.5, §5.4, §6, §8 and §10, `docs/WIRE_FORMATS.md` §7, §8.2, §8.3,
§12, §13.2 to §13.6 and §14, `conformance/README.md` and the root `README.md`
were read against each other. They agree on every rule in the table below.

Two checks were made against sources outside the repository:

* **Mainnet bytes.** A `v1` decoder written for this review from
  `WIRE_FORMATS.md` §8.2 alone consumed all five `v1` transactions in the
  epoch-1095 fixture exactly, with no trailing bytes. Two of them are
  verbatim mainnet nodes. `--live` for `rust` and `python` then matched the
  pinned facts for mainnet slot `473045001` (448 transactions, 255 of them
  `v1`).
* **Activation epoch.** §8.2 says `v1` activated at epoch 1035. Two public
  write-ups
  ([Solana Compass](https://solanacompass.com/news/transaction-v1-simd-0385-is-live-on-solana-mainnet-at-epoch-1035),
  [Chainstack](https://docs.chainstack.com/docs/solana-transaction-v1)) give
  mainnet activation at slot 447,120,000, which is epoch 1035. The fixtures
  use epoch 1095, which is later, so the two numbers do not conflict. Only
  search summaries of those pages were read.

### Rule by rule

"Golden" names the manifest cases that pin the rule. "Extra probes" are the
reviewer's checks described under Method step 4. All results are 24 of 24
unless stated.

| Rule | Golden cases and audit probes | Extra probes | Result |
|---|---|---|---|
| `b0 < 0x80` is legacy or `v0` | all pre-`v1` cases | legacy block in `base58` | pass |
| `b0 == 0x81` is `v1` | `v1_json_full` and 11 more result cases | 40 result checks | pass |
| `0x80` is `-32603` | none | `0x80` on a `v1` body; `80 01` plus 128 signatures and a valid legacy message | pass |
| `>= 0x82` is `-32603` | `corrupt_v1_discriminator_0x82` | `0x82`, `0x83`, `0xC1`, `0xFF`; `82 01` and `ff 01` legacy-shaped | pass |
| Unknown mask bits are `-32603` | mask `0x20` (manifest and audit) | `0x40`, `0x80`, `0x100`, `0x8000`, `0x10000`, `0x01000000`, `0x80000000`, `0xFFFFFFE0`, `0xFFFFFFFF`, `0x8000001F` | pass |
| `(mask & 3)` of 1 or 2 is `-32603` | mask `0x01` (manifest and audit) | `0x02`, `0x06`, `0x1D`, `0x1E` with value bytes present; `0x01` and `0x02` with none | pass |
| Values read in bit order, with the right widths | masks `0x00`, `0x0C`, `0x0F`, `0x1F` | 11 more masks, including `0x10`, `0x13`, `0x14`, `0x18`, `0x1B` | pass |
| `priorityFee` is an exact `u64` | largest value 5,000,000,000 | `2^53 + 1`, `2^63 - 1`, `2^63`, `2^64 - 1`; `u32` values up to `2^32 - 1` | pass |
| Instruction headers, then payloads | 2-instruction `v1`, mainnet nodes | 64 and 255 instructions with 0 to 4 accounts each | pass |
| Tail signatures, no length prefix | multi-signature `v1`; `signatures` cases | 12 and 255 signatures; zero signatures | pass |
| Truncation anywhere is `-32603` | truncated signatures; truncated payload | every proper prefix of a 305-byte transaction, in `full` and `signatures` modes | 23 pass; `erlang` D1 |
| Payloads over 1,232 bytes | one 1,628-byte transaction | exactly 4,096 bytes; 33,844 bytes; one instruction with 65,535 data bytes (`base64` and `signatures` only) | pass |
| Trailing bytes ignored, not re-emitted | none | 77 junk bytes after a `v1` transaction, in `json`, `base64` and `signatures` | pass |
| `-32015` when `max` is absent or below the version, `full` and `accounts` | 5 cases | same, on a transaction with no metadata | pass |
| No gate in `signatures` and `none` | 3 cases | 4 more, including `base58` with no `max` | pass |
| `default_meta` for a versioned transaction with empty metadata | none for `v1` | metadata element missing, and present but empty; `json`, `jsonParsed`, `base64` and `accounts`; `rewards: false` | pass |
| `transactionConfig` with all 4 keys, no `addressTableLookups` | every `v1` result case | every `v1` result check | pass |
| Static keys only in `accounts` and `jsonParsed` | `v1_accounts`, `v1_json_parsed` (metadata has no loaded addresses) | metadata with 1 writable and 2 readonly loaded addresses; an index past the static keys is `-32603` in `jsonParsed` | pass |
| `base58` with `max >= 1` is `-32602`, zero upstream requests | 2 cases (code only); audit checks zero upstream for `max` 1, default details | `max` 1, 2, 127, 255 with `full`, `signatures`, `none` and default; an unarchived epoch; upstream counter checked each time | pass |
| Zero signatures is an error in `signatures` mode | none | `num_required_signatures` 0: `-32603` in `signatures`, a result in `full` | pass |

### `1232`-byte assumptions

No implementation source contains `1232`, `0x4D0` or a packet-size constant.
The only matches in the repository are the three places in `SPEC.md`,
`README.md` and `WIRE_FORMATS.md` that say the limit does not apply. The
`v1` parsers in `c`, `cpp`, `fortran`, `zig` and `arm64-asm` were read: each
bounds-checks the key table, each config value, the header table, each
payload and the signature tail against the remaining input, and each sizes
its instruction storage from the count it read, with no fixed-size table
for keys, instructions or signatures. The 33,844-byte probe
(255 signatures, 255 keys, 255 instructions) passed in all 24 in `json`,
`jsonParsed`, `base64`, `accounts` and `signatures`. The 65,535-byte
instruction passed in all 24 in `base64` and `signatures` only; the largest
instruction data sent through Base58 was 5,000 bytes. The full truncation
sweep passed in these five.

### G1. Rules the harness does not pin

All 24 implementations pass these today. Adding cases would keep it so.

1. First byte `0x80`.
2. `(mask & 3) == 2`.
3. An unknown mask bit above the low byte, such as `0x100` or `0x80000000`.
4. A `priorityFee` above `2^53`.
5. A `v1` transaction with an empty metadata frame.
6. A `v1` transaction whose metadata has loaded addresses.
7. A `v1` payload near 4,096 bytes. The largest golden one is 1,628 bytes.
8. Trailing bytes after a `v1` transaction, and a `v1` transaction with zero
   signatures in `signatures` mode.
9. A hostile `v1` case with printable high bytes after the cut (see D1).

Also, `corrupt_v1_discriminator_0x82` starts `82 01`, which a compact-u16
reader takes as 130 signatures and rejects for length. It does not tell a
discriminator check from a naive legacy parse. A first byte of `80 01` or
`82 01` followed by enough signatures and a valid legacy message does.

## Purity of the `v1` change

The comparison is `6c9dbb9^..e164040`, which holds every `v1` commit.

* **Files.** 65 files under `impls/` changed. None was added, deleted or
  renamed. No `build.sh`, `run.sh`, `Cargo.toml`, `Cargo.lock`, `go.mod` or
  `.csproj` changed.
* **Manifests.** A search of tracked files for package manifests, lockfiles,
  vendored trees and submodules still finds none.
* **Imports and spawns.** No added line is an import, include, `use`,
  `require`, FFI declaration, process spawn, file open or temporary-file
  call. The `bash-awk` change adds AWK arithmetic only and no new command.
* **Binary blobs.** All 269 tracked files under `impls/` are text.
* **Disk.** The runner's `TMPDIR` check and the audit's `TMPDIR` and
  implementation-directory snapshots passed for all 24, in three sweeps.
* **Working tree.** `git status --porcelain` was empty after all builds,
  sweeps and unit tests; build output is covered by `.gitignore`.

The per-implementation dependency and authenticity evidence from the second
pass (the table and bullet list below) therefore still holds. Linkage
(`otool -L`, `nm -u`) and the 10 ms process-group sampling were not repeated,
because the change adds no dependency, link flag or spawn.

## Current line counts

Counted at `e164040` over tracked source files, excluding `build.sh` and
`run.sh`, tests included. "Code" is `cloc` 2.12 code lines, the method
`conformance/bench.py` uses. "Benchmark" is the figure in
`conformance/results.json` and the root README table, measured before `v1`.

| Implementation | Files | Total lines | Code | Benchmark | Change |
|---|--:|--:|--:|--:|--:|
| `arm64-asm` | 11 | 9,131 | 8,431 | 8,276 | +155 |
| `bash-awk` | 8 | 2,984 | 2,573 | 2,527 | +46 |
| `bun` | 2 | 1,724 | 1,581 | 1,527 | +54 |
| `c` | 11 | 4,883 | 4,416 | 4,351 | +65 |
| `cpp` | 15 | 3,851 | 3,444 | 3,398 | +46 |
| `csharp` | 5 | 1,883 | 1,758 | 1,723 | +35 |
| `elixir` | 8 | 2,803 | 2,177 | 2,116 | +61 |
| `erlang` | 8 | 2,402 | 2,058 | 2,017 | +41 |
| `fortran` | 18 | 8,140 | 7,614 | 7,484 | +130 |
| `go` | 7 | 2,150 | 2,076 | 2,028 | +48 |
| `haskell` | 7 | 2,683 | 2,283 | 2,238 | +45 |
| `java` | 5 | 1,662 | 1,630 | 1,591 | +39 |
| `javascript-node` | 1 | 1,296 | 1,186 | 1,143 | +43 |
| `kotlin` | 5 | 1,557 | 1,515 | 1,480 | +35 |
| `ocaml` | 6 | 2,397 | 2,063 | 2,013 | +50 |
| `perl` | 4 | 1,615 | 1,589 | 1,554 | +35 |
| `php` | 6 | 2,015 | 1,843 | 1,794 | +49 |
| `python` | 4 | 1,872 | 1,570 | 1,533 | +37 |
| `ruby` | 4 | 1,854 | 1,623 | 1,589 | +34 |
| `rust` | 24 | 7,341 | 6,497 | 6,416 | +81 |
| `swift` | 8 | 1,925 | 1,875 | 1,834 | +41 |
| `tcl` | 6 | 2,028 | 2,007 | 1,966 | +41 |
| `typescript-deno` | 1 | 2,379 | 2,223 | 2,169 | +54 |
| `zig` | 5 | 1,755 | 1,714 | 1,654 | +60 |
| **Total** | **179** | **72,330** | **65,746** | **64,421** | **+1,325** |

`impls/arm64-asm/README.md` gives 9,131 total and 8,431 non-blank,
non-comment lines, which match.

## Open items in detail

### O1. `inet_gethost` in both BEAM servers (unchanged)

After the first `getBlock` against the mock origin, both `erlang` and
`elixir` have three child processes: `erl_child_setup` and two
`inet_gethost`. At idle both have `erl_child_setup` only. The helper is OTP's
own native resolver, started because `gen_tcp:connect` and `ssl:connect` are
given the archive host as a string (`impls/erlang/src/ob_archive.erl:223-225`,
`impls/elixir/lib/archive.ex:278-281`). It is part of the runtime, not a
third-party dependency. This was observed in the second pass and the code
has not changed.

Three places still disagree with that behaviour:

* `SPEC.md` §1 allows "a VM's port helper" and names only `erl_child_setup`.
* `impls/erlang/README.md:39-43` says "The only other process is the VM's
  own `erl_child_setup`" and "The server never opens a port or child
  process".
* `impls/elixir/README.md:39` says "Hostname lookups can start OTP's
  `inet_gethost` helper". A numeric archive address starts it too.

Suggested resolution: name `inet_gethost` beside `erl_child_setup` in §1 and
correct the two README passages.

### O2. `bash fetch.bash` is not in the §1 list (unchanged)

For each `http://` Range read, the AWK engine starts a fresh
`bash fetch.bash`, which opens a `/dev/tcp` socket and then `exec`s `od`
(`impls/bash-awk/wire.awk:36`, `fetch.bash:12`). §1 lists the listener, its
handler subshells, the AWK engine and "`sh`, `od` and `sleep`". The README
names the fetcher; §1 does not.

### O3. Benchmark results predate `v1`

`conformance/results.json` records source revision `2d06a86`. That tree
has the AWK Zstandard decoder, so the `bash-awk` rows the second pass called
stale are now current, but it does not have `v1`. Two things follow:

* The "Source LOC" column of the root README table is low by 34 to 155 lines
  per implementation (see the table above). "Fewest lines" and "Most lines"
  still name the right implementations, with 1,186 and 8,431.
* `README.md:212` says all 24 passed "the four live probes". The live probe
  now has five targets, and no committed result covers the `v1` slot. This
  review ran `--live` for `rust` and `python` only.

`conformance/security_report.md` is no longer part of this item: it was
regenerated in `e164040` and matches this run.

Suggested resolution: run `make bench` and update the README table.

## Method

1. **Suites.** With the `PATH` the task gives, in order:
   `runner.py --self-test`, `runner.py --strict-parsed`,
   `security_audit.py --skip-build`, then `runner.py`. Each exited 0. The
   manifest holds 103 cases (34 results, 67 errors, 2 batches), 22 of them
   added for `v1`. The audit records 25 checks per implementation: 21 request
   probes plus launch, `TMPDIR`, liveness and implementation-directory disk.
2. **Golden coverage.** Mapped every `v1` case in the manifest and every
   `v1` probe in the audit to the rules of `WIRE_FORMATS.md` §8.2 and §13 and
   `SPEC.md` §5.4.
3. **Fixture decode.** Decoded every transaction in
   `fixtures/epochs/1095/epoch-1095.car` with a decoder written from §8.2.
   CAR and DataFrame extraction reused `impls/python/wire.py`.
4. **Extra probes.** A scratch script built 342 synthetic slots in epoch 700
   and served them from its own loopback Range origin. It ran 128 checks
   against each implementation: 73 error checks, 47 result checks compared
   with JSON produced by an encoder written for this review, and 8 batches
   of up to 100 truncated transactions. It reused the audit's launcher and
   the runner's comparator in strict mode, and it checked `getHealth` after
   every request. A control run with four deliberately wrong expectations
   failed all four. The script is not in the repository.
5. **Diff review.** Read the `v1` diff for purity (added files, build
   scripts, imports, spawns, file access) and read the `v1` parsers of
   `arm64-asm`, `bash-awk`, `c`, `cpp`, `erlang`, `fortran` and `zig` in
   full.
6. **Live.** `runner.py --impl rust --impl python --live`, exit 0.
7. **Unit tests.** `cargo test --offline` (40 passed), `go vet` and
   `go test` (ok), `zig test metadata.zig` (1 passed), Fortran
   `build.sh --test` (all checks passed).
8. **Line counts.** `cloc` and a plain line count over `git ls-files`.
9. **Stale references.** Re-derived every `file:line` in this document that
   points into a file the `v1` change touched.

Not covered in this revision:

* The SIMD-0385 text itself was not read. The layout and mask rules were
  checked against the contract in `WIRE_FORMATS.md` §8.2, the two verbatim
  mainnet fixture transactions (masks `0x0C` and `0x0F`) and the pinned
  facts of the live slot.
* `--live` for the other 22 implementations.
* `make bench`. No latency, memory or build-time figure was re-measured.
* Linkage inspection, the process-group sampler and the BEAM child-process
  listing. These were last run in the second pass.
* Toolchain versions in note N9, which were not re-checked.
* The `v1` parsers of the other 17 implementations were tested by the
  suites and the extra probes but not read line by line.
* The branding search of the second pass.

### Reading of SPEC §3 used here

SPEC §3.1 allows the standard library "as shipped with its toolchain". The
table in §3.2 lists the HTTP client and server, CRC-64 and FNV-1a without the
"unless in stdlib" wording that JSON and zstd carry. This review treats any
standard-library module as allowed, including HTTP servers and clients and
hash functions, and applies that to all 24 implementations. The "HTTP" column
below records which implementations rely on it.

## Per-implementation results

Dependency verdict: third-party packages, vendored code and non-OS binaries.
Authenticity: the work is done in the named language, with no helper in
another language beyond the SPEC §3.3 HTTPS transport and the §1 runtime
plumbing. HTTP: "own" means an HTTP/1.1 client and server written over raw
sockets; "stdlib" means a standard-library HTTP module. `v1`: the extra
probes of Method step 4. All 24 pass the three mandated suites.

| Implementation | Dependencies | Authenticity | `v1` extra probes | HTTP | JSON | zstd | HTTPS transport |
|---|---|---|---|---|---|---|---|
| `arm64-asm` | PASS | PASS | 128 of 128 | own | own | own | system libcurl |
| `bash-awk` | PASS | PASS | 128 of 128 | own | own | own | `/usr/bin/curl` |
| `bun` | PASS | PASS; note N2 | 128 of 128 | stdlib (`Bun.serve`, `fetch`) | stdlib | stdlib, frame-walked | runtime |
| `c` | PASS | PASS | 128 of 128 | own | own | own | system libcurl |
| `cpp` | PASS | PASS | 128 of 128 | own | own | own | system libcurl |
| `csharp` | PASS | PASS | 128 of 128 | stdlib (`HttpListener`, `HttpClient`) | stdlib | own | runtime |
| `elixir` | PASS | PASS | 128 of 128 | own over `:gen_tcp` | own | own | OTP `:ssl` |
| `erlang` | PASS | PASS | 124 of 128 (D1) | own over `gen_tcp` | own | own | OTP `ssl` |
| `fortran` | PASS | PASS | 128 of 128 | own | own | own | `/usr/bin/curl` via `popen` |
| `go` | PASS | PASS | 128 of 128 | stdlib (`net/http`) | stdlib | own | runtime |
| `haskell` | PASS | PASS | 128 of 128 | own | own | own | `/usr/bin/curl` |
| `java` | PASS | PASS | 128 of 128 | stdlib (JDK) | own | own | runtime |
| `javascript-node` | PASS | PASS | 128 of 128 | stdlib (`node:http`) | stdlib | stdlib, frame-walked | runtime |
| `kotlin` | PASS | PASS | 128 of 128 | stdlib (JDK) | own | own | runtime |
| `ocaml` | PASS | PASS | 128 of 128 | own | own | own | `/usr/bin/curl` |
| `perl` | PASS | PASS | 128 of 128 | own | core `JSON::PP` | own | `/usr/bin/curl` |
| `php` | PASS | PASS | 128 of 128 | own over streams | bundled `json` | own | bundled OpenSSL |
| `python` | PASS | PASS | 128 of 128 | stdlib (`http.server`, `http.client`) | stdlib | own | runtime |
| `ruby` | PASS | PASS | 128 of 128 | stdlib (WEBrick, `Net::HTTP`) | stdlib | own | runtime |
| `rust` | PASS | PASS | 128 of 128 | own | own | own | `/usr/bin/curl` |
| `swift` | PASS | PASS | 128 of 128 | own listener; `Network` client | Foundation | own | `Network` |
| `tcl` | PASS | PASS | 128 of 128 | own | own | own | `/usr/bin/curl` |
| `typescript-deno` | PASS | PASS | 128 of 128 | stdlib (`Deno.serve`, `fetch`) | stdlib | own | runtime |
| `zig` | PASS | PASS | 128 of 128 | stdlib (`std.http`) | stdlib | stdlib, frame-walked | runtime |

READMEs: all 24 exist. The `v1` change edited eight of them, each to name
`v1` in a file description or update a line count; those edits are accurate.
The `erlang` and `elixir` process-model sentences in O1 are still wrong.

### Evidence per implementation

Collected in the first two passes. The `v1` change touched none of the facts
below except the line counts and line numbers, which are updated here.

* **`arm64-asm`**: eleven `.s` files, 9,131 lines. No compiler-output markers
  (`.cfi_`, `; %bb.`, `Lloh`, `LCPI`, `.subsections_via_symbols`); the code
  uses its own macros and numeric local labels. `build.sh` assembles only
  `*.s`. The binary links `/usr/lib/libcurl.4.dylib` and `libSystem` only, and
  its undefined symbols are libc and six `curl_easy_*` calls. libcurl is
  reached only when the base URL is `https://` (`fetch.s:335`).
* **`bash-awk`**: JSON, CAR, CBOR, protobuf, bincode, Base58, CRC-64, the LRU
  caches and Zstandard (`zstd.awk`, 599 lines) are AWK. The listener is
  Bash's own `accept` loadable builtin. No Python, Perl, C, `zstd` or `xxd`.
  The external commands are `/usr/bin/awk`, `/usr/bin/od`, `/bin/sleep`,
  `/usr/bin/curl` (for `https://` only) and awk's own `sh` for pipes.
* **`bun`**: one local import (`./archive.ts`), no `package.json` or
  lockfile. `Bun.zstdDecompressSync` runs one preflighted frame at a time
  under a 512 MiB budget.
* **`c`**: only libc, pthread and `curl/curl.h` headers. Links `libSystem`
  and system libcurl. libcurl is used only for `https://`
  (`src/upstream.c:602`).
* **`cpp`**: only C++ standard headers, POSIX socket headers and
  `curl/curl.h`. Links `libc++`, `libSystem` and system libcurl, which is used
  only for `https://` (`src/archive.cpp:363`).
* **`csharp`**: `OnlyBlocks.csproj` has no `PackageReference`; the published
  `deps.json` lists only the project. All `using` lines are `System.*`. The
  build restores from the local directory, not from NuGet.
* **`elixir`**: no Mix project and no Hex. Modules used are Elixir's standard
  library and OTP (`:gen_tcp`, `:ssl`, `:ets`, `:atomics`, `:public_key`). No
  `System.cmd`, `Port.open` or NIFs in the source. `File.read` loads the TLS
  trust store only. `build.sh:17` runs `nix shell --offline` only. See O1.
* **`erlang`**: OTP modules only, compiled with `erlc`. No `os:cmd`,
  `open_port` or NIFs in the source. See O1 and D1.
* **`fortran`**: no C source. `bind(c)` declares 20 libc symbols and nothing
  else. `popen` runs `curl` only for `https://` (`src/ob_http.f90:480-482`),
  and the base URL is rejected at start-up if it contains a quote, control
  or non-ASCII character (`src/ob_http.f90:434`), so the shell command cannot
  be injected. The binary links `libgfortran`, `libquadmath` and `libSystem`.
* **`go`**: `go.mod` has no `require` and there is no `go.sum`; `go list -m
  all` prints one module. All imports are standard library. Built with
  `CGO_ENABLED=0`.
* **`haskell`**: built with `-hide-all-packages` and seven named GHC boot
  packages, so any other import fails to compile. Sockets are libc calls
  through `foreign import ccall`. `curl` is spawned only for `https://`
  (`Net.hs:389`). The binary links `libgmp`, `libffi` and `libiconv` from the
  Nix store; these belong to the GHC runtime.
* **`java`**: imports are `java.*` and the JDK's `com.sun.net.httpserver`.
  Built with `javac` alone. No `ProcessBuilder` or native methods.
* **`javascript-node`**: four `node:` imports and no `package.json`.
  `zstdDecompressSync` gets one frame at a time with `maxOutputLength`.
* **`kotlin`**: imports are `java.*` and `com.sun.net.httpserver`. The JAR
  holds only the application classes and the Kotlin standard library that
  `-include-runtime` bundles.
* **`ocaml`**: standard library plus the compiler's `unix` and `threads`
  libraries. No `external` declarations. `curl` is spawned only for `https://`
  (`http.ml:293`). The binary links `libSystem` only.
* **`perl`**: `/usr/bin/perl` with `JSON::PP`, `MIME::Base64`,
  `IO::Socket::INET`, `Time::HiRes` and `POSIX`, all confirmed core by
  `Module::CoreList`. `curl` is opened in list form (no shell) only for
  `https://` (`server.pl:245-247`).
* **`php`**: no Composer. Uses streams, `json_decode`/`json_encode`,
  `base64_encode` and the bundled OpenSSL and pcntl extensions. No `exec`,
  `proc_open`, FFI or curl extension.
* **`python`**: every import is in `sys.stdlib_module_names`. `run.sh` passes
  `-EBS`, which disables `site-packages`. No `subprocess` or `ctypes`.
* **`ruby`**: `/usr/bin/ruby --disable=gems`. WEBrick, JSON and Base64 load
  from the system Ruby 2.6 library directory, not from gems. No `system`,
  backticks, `IO.popen` or Fiddle.
* **`rust`**: empty `[dependencies]` and `[dev-dependencies]`; `Cargo.lock`
  has one package; `cargo tree --offline` prints one line. The only
  `extern "C"` is libc `signal`. `curl` is spawned only for `https://`
  (`src/http_client.rs:114-115`). The binary links `libSystem` only.
* **`swift`**: imports `Foundation`, `Network` and `Darwin`. No
  `Package.swift`, no `Process`, no `URLSession`. Links only system
  frameworks and the Swift runtime.
* **`tcl`**: no `package require` at all, so no `tls`, `http` or `json`
  packages. `curl` is opened as a pipe only for `https://`
  (`http.tcl:144-146`).
* **`typescript-deno`**: zero imports, no `deno.json` or lockfile. The
  Zstandard decoder is written in TypeScript.
* **`zig`**: imports `std` and local files only, with no `build.zig.zon`.
  `std.compress.zstd` gets one preflighted frame at a time; the wrapper checks
  the 512 MiB budget, the content size and the XXH64 checksum
  (`metadata.zig:360-420`). The binary links `libSystem` only.

### Runtime probe (second pass, not repeated)

| Property | Result |
|---|---|
| One process in the launcher's process group while serving | 23 of 24; `bash-awk` runs `bash`, `awk`, `sh` and `od`, as §1 allows (O2) |
| Children outside that group (BEAM servers only) | `erl_child_setup` at idle; `erl_child_setup` and two `inet_gethost` after the first upstream connection (O1) |
| No entries left in `TMPDIR` | 24 of 24 (repeated in this revision by the suites) |
| `ftp://` base URL exits non-zero | 24 of 24 |
| `POST /x` | 404 from all 24 |
| `GET /` | 405 from 18; 404 from `csharp`, `perl`, `php`, `python`, `ruby`, `tcl` (both allowed) |
| SIGTERM | all exit within 3 s; 21 exit `0`; `java` and `kotlin` exit `143`; `tcl` dies on the signal |

Exit status `0` is "preferred" in SPEC §2.3, so the three non-zero exits are
not violations.

## Branding

A case-insensitive search for the pre-rebrand name and for an old-prefix
environment variable found nothing in tracked files or file names in the
second pass. It was not repeated here.

## `getTransaction`

No implementation serves it. Every mention is the `-32601` rule, a test or
benchmark of that rule, or documentation of it. Line numbers are current.

| Location | Kind |
|---|---|
| `SPEC.md:35`, `389`, `475`, `555`, `609-610` | Spec text for the `-32601` rule |
| `README.md:53`, `58`, `60`, `154`, `371` | Root README: why the method is dropped, and the check that it is |
| `docs/ARCHITECTURE.svg:19` | Diagram label |
| `conformance/README.md:43` | Harness documentation |
| `conformance/runner.py:450`, `467`, `469`, `893`, `948` | Negative test and self-test |
| `conformance/fixtures/manifest.json:2919-2920`, `3056` | Negative golden cases (single and batch) |
| `conformance/security_audit.py:705`, `823` | Negative probe (`-32601`, no upstream request) and its report line |
| `conformance/security_report.md:51` | Report line for that probe |
| `conformance/bench.py:140` | Label for the live removed-method check |
| `conformance/results.json` (24 keys, one per implementation) | Recorded result of that check: `"error_code": -32601` |
| `impls/rust/tests/golden.rs:279-280` | Negative unit test |
| `impls/rust/src/rpc.rs:119` | Code comment on the `-32601` branch |
| `impls/cpp/src/main.cpp:120` | Code comment on the `-32601` branch |
| `impls/rust/README.md:60`, `impls/c/README.md:5`, `49`, `impls/cpp/README.md:5`, `53` | README statements that the method is rejected |

## Notes (not blocking)

N1, N3, N4 and N8 are closed. N8 asked the root README to list all 24
implementations and the conformance runner; it now does both.

* **N2. `impls/bun/`** shares 1,584 of its 1,724 lines with
  `impls/typescript-deno/onlyblocks.ts` (matching blocks from a sequence
  diff of the two Bun files against the Deno file). The Bun-specific parts
  are the server, the launcher and the Zstandard wrapper. It is the same
  language on a second runtime, so this is a variant, not a separate
  implementation.
* **N5. `impls/ruby/`** depends on WEBrick being in the standard library,
  which holds for the pinned system Ruby 2.6 and not for Ruby 3.0 or later.
  The README states the Ruby version.
* **N6. Serial servers.** `arm64-asm`, `bash-awk`, `fortran`, `perl` and
  `php` serve one connection at a time, so a slow upstream fetch delays
  `getHealth`. SPEC §2.4 recommends concurrency and does not require it.
* **N7. `curl` lookup.** `rust`, `haskell`, `ocaml` and `fortran` use
  `/usr/bin/curl` and fall back to `curl` on `PATH` when it is missing.
  `perl`, `tcl` and `bash-awk` use `/usr/bin/curl` only.
* **N9. Toolchain pins.** Several launchers hard-code this machine's
  layout: `/opt/homebrew/bin/tclsh`, `/opt/homebrew/opt/openjdk@17`,
  `/usr/bin/swiftc`, `python3.11`, and `zig` through `nix shell` only.
* **N10. Error text echoes archive bytes.** `erlang` and `elixir` put the
  unmatched remainder of a corrupt transaction into the `-32603` message.
  That is harmless for public archive data, and in `erlang` it is the cause
  of D1.
* **N11. Larger-than-protocol payloads cost time in two implementations.**
  The 33,844-byte `v1` transaction took about 1.5 s in `bash-awk` and 1.3 s
  in `tcl` in `jsonParsed`, and under 0.2 s in the other 22. Mainnet caps a
  transaction at 4,096 bytes, so this is not reachable with real data.
