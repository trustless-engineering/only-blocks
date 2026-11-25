# OnlyBlocks general and purity review

Independent audit of the merged repository, covering `SPEC.md`, `docs/`,
`conformance/` and all 24 directories under `impls/`. The first pass ran at
commit `b55e98f` and found four items needing rework (R1 to R4). This
revision re-verifies at commit `6f8536b`, after those fixes merged. Both
passes ran on macOS arm64 on 2026-11-25.

## Verdict

**Clean on all four audit checks. No blocking findings remain.** Three small
documentation items are still open and are listed below.

| Check | Result at `6f8536b` |
|---|---|
| Zero third-party dependencies | 24 of 24 pass |
| Authenticity (no hidden helpers in another language) | 24 of 24 pass |
| Pre-rebrand branding | None left |
| `getTransaction` | Absent as a feature; only `-32601` rejections and their tests, benchmarks and docs remain |
| Offline conformance sweep | 24 of 24 PASS, exit 0 |
| `--strict-parsed` sweep | 24 of 24 PASS, exit 0 |
| READMEs | All 24 exist; 22 are accurate, and `erlang` and `elixir` each have one process-model sentence to correct (O1) |

### Rework items from the first pass

| # | Where | First-pass finding | Status |
|---|---|---|---|
| R1 | `impls/bash-awk/` | Zstandard decoded by the Homebrew `zstd` CLI | **Fixed.** `zstd.awk` is an RFC 8878 decoder in AWK. |
| R2 | `impls/bash-awk/` | Several OS processes against SPEC §1 | **Resolved in the spec.** §1 now lists this entry's processes; see O2 for one it does not name. |
| R3 | `impls/elixir/build.sh` | Non-offline `nix shell` fallback | **Fixed.** Only `--offline` remains. |
| R4 | `impls/elixir/` | `inet_gethost` helpers started at boot | **Fixed for the bind address.** The helper still starts on the first upstream connection, in `erlang` too; see O1. |

### Open items (not blocking)

| # | Where | Item |
|---|---|---|
| O1 | `impls/erlang/`, `impls/elixir/`, `SPEC.md` §1 | Both BEAM servers start OTP's `inet_gethost` helper on the first upstream connection. §1 names only `erl_child_setup`, and both READMEs describe this wrongly or incompletely. |
| O2 | `SPEC.md` §1 | The `bash-awk` process list does not name the short-lived `bash fetch.bash` process that makes each `http://` Range read. |
| O3 | `conformance/security_report.md`, `conformance/results.json` | The committed `bash-awk` rows were produced before the AWK decoder existed. |

## What was re-verified

### `impls/bash-awk/` (R1, R2)

* **No external decoder.** `server.bash` no longer resolves `zstd` or `xxd`.
  `zstd.awk` (599 lines) contains no `system`, `getline`, pipe or `ENVIRON`
  use. The only external commands left in the implementation are
  `/usr/bin/awk`, `/usr/bin/od`, `/bin/sleep`, `/usr/bin/curl` (for
  `https://` only) and awk's own `sh` for pipes.
* **Stub test.** With `zstd` and `xxd` stubs that exit 1 placed first on
  `PATH`, all 81 golden cases pass. At `b55e98f` the same test failed 17
  cases.
* **Runtime probe.** While serving golden cases, the process group held
  `bash`, `awk`, `sh` and `od` only, with a peak of 5 processes. No `zstd` or
  `xxd` process appeared.
* **Differential test of the decoder.** A driver fed `zstd.awk` 305 frames
  made with the `zstd` 1.5.7 CLI, used here only as a test oracle: text,
  skewed binary, random and all-zero inputs from 0 to 140,000 bytes, at
  levels `--fast=5`, 1, 3, 5, 7, 9 and 19, with and without checksums, with
  1 KiB blocks, plus concatenated and skippable frames. All 305 outputs were
  byte-identical (5,965,960 bytes in total). Of 128 corrupted inputs (120
  single-bit flips, 6 truncations, trailing garbage, a gzip prefix), the
  decoder rejected all 128 and the CLI also rejected all 128.
* **Hostile input.** `conformance/security_audit.py --impl bash-awk` passes
  every probe, including the 512 MiB + 1 byte Zstandard bomb and the
  oversized content-size frame.
* **Size limit.** The 450 KB compressed-frame limit is gone from the code.
  The README now says that the 75 MB epoch-boundary rewards payload would be
  impractically slow and large in AWK. That estimate was not tested here.
* **README.** The false "the spec permits this" claim is gone. The process
  model section matches what the probe saw.

### `impls/elixir/` (R3, R4)

* `build.sh:17` runs `nix shell --offline` only. No build or run script in
  the repository calls `nix shell` without `--offline`.
* `lib/server.ex:172-176` parses a numeric bind address with
  `:inet.parse_address/1` before resolving. A started server now has one
  child, `erl_child_setup`, where the first pass saw `inet_gethost` as well.
* Conformance, strict conformance, the runtime probe and
  `security_audit.py --impl elixir` all pass.

### `SPEC.md`

§1 now lists the allowed runtime plumbing. §3.3 still said the HTTPS `curl`
"is the only permitted child process", which contradicted it. This revision
changes that sentence to "Apart from the runtime plumbing that §1 lists, this
is the only permitted child process." No other spec text was changed.

### Notes closed since the first pass

* **N1.** `impls/arm64-asm/README.md` now gives 8,963 total and 8,276
  non-blank, non-comment lines, which match the files.
* **N3.** `impls/fortran/README.md` now lists `shutdown` and `freeaddrinfo`.
* **N4.** The `java`, `kotlin` and `swift` READMEs now show the run flags and
  a source-file table. Every file they name exists, and the descriptions
  match the code.

## Open items in detail

### O1. `inet_gethost` in both BEAM servers

After the first `getBlock` against the mock origin (`http://127.0.0.1:<port>`),
both `erlang` and `elixir` have three child processes: `erl_child_setup` and
two `inet_gethost`. At idle both have `erl_child_setup` only. The helper is
OTP's own native resolver, started because `gen_tcp:connect` and
`ssl:connect` are given the archive host as a string
(`impls/erlang/src/ob_archive.erl:223-225`,
`impls/elixir/lib/archive.ex:278-281`). It is part of the runtime, not a
third-party dependency, and with a real archive hostname it cannot be avoided
while the native resolver is in use.

This corrects the first pass, which reported that the Erlang server showed
only `erl_child_setup`. That observation was made at idle, before any
upstream connection.

Three places disagree with the observed behaviour:

* `SPEC.md` §1 allows "a VM's port helper" and gives `erl_child_setup` as the
  example. `inet_gethost` fits that description but is not named.
* `impls/erlang/README.md:38-42` says "The only other process is the VM's own
  `erl_child_setup`" and "The server never opens a port or child process".
  Both are wrong after the first upstream fetch.
* `impls/elixir/README.md` says "Hostname lookups can start OTP's
  `inet_gethost` helper". A numeric archive address starts it too.

Suggested resolution: name `inet_gethost` beside `erl_child_setup` in §1 and
correct the two README passages. The alternative is to pass a parsed address
tuple to `connect` for numeric hosts, which removes the helper on the
conformance path but not against the real archive. Neither was done in this
revision, because both are the spec owner's decision.

### O2. `bash fetch.bash` is not in the §1 list

For each `http://` Range read, the AWK engine starts a fresh
`bash fetch.bash`, which opens a `/dev/tcp` socket and then `exec`s `od`
(`impls/bash-awk/wire.awk:36`, `fetch.bash:12`). §1 lists the listener, its
handler subshells, the AWK engine and "`sh`, `od` and `sleep`". The fetcher is
Bash itself, so it is in the spirit of the entry, but the list does not name
it. The README does. Suggested resolution: add it to the §1 sentence.

### O3. Committed results that predate the AWK decoder

`conformance/security_report.md` and `conformance/results.json` were
committed in `cd9c096` and `3ee77b8`, before `zstd.awk` was added in
`d80eb3e`. Their `bash-awk` rows therefore describe the old CLI-based
decoder. The security audit was re-run here for `bash-awk`, `elixir` and
`erlang` and passes, with output kept out of the repository. The benchmark
was not re-run, so the `bash-awk` latency, memory and live figures in
`results.json` are stale.

## Method

The first pass at `b55e98f` ran every step below for all 24 implementations.
Since then, source changes are confined to `impls/bash-awk/` and
`impls/elixir/`, with README-only changes in `arm64-asm`, `fortran`, `java`,
`kotlin` and `swift`. Steps 1 to 6 and 9 were therefore repeated only for the
changed files. Steps 7 and 8 were repeated in full at `6f8536b`.

1. **Manifests and build scripts.** Read every `build.sh`, `run.sh`,
   `Cargo.toml`, `Cargo.lock`, `go.mod` and `.csproj`. Searched tracked files
   for package manifests and lockfiles (`package.json`, `node_modules`,
   `requirements`, `Gemfile`, `composer.json`, `pom.xml`, Gradle, NuGet,
   `mix.exs`, `rebar`, `.cabal`, `dune`, `opam`, `Package.swift`,
   `build.zig.zon`, `deno.json`, `bun.lock`, `go.sum`, `cpanfile`, submodules,
   vendored trees). None exist.
2. **Imports.** Listed every import, include, `use` and `require` per
   language and checked each against the standard library.
3. **Spawn and FFI.** Searched every source for process spawning and foreign
   calls. Each hit is the HTTPS-only `curl` path, a libc binding, or the
   `bash-awk` stream tools that §1 now lists. The C and C++ sources contain no
   `popen`, `system`, `fork`, `exec*`, `posix_spawn` or `dlopen` call.
4. **Linkage.** Ran `otool -L` and `nm -u` on the ten native binaries and
   inspected the Kotlin JAR, the Java class directory, the .NET `deps.json`
   and the BEAM output directories. The Go, Haskell, OCaml, Rust and Zig
   binaries import `exec*`, `fork` or `posix_spawn` symbols through their
   runtime libraries; in the sources, the only spawn calls are the `curl`
   paths in Haskell, OCaml and Rust, and Go and Zig have none.
5. **Fixture cheating.** Searched implementation sources for fixture paths,
   harness endpoints, fixture slot numbers and the six fixture blockhashes.
   The only hits are in `impls/rust/tests/golden.rs`, which is a test.
6. **Binary blobs.** Every tracked file under `impls/` is text. There are no
   symlinks or submodules, and every `run.sh` and `build.sh` is executable.
7. **Conformance.** `python3 conformance/runner.py` (24 PASS, exit 0) and
   `--strict-parsed` (24 PASS, exit 0), both at `6f8536b`. `--self-test`
   passed at `b55e98f`; the harness has not changed since.
8. **Runtime probe.** A script started each server against the mock origin,
   sampled its process group every 10 ms while 25 `getBlock` golden cases
   ran, and then checked `GET /`, `POST /x`, SIGTERM and a `ftp://` base URL.
   All 24 were probed at `b55e98f`; `bash-awk`, `elixir` and `erlang` were
   probed again at `6f8536b`, and the two BEAM servers also had their full
   child-process trees listed before and after a `getBlock`.
9. **Advertised unit tests.** `cargo test --offline` (40 passed), `go vet` and
   `go test` (ok), `zig test metadata.zig` (1 passed), Fortran
   `build.sh --test` (all checks passed). These sources are unchanged.

Not covered:

* `--live` was not run in this review, so no HTTPS path was exercised here.
  The `curl`, libcurl and standard-library TLS paths were reviewed by reading
  the code only. `conformance/results.json` records live results from a
  separate benchmark task; they were not reproduced.
* README figures for latency, throughput, memory, sanitizer runs, fuzzing,
  differential runs and live results were not re-measured. "Accurate" in the
  table below covers build and run instructions, file and module
  descriptions, named toolchain versions, and the test counts and binary
  sizes that were checked (Rust 40 tests and 951 KB, C 143 KB, Fortran
  355 KB).
* `conformance/bench.py` and `conformance/security_audit.py` were checked for
  branding, `getTransaction` use and imports (the standard library and the
  local `runner` module only). They were not otherwise reviewed.

### Reading of SPEC §3 used here

SPEC §3.1 allows the standard library "as shipped with its toolchain". The
table in §3.2 lists the HTTP client and server, CRC-64 and FNV-1a without the
"unless in stdlib" wording that JSON and zstd carry. This review treats any
standard-library module as allowed, including HTTP servers and clients and
hash functions, and applies that to all 24 implementations. The "HTTP" column
below records which implementations rely on it. If the spec owner intends the
stricter reading, the implementations marked "stdlib" in that column are
affected, and §3.2 should say so.

## Per-implementation results

Dependency verdict: third-party packages, vendored code and non-OS binaries.
Authenticity: the work is done in the named language, with no helper in
another language beyond the SPEC §3.3 HTTPS transport and the §1 runtime
plumbing. HTTP: "own" means an HTTP/1.1 client and server written over raw
sockets; "stdlib" means a standard-library HTTP module. All 24 pass both
conformance sweeps.

| Implementation | Dependencies | Authenticity | HTTP | JSON | zstd | HTTPS transport | README |
|---|---|---|---|---|---|---|---|
| `arm64-asm` | PASS | PASS | own | own | own | system libcurl | accurate |
| `bash-awk` | PASS | PASS | own | own | own | `/usr/bin/curl` | accurate |
| `bun` | PASS | PASS; note N2 | stdlib (`Bun.serve`, `fetch`) | stdlib | stdlib, frame-walked | runtime | accurate |
| `c` | PASS | PASS | own | own | own | system libcurl | accurate |
| `cpp` | PASS | PASS | own | own | own | system libcurl | accurate |
| `csharp` | PASS | PASS | stdlib (`HttpListener`, `HttpClient`) | stdlib | own | runtime | accurate |
| `elixir` | PASS | PASS | own over `:gen_tcp` | own | own | OTP `:ssl` | one incomplete sentence (O1) |
| `erlang` | PASS | PASS | own over `gen_tcp` | own | own | OTP `ssl` | one wrong sentence (O1) |
| `fortran` | PASS | PASS | own | own | own | `/usr/bin/curl` via `popen` | accurate |
| `go` | PASS | PASS | stdlib (`net/http`) | stdlib | own | runtime | accurate |
| `haskell` | PASS | PASS | own | own | own | `/usr/bin/curl` | accurate |
| `java` | PASS | PASS | stdlib (JDK) | own | own | runtime | accurate |
| `javascript-node` | PASS | PASS | stdlib (`node:http`) | stdlib | stdlib, frame-walked | runtime | accurate |
| `kotlin` | PASS | PASS | stdlib (JDK) | own | own | runtime | accurate |
| `ocaml` | PASS | PASS | own | own | own | `/usr/bin/curl` | accurate |
| `perl` | PASS | PASS | own | core `JSON::PP` | own | `/usr/bin/curl` | accurate |
| `php` | PASS | PASS | own over streams | bundled `json` | own | bundled OpenSSL | accurate |
| `python` | PASS | PASS | stdlib (`http.server`, `http.client`) | stdlib | own | runtime | accurate |
| `ruby` | PASS | PASS | stdlib (WEBrick, `Net::HTTP`) | stdlib | own | runtime | accurate; note N5 |
| `rust` | PASS | PASS | own | own | own | `/usr/bin/curl` | accurate |
| `swift` | PASS | PASS | own listener; `Network` client | Foundation | own | `Network` | accurate |
| `tcl` | PASS | PASS | own | own | own | `/usr/bin/curl` | accurate |
| `typescript-deno` | PASS | PASS | stdlib (`Deno.serve`, `fetch`) | stdlib | own | runtime | accurate |
| `zig` | PASS | PASS | stdlib (`std.http`) | stdlib | stdlib, frame-walked | runtime | accurate |

### Evidence per implementation

* **`arm64-asm`**: eleven `.s` files, 8,963 lines. No compiler-output markers
  (`.cfi_`, `; %bb.`, `Lloh`, `LCPI`, `.subsections_via_symbols`); the code
  uses its own macros and numeric local labels. `build.sh` assembles only
  `*.s`. The binary links `/usr/lib/libcurl.4.dylib` and `libSystem` only, and
  its undefined symbols are libc and six `curl_easy_*` calls. libcurl is
  reached only when the base URL is `https://` (`fetch.s:335`).
* **`bash-awk`**: JSON, CAR, CBOR, protobuf, bincode, Base58, CRC-64, the LRU
  caches and now Zstandard are AWK. The listener is Bash's own `accept`
  loadable builtin. No Python, Perl, C, `zstd` or `xxd`. See "What was
  re-verified" above.
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
  trust store only. See O1.
* **`erlang`**: OTP modules only, compiled with `erlc`. No `os:cmd`,
  `open_port` or NIFs in the source. See O1.
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
  `https://` (`server.pl:244-246`).
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

### Runtime probe

| Property | Result |
|---|---|
| One process in the launcher's process group while serving | 23 of 24; `bash-awk` runs `bash`, `awk`, `sh` and `od`, as §1 now allows (O2) |
| Children outside that group (BEAM servers only) | `erl_child_setup` at idle; `erl_child_setup` and two `inet_gethost` after the first upstream connection (O1) |
| No entries left in `TMPDIR` | 24 of 24 |
| `ftp://` base URL exits non-zero | 24 of 24 |
| `POST /x` | 404 from all 24 |
| `GET /` | 405 from 18; 404 from `csharp`, `perl`, `php`, `python`, `ruby`, `tcl` (both allowed) |
| SIGTERM | all exit within 3 s; 21 exit `0`; `java` and `kotlin` exit `143`; `tcl` dies on the signal |

Exit status `0` is "preferred" in SPEC §2.3, so the three non-zero exits are
not violations.

## Branding

A case-insensitive search for the pre-rebrand name (with space, hyphen,
underscore or no separator) and for an old-prefix environment variable finds
nothing in tracked files or file names, including the four files added to
`conformance/` since the first pass. The only match in the checkout is the
worktree's `.git` pointer file, whose `gitdir` path includes the directory
name of the main checkout. That is local Git plumbing, not repository content.

## `getTransaction`

No implementation serves it. Every remaining mention is the `-32601` rule,
a test or benchmark of that rule, or documentation of it.

| Location | Kind |
|---|---|
| `SPEC.md:35`, `387`, `460`, `535`, `586-587` | Spec text for the `-32601` rule |
| `conformance/README.md:43` | Harness documentation |
| `conformance/runner.py:440`, `457`, `459`, `854`, `909` | Negative test and self-test |
| `conformance/fixtures/manifest.json:2881-2882`, `3018` | Negative golden cases (single and batch) |
| `conformance/security_audit.py:671`, `785` | Negative probe (`-32601`, no upstream request) and its report line |
| `conformance/security_report.md:51` | Report line for that probe |
| `conformance/bench.py:140` | Label for the live removed-method check |
| `conformance/results.json` (24 keys, one per implementation) | Recorded result of that check: `"error_code": -32601` |
| `impls/rust/tests/golden.rs:279-280` | Negative unit test |
| `impls/rust/src/rpc.rs:119` | Code comment on the `-32601` branch |
| `impls/cpp/src/main.cpp:121` | Code comment on the `-32601` branch |
| `impls/rust/README.md:60`, `impls/c/README.md:5`, `49`, `impls/cpp/README.md:5`, `53` | README statements that the method is rejected |

The two code comments and the five README lines are not tests. They describe
the rejection and are harmless, but they fall outside a strict reading of
"absent everywhere except negative tests". Remove them if that reading is
intended.

## Notes (not blocking)

N1, N3 and N4 from the first pass are closed (see above). The rest stand.

* **N2. `impls/bun/`** shares 1,528 of its 1,668 lines verbatim with
  `impls/typescript-deno/onlyblocks.ts`. The Bun-specific parts are the
  server, the launcher and the Zstandard wrapper. It is the same language on
  a second runtime, so this is a variant, not a separate implementation.
* **N5. `impls/ruby/`** depends on WEBrick being in the standard library,
  which holds for the pinned system Ruby 2.6 and not for Ruby 3.0 or later.
  The README states the Ruby version.
* **N6. Serial servers.** `arm64-asm`, `bash-awk`, `fortran`, `perl` and
  `php` serve one connection at a time, so a slow upstream fetch delays
  `getHealth`. SPEC §2.4 recommends concurrency and does not require it. In
  `bash-awk` the Bash front end forks per connection, but the single AWK
  engine answers requests in turn.
* **N7. `curl` lookup.** `rust`, `haskell`, `ocaml` and `fortran` use
  `/usr/bin/curl` and fall back to `curl` on `PATH` when it is missing.
  `perl`, `tcl` and `bash-awk` use `/usr/bin/curl` only.
* **N8. Root `README.md`** names only the Rust implementation. It does not
  list the other 23 or mention the conformance runner.
* **N9. Toolchain pins.** Several launchers hard-code this machine's
  layout: `/opt/homebrew/bin/tclsh`, `/opt/homebrew/opt/openjdk@17`,
  `/usr/bin/swiftc`, `python3.11`, and `zig` through `nix shell` only. The
  installed versions match every version a README names (Bun 1.4.0, Node
  25.2.1, Deno 2.6.3, Go 1.25.5, Swift 6.4, Tcl 9.0.3, Ruby 2.6.10, GNU
  Fortran 14.1, Python 3.11.10, OTP 26, Bash 5.3.9, awk 20200816).
