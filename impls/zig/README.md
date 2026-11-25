# OnlyBlocks in Zig

Built with Zig 0.17.1. Provision the compiler with
`nix shell nixpkgs#zig -c zig version` before the first build. From this
directory, run `./build.sh` and then `./run.sh --bind 127.0.0.1:8899`.
Override the archive origin with `--base-url` or `OLD_FAITHFUL_BASE_URL`.
The build uses the locally provisioned toolchain in offline mode. The
launch script execs the compiled binary.

Zig's standard library provides HTTP, TLS, Zstd, JSON, and hashing.
Each HTTP request owns an arena for wire data and JSON construction.
Intrusive lists back the two bounded, shared LRU caches. Frame validation
around the standard Zstd decoder enforces the cumulative 512 MiB output
limit and verifies XXH64 checksums. The server uses the system libc for
signal handling and has no Zig package dependencies.

Run `nix shell nixpkgs#zig --offline -c zig test metadata.zig` here for
decoder tests. From the repository root, run
`python3 conformance/runner.py --impl zig`.
