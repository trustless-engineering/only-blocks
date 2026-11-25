# OnlyBlocks in PHP

Use 64-bit PHP CLI 8.1 or later with the bundled OpenSSL and pcntl extensions.
To provision it with Nix, run `nix shell nixpkgs#php -c php --version` before
the first build. Run `./build.sh` and then
`./run.sh --bind 127.0.0.1:8899` from this directory. The build records the
local interpreter path for direct exec. Set `--base-url` or
`OLD_FAITHFUL_BASE_URL` to use a different archive origin.

The server handles one connection at a time over PHP streams. It uses the
bundled TLS support for HTTPS and keeps range and blockhash LRUs in RAM.
Binary readers use `unpack` with explicit byte boundaries. The decoders,
including Zstd and XXH64, are written in PHP. Exact unsigned integers use
signed bit patterns internally and decimal JSON tokens on output. The
server has no Composer dependencies.

From the repository root, run `python3 conformance/runner.py --impl php`.
