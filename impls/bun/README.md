# OnlyBlocks on Bun

Run with Bun 1.4.0 or newer.

```sh
./impls/bun/run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
python3 conformance/runner.py --impl bun
```

`Bun.serve` routes the JSON-RPC endpoint, and native `fetch` makes HTTP and
HTTPS Range requests. The local TypeScript archive module uses
`Bun.zstdDecompressSync` for frames whose maximum output fits the remaining
budget and Bun's streaming Zstandard decoder for larger bounds. Frame
validation handles concatenated and skippable frames and enforces a 512 MiB
aggregate output limit. The server runs with zero package dependencies and
keeps its bounded LRUs in RAM.
