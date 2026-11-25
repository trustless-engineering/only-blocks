# OnlyBlocks on Deno

Run with Deno 2.6.3 or newer.

```sh
./impls/typescript-deno/run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
python3 conformance/runner.py --impl typescript-deno
```

`onlyblocks.ts` is a single strict TypeScript file with zero imports.
`Deno.serve` handles JSON-RPC, and native `fetch` makes HTTP and HTTPS Range
requests. The wire readers use `Uint8Array`, `DataView` and `bigint`. A
TypeScript Zstandard decoder handles raw, RLE and compressed blocks, verifies
frame checksums, and caps output at 512 MiB across concatenated frames.
Slot ranges and block hashes live in bounded, in-memory LRUs.
