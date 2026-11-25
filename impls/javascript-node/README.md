# OnlyBlocks in Node.js

Requires Node.js 25.2 or later. Run the server with:

```sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

The single ES module uses Node's HTTP and HTTPS agents for Range requests,
Buffer for padded Base64, and `zstdDecompressSync` for Zstandard. It walks
Zstandard frame boundaries so the decoder handles concatenated and skippable
frames under one output limit.

CAR, DAG-CBOR, Solana transaction, protobuf and bincode readers share a
bounds-checked DataView cursor. BigInt preserves 64-bit wire values, and
JavaScript's JSON reviver source text and `JSON.rawJSON` preserve exact
integers over JSON-RPC. Map insertion order drives both in-memory LRUs.

From the repository root, run the golden and live conformance checks with
`python3 conformance/runner.py --impl javascript-node --live`.
