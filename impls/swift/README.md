# OnlyBlocks in Swift

OnlyBlocks serves historical Solana `getBlock` requests from Old Faithful.
Build with Apple Swift 6.4 on macOS and run these commands from this directory.

```sh
./build.sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

`build.sh` compiles the sources directly with `swiftc`. The binary uses
only the Swift runtime and macOS APIs. Darwin sockets accept inbound
connections, Network provides upstream TCP and TLS, and Foundation
serializes JSON responses. Swift code handles HTTP framing and archive
decoding. The slot-range and blockhash LRU caches each hold up to 100,000
entries in memory.

## Sources

| File | Role |
|---|---|
| `main.swift` | Listener, CLI options, and JSON-RPC dispatch |
| `HTTPInput.swift` | Buffered HTTP parsing and body framing |
| `HTTPClient.swift` | HTTP Range transport over TCP and TLS |
| `Archive.swift` | `getBlock` pipeline, Range retries, and LRU caches |
| `JSON.swift` | Request parser and response encoding with exact numeric IDs |
| `Wire.swift` | Byte cursors, CARv1, CIDs, DAG-CBOR, and DataFrame reassembly |
| `Solana.swift` | Transactions, protobuf and bincode metadata, and rewards |
| `Zstd.swift` | Zstandard frame and block decoding |
