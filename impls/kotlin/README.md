# OnlyBlocks in Kotlin

OnlyBlocks serves historical Solana `getBlock` requests from Old Faithful.
The build needs JDK 17 and `kotlinc` from `PATH` or the offline Nix store.
Run these commands from this directory.

```sh
./build.sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

`kotlinc` bundles the Kotlin standard library into the executable JAR.
The server runs in one JVM with zero third-party dependencies. It uses
the JDK's `HttpServer` for inbound requests and `HttpClient` for upstream
HTTP and TLS Range reads. Kotlin code implements the JSON and archive
codecs using bounded byte cursors, unsigned integers, and a sealed
protobuf schema. The slot-range and blockhash LRU caches each hold up to
100,000 entries in memory.

## Sources

| File | Role |
|---|---|
| `Server.kt` | HTTP listener, JSON-RPC dispatch, Range reads, retries, and caches |
| `Json.kt` | JSON parser and writer with numeric lexemes |
| `Wire.kt` | Byte cursors, CARv1, CIDs, DAG-CBOR, and DataFrame reassembly |
| `Solana.kt` | Transactions, protobuf and bincode metadata, rewards, and response rendering |
| `Zstd.kt` | Zstandard frame and block decoding |
