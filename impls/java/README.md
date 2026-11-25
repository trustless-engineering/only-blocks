# OnlyBlocks in Java

OnlyBlocks serves historical Solana `getBlock` requests from Old Faithful.
With JDK 17 available, run these commands from this directory.

```sh
./build.sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

`build.sh` compiles the sources directly with `javac --release 17`. The
server runs in one JVM and depends only on the JDK. `HttpServer` handles
inbound requests and `HttpClient` handles upstream HTTP and TLS Range reads.
The archive codecs and JSON parser are implemented in Java. The parser keeps
numeric lexemes for unsigned slots and exact JSON-RPC IDs. The slot-range
and blockhash LRU caches each hold up to 100,000 entries in memory.

## Sources

| File | Role |
|---|---|
| `Server.java` | HTTP listener, JSON-RPC dispatch, Range reads, retries, and caches |
| `Json.java` | JSON parser and writer |
| `Wire.java` | Byte cursors, CARv1, CIDs, DAG-CBOR, and DataFrame reassembly |
| `Solana.java` | Transactions, protobuf and bincode metadata, rewards, and response rendering |
| `Zstd.java` | Zstandard frame and block decoding |
