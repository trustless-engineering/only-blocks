# OnlyBlocks in Kotlin

Install the Kotlin compiler or provision it with
`nix shell nixpkgs#kotlin -c kotlinc -version` before building. Run
`./build.sh` and `./run.sh --bind 127.0.0.1:8899` with JDK 17.

The compiler bundles the Kotlin standard library into the executable JAR.
The server uses the JDK HTTP server and HTTP/TLS client. Archive codecs and
JSON use bounded byte cursors, unsigned integers, and a sealed protobuf
schema implemented in Kotlin. Both LRU caches live in memory.
