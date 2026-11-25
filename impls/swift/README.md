# OnlyBlocks in Swift

Run `./build.sh` with Apple Swift 6.4, then `./run.sh`. There are no SwiftPM
packages. The listener uses Darwin sockets, Network provides TCP and TLS, and
Foundation provides JSON serialization. Swift implements the CAR, CBOR,
transaction, metadata, and Zstandard codecs. Both LRU caches live in memory.
