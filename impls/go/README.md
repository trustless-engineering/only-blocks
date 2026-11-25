# OnlyBlocks in Go

Requires Go 1.25. From this directory, run `./build.sh` and then
`./run.sh --bind 127.0.0.1:8899`. Override the archive origin with
`--base-url` or `OLD_FAITHFUL_BASE_URL`. The launch script execs one
binary. There are no module dependencies or cgo calls.

Go's HTTP stack handles concurrent requests, TLS, and body framing.
A buffered channel bounds upstream attempts, and a generic map-and-list
LRU stores slot ranges and Base58 block hashes in RAM. The binary readers
keep CAR and transaction fields as slices of the received bytes. The
pure-Go Zstd decoder implements RFC 8878, including checksums, concatenated
frames, skippable frames, and the 512 MiB output limit.

Run `go test` here for decoder tests. From the repository root, run
`python3 conformance/runner.py --impl go`.
