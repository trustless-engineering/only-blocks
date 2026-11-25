# OnlyBlocks in Python

Run with Python 3.11 on PATH.

```sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

A threaded HTTP server keeps health probes independent of upstream requests.
`http.client` handles HTTP and TLS. `OrderedDict` provides constant-time LRU
updates under a lock, and a semaphore limits concurrent range attempts.

CAR sections use `memoryview` slices, so indexing doesn't copy the slice.
The wire codecs and RFC 8878 Zstandard decoder are pure Python. The launcher
disables bytecode writes and ignores Python environment settings so the
runtime uses only the standard library and these source files.
