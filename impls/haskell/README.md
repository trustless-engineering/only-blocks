# OnlyBlocks in Haskell

A historical Solana `getBlock` JSON-RPC 2.0 server that reads blocks from Old
Faithful with two HTTP Range reads. It is one native executable built by
GHC. There is no Cabal or Stack project and nothing from Hackage.

```sh
bash build.sh      # ghc -O2 -threaded -hide-all-packages -package base ... Main.hs
bash run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

`build.sh` uses `ghc` from `PATH` if there is one. Otherwise it runs
`nix shell nixpkgs#ghc --offline`, so GHC has to be in the Nix store already.
A clean `-O2` build takes about 8 s. Build products go to `build/` and
`bin/`, and both are git-ignored.

## How it stays at zero dependencies

The build passes `-hide-all-packages` and then names each package it uses.
All of them are **GHC boot packages**, which ship inside the compiler:

| Package | Used for |
|---|---|
| `base` | the FFI, `forkIO`, `MVar`, `QSem`, exceptions, `System.Timeout` |
| `bytestring` | strict `ByteString`, `Builder` |
| `containers` | `Map` and `Set` (the CAR index and the LRUs) |
| `array` | unboxed FSE and Huffman tables, the Base58 digit buffer |
| `unix` | signal handlers, `setFdOption`, `closeFd` |
| `process` | spawning the OS `curl`, only for `https://` (SPEC §3.3) |
| `time` | the clock for HTTP-date `Retry-After` values |

If an import came from any other package, the build would fail.

The `network` package is not a boot package, so `Net.hs` binds the POSIX
socket API directly with `foreign import ccall`: `socket`, `bind`, `listen`,
`accept`, `connect`, `recv`, `send`, `setsockopt`, `getsockopt`,
`getaddrinfo` and `freeaddrinfo`, in about 60 lines. Every descriptor is
non-blocking. When a call returns `EAGAIN` or `EINPROGRESS`, the thread parks
in `threadWaitRead` or `threadWaitWrite`, and GHC's IO manager (kqueue or
epoll) wakes it. Each connection is one green thread, so a slow upstream
never blocks `getHealth`, and `System.Timeout.timeout` can enforce the 10 s
connect and 60 s per-attempt limits. Two things differ between macOS and
Linux, and both are picked at run time from `System.Info.os`: the
`SOL_SOCKET`, `SO_REUSEADDR` and `SO_ERROR` constants, and the order of the
`ai_addr` and `ai_canonname` fields in `struct addrinfo`.

HTTPS: GHC's boot libraries have no TLS. For `https://` base URLs the server
spawns the OS `curl` binary with `--http1.1 --raw -i`. curl's stdout is then
the raw HTTP/1.1 response, and it is parsed by the same `readResponse` that
reads sockets. Plain `http://`, which the conformance mock uses, goes over the
FFI sockets.

## Haskell idioms worth a look

* **One parser-combinator monad for every format.** `Parse.hs` defines
  `newtype P a = P (ByteString -> Int -> R a)`, a strict, backtracking
  parser over a strict `ByteString`. That type is used for CARv1 sections,
  DAG-CBOR, CIDs, protobuf fields, every bincode layout, Solana
  `VersionedTransaction`, and the JSON-RPC request body. Two examples:
  * The bincode fallback chain from `WIRE_FORMATS.md` §11.4 is a list
    comprehension: `[v | p <- layouts, Right v <- [runP p bytes]]`.
  * The EOF-default fields are a single combinator:
    ``eofOpt p = atEnd >>= \e -> if e then pure Nothing else bOption p``.
* **Algebraic types for the data.** `data Cbor = CU Word64 | CN Word64 |
  CB ByteString | ...` and `data TxErr = EStr | EObj | EArr | EInt` mirror the
  wire and JSON shapes, and decoding is pattern matching on them, as in
  `kind n (CA xs@(CU k : _))`.
* **Parse and convert are separate stages.** `protoMeta` has type
  `ByteString -> Either String (Either String Meta)`. A `Left` from the outer
  `Either` means the bytes did not parse as protobuf, so the bincode fallback
  runs. A `Left` from the inner one means conversion failed, which is final.
  That is the rule in `WIRE_FORMATS.md` §9.2.
* **Native `Word64`.** Slots, offsets, balances, CRC-64 and FNV-1a are plain
  `Word64` with wrapping arithmetic. `2^64-1` is a valid slot, and the server
  answers `-32004` for it.
* **A pure Zstandard decoder with a mutable inside.** `Zstd.decompress ::
  ByteString -> Either String ByteString` is a pure function. Inside, it
  works like libzstd: unboxed `UArray` FSE and Huffman tables, one growable
  `ForeignPtr` output buffer, and sequence execution with `copyBytes`. Bit
  readers are plain `Int` state passed through strict loops.
* **Laziness is kept in check.** Every reply is rendered to a strict
  `ByteString` and forced with `evaluate` inside the request's exception
  handler, so a decode error cannot surface while the bytes are being sent.
  Asynchronous exceptions are re-thrown, not converted to `-32603`.
