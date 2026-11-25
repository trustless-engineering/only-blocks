# OnlyBlocks in OCaml

A historical Solana `getBlock` JSON-RPC 2.0 server that reads blocks from Old
Faithful with two HTTP Range reads. It is one native executable built by
`ocamlopt`. Nothing else is installed: no OPAM packages, no dune, no
ocamlfind.

```sh
bash build.sh      # ocamlopt -O2 -I +unix -I +threads unix.cmxa threads.cmxa ...
bash run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

`build.sh` uses `ocamlopt` from `PATH` if there is one. Otherwise it runs
`nix shell nixpkgs#ocaml --offline`, so the compiler has to be in the Nix
store already. It copies the sources into `build/`, so the source tree never
gets `.cmx`, `.cmi` or `.o` files. The binary goes to `bin/onlyblocks`.

## How it stays at zero dependencies

It links only two libraries, and both ship with the compiler:

* `unix.cmxa` for sockets, `select`, pipes, `getaddrinfo`, `create_process`
  and signals;
* `threads.cmxa` for systhreads: one thread per connection and one thread
  that waits for signals. The assignment names only `unix.cmxa`, but threads
  is part of the same OCaml distribution and is not a package. Without it,
  a slow upstream fetch would block `getHealth`.

Everything else is plain OCaml in this directory:

| File | What it does |
|---|---|
| `zstd.ml` | An RFC 8878 decoder ported from `docs/ZSTD_MINI_SPEC.md`: FSE, Huffman (1 and 4 streams, direct and FSE-coded weights), all four sequence modes, repeat offsets, XXH64 checksums, skippable and concatenated frames, the 512 MiB limit |
| `wire.ml` | A bounds-checked cursor, LEB128 and compact-u16, DAG-CBOR (indefinite lengths, half floats, tags stripped), CIDv0/v1, the CARv1 section index, DataFrame DFS reassembly checked with CRC-64/GO-ISO or FNV-1a, Base58, Base64, `VersionedTransaction` |
| `meta.ml` | A protobuf wire reader driven by a small schema table, prost-style merging of repeated message fields, the bincode `StoredTransactionStatusMeta` layouts (the current one, legacy V1/V2/V3, and a lenient fallback), `TransactionError`, and the epoch-157 / zstd fallback chain |
| `json.ml` | A depth-limited JSON parser that keeps number tokens as source text, and a JSON printer |
| `http.ml` | The inbound HTTP/1.1 reader (Content-Length and chunked bodies, 413 above 1 MiB), the outbound Range client, and Retry-After parsing (delta-seconds and IMF-fixdate) |
| `main.ml` | Bounded LRUs, the 2-range-read pipeline with retries, the `getBlock` JSON encoder and JSON-RPC dispatch |

HTTPS: OCaml's standard library has no TLS. For `https://` base URLs the
server spawns the OS `curl` binary, the transport exception in SPEC §3.3. It
passes `--http1.1 --raw -i`, so curl's stdout is the raw HTTP/1.1 response:
headers plus the undecoded body. That stream goes through a pipe into the
same response parser the socket path uses, so the 206/404/429/5xx handling
and the length caps work the same on both. Plain `http://`, which the
conformance mock uses, goes over native `Unix` sockets.

## OCaml idioms worth a look

* **The 63-bit `int` problem.** OCaml's native `int` is 63 bits, which cannot
  hold a `u64` slot, a CBOR `uint64` DataFrame hash or a CRC. Those values
  are `Int64` and handled with `Int64.unsigned_compare`, `unsigned_div`,
  `unsigned_rem` and `%Lu`. `18446744073709551615` is a valid slot, and the
  server answers `-32004` for it.
* **Parse and convert are separate stages.** `Meta.proto_meta` parses the
  whole protobuf message at the wire level and returns a `unit -> meta`
  thunk. If parsing fails, the bincode fallback gets its turn. If the thunk
  fails, for example on a bad `TransactionError` or a 31-byte pubkey, the
  error is final, which is the rule in `WIRE_FORMATS.md` §9.2.
* **`match ... with exception`.** The zstd, bincode and protobuf fallback
  chains are pattern matches with `exception` arms, not nested `try` blocks.
* **Merging by concatenation.** In protobuf, a non-repeated message field
  that appears more than once is merged field by field. Concatenating its
  encodings and parsing the result once gives the same merge.
* **Signals.** `SIGINT` and `SIGTERM` are blocked in every thread. One
  thread takes them with `Thread.wait_signal`, so a signal can never land in
  the middle of a socket read.
