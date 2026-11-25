# OnlyBlocks in Elixir

Standalone Elixir: no Mix project, no Hex packages. `build.sh` compiles
`lib/*.ex` with `elixirc` into `_build/ebin`. It uses Elixir from `PATH`,
reuses a cached toolchain path when available, or looks it up in the local
Nix store with `nix shell --offline nixpkgs#elixir`. It records the path in
`_build/elixir_bin`. `run.sh` builds if artifacts are missing, then `exec`s
`elixir --no-halt` directly.

```sh
./build.sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

* **Pattern-matched binaries everywhere.** Decoders are multi-clause
  functions such as `defp uvarint(<<1::1, x::7, r::binary>>, shift, acc)`.
  Results feed `|>` pipelines:
  `index |> Wire.frame_payload(frame) |> Wire.transaction()`.
* **Zstandard bitstreams.** Each backward bitstream is reversed once, so a
  bit read is `<<_::size(c), v::size(n), _::bits>> = rev`. Huffman literal
  weights come from a binary comprehension: `for <<w::4 <- packed>>, do: w`.
* **Errors.** Decode errors raise `OnlyBlocks.DecodeError`. RPC errors are
  thrown as `{:rpc, code, message}`. The codec fallbacks (zstd → raw,
  protobuf ⇄ bincode, strict → lenient) `rescue` only exceptions, so a thrown
  RPC error always reaches the client.
* **Bounded LRUs.** Each `OnlyBlocks.LRU` cache is a `GenServer` that owns
  an ETS `:set` of values and an `:ordered_set` of recency ticks.
* **Networking.** HTTP runs over `:gen_tcp` and `:ssl` with
  `:erlang.decode_packet/3` for parsing. Each connection gets its own
  process, and an `:atomics` counter caps upstream attempts at 32.
* **JSON.** `OnlyBlocks.JSON` is a small parser that keeps number source
  text, so slots are validated as literals and ids are echoed verbatim.
  Nesting is capped at 128 levels.

**Process model.** The server runs in `beam.smp`. The BEAM starts its own
`erl_child_setup` OS helper for managing external port programs. The
listener uses OTP TCP sockets. Numeric bind addresses are parsed directly,
so binding `127.0.0.1` skips hostname resolution. Hostname lookups can
start OTP's `inet_gethost` helper. HTTP and TLS run inside the BEAM.
