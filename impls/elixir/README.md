# OnlyBlocks in Elixir

Standalone Elixir: no Mix project, no Hex packages. `build.sh` compiles
`lib/*.ex` with `elixirc` into `_build/ebin`. It takes Elixir from `PATH` or
from the local Nix store (`nix shell nixpkgs#elixir`, offline first) and
records that toolchain path in `_build/elixir_bin`. `run.sh` `exec`s
`elixir --no-halt` directly, so it starts in about a second and never
invokes nix.

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
