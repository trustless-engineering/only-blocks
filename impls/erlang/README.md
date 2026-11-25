# OnlyBlocks in Erlang/OTP 26

Uses only OTP: no rebar3 and no Hex packages. `build.sh` compiles `src/*.erl`
to `ebin/` with `erlc`, and `run.sh` `exec`s `erl -noshell`.

```sh
./build.sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

* **Bit syntax does the decoding.** Each wire format is a set of binary
  patterns:
  * LEB128 varints: `<<1:1, X:7, R/binary>>`;
  * compact-u16: `<<1:1, A:7, 0:1, B:7, R/binary>>` when `B =/= 0`;
  * CBOR heads: `<<Major:3, Info:5, R/binary>>`;
  * v0 messages: `<<1:1, 0:7, A, B, C, X/binary>>`;
  * v1 transactions: `<<16#81, A, B, C, ConfigMask:32/little, X/binary>>`;
  * Zstandard frame headers: `<<Fcs:2, Single:1, _:1, 0:1, Chk:1, Did:2, ...>>`.
* **Zstandard bitstreams.** The RFC 8878 decoder reverses each backward
  bitstream (Huffman, FSE weights, sequences) once. After that, reading N
  bits from the top is the big-endian match `<<_:Consumed, V:N, _/bits>>`.
  Match copies append to a growing binary, which the BEAM extends in place.
* **One process per connection.** Sixteen acceptors share the listen
  socket, so `getHealth` never waits behind an upstream fetch. Upstream
  concurrency is capped at 32 attempts with an `atomics` counter.
* **The VM parses HTTP.** `erlang:decode_packet(http_bin | httph_bin, ...)`
  parses inbound requests and Old Faithful responses. `gen_tcp` carries
  `http://`, and OTP `ssl` carries `https://`, verified against the OS
  trust store PEM.
* **Bounded LRUs.** Each cache (`slot → range`, `slot → blockhash`; 100 000
  entries) is a process that owns two ETS tables: a `set` of values and an
  `ordered_set` of recency ticks.
* **JSON.** OTP 26 predates the `json` module, so `ob_json` is a small parser
  that keeps number source text. That lets slot literals be validated exactly
  and ids be echoed byte for byte. Nesting is capped at 128 levels.
* **Errors.** RPC errors are `throw({rpc, Code, Msg})`. Every other
  exception becomes `-32603`.

**Process model.** The server is one OS process (`beam.smp`). The only
other process is the VM's own `erl_child_setup`. Every BEAM forks this
helper at boot to spawn ports; it is part of the runtime and can't be
turned off. The server never opens a port or child process: no `curl`,
no `os:cmd`, and the TLS trust store is read from a PEM file.
