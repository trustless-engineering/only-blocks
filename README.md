# instant-rpc

Historical-only Solana JSON-RPC 2.0 server backed directly by [Old Faithful](https://old-faithful.net/) (`https://files.old-faithful.net`) over HTTP/2 Range requests — with **zero local disk downloads**.

## Architecture

`instant-rpc` is a single standalone Rust binary that serves historical Solana blocks and transactions directly from Old Faithful's public archive strictly in RAM:

1. **Range Read 1 (12 bytes):** Given a `slot`, compute `epoch = slot / 432_000` and `slot_idx = slot % 432_000`, then fetch bytes `[slot_idx * 12, slot_idx * 12 + 11]` from `/{epoch}/epoch-{epoch}-slot-ranges.raw` to resolve the slot's `(offset: u64, length: u32)` inside the epoch CAR archive (cached in a bounded RAM-only LRU).
2. **Range Read 2 (exact slot slice):** Fetch bytes `[offset, offset + length - 1]` from `/{epoch}/epoch-{epoch}.car` into RAM, parse CARv1 / IPLD DAG-CBOR sections zero-copy, reassemble single- and multi-frame `DataFrame`s (CRC64 / FNV verified), decode transaction metadata and block rewards, and encode the Solana JSON-RPC response.
3. **Zero Disk Writes:** No CAR files, no index files (`compiszd` / `sig-to-cid.index`), no temp files, and no disk caches are ever written. All HTTP buffers and LRU caches (`slot -> range` and `slot -> blockhash`) live strictly in bounded RAM.

## Build & Run

Requires a Rust toolchain (`cargo` / `rustc`).

```sh
cargo build --release
./target/release/instant-rpc
```

By default the server listens on `127.0.0.1:8899` and queries `https://files.old-faithful.net`.

### CLI Options

Run `./target/release/instant-rpc --help` for full option details:

| Flag | Env Var | Default | Description |
| --- | --- | --- | --- |
| `--bind <BIND>` | `INSTANT_RPC_BIND` | `127.0.0.1:8899` | Socket address to bind the JSON-RPC HTTP server to |
| `--base-url <BASE_URL>` | `OLD_FAITHFUL_BASE_URL` | `https://files.old-faithful.net` | Base URL for the Old Faithful archive |
| `--max-slice-bytes <BYTES>` | — | `134217728` (128 MiB) | Maximum allowed CAR slice size in bytes |
| `--max-concurrent-requests <N>` | — | `32` | Maximum concurrent in-flight HTTP/2 Range requests to Old Faithful |
| `--slot-range-cache-capacity <N>` | — | `100000` | Capacity of the RAM-only `slot -> range` LRU cache (`0` disables) |
| `--blockhash-cache-capacity <N>` | — | `100000` | Capacity of the RAM-only `slot -> blockhash` LRU cache (`0` disables) |
| `--max-request-body-bytes <BYTES>` | — | `1048576` (1 MiB) | Maximum HTTP request body size accepted by the server |
| `--max-batch-size <N>` | — | `100` | Maximum number of requests allowed in a single JSON-RPC batch array |
| `--connect-timeout-secs <SECS>` | — | `10` | HTTP connect timeout in seconds |
| `--request-timeout-secs <SECS>` | — | `60` | Per-request HTTP timeout in seconds |
| `--max-retries <N>` | — | `4` | Maximum retry attempts on transient `429`/`5xx`/transport errors (`404` is never retried) |

Logging verbosity is controlled via `RUST_LOG` (default `info`). The server shuts down gracefully on `SIGINT` and `SIGTERM`.

## Supported RPC Methods

All JSON-RPC 2.0 requests are sent via `POST /` with `Content-Type: application/json`.

### `getHealth`

```sh
curl -sS -X POST http://127.0.0.1:8899 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
```

### `getBlock`

Supports `encoding` (`json`, `jsonParsed`, `base64`, `base58`), `transactionDetails` (`full`, `accounts`, `signatures`, `none`), `rewards` (`true`/`false`), `maxSupportedTransactionVersion`, and `commitment` (`finalized`/`confirmed`).

```sh
# Modern archived slot (Epoch 700, contains v0 transactions)
curl -sS -X POST http://127.0.0.1:8899 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getBlock",
    "params": [302400001, {
      "encoding": "jsonParsed",
      "transactionDetails": "full",
      "rewards": true,
      "maxSupportedTransactionVersion": 0
    }]
  }'
```

### `getTransaction` (Slot-Hinted)

**Requires a `slot` hint in the config object.**

```sh
curl -sS -X POST http://127.0.0.1:8899 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getTransaction",
    "params": ["<BASE58_SIGNATURE>", {
      "slot": 302400001,
      "encoding": "jsonParsed",
      "maxSupportedTransactionVersion": 0
    }]
  }'
```

## Scope & Behavior Notes

- **Required `slot` hint for `getTransaction`:** `instant-rpc` does **not** scan epochs, does **not** download `sig-to-cid.index` / `compiszd` indexes, and does **not** query an upstream Solana RPC for slot discovery. Calling `getTransaction` without a valid non-negative integer `slot` in the config object immediately returns JSON-RPC `-32602` (`Invalid params`) with zero outbound HTTP requests.
- **Historical-only (no upstream Solana RPC proxying):** Every lookup is served exclusively from Old Faithful. Requests for unarchived/future slots return JSON-RPC `-32004` (`Block not available ... historical-only server`) without retrying `404` responses.
- **Skipped slots:** `getBlock` returns `-32007` (`Slot ... was skipped`); `getTransaction` returns `{"result": null}` (matching standard Solana RPC behavior).
- **All 4 transaction encodings:** `json`, `jsonParsed`, `base64`, and `base58` are supported for both `getBlock` and `getTransaction`.
- **Full historical compatibility:** Handles pre-Epoch 157 (`slot < 67_824_000`) legacy bincode transaction metadata and rewards, modern zstd-compressed protobuf metadata and rewards, multi-frame `DataFrame` continuations, and ~55 MiB epoch-boundary reward blocks (e.g., slot `302_400_000`).
- **Versioned transactions:** Requests encountering v0 transactions without `"maxSupportedTransactionVersion": 0` return `-32015`.

## Testing

### Unit & Mock Integration Tests (Offline)

```sh
cargo test
```

Includes CAR/IPLD decoding, pre-Epoch 157 bincode + protobuf decoding, JSON-RPC 2.0 edge-case and limit enforcement tests, and a deterministic mock-server concurrency & `429` burst soak test verifying bounded in-flight concurrency and RAM LRU eviction.

### Live Old Faithful Integration Tests

Live tests hit `https://files.old-faithful.net` and are marked `#[ignore]` so `cargo test` stays offline and fast. Run them explicitly with:

```sh
cargo test -- --ignored --nocapture
```
