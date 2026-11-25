# OnlyBlocks Wire Formats: byte-level decoding reference

Status: **normative**. This document plus [`SPEC.md`](../SPEC.md) and
[`ZSTD_MINI_SPEC.md`](ZSTD_MINI_SPEC.md) are everything needed to turn
Old Faithful bytes into a byte-for-byte compatible `getBlock` JSON result. You
do not need to read any Rust crate or Solana repository.

The behaviour described here is the behaviour of the original crate-based
Rust reference oracle (the server that generated `conformance/fixtures/`),
including its use of `solana-transaction-status 3.1.14`, `serde_cbor 0.11`,
`cid 0.11`, `bincode 1.3` and `prost 0.14`. That oracle is no longer in the
tree. Its zero-crate successor `impls/rust/` and the independent
`impls/javascript-node/` both implement this document. They agree with each
other on every golden fixture and return identical JSON values for mainnet
slots `302400001` and `43200000`, so "the reference" below always means the
behaviour, not a file you need to read.
Wherever the reference is lenient (ignores
a field, defaults a value, falls back to another layout), this document says
so explicitly, because conformance fixtures depend on those exact choices. The
one deliberate OnlyBlocks deviation (`jsonParsed` instructions) is called out
in §13.5.

**How this document was verified.** An independent, stdlib-only Python
decoder was written from this text and the zstd mini-spec, not from the Rust
code. It reproduces:

* every applicable `getBlock` golden result in
  `conformance/fixtures/manifest.json` exactly (19 of 19);
* mainnet slot `302400001`, which has 140 transactions including v0
  transactions with lookup tables, compared against the Rust reference binary
  in all four encodings and all four `transactionDetails` modes, with
  `rewards` on and off. The only differences are the reference's parsed
  instructions of well-known programs (the §13.5 deviation);
* mainnet slot `43200000` (epoch 100, pre-157), compared the same way. It has
  208 transactions with zstd-wrapped bincode metadata: 204 use the current
  `StoredTransactionStatusMeta` layout and 4 use legacy layout #2 (§11.4: no
  `stack_height`, V1 token balances);
* genesis-era slots `1`, `2`, `5` and `10` (epoch 0), compared the same way.
  They have empty metadata frames (`"meta": null`, §12) and `blockTime: null`.

Contents:

1. Notation
2. Old Faithful files
3. CARv1 section stream
4. DAG-CBOR
5. Old Faithful IPLD node schemas
6. DataFrame reassembly, CRC-64/GO-ISO, FNV-1a
7. From a CAR slice to a block
8. Solana `VersionedTransaction` wire format
9. Transaction-metadata and rewards frames (zstd, epoch-157 split)
10. Protobuf
11. Bincode (pre-epoch-157 metadata, `TransactionError`)
12. Internal data model
13. JSON serialization of a `getBlock` result
14. Account flags (`signer` / `writable`) and the reserved-key list
15. Base58, Base64, numbers, `real_number_string_trimmed`
16. Worked hex examples (from `conformance/fixtures`)

---

## 1. Notation

* `u8/u16/u32/u64` are unsigned and `i32/i64` are two's complement. **LE** means
  little-endian.
* `bytes[a..b]` is a half-open range.
* "**Error**" means the request fails with JSON-RPC `-32603 Internal error`
  (see `SPEC.md` §6). It never means a crash: every bounds check must be explicit.
* Base58 below always means the Bitcoin alphabet (§15.1). A "pubkey" or "hash"
  string is the Base58 of 32 bytes, and a "signature" string is the Base58 of 64
  bytes.

---

## 2. Old Faithful files

For slot `S`: `epoch = S / 432000`, `slot_idx = S % 432000`.

| File | URL path | Content |
|---|---|---|
| slot index | `/{epoch}/epoch-{epoch}-slot-ranges.raw` | `432000` fixed 12-byte records |
| archive | `/{epoch}/epoch-{epoch}.car` | CARv1 stream; each slot's sections are contiguous |

Record `slot_idx` lives at bytes `[slot_idx*12, slot_idx*12 + 11]` (inclusive):

```
offset 0..8   u64 LE  offset  - first byte of the slot inside epoch-{epoch}.car
offset 8..12  u32 LE  length  - byte length of the slot's CAR slice; 0 = skipped slot
```

Example (golden fixture `epoch-100-slot-ranges.raw`, slot `43200001` =
`slot_idx 1`, bytes `12..23`):

```
b6 00 00 00 00 00 00 00  a3 03 00 00
offset = 0xb6 = 182      length = 0x3a3 = 931   -> Range: bytes=182-1112 on epoch-100.car
```

The CAR slice of one slot (`bytes=offset-(offset+length-1)`) is a
**headerless** CARv1 section stream (§3). Its last section is normally the
slot's `Block` node.

---

## 3. CARv1 section stream

### 3.1 Unsigned LEB128 varint (`uvarint`)

Little-endian base-128. Each byte contributes its low 7 bits, and bit 7 (`0x80`)
means "more bytes follow".

```
x = 0; shift = 0
for i in 0..10:
    if no byte left: Error (truncated)
    b = next byte
    if b < 0x80:
        if i == 9 and b > 1: Error (overflow)
        return x | (b << shift)
    x |= (b & 0x7f) << shift
    shift += 7
Error (overflow: more than 10 bytes)
```

Examples: `4a` = 74, `ac 02` = 300, `80 80 04` = 65536.

### 3.2 Sections

```
section := uvarint(L)  CID  node_bytes      // CID ++ node_bytes is exactly L bytes
```

Parse sections until the slice is exhausted:

1. Read `L`. If `L == 0`, skip it (no payload) and continue.
2. If `L > 33_554_432` (32 MiB): Error. If fewer than `L` bytes remain: Error.
3. **Optional CARv1 header** (useful for full `.car` files and synthetic
   fixtures). This applies only to the *first non-empty* section. If its first
   byte has CBOR major type 5 (`(b & 0xE0) == 0xA0`), *and* the whole section
   parses as one CBOR map, *and* that map has a text key `"version"`, then skip
   the section. Otherwise treat it like any other section.
4. Parse a CID from the start of the section (§3.3). The rest of the section
   is the node's DAG-CBOR bytes (not validated yet).
5. Store `index[cid_bytes] = node_bytes`. A later duplicate CID overwrites an
   earlier one. Key the map by the **raw CID bytes** exactly as they appear;
   CID equality is byte equality.
6. **Block detection.** If `node_bytes` starts with a CBOR array header
   (major type 4, additional info `0..27` or `31`) *and* the byte immediately
   after that header is `0x02` (the small unsigned integer kind `2`), remember
   this section as "the Block section". The **last** such section wins.

### 3.3 CIDs

Read two uvarints `a`, `b` from the section start:

* `a == 0x12 && b == 0x20`: **CIDv0**. The next 32 bytes are a SHA-256
  digest. The CID bytes are `12 20 <32 bytes>` (34 bytes).
* Otherwise `a` is the CID version. `a == 0` → Error ("explicit CIDv0").
  `a >= 2` → Error. `a == 1`: **CIDv1**, `b` is the multicodec (`0x71`
  dag-cbor, `0x55` raw), then uvarint `hash_code`, uvarint `hash_len`
  (`hash_len > 64` → Error), then `hash_len` digest bytes. The CID bytes are
  everything from `a` through the digest.

Old Faithful nodes use CIDv1 + dag-cbor + sha2-256, which is 36 bytes:
`01 71 12 20 <32-byte digest>`.

**Empty identity CID** `bafkqaaa` = bytes `01 55 00 00` (v1, raw, identity
hash `0x00`, length `0`). A CID with `hash_code == 0x00 && hash_len == 0`
means "absent" (used for a `Block` without rewards).

---

## 4. DAG-CBOR (RFC 8949 subset as decoded by the reference)

A node's bytes must decode as **exactly one** CBOR data item. Trailing bytes
are an Error. Nesting deeper than 128 levels may be rejected.

Initial byte: `major = b >> 5`, `info = b & 0x1F`. Argument:

| `info` | Argument |
|---|---|
| `0..23` | the value itself |
| `24` | next 1 byte |
| `25` | next 2 bytes, big-endian |
| `26` | next 4 bytes, big-endian |
| `27` | next 8 bytes, big-endian |
| `28..30` | Error |
| `31` | indefinite length (majors 2, 3, 4, 5 only; terminated by a `0xFF` "break") |

Non-shortest argument encodings are accepted.

| Major | Meaning | Decoded value |
|---|---|---|
| 0 | unsigned int | `n` (`0..2^64-1`) |
| 1 | negative int | `-1 - n` |
| 2 | byte string | `n` bytes (indefinite: concatenation of definite chunks) |
| 3 | text string | `n` bytes of UTF-8 (invalid UTF-8 → Error) |
| 4 | array | `n` items |
| 5 | map | `n` key/value pairs |
| 6 | tag | tag number `n`, then **one** item. **The tag is discarded and the item is returned as is.** |
| 7 | simple/float | `0xF4` false, `0xF5` true, `0xF6` null, `0xF7` undefined (treat as null), `0xF9/0xFA/0xFB` half/single/double float |

**CID links.** DAG-CBOR writes a link as tag 42 (`D8 2A`) wrapping a byte
string whose first byte is `0x00` (the multibase identity prefix), followed by
the raw CID bytes. Because tags are discarded, a link is decoded as "a byte
string whose first byte is `0x00`". Then:

* parse the CID from `bytes[1..]` (§3.3). Trailing bytes after the CID are
  ignored.
* A link position holding a byte string that is empty or whose first byte is
  not `0x00` is an Error. So is any non-byte-string value where the schema
  requires a link inside a list (§5).

Example: `d8 2a 58 25 00 01 71 12 20 <32 bytes>` is tag 42, then bytes(37),
then `00`, then the 36-byte CIDv1.

"Integer" accessors used in §5:

* `as_u64(v)`: `v` is a CBOR integer in `0..2^64-1`, otherwise *none*. Floats
  are never integers.
* `as_i64(v)`: `v` is a CBOR integer in `-2^63..2^63-1`, otherwise *none*.

---

## 5. Old Faithful IPLD node schemas

Every node is a CBOR **array** whose element `[0]` is the node kind:

| Kind | Name | Layout (array elements) |
|---|---|---|
| `0` | Transaction | `[0, data: DataFrame, metadata: DataFrame, slot, index]` |
| `1` | Entry | `[1, num_hashes, hash: bytes(32), transactions: [link…]]` |
| `2` | Block | `[2, slot, shredding: [...], entries: [link…], meta: [parent_slot, blocktime, block_height], rewards: link]` |
| `3` | Subset | `[3, first, last, blocks: [link…]]` (not used by getBlock) |
| `4` | Epoch | `[4, epoch, subsets: [link…]]` (not used by getBlock) |
| `5` | Rewards | `[5, slot, data: DataFrame]` |
| `6` | DataFrame | `[6, hash, index, total, data: bytes, next: [link…]]` |

A node that is not an array, or whose `[0]` is not the expected kind, is an
Error. Missing trailing elements are treated as absent. Field extraction
rules, exactly as the reference applies them:

**DataFrame** (inline inside Transaction/Rewards, or a separate section when
it is a continuation):

* `hash = as_u64([1])`, so null, missing or non-integer gives *none*.
* `[2]` (index) and `[3]` (total) are **ignored**.
* `data = [4]` if it is a byte string, else empty.
* `next = [5]` if it is a **non-empty** array: every element must be a link
  (Error otherwise). Anything else (null, missing, `[]`) gives *none*.

**Block**:

* `slot = as_u64([1])`. *none* is an Error.
* `entries = [3]` if it is an array (every element must be a link), else empty.
* `meta = [4]` if it is an array, else all defaults:
  * `parent_slot = as_u64(meta[0])`, or `0`;
  * `blocktime = as_i64(meta[1])`, but **`0` maps to *none*** (null in JSON);
  * `block_height = as_u64(meta[2])`, or *none*.
* `rewards`: if `[5]` is a byte string, it must be a valid link. If that CID is
  the empty identity CID, rewards are *none*. A missing or non-bytes `[5]`
  also gives *none*.
* `[2]` (shredding) is ignored.

**Entry**:

* `hash = [2]`, which must be a byte string of exactly 32 bytes (Error otherwise).
* `transactions = [3]` if it is an array (every element a link), else empty.
* `[1]` (num_hashes) is ignored.

**Transaction**:

* `data = [1]`, which must exist and be a DataFrame array (kind 6); Error otherwise.
* `metadata = [2]`: if it is an array, it is parsed as a DataFrame (errors
  propagate). Otherwise (null or missing) it is an empty DataFrame
  (`hash` *none*, no data, no `next`).
* `[3]` (slot) and `[4]` (index) are ignored.

**Rewards**:

* `data = [2]` parsed as a DataFrame if present (errors propagate), else an
  empty DataFrame. `[1]` is ignored.

---

## 6. DataFrame reassembly, CRC-64/GO-ISO, FNV-1a

### 6.1 Reassembly (iterative DFS)

```
reassemble(first):
    if first.next is none:
        if first.hash is some: verify(first.data, first.hash)
        return first.data
    out = copy of first.data
    visited = {}
    stack = reverse(first.next)               // pop() yields first.next[0] first
    while stack not empty:
        cid = stack.pop()
        if cid in visited: Error (cyclic DataFrame)  // any repeat, even in a DAG
        visited.add(cid)
        node = index[cid] or Error (missing CID)
        frame = parse DataFrame(node)          // must be kind 6
        out += frame.data
        if frame.next is some: push reverse(frame.next) onto stack
    if first.hash is some: verify(out, first.hash)
    return out
```

Only the **first** frame's `hash` is checked, against the **whole**
reassembled payload. Continuation frames' `hash`, `index` and `total` are
ignored.

`verify(data, expected)` passes if **either** `crc64_go_iso(data) == expected`
**or** `fnv1a_64(data) == expected`. Otherwise it is an Error.

### 6.2 CRC-64/GO-ISO

The reveng catalogue's `CRC-64/GO-ISO`: width 64, poly `0x1B` (reflected
`0xD800000000000000`), **init `0xFFFFFFFFFFFFFFFF`**, refin/refout true,
**xorout `0xFFFFFFFFFFFFFFFF`**. (Go's `crc64.Checksum(data,
crc64.MakeTable(crc64.ISO))` computes the same value. Go's API takes a `0`
initial value because it inverts internally.)

```
crc = 0xFFFFFFFFFFFFFFFF
for byte in data:
    crc ^= byte
    repeat 8 times:
        crc = (crc >> 1) ^ 0xD800000000000000  if (crc & 1) else  crc >> 1
return crc ^ 0xFFFFFFFFFFFFFFFF
```

Check values: `crc64("123456789") = 0xB90956C775A41001` and `crc64("") = 0`.

### 6.3 FNV-1a 64

The Rust `fnv::FnvHasher` is **FNV-1a**: XOR first, then multiply.

```
h = 0xCBF29CE484222325
for byte in data: h = ((h ^ byte) * 0x100000001B3) mod 2^64
return h
```

Check values: `fnv1a("") = 0xCBF29CE484222325`, `fnv1a("a") =
0xAF63DC4C8601EC8C` and `fnv1a("123456789") = 0x06D5573923C6CDFC`.

---

## 7. From a CAR slice to a block

Given requested slot `S` and its CAR slice:

1. Index the slice (§3). No Block section → Error. Parse the Block (§5).
   `block.slot != S` → Error.
2. **blockhash** = the `hash` of the Entry referenced by the **last** link in
   `block.entries` (missing CID → Error). If `entries` is empty, it is 32 zero
   bytes (Base58 `11111111111111111111111111111111`).
3. **previousBlockhash** is resolved by the server (`SPEC.md` §4.5), before
   any transaction or reward is decoded.
4. **Transactions** (only when `transactionDetails` ≠ `"none"`). For each
   entry link in order (missing → Error), parse the Entry. For each
   transaction link in order (missing → Error), parse the Transaction node:
   1. `tx_bytes = reassemble(tx.data)` and decode it as a
      `VersionedTransaction` (§8). A decode failure is an Error.
   2. If metadata is wanted (`transactionDetails` `"full"` or `"accounts"`):
      `meta_bytes = reassemble(tx.metadata)` and decode the metadata frame
      (§9). The result is one of:
      * a metadata value → `Complete(tx, meta)`;
      * *none* (empty frame) and a **legacy** message → `MissingMetadata(tx)`;
      * *none* and a **v0** message → `Complete(tx, default_meta)` (§12).
   3. If metadata is not wanted (`"signatures"`), the metadata DataFrame is
      not touched at all. Its bytes may be corrupt without causing an error.
5. **Rewards** (only when `rewards: true`). If `block.rewards` is *none*, or its
   CID is **not in the index**, rewards are empty with no partition count. No
   error in either case. Otherwise parse the Rewards node, reassemble its
   DataFrame, and decode the rewards frame (§9).
6. `parentSlot = block.meta.parent_slot`, `blockTime = block.meta.blocktime`,
   `blockHeight = block.meta.block_height`.

The order of the `transactions` array equals entry order, then
transaction-link order within each entry.

---

## 8. Solana `VersionedTransaction` wire format

### 8.1 compact-u16 (`short_vec` length)

1 to 3 bytes, LEB128-style. Byte `k` contributes `(b & 0x7F) << (7*k)`, and
`b & 0x80` means "continue". Strict rules (violations are Errors):

* a byte equal to `0x00` in position 1 or 2 (an alias/non-canonical encoding);
* a continuation bit on the 3rd byte;
* a value above `0xFFFF`.

Examples: `00`=0, `7f`=127, `80 01`=128, `ff 7f`=16383, `80 80 01`=16384,
`ff ff 03`=65535.

### 8.2 Layout

```
VersionedTransaction:
  compact-u16 num_signatures, then num_signatures × 64-byte signatures
  message

message (first byte p):
  if p & 0x80 == 0:  LEGACY message, and p itself is num_required_signatures
  else: version = p & 0x7F
        version 0  -> v0 message follows (p consumed)
        version 127 -> Error ("off-chain messages are not accepted")
        other      -> Error (unsupported version)

legacy message:
  u8  num_required_signatures (= p)
  u8  num_readonly_signed_accounts
  u8  num_readonly_unsigned_accounts
  compact-u16 n, n × 32-byte account keys
  32-byte recent_blockhash
  compact-u16 m, m × CompiledInstruction

v0 message (after the 0x80 prefix):
  u8 ×3 header (same three fields)
  compact-u16 n, n × 32-byte static account keys
  32-byte recent_blockhash
  compact-u16 m, m × CompiledInstruction
  compact-u16 t, t × MessageAddressTableLookup

CompiledInstruction:
  u8 program_id_index
  compact-u16 k, k × u8 account indexes
  compact-u16 d, d × u8 data

MessageAddressTableLookup:
  32-byte account_key (the lookup table address)
  compact-u16 w, w × u8 writable_indexes
  compact-u16 r, r × u8 readonly_indexes
```

* Trailing bytes after the transaction are **ignored** (the reference uses
  bincode's default "allow trailing bytes").
* No sanitization is performed (signature counts, index bounds), *except*
  where an index is dereferenced during JSON encoding (§13).
* The "version" of a transaction is `"legacy"` or the number `0`.

### 8.3 Raw bytes for `base64` / `base58`

The reference re-serializes the decoded transaction. Because every length is
canonical (§8.1), that is exactly **the prefix of `tx_bytes` consumed by the
parser**, without any trailing bytes. Encode that prefix with Base64 (§15.2) or
Base58 (§15.1).

---

## 9. Transaction-metadata and rewards frames

`BINCODE_SLOT_CUTOFF = 157 * 432000 = 67_824_000`. Slots **below** it are
"pre-157" and slots at or above it are "modern". `MAX_DECOMPRESSED_BYTES =
512 MiB` applies to every zstd decode.

### 9.1 Frame unwrapping (identical for metadata and rewards)

```
decode_frame(slot, frame):
    if frame is empty:
        metadata -> none            rewards -> (empty list, no partitions)
    if frame starts with 28 B5 2F FD:
        try plain = zstd_decompress(frame)          # ZSTD_MINI_SPEC.md
        on success: return decode_bytes(slot, plain)      # its errors propagate
        on zstd failure: return decode_bytes(slot, frame) # or Error
    else:
        try return decode_bytes(slot, frame)
        on failure: try plain = zstd_decompress(frame)
                    success -> return decode_bytes(slot, plain)
                    failure -> Error (the first failure)
```

### 9.2 Payload decoding with the epoch-157 split

```
decode_metadata_bytes(slot, b):
    if slot < 67_824_000:
        bincode_metadata(b)  (§11.4)          -> on success return it
        else protobuf TransactionStatusMeta(b) -> convert (§10.3) or Error
    else:
        protobuf TransactionStatusMeta(b) parses -> convert (§10.3); conversion errors are final
        protobuf parse fails -> bincode_metadata(b) or Error

decode_rewards_bytes(slot, b):
    if slot < 67_824_000:
        bincode_rewards(b) (§11.5)  -> (list, no partitions)
        else protobuf Rewards(b)    -> (list, num_partitions) or Error
    else:
        protobuf Rewards(b)         -> (list, num_partitions)
        else bincode_rewards(b)     -> (list, no partitions) or Error
```

Note: a zero-length protobuf message is valid and gives all defaults. An
empty *decompressed* modern rewards payload therefore gives no rewards and no
partition count.

---

## 10. Protobuf (`solana.storage.ConfirmedBlock`)

### 10.1 Wire format

A message is a sequence of `key` + `value` pairs. `key = uvarint`, where
`field_number = key >> 3` and `wire_type = key & 7`:

| Wire type | Encoding |
|---|---|
| `0` VARINT | uvarint, at most 10 bytes (10th byte `<= 1`) |
| `1` I64 | 8 bytes LE (`double` here) |
| `2` LEN | uvarint length, then that many bytes |
| `5` I32 | 4 bytes LE |
| `3`/`4` | deprecated groups: skip to the matching end-group (or Error) |

Decoding rules (prost semantics):

* Unknown field numbers are skipped according to their wire type.
* A known field with the wrong wire type is an Error. Exception: a `repeated`
  scalar (`uint64` balances) is accepted both **packed** (wire type 2
  containing concatenated varints) and **unpacked** (one wire-type-0 key per
  element), and both may be mixed.
* Missing fields take defaults: `0`, `false`, `""`, empty bytes, empty list.
  Missing `optional` scalars and message fields are *absent*.
* A non-repeated scalar appearing twice: the last value wins. A non-repeated
  message appearing twice: the occurrences are merged field by field.
* `uint32` fields are the varint truncated to 32 bits. `int64` and `int32`
  are two's complement (negative values use 10-byte varints) and `int32`
  truncates to 32 bits. `bool` is `varint != 0`.
* `string` must be valid UTF-8, otherwise the whole message fails to parse.
* Truncated input, or a length running past its enclosing message, is a parse
  failure.

### 10.2 Schemas (field number: type name)

`TransactionStatusMeta`:

| # | Type | Name |
|---|---|---|
| 1 | `TransactionError` (message) | `err` |
| 2 | `uint64` | `fee` |
| 3 | `repeated uint64` | `pre_balances` |
| 4 | `repeated uint64` | `post_balances` |
| 5 | `repeated InnerInstructions` | `inner_instructions` |
| 6 | `repeated string` | `log_messages` |
| 7 | `repeated TokenBalance` | `pre_token_balances` |
| 8 | `repeated TokenBalance` | `post_token_balances` |
| 9 | `repeated Reward` | `rewards` |
| 10 | `bool` | `inner_instructions_none` |
| 11 | `bool` | `log_messages_none` |
| 12 | `repeated bytes` | `loaded_writable_addresses` |
| 13 | `repeated bytes` | `loaded_readonly_addresses` |
| 14 | `ReturnData` (message) | `return_data` |
| 15 | `bool` | `return_data_none` |
| 16 | `optional uint64` | `compute_units_consumed` |
| 17 | `optional uint64` | `cost_units` |

`TransactionError`: `1: bytes err`. It holds the **bincode** encoding of a
`TransactionError` (§11.3).

`InnerInstructions`: `1: uint32 index`, `2: repeated InnerInstruction instructions`.

`InnerInstruction`: `1: uint32 program_id_index`, `2: bytes accounts` (each
byte is an account index), `3: bytes data`, `4: optional uint32 stack_height`.

`TokenBalance`: `1: uint32 account_index`, `2: string mint`,
`3: UiTokenAmount ui_token_amount`, `4: string owner`, `5: string program_id`.

`UiTokenAmount`: `1: double ui_amount`, `2: uint32 decimals`, `3: string amount`,
`4: string ui_amount_string`.

`ReturnData`: `1: bytes program_id`, `2: bytes data`.

`Rewards`: `1: repeated Reward rewards`, `2: NumPartitions num_partitions`.

`Reward`: `1: string pubkey`, `2: int64 lamports`, `3: uint64 post_balance`,
`4: int32 reward_type`, `5: string commission`, `6: string commission_bps`.

`NumPartitions`: `1: uint64 num_partitions`.

### 10.3 Converting protobuf to the internal model (§12)

`TransactionStatusMeta`:

* `status`: if `err` is present, bincode-decode `err.err` as a
  `TransactionError` (§11.3, **trailing bytes allowed**). Failure is an
  Error, including for an empty `err` message. If `err` is absent, the status
  is `Ok`.
* `fee`, `pre_balances`, `post_balances`: copied as they are.
* `inner_instructions`: *none* if `inner_instructions_none`, else the list
  (possibly empty). For each `InnerInstructions`: `index = index mod 256`. For
  each instruction: `program_id_index = value mod 256`, `accounts` and `data`
  as bytes, and `stack_height` = the optional value (absent → *none*).
* `log_messages`: *none* if `log_messages_none`, else the list (possibly empty).
* `pre_token_balances` / `post_token_balances`: **always present** (possibly
  empty). Each `TokenBalance` becomes:
  * `account_index = account_index mod 256`, plus `mint`, `owner` and
    `program_id` (strings, `""` if missing);
  * `ui_token_amount` defaults to all-zero/empty if absent. Then
    `decimals = decimals mod 256`, `amount` as it is, and
    `ui_amount = ui_amount` if `|ui_amount| > 2.220446049250313e-16`
    (f64 epsilon), **else *none***;
  * `ui_amount_string = ui_amount_string` if non-empty, else
    `real_number_string_trimmed(parse_u64(amount) or 0, decimals)` (§15.4).
* `rewards`: **always present**, with each `Reward` converted as below.
* `loaded_addresses`: `writable` from field 12 and `readonly` from field 13.
  Each entry must be exactly 32 bytes (Error otherwise).
* `return_data`: *none* if `return_data_none`. Otherwise, if field 14 is
  present, `program_id` must be 32 bytes (Error otherwise) and `data` is the
  bytes. If field 14 is absent, *none*.
* `compute_units_consumed`, `cost_units`: present iff the field appeared.

`Reward` (in metadata or in a block's Rewards):

* `pubkey` (string, copied verbatim), `lamports` (i64), `post_balance` (u64).
* `reward_type`: `1` Fee, `2` Rent, `3` Staking, `4` Voting, anything else
  (including `0`) is *none*.
* `commission`: if `commission` parses as a `u8`, use that number. Otherwise,
  if `commission_bps` parses as a `u16`, use `bps / 100` (integer division)
  when the result is `<= 255`, else *none*. Otherwise *none*. "Parses" means
  Rust `from_str`: ASCII digits with an optional leading `+`, no whitespace,
  no other signs, and the value must fit the type.

`Rewards`: `num_partitions = num_partitions.num_partitions` if the field-2
message is present (`0` if its inner field is missing), else *none*.

---

## 11. Bincode (pre-epoch-157 payloads, `TransactionError`)

### 11.1 Primitives (bincode 1.x, fixed-int encoding)

| Type | Encoding |
|---|---|
| `u8`/`u16`/`u32`/`u64`/`i64` | fixed width, LE |
| `f64` | 8 bytes LE IEEE-754 |
| `bool` | 1 byte, `0`/`1` (else Error) |
| `String` | `u64` LE byte length, then UTF-8 bytes (invalid UTF-8 → Error) |
| `Vec<T>` | `u64` LE element count, then elements |
| `Option<T>` | 1 byte tag: `0` None, `1` Some + `T` (else Error) |
| `enum` | `u32` LE variant index, then the variant's fields in order |
| `Result<T, E>` | enum: `0` = Ok(T), `1` = Err(E) |
| `Pubkey` / `Hash` | 32 raw bytes |
| `CompiledInstruction` | `u8 program_id_index`, **compact-u16** + account bytes, **compact-u16** + data bytes (same as §8.2) |
| `RewardType` | enum: `0` Fee, `1` Rent, `2` Staking, `3` Voting |

**EOF-default fields** (marked `eof` below). If the input is already
exhausted when such a field starts, the field (and therefore every later
field) takes its default (`None`, `0` or `""`) instead of failing. (Reference
quirk, informative: the default also applies if a fixed-width integer read
*inside* the field runs out of bytes, but not if a string/byte payload is
truncated. Conformance does not depend on it.)

**Strict mode** means the whole buffer must be consumed (trailing bytes are
an Error). **Lenient mode** ignores trailing bytes.

### 11.2 `InstructionError` (enum, `u32` variant index)

| # | Variant | # | Variant | # | Variant |
|---|---|---|---|---|---|
| 0 | GenericError | 18 | RentEpochModified | 36 | InvalidRealloc |
| 1 | InvalidArgument | 19 | NotEnoughAccountKeys | 37 | ComputationalBudgetExceeded |
| 2 | InvalidInstructionData | 20 | AccountDataSizeChanged | 38 | PrivilegeEscalation |
| 3 | InvalidAccountData | 21 | AccountNotExecutable | 39 | ProgramEnvironmentSetupFailure |
| 4 | AccountDataTooSmall | 22 | AccountBorrowFailed | 40 | ProgramFailedToComplete |
| 5 | InsufficientFunds | 23 | AccountBorrowOutstanding | 41 | ProgramFailedToCompile |
| 6 | IncorrectProgramId | 24 | DuplicateAccountOutOfSync | 42 | Immutable |
| 7 | MissingRequiredSignature | 25 | **Custom(u32)** | 43 | IncorrectAuthority |
| 8 | AccountAlreadyInitialized | 26 | InvalidError | 44 | BorshIoError |
| 9 | UninitializedAccount | 27 | ExecutableDataModified | 45 | AccountNotRentExempt |
| 10 | UnbalancedInstruction | 28 | ExecutableLamportChange | 46 | InvalidAccountOwner |
| 11 | ModifiedProgramId | 29 | ExecutableAccountNotRentExempt | 47 | ArithmeticOverflow |
| 12 | ExternalAccountLamportSpend | 30 | UnsupportedProgramId | 48 | UnsupportedSysvar |
| 13 | ExternalAccountDataModified | 31 | CallDepth | 49 | IllegalOwner |
| 14 | ReadonlyLamportChange | 32 | MissingAccount | 50 | MaxAccountsDataAllocationsExceeded |
| 15 | ReadonlyDataModified | 33 | ReentrancyNotAllowed | 51 | MaxAccountsExceeded |
| 16 | DuplicateAccountIndex | 34 | MaxSeedLengthExceeded | 52 | MaxInstructionTraceLengthExceeded |
| 17 | ExecutableModified | 35 | InvalidSeeds | 53 | BuiltinProgramsMustConsumeComputeUnits |

Every variant is a unit variant except `25 Custom(u32)`, which is followed by
a `u32` LE. Variant `44 BorshIoError` is a unit variant in the reference's SDK
(v3). Historically it carried a `String`. In the protobuf path (lenient) any
such trailing string is simply ignored. An index `>= 54` is an Error.

JSON: a unit variant is its name as a string (`"InvalidArgument"`).
`Custom(n)` is `{"Custom": n}`.

### 11.3 `TransactionError` (enum, `u32` variant index)

| # | Variant | Payload | # | Variant | Payload |
|---|---|---|---|---|---|
| 0 | AccountInUse | | 20 | WouldExceedMaxAccountCostLimit | |
| 1 | AccountLoadedTwice | | 21 | WouldExceedAccountDataBlockLimit | |
| 2 | AccountNotFound | | 22 | TooManyAccountLocks | |
| 3 | ProgramAccountNotFound | | 23 | AddressLookupTableNotFound | |
| 4 | InsufficientFundsForFee | | 24 | InvalidAddressLookupTableOwner | |
| 5 | InvalidAccountForFee | | 25 | InvalidAddressLookupTableData | |
| 6 | AlreadyProcessed | | 26 | InvalidAddressLookupTableIndex | |
| 7 | BlockhashNotFound | | 27 | InvalidRentPayingAccount | |
| 8 | **InstructionError** | `u8` instruction index, `InstructionError` | 28 | WouldExceedMaxVoteCostLimit | |
| 9 | CallChainTooDeep | | 29 | WouldExceedAccountDataTotalLimit | |
| 10 | MissingSignatureForFee | | 30 | **DuplicateInstruction** | `u8` |
| 11 | InvalidAccountIndex | | 31 | **InsufficientFundsForRent** | `u8 account_index` |
| 12 | SignatureFailure | | 32 | MaxLoadedAccountsDataSizeExceeded | |
| 13 | InvalidProgramForExecution | | 33 | InvalidLoadedAccountsDataSizeLimit | |
| 14 | SanitizeFailure | | 34 | ResanitizationNeeded | |
| 15 | ClusterMaintenance | | 35 | **ProgramExecutionTemporarilyRestricted** | `u8 account_index` |
| 16 | AccountBorrowOutstanding | | 36 | UnbalancedTransaction | |
| 17 | WouldExceedMaxBlockCostLimit | | 37 | ProgramCacheHitMaxLimit | |
| 18 | UnsupportedVersion | | 38 | CommitCancelled | |
| 19 | InvalidWritableAccount | | | | |

An index `>= 39` is an Error.

JSON forms:

| Variant kind | JSON |
|---|---|
| unit | `"AccountInUse"` |
| `InstructionError(i, e)` | `{"InstructionError": [i, <InstructionError JSON>]}`, e.g. `{"InstructionError":[0,{"Custom":42}]}` or `{"InstructionError":[2,"InvalidArgument"]}` |
| `DuplicateInstruction(i)` | `{"DuplicateInstruction": i}` |
| `InsufficientFundsForRent{account_index}` | `{"InsufficientFundsForRent": {"account_index": i}}` (snake_case key) |
| `ProgramExecutionTemporarilyRestricted{account_index}` | `{"ProgramExecutionTemporarilyRestricted": {"account_index": i}}` |

Bincode example: `08 00 00 00  00  19 00 00 00  2a 00 00 00` is
`InstructionError(0, Custom(42))`.

### 11.4 Pre-157 `TransactionStatusMeta` layouts

**Current layout `StoredTransactionStatusMeta`** (fields in order):

```
status                Result<(), TransactionError>
fee                   u64
pre_balances          Vec<u64>
post_balances         Vec<u64>
inner_instructions    Option<Vec<InnerInstructions>>            eof
log_messages          Option<Vec<String>>                       eof
pre_token_balances    Option<Vec<StoredTokenBalance>>           eof
post_token_balances   Option<Vec<StoredTokenBalance>>           eof
rewards               Option<Vec<StoredExtendedReward>>         eof
return_data           Option<ReturnData>                        eof
compute_units_consumed Option<u64>                              eof
cost_units            Option<u64>                               eof

InnerInstructions    { index: u8, instructions: Vec<InnerInstruction> }
InnerInstruction     { instruction: CompiledInstruction, stack_height: Option<u32> }
StoredTokenBalance   { account_index: u8, mint: String, ui_token_amount: StoredTokenAmount,
                       owner: String (eof), program_id: String (eof) }
StoredTokenAmount    { ui_amount: f64, decimals: u8, amount: String }
StoredExtendedReward { pubkey: String, lamports: i64, post_balance: u64 (eof),
                       reward_type: Option<RewardType> (eof), commission: Option<u8> (eof) }
ReturnData           { program_id: Pubkey, data: Vec<u8> }
```

**Legacy layouts** are identical except:

* `InnerInstructions` is `{ index: u8, instructions: Vec<CompiledInstruction> }`,
  with no `stack_height`, so the decoded `stack_height` is *none*;
* the token balance type `TB` is one of:
  * `V1 { account_index: u8, mint: String, ui_token_amount: StoredTokenAmount }`
    (owner = program_id = `""`);
  * `V2 { account_index, mint, ui_token_amount, owner: String }`
    (program_id = `""`);
  * `StoredTokenBalance` as above.

**`bincode_metadata(b)`**: try in this order and return the first success:

1. strict `StoredTransactionStatusMeta`;
2. strict legacy layout with `TB = V1`;
3. strict legacy layout with `TB = V2`;
4. strict legacy layout with `TB = StoredTokenBalance`;
5. **lenient** `StoredTransactionStatusMeta` (its failure is the final Error).

Conversion to the internal model:

* `loaded_addresses` is always empty.
* Every other field maps 1:1 (`Option` → present/absent).
* A stored token amount becomes `ui_amount = Some(ui_amount)` (**always
  present, even `0.0`**), `decimals`, `amount`, and
  `ui_amount_string = real_number_string_trimmed(parse_u64(amount) or 0, decimals)`.
* A stored reward maps field for field. A missing `commission` or
  `reward_type` is *none*.

### 11.5 Pre-157 rewards

**`bincode_rewards(b)`**: try in this order:

1. strict `Vec<StoredExtendedReward>`;
2. strict `Vec<{ pubkey: String, lamports: i64, post_balance: u64,
   reward_type: Option<RewardType> }>` (no `eof` fields, commission = *none*);
3. lenient `Vec<StoredExtendedReward>` (final).

Bincode rewards never carry a partition count.

---

## 12. Internal data model

```
Block {
  previous_blockhash: string, blockhash: string, parent_slot: u64,
  transactions: [TxWithMeta], rewards: [Reward], num_partitions: u64?,
  block_time: i64?, block_height: u64?
}
TxWithMeta = Complete { tx: VersionedTransaction, meta: Meta }
           | MissingMetadata { tx: legacy VersionedTransaction }
Meta {
  status: Ok | Err(TransactionError), fee: u64,
  pre_balances: [u64], post_balances: [u64],
  inner_instructions: [ {index: u8, instructions: [ {program_id_index: u8,
                         accounts: [u8], data: bytes, stack_height: u32?} ]} ]?,
  log_messages: [string]?,
  pre_token_balances: [TokenBalance]?, post_token_balances: [TokenBalance]?,
  rewards: [Reward]?,
  loaded_addresses: {writable: [pubkey], readonly: [pubkey]},
  return_data: {program_id: pubkey, data: bytes}?,
  compute_units_consumed: u64?, cost_units: u64?
}
TokenBalance { account_index: u8, mint: string, owner: string, program_id: string,
               ui_amount: f64?, decimals: u8, amount: string, ui_amount_string: string }
Reward { pubkey: string, lamports: i64, post_balance: u64,
         reward_type: Fee|Rent|Staking|Voting?, commission: u8? }
```

`default_meta` (used for a v0 transaction whose metadata frame is empty):
status `Ok`, fee `0`, empty balances, every optional *none*, and
`loaded_addresses` empty.

---

## 13. JSON serialization of a `getBlock` result

Key order is irrelevant (the reference happens to emit keys sorted). "Omitted"
means the key is absent. "null" means the key is present with value `null`.

### 13.1 Block object

| Key | Value | Present when |
|---|---|---|
| `previousBlockhash` | string | always |
| `blockhash` | string | always |
| `parentSlot` | u64 | always |
| `transactions` | array (§13.2) | `transactionDetails` is `"full"` or `"accounts"` |
| `signatures` | array of strings: the **first** signature of each transaction | `transactionDetails` is `"signatures"` |
| `rewards` | array of Reward (§13.7), possibly `[]` | `rewards` option is `true` |
| `numRewardPartitions` | u64 | `rewards: true` **and** a partition count was decoded |
| `blockTime` | i64 or null | always |
| `blockHeight` | u64 or null | always |

With `"none"`, neither `transactions` nor `signatures` is present. A
transaction with zero signatures is an Error in `"signatures"` mode.

### 13.2 Transaction version gate (`-32015`)

For every `Complete` transaction in `"full"` or `"accounts"` mode, with
`max = maxSupportedTransactionVersion` (absent or null means *none*):

| `max` | tx version | Result |
|---|---|---|
| *none* | legacy | OK, `version` key **omitted** |
| *none* | `0` | **whole request fails with `-32015`** |
| `n` | legacy | OK, `"version": "legacy"` |
| `n` | `0` | OK, `"version": 0` (always, since `0 <= n`) |

`MissingMetadata` transactions are never gated and never carry `version`.

Each element of `transactions` is:

```
{ "transaction": <§13.3/§13.4/§13.5/§13.6>, "meta": <§13.8> | null, "version": ... }
```

`meta` is `null` exactly for `MissingMetadata`.

### 13.3 `encoding: "json"`, `transactionDetails: "full"`

```json
"transaction": {
  "signatures": ["<sig b58>", ...],            // all signatures, in order
  "message": {
    "header": {"numRequiredSignatures": 1, "numReadonlySignedAccounts": 0,
               "numReadonlyUnsignedAccounts": 1},
    "accountKeys": ["<pubkey b58>", ...],        // static keys only
    "recentBlockhash": "<hash b58>",
    "instructions": [
      {"programIdIndex": 2, "accounts": [0, 1], "data": "<b58 of data>", "stackHeight": 1}
    ],
    "addressTableLookups": [                     // v0 ONLY (may be []); omitted for legacy
      {"accountKey": "<b58>", "writableIndexes": [4], "readonlyIndexes": [9]}
    ]
  }
}
```

Top-level instructions always have **`"stackHeight": 1`** (the reference's
`TRANSACTION_LEVEL_STACK_HEIGHT`).

### 13.4 `encoding: "json"`, `transactionDetails: "accounts"`

```json
"transaction": {
  "signatures": ["<sig b58>", ...],
  "accountKeys": [
    {"pubkey": "<b58>", "writable": true, "signer": true, "source": "transaction"},
    {"pubkey": "<b58>", "writable": true, "signer": false, "source": "lookupTable"}
  ]
}
```

For legacy, the list is the static keys. For v0 it is the static keys, then
`loaded_addresses.writable`, then `loaded_addresses.readonly`, with
`source: "lookupTable"` for the loaded ones. `signer` and `writable` are
defined in §14. The `meta` is the reduced form (§13.8).

### 13.5 `encoding: "jsonParsed"`, `transactionDetails: "full"`

```json
"transaction": {
  "signatures": [...],
  "message": {
    "accountKeys": [ {"pubkey", "writable", "signer", "source"} ...],  // as in §13.4
    "recentBlockhash": "<b58>",
    "instructions": [
      {"programId": "<b58>", "accounts": ["<b58>", ...], "data": "<b58>", "stackHeight": 1}
    ],
    "addressTableLookups": [...]        // v0 ONLY; omitted for legacy
  }
}
```

**OnlyBlocks profile (deliberate deviation):** every instruction, top-level
and inner, is emitted in this **partially decoded** form:

* `programId = keys[program_id_index]`;
* `accounts = [keys[i] for i in accounts]`;
* `data = base58(data)`.

`keys` is the static keys, plus (v0 with metadata) `loaded.writable`, plus
`loaded.readonly`. An index out of range is an Error. The Rust reference
additionally parses instructions of well-known programs (System, Vote, Stake,
SPL Token / Token-2022, Associated Token Account, Memo, BPF loaders, Address
Lookup Table) into `{"program", "programId", "parsed", "stackHeight"}`.
OnlyBlocks implementations MUST NOT do that. The conformance runner accepts
either form for top-level instructions of those programs, and golden fixtures
only use custom programs.

For a `MissingMetadata` legacy transaction, `keys` is the static keys.

### 13.6 `encoding: "base64"` / `"base58"`, `transactionDetails: "full"`

```json
"transaction": ["<base64 of raw tx bytes>", "base64"]
"transaction": ["<base58 of raw tx bytes>", "base58"]
```

The bytes are those defined in §8.3. The `meta` is the same as for `"json"`.

### 13.7 Reward object

```json
{"pubkey": "<string>", "lamports": -5, "postBalance": 1000,
 "rewardType": "Fee" | "Rent" | "Staking" | "Voting" | null, "commission": 7 | null}
```

### 13.8 Metadata object

Rules per key. `json` also applies to `base64` and `base58`.

| Key | `json` / `base64` / `base58` | `jsonParsed` | `accounts` |
|---|---|---|---|
| `err` | `null` or TransactionError JSON | same | same |
| `status` | `{"Ok": null}` or `{"Err": <err>}` | same | same |
| `fee` | u64 | same | same |
| `preBalances`, `postBalances` | `[u64]` | same | same |
| `innerInstructions` | `null` if *none*, else `[{"index": n, "instructions": [compiled]}]` | same, but instructions partially decoded (§13.5) | **omitted** |
| `logMessages` | `null` or `[string]` | same | **omitted** |
| `preTokenBalances`, `postTokenBalances` | `null` or `[TokenBalance]` | same | same |
| `rewards` | `rewards:true`: `null` if *none*, else `[Reward]`. `rewards:false`: **`null`** | same | `rewards:true`: `null` or `[Reward]`. `rewards:false`: **omitted** |
| `loadedAddresses` | **always** `{"writable": [b58], "readonly": [b58]}` | **omitted** | **omitted** |
| `returnData` | omitted if *none*, else `{"programId": "<b58>", "data": ["<base64>", "base64"]}` | same | **omitted** |
| `computeUnitsConsumed` | omitted if *none*, else u64 | same | **omitted** |
| `costUnits` | omitted if *none*, else u64 | same | **omitted** |

Compiled inner instruction (`json`):
`{"programIdIndex": u8, "accounts": [u8], "data": "<b58>", "stackHeight": n | null}`.
Partially decoded inner instruction (`jsonParsed`):
`{"programId", "accounts": [b58], "data", "stackHeight": n | null}`. Inner
instructions use the stack height from metadata, which may be `null`.

TokenBalance:

```json
{"accountIndex": 1, "mint": "<string>",
 "uiTokenAmount": {"uiAmount": 1.25 | null, "decimals": 6, "amount": "1250000",
                   "uiAmountString": "1.25"},
 "owner": "<string>",       // omitted when ""
 "programId": "<string>"}   // omitted when ""
```

---

## 14. Account flags (`signer` / `writable`)

Let `h = header`, `nrs = h.num_required_signatures`,
`nros = h.num_readonly_signed_accounts`, `nrou = h.num_readonly_unsigned_accounts`,
`S = number of static keys`, and `W = len(loaded.writable)`. For the combined key
list `keys` (§13.4), index `i`:

```
signer(i) = i < nrs

writable_index(i) =
    if i >= S:          (i - S) < W                         # loaded: writable list first
    elif i >= nrs:      (i - nrs) < max(0, S - nrs - nrou)  # unsigned static
    else:               i < max(0, nrs - nros)              # signed static

demoted(i) = (i <= 255 and some top-level instruction has program_id_index == i)
             and not (any key in keys == "BPFLoaderUpgradeab1e11111111111111111111111")

writable(i) = writable_index(i) and keys[i] not in RESERVED and not demoted(i)
```

(For a legacy message, `W = 0` and there are no `i >= S`.)

`RESERVED` is the full list below (Agave's reserved keys with every feature
activated). These keys are **never** `writable`, whatever the header says:

```
AddressLookupTab1e1111111111111111111111111   BPFLoader2111111111111111111111111111111111
BPFLoader1111111111111111111111111111111111   BPFLoaderUpgradeab1e11111111111111111111111
ComputeBudget111111111111111111111111111111   Config1111111111111111111111111111111111111
Ed25519SigVerify111111111111111111111111111   Feature111111111111111111111111111111111111
LoaderV411111111111111111111111111111111111   KeccakSecp256k11111111111111111111111111111
Secp256r1SigVerify1111111111111111111111111   StakeConfig11111111111111111111111111111111
Stake11111111111111111111111111111111111111   11111111111111111111111111111111
Vote111111111111111111111111111111111111111   ZkE1Gama1Proof11111111111111111111111111111
ZkTokenProof1111111111111111111111111111111   SysvarC1ock11111111111111111111111111111111
SysvarEpochRewards1111111111111111111111111   SysvarEpochSchedu1e111111111111111111111111
SysvarFees111111111111111111111111111111111   Sysvar1nstructions1111111111111111111111111
SysvarLastRestartS1ot1111111111111111111111   SysvarRecentB1ockHashes11111111111111111111
SysvarRent111111111111111111111111111111111   SysvarRewards111111111111111111111111111111
SysvarS1otHashes111111111111111111111111111   SysvarS1otHistory11111111111111111111111111
SysvarStakeHistory1111111111111111111111111   NativeLoader1111111111111111111111111111111
Sysvar1111111111111111111111111111111111111
```

(31 keys. Compare the 32 decoded bytes or the Base58 strings; both work.)

---

## 15. Base58, Base64, numbers, `real_number_string_trimmed`

### 15.1 Base58 (Bitcoin alphabet)

Alphabet: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`.

```
encode(bytes):
    zeros = number of leading 0x00 bytes
    digits = []                       # base-58 digits, little-endian
    for b in bytes[zeros:]:
        carry = b
        for j in 0..len(digits): carry += digits[j] << 8; digits[j] = carry % 58; carry //= 58
        while carry: digits.append(carry % 58); carry //= 58
    return "1" * zeros + "".join(ALPHABET[d] for d in reversed(digits))

decode(s):                            # not needed for getBlock; for completeness
    zeros = number of leading "1"
    out = []                          # bytes, little-endian
    for c in s[zeros:]:
        carry = ALPHABET.index(c) (Error if absent)
        for j in 0..len(out): carry += out[j] * 58; out[j] = carry & 0xFF; carry >>= 8
        while carry: out.append(carry & 0xFF); carry >>= 8
    return [0x00] * zeros + reversed(out)
```

Examples: 32 zero bytes → `11111111111111111111111111111111` (32 × `1`).
Empty input → `""`, so empty instruction `data` is `""`. Bytes
`00 01 2a ff` → `1Pki`: one leading zero byte gives `1`, and
`0x012aff = 76543 = 22·58² + 43·58 + 41`, which gives `P k i`.

### 15.2 Base64

RFC 4648 **standard** alphabet (`A-Z a-z 0-9 + /`) **with `=` padding**. Used
for `"base64"` transactions and `returnData.data`. Example: bytes
`00 ff 01 2a` → `AP8BKg==`.

### 15.3 JSON numbers and strings

* Integers (`u64`, `i64`, `u8`, `u32`) are emitted as exact JSON integers, never
  in exponent form (`u64` values up to `18446744073709551615`).
* `uiAmount` (f64) must round-trip: emit the shortest representation that
  parses back to the same double (`%.17g` is acceptable). Values may be written
  `1.0` or `1`, and `5e-06` or `0.000005`. NaN and infinities are `null`.
* Strings are standard JSON. Escape `"` `\` and control characters
  `< 0x20`. Emit non-ASCII UTF-8 as raw UTF-8 (escaping it as `\uXXXX` is
  also valid JSON).

### 15.4 `real_number_string_trimmed(amount: u64, decimals: u8)`

```
if decimals == 0: return decimal(amount)
s = decimal(amount)
if len(s) <= decimals: s = "0." + "0" * (decimals - len(s)) + s
else:                  s = s[:len(s)-decimals] + "." + s[len(s)-decimals:]
strip trailing "0" characters, then strip one trailing "." if present
```

Vectors: `(1000000, 6)` → `"1"`, `(1250000, 6)` → `"1.25"`, `(5, 6)` →
`"0.000005"`, `(0, 6)` → `"0"`, `(42, 0)` → `"42"`, `(1, 20)` →
`"0.00000000000000000001"`, `(0, 255)` → `"0"`, `(18446744073709551615, 20)`
→ `"0.18446744073709551615"`. It must work for every `decimals` in `0..=255`,
so never compute `10^decimals` in fixed-width integers.

`parse_u64(amount)`: ASCII decimal digits with an optional leading `+`. On
failure, or if the value does not fit in a `u64`, use `0`.

---

## 16. Worked hex examples (`conformance/fixtures`)

### 16.1 Entry section (epoch 100, slot 43200000)

```
4a                                     uvarint section length = 74
01 71 12 20 52 39 16 c2 … fb c0        CIDv1 dag-cbor sha2-256 (36 bytes)
84                                     array(4)
   01                                  kind 1 = Entry
   0a                                  num_hashes = 10 (ignored)
   58 20 1e 1e … 1e                    bytes(32) hash
   80                                  transactions = []
```

### 16.2 Block section (same slot)

```
6a                                     length = 106
01 71 12 20 1f f8 21 0e … 1b aa        CID (36 bytes)
86                                     array(6)
   02                                  kind 2 = Block
   1a 02 93 2e 00                      slot = 43200000
   80                                  shredding = []
   81 d8 2a 58 25 00 01 71 12 20 52 39 16 c2 … fb c0
                                       entries = [link to the Entry above]
   83 1a 02 93 2d ff f6 1a 02 93 2d 9c meta = [parent 43199999, blocktime null, height 43199900]
   d8 2a 45 00 01 55 00 00             rewards = link bafkqaaa (empty identity → no rewards)
```

Because the block has one entry with no transactions,
`blockhash = base58(1e × 32)`, `blockTime = null` and `blockHeight = 43199900`.

### 16.3 Transaction node and legacy transaction (epoch 700, slot 302400011)

```
85                                     array(5): Transaction
   00                                  kind 0
   86 06 f6 f6 f6 58 cf <207 bytes> f6 data DataFrame [6, null, null, null, bytes(207), null]
   86 06 f6 f6 f6 59 01 3d 28 b5 2f fd … f6
                                       metadata DataFrame: bytes(317), a zstd frame
   …                                   slot, index (ignored)
```

The 207 transaction bytes:

```
01                                     compact-u16: 1 signature
3e × 64                                signature
01 00 01                               legacy header: nrs=1, nros=0, nrou=1 (first byte < 0x80)
03                                     3 account keys
01 × 32, 02 × 32, 05 × 32              keys
29 × 32                                recent_blockhash
01                                     1 instruction
   02                                  program_id_index = 2
   02 00 01                            accounts [0, 1]
   04 00 01 2a ff                      data (4 bytes) -> base58 "1Pki"
```

The second transaction in the same entry begins `01 3f×64 80 01 00 01 02 …`.
`0x80` is the v0 prefix, followed by the header `(1, 0, 1)` and 2 static keys.

### 16.4 Rewards node (same slot)

```
83 05 1a 12 06 42 0b                   [5, slot 302400011,
   86 06 f6 f6 f6 58 b8 28 b5 2f fd …     DataFrame bytes(184) = zstd(protobuf Rewards)]
```

### 16.5 Protobuf `TransactionStatusMeta` (slot 302400011, transaction 1, failed)

The metadata DataFrame holds a 351-byte zstd frame, which decompresses to 678
bytes of protobuf. Annotated, with `…` abbreviating repeated text:

```
0a 0f                    field 1 (err) LEN 15
   0a 0d                   TransactionError.field 1 (err bytes) LEN 13
      08 00 00 00            bincode u32 8  = InstructionError
      00                     u8  0          = instruction index
      19 00 00 00            u32 25         = Custom
      2a 00 00 00            u32 42         -> {"InstructionError":[0,{"Custom":42}]}
10 88 27                 field 2 (fee) varint 5000
1a 07 d0 86 03 01 90 4e 01   field 3 (pre_balances) packed: 50000, 1, 10000, 1
22 07 c8 df 02 01 90 4e 01   field 4 (post_balances) packed: 45000, 1, 10000, 1
2a 0f                    field 5 (inner_instructions) LEN 15  (index field absent -> 0)
   12 0d                   field 2 (instructions) LEN 13
      08 01                  program_id_index 1
      12 02 02 03            accounts [2, 3]
      1a 03 00 07 c8         data 00 07 c8 -> base58 "1bM"
      20 02                  stack_height 2
32 3e "Program QWmr…zwF invoke [1]"        field 6 (log_messages), repeated ×3
3a 9f 01                 field 7 (pre_token_balances) LEN 159
   08 02                   account_index 2
   12 2b "swqrv48g…iLCC"   mint (43 bytes)
   1a 14                   ui_token_amount LEN 20
      09 00 00 00 00 00 00 f4 3f   ui_amount double 1.25 (wire type 1)
      10 06                        decimals 6
      1a 07 "1250000"              amount ("ui_amount_string" absent -> computed "1.25")
   22 2b "CktRuQ2m…zy8"    owner
   2a 2b "QWmroo4Y…zwF"    program_id
42 9f 01 …               field 8 (post_token_balances), same shape
62 20 04 × 32            field 12 (loaded_writable_addresses) 1 × 32 bytes
6a 20 0a × 32            field 13 (loaded_readonly_addresses) 1 × 32 bytes
72 28                    field 14 (return_data) LEN 40
   0a 20 06 × 32           program_id
   12 04 00 ff 01 2a       data -> base64 "AP8BKg=="
80 01 c2 03              field 16 (key 0x80 0x01 = 16<<3|0) compute_units_consumed 450
88 01 84 07              field 17 cost_units 900
```

Fields 10, 11 and 15 (`*_none`) are absent, which means `false`.

### 16.6 Protobuf `Rewards` (slot 302400011)

184-byte zstd frame → 175 bytes:

```
0a 36                    field 1 (rewards) LEN 54
   0a 2b "US517G59…ELFx"   pubkey (43 bytes of Base58 text)
   10 c4 13                lamports 2500
   18 94 9a 03             post_balance 52500
   20 01                   reward_type 1 = Fee      (commission fields absent -> null)
0a 36 … 10 d2 09 18 a2 90 03 20 03        lamports 1234, postBalance 51234, Staking
0a 39 … 10 c1 02 18 91 89 03 20 04 2a 01 37
                                          lamports 321, postBalance 50321, Voting, commission "7" -> 7
12 02 08 04              field 2 (num_partitions) { num_partitions: 4 } -> "numRewardPartitions": 4
```

### 16.7 Bincode pre-157 metadata and rewards (slot 43200001)

Metadata (a zstd frame decompressing to 547 bytes; the current
`StoredTransactionStatusMeta` layout matches strictly):

```
00 00 00 00                          status: Result variant 0 = Ok
88 13 00 00 00 00 00 00              fee 5000
03 00 00 00 00 00 00 00              pre_balances: Vec len 3
   50 c3 00 00 00 00 00 00  10 27 00 00 00 00 00 00  01 00 00 00 00 00 00 00   [50000, 10000, 1]
03 00 00 00 00 00 00 00              post_balances len 3: [44000, 11000, 1]
   e0 ab 00 00 00 00 00 00  f8 2a 00 00 00 00 00 00  01 00 00 00 00 00 00 00
00                                   inner_instructions: None -> "innerInstructions": null
01 01 00 00 00 00 00 00 00           log_messages: Some, Vec len 1
   3b 00 00 00 00 00 00 00 "Program LbUi…fcY success"   String len 59
01 01 00 00 00 00 00 00 00           pre_token_balances: Some, Vec len 1
   01                                   account_index 1
   2b 00 00 00 00 00 00 00 "swqr…iLCC"  mint
   00 00 00 00 00 00 f0 3f              ui_amount f64 1.0  (bincode path: always present)
   06                                   decimals 6
   07 00 00 00 00 00 00 00 "1000000"    amount -> uiAmountString "1"
   2b 00 … "4vJ9…LKi"                   owner
   2b 00 … "LbUi…fcY"                   program_id
01 01 00 00 00 00 00 00 00 …         post_token_balances: Some, len 1 (ui_amount 1.25, "1250000")
01 00 00 00 00 00 00 00 00           rewards: Some, Vec len 0 -> "rewards": []
00                                   return_data: None (omitted)
01 96 00 00 00 00 00 00 00           compute_units_consumed: Some(150)
00                                   cost_units: None (omitted)
```

Rewards (81 bytes, strict `Vec<StoredExtendedReward>`):

```
01 00 00 00 00 00 00 00              Vec len 1
   2b 00 00 00 00 00 00 00 "US517G59…ELFx"   pubkey String (43 bytes)
   c4 09 00 00 00 00 00 00                    lamports i64 2500
   50 c3 00 00 00 00 00 00                    post_balance u64 50000
   01 00 00 00 00                             reward_type: Some(variant 0 = Fee)
   00                                         commission: None
```

### 16.8 Multi-frame DataFrame chain (slot 302400012, transaction 0 data)

```
Transaction node: 85 00
  86 06 1b 70 28 0d c4 ad 6a cf d7 00 03 58 45 <69 bytes> 81 d8 2a 58 25 00 01 71 12 20 a9 65 …
     [6, hash=0x70280dc4ad6acfd7, index 0, total 3, bytes(69), next=[CID A]]
section CID A: 86 06 1b 70 28 0d c4 ad 6a cf d7 01 03 58 45 <69 bytes> 81 d8 2a … c4 f5 …
     [6, hash (ignored), 1, 3, bytes(69), next=[CID B]]
section CID B: 86 06 1b 70 28 0d c4 ad 6a cf d7 02 03 58 45 <69 bytes> 80
     [6, hash (ignored), 2, 3, bytes(69), next=[] -> none]
```

The reassembled payload is 207 bytes: frame 0, then A, then B.
`crc64_go_iso(payload) = 0x70280dc4ad6acfd7`, which equals the first frame's
`hash`, so verification passes. (`fnv1a(payload) = 0xa89881652b530efd`
does not match, which is fine: either one may match.) The hash is a CBOR
`uint64` (`1b` + 8 bytes, big-endian).

### 16.9 Golden JSON

`conformance/fixtures/manifest.json` contains the exact expected `getBlock`
JSON for these slots in every encoding and mode. Use it as the end-to-end
oracle for everything in this document.
