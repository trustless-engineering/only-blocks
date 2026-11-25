defmodule OnlyBlocks.DecodeError do
  defexception [:message]
end

defmodule OnlyBlocks.Wire do
  @moduledoc """
  CARv1 sections, DAG-CBOR, CIDs, DataFrame reassembly, CRC-64/GO-ISO and
  FNV-1a, Base58/Base64, and the Solana `VersionedTransaction` wire format.

  CBOR values decode to: integer | binary (bytes) | `{:text, binary}` | list
  | `{:map, [{k, v}]}` | `true` | `false` | `nil` | `:float`.
  """
  import Bitwise

  @u64 0xFFFFFFFFFFFFFFFF

  def fail(why), do: raise(OnlyBlocks.DecodeError, message: to_string(why))

  # ---------------------------------------------------------------- varints

  @doc "Unsigned LEB128, at most 10 bytes (the 10th byte must be 0 or 1)."
  def uvarint(bin), do: uvarint(bin, 0, 0)

  defp uvarint(<<0::1, x::7, r::binary>>, shift, acc) when shift < 63 or x <= 1, do: {acc ||| x <<< shift, r}
  defp uvarint(<<1::1, x::7, r::binary>>, shift, acc) when shift < 63, do: uvarint(r, shift + 7, acc ||| x <<< shift)
  defp uvarint(<<>>, _, _), do: fail("truncated varint")
  defp uvarint(_, _, _), do: fail("varint overflow")

  @doc "Solana short_vec length: canonical 1..3 bytes, at most 0xFFFF."
  def compact(<<0::1, a::7, r::binary>>), do: {a, r}
  def compact(<<1::1, a::7, 0::1, b::7, r::binary>>) when b != 0, do: {a ||| b <<< 7, r}

  def compact(<<1::1, a::7, 1::1, b::7, c, r::binary>>) when c != 0 and c <= 3,
    do: {a ||| b <<< 7 ||| c <<< 14, r}

  def compact(_), do: fail("bad compact-u16")

  # ---------------------------------------------------------------- DAG-CBOR

  def cbor(bin) do
    case item(bin, 0) do
      {value, <<>>} -> value
      _ -> fail("trailing CBOR bytes")
    end
  end

  def utf8(bin) do
    if String.valid?(bin), do: bin, else: fail("invalid UTF-8")
  end

  defp arg(info, r) when info < 24, do: {info, r}
  defp arg(24, <<v::8, r::binary>>), do: {v, r}
  defp arg(25, <<v::16, r::binary>>), do: {v, r}
  defp arg(26, <<v::32, r::binary>>), do: {v, r}
  defp arg(27, <<v::64, r::binary>>), do: {v, r}
  defp arg(31, r), do: {:indefinite, r}
  defp arg(_, _), do: fail("bad CBOR argument")

  defp item(_, depth) when depth > 128, do: fail("CBOR nesting limit")

  defp item(<<7::3, info::5, r::binary>>, _) do
    case {info, r} do
      {20, _} -> {false, r}
      {21, _} -> {true, r}
      {22, _} -> {nil, r}
      {23, _} -> {nil, r}
      {25, <<_::16, r::binary>>} -> {:float, r}
      {26, <<_::32, r::binary>>} -> {:float, r}
      {27, <<_::64, r::binary>>} -> {:float, r}
      _ -> fail("unsupported CBOR simple value")
    end
  end

  defp item(<<major::3, info::5, r::binary>>, depth) do
    {arg, r} = arg(info, r)
    if arg == :indefinite and major not in 2..5, do: fail("invalid indefinite CBOR item")

    case major do
      0 -> {arg, r}
      1 -> {-1 - arg, r}
      6 -> item(r, depth + 1)
      2 -> string(arg, r, 2)
      3 -> with {s, r} <- string(arg, r, 3), do: {{:text, s}, r}
      4 -> sequence(arg, r, depth, :array, [])
      5 -> sequence(arg, r, depth, :map, [])
    end
  end

  defp item(<<>>, _), do: fail("truncated CBOR")

  defp string(:indefinite, r, major), do: chunks(r, major, [])

  defp string(n, r, major) do
    case r do
      <<s::binary-size(n), r::binary>> -> {if(major == 2, do: s, else: utf8(s)), r}
      _ -> fail("truncated CBOR string")
    end
  end

  defp chunks(<<0xFF, r::binary>>, _major, acc), do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), r}

  defp chunks(<<major::3, info::5, r::binary>>, major, acc) when info != 31 do
    {n, r} = arg(info, r)
    {s, r} = string(n, r, major)
    chunks(r, major, [s | acc])
  end

  defp chunks(_, _, _), do: fail("invalid CBOR string chunk")

  defp sequence(:indefinite, <<0xFF, r::binary>>, _depth, kind, acc), do: finish(kind, acc, r)
  defp sequence(0, r, _depth, kind, acc), do: finish(kind, acc, r)

  defp sequence(n, r, depth, kind, []) when is_integer(n) do
    if n > div(byte_size(r), if(kind == :array, do: 1, else: 2)), do: fail("CBOR count exceeds input")
    element(n, r, depth, kind, [])
  end

  defp sequence(n, r, depth, kind, acc), do: element(n, r, depth, kind, acc)

  defp element(n, r, depth, :array, acc) do
    {v, r} = item(r, depth + 1)
    sequence(dec(n), r, depth, :array, [v | acc])
  end

  defp element(n, r, depth, :map, acc) do
    {k, r} = item(r, depth + 1)
    {v, r} = item(r, depth + 1)
    sequence(dec(n), r, depth, :map, [{k, v} | acc])
  end

  defp dec(:indefinite), do: :indefinite
  defp dec(n), do: n - 1

  defp finish(:array, acc, r), do: {Enum.reverse(acc), r}
  defp finish(:map, acc, r), do: {{:map, Enum.reverse(acc)}, r}

  # ---------------------------------------------------------------- CIDs

  @doc "Returns `{cid_bytes, absent?, rest}`."
  def cid(bin) do
    {a, r} = uvarint(bin)
    {b, r} = uvarint(r)

    case {a, b} do
      {0x12, 0x20} ->
        case r do
          <<_::binary-size(32), rest::binary>> -> {consumed(bin, rest), false, rest}
          _ -> fail("truncated CID")
        end

      {1, _} ->
        {code, r} = uvarint(r)
        {len, r} = uvarint(r)
        if len > 64, do: fail("CID digest too long")

        case r do
          <<_::binary-size(len), rest::binary>> -> {consumed(bin, rest), code == 0 and len == 0, rest}
          _ -> fail("truncated CID")
        end

      _ ->
        fail("unsupported CID version")
    end
  end

  defp consumed(whole, rest), do: binary_part(whole, 0, byte_size(whole) - byte_size(rest))

  @doc "A DAG-CBOR link (tag 42 already discarded): byte string `0x00 ++ CID`."
  def link(<<0, cid::binary>>) do
    {key, absent, _} = cid(cid)
    {key, absent}
  end

  def link(_), do: fail("invalid CID link")

  def links(items) when is_list(items), do: Enum.map(items, &elem(link(&1), 0))
  def links(_), do: []

  # ---------------------------------------------------------------- CAR

  def at(list, i) when is_list(list), do: Enum.at(list, i)
  def at(_, _), do: nil

  def u64(v) when is_integer(v) and v >= 0 and v <= @u64, do: v
  def u64(_), do: nil

  def i64(v) when is_integer(v) and v >= -(1 <<< 63) and v < 1 <<< 63, do: v
  def i64(_), do: nil

  defp kind(node, kind) do
    if is_list(node) and u64(at(node, 0)) == kind, do: node, else: fail("expected IPLD node kind #{kind}")
  end

  def indexed(index, key, kind) do
    case index do
      %{^key => bytes} -> bytes |> cbor() |> kind(kind)
      _ -> fail("CID missing from CAR slice")
    end
  end

  @doc "Index a headerless CARv1 slice. Returns `{index, block_node}`."
  def index_car(data), do: sections(data, %{}, nil, true)

  defp sections(<<>>, _index, nil, _), do: fail("no Block node in CAR slice")
  defp sections(<<>>, index, block, _), do: {index, block |> cbor() |> kind(2)}

  defp sections(data, index, block, first) do
    case uvarint(data) do
      {0, r} ->
        sections(r, index, block, first)

      {size, _} when size > 32 * 1024 * 1024 ->
        fail("oversize CAR section")

      {size, r} ->
        case r do
          <<section::binary-size(size), rest::binary>> ->
            if first and car_header?(section) do
              sections(rest, index, block, false)
            else
              {key, _, node} = cid(section)
              sections(rest, Map.put(index, key, node), block_candidate(node, block), false)
            end

          _ ->
            fail("truncated CAR section")
        end
    end
  end

  defp car_header?(<<5::3, _::5, _::binary>> = section) do
    case cbor(section) do
      {:map, pairs} -> List.keymember?(pairs, {:text, "version"}, 0)
      _ -> false
    end
  rescue
    _ -> false
  end

  defp car_header?(_), do: false

  # An array header immediately followed by the kind byte 2 marks the Block.
  defp block_candidate(<<4::3, info::5, r::binary>> = node, block) when info < 28 or info == 31 do
    skip = if info < 24 or info == 31, do: 0, else: 1 <<< (info - 24)

    case r do
      <<_::binary-size(skip), 2, _::binary>> -> node
      _ -> block
    end
  end

  defp block_candidate(_, block), do: block

  # ---------------------------------------------------------------- DataFrames

  defp frame_data(frame) do
    case at(frame, 4) do
      b when is_binary(b) -> b
      _ -> <<>>
    end
  end

  defp frame_next(frame) do
    case at(frame, 5) do
      [_ | _] = list -> links(list)
      _ -> []
    end
  end

  def frame_payload(index, root) do
    kind(root, 6)
    first = frame_data(root)
    payload = index |> reassemble(frame_next(root), MapSet.new(), byte_size(first), [first]) |> IO.iodata_to_binary()

    case u64(at(root, 1)) do
      nil ->
        payload

      expected ->
        if crc64(payload) != expected and fnv1a(payload) != expected, do: fail("DataFrame hash mismatch")
        payload
    end
  end

  # Iterative DFS: the stack head is the next CID to visit.
  defp reassemble(_index, [], _seen, _size, acc), do: Enum.reverse(acc)

  defp reassemble(index, [key | stack], seen, size, acc) do
    if MapSet.member?(seen, key), do: fail("cyclic DataFrame")
    frame = indexed(index, key, 6)
    data = frame_data(frame)
    size = size + byte_size(data)
    if size > 128 * 1024 * 1024, do: fail("oversize reassembled DataFrame")
    reassemble(index, frame_next(frame) ++ stack, MapSet.put(seen, key), size, [data | acc])
  end

  # ---------------------------------------------------------------- checksums

  @crc_table (for i <- 0..255 do
                Enum.reduce(1..8, i, fn _, v ->
                  if (v &&& 1) == 1, do: bxor(v >>> 1, 0xD800000000000000), else: v >>> 1
                end)
              end)
             |> List.to_tuple()

  def crc64(data), do: data |> crc64(@u64) |> bxor(@u64)
  defp crc64(<<b, r::binary>>, c), do: crc64(r, bxor(c >>> 8, elem(@crc_table, bxor(c &&& 255, b))))
  defp crc64(<<>>, c), do: c

  def fnv1a(data), do: fnv1a(data, 0xCBF29CE484222325)
  defp fnv1a(<<b, r::binary>>, h), do: fnv1a(r, bxor(h, b) * 0x100000001B3 &&& @u64)
  defp fnv1a(<<>>, h), do: h

  # ---------------------------------------------------------------- Base58/64

  @alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" |> List.to_tuple()

  def base58(bin) do
    zeros = leading_zeros(bin, 0)
    digits = bin |> :binary.decode_unsigned() |> b58_digits([])
    :binary.copy("1", zeros) <> List.to_string(digits)
  end

  defp leading_zeros(<<0, r::binary>>, n), do: leading_zeros(r, n + 1)
  defp leading_zeros(_, n), do: n

  defp b58_digits(0, acc), do: acc
  defp b58_digits(v, acc), do: b58_digits(div(v, 58), [elem(@alphabet, rem(v, 58)) | acc])

  def base64(bin), do: Base.encode64(bin)

  def pubkey(<<_::binary-size(32)>> = key), do: base58(key)
  def pubkey(_), do: fail("expected a 32-byte hash or public key")

  # ---------------------------------------------------------------- transactions

  @doc "Decode a VersionedTransaction; `raw` is the consumed prefix (trailing bytes ignored)."
  def transaction(data) do
    {tx, rest} =
      case data do
        <<0x81, r::binary>> -> transaction_v1(r)
        <<nsig, r::binary>> when nsig < 0x80 -> transaction_legacy_or_v0(nsig, r)
        _ -> fail("invalid transaction discriminator")
      end

    Map.put(tx, :raw, consumed(data, rest))
  end

  defp transaction_legacy_or_v0(nsig, r) do
    if nsig > div(byte_size(r), 64), do: fail("signature count exceeds input")
    <<sig_bytes::binary-size(nsig * 64), r::binary>> = r
    signatures = for <<sig::binary-size(64) <- sig_bytes>>, do: sig

    {version, header, r} =
      case r do
        <<1::1, 0::7, a, b, c, x::binary>> -> {0, {a, b, c}, x}
        <<a, b, c, x::binary>> when a < 0x80 -> {:legacy, {a, b, c}, x}
        <<1::1, _::7, _::binary>> -> fail("unsupported transaction version")
        _ -> fail("truncated transaction")
      end

    {keys, r} = counted(r, 32, fn <<k::binary-size(32), x::binary>> -> {k, x} end)
    <<recent::binary-size(32), r::binary>> = r
    {instructions, r} = counted(r, 3, &instruction/1)
    {lookups, r} = if version == 0, do: counted(r, 34, &lookup/1), else: {nil, r}

    {%{
      version: version,
      signatures: signatures,
      header: header,
      keys: keys,
      recent: recent,
      instructions: instructions,
      lookups: lookups
    }, r}
  end

  defp transaction_v1(<<a, b, c, mask::little-32, recent::binary-size(32), nix, nkeys, r::binary>>) do
    if mask > 0x1F or (mask &&& 3) in [1, 2], do: fail("invalid transaction config mask")
    <<key_bytes::binary-size(nkeys * 32), r::binary>> = r
    keys = for <<key::binary-size(32) <- key_bytes>>, do: key
    {fee, r} = config_value(mask, 3, 64, r)
    {compute_limit, r} = config_value(mask, 4, 32, r)
    {loaded_data_limit, r} = config_value(mask, 8, 32, r)
    {heap_size, r} = config_value(mask, 16, 32, r)
    config = %{
      priorityFee: fee,
      computeUnitLimit: compute_limit,
      loadedAccountsDataSizeLimit: loaded_data_limit,
      heapSize: heap_size
    }

    <<header_bytes::binary-size(nix * 4), r::binary>> = r
    headers = for <<program, na, nd::little-16 <- header_bytes>>, do: {program, na, nd}

    {instructions, r} =
      Enum.map_reduce(headers, r, fn {program, na, nd}, payload ->
        <<accounts::binary-size(na), data::binary-size(nd), rest::binary>> = payload
        {{program, accounts, data}, rest}
      end)

    <<sig_bytes::binary-size(a * 64), r::binary>> = r
    signatures = for <<sig::binary-size(64) <- sig_bytes>>, do: sig

    {%{
      version: 1,
      signatures: signatures,
      header: {a, b, c},
      keys: keys,
      recent: recent,
      instructions: instructions,
      config: config
    }, r}
  end

  defp transaction_v1(_), do: fail("truncated transaction")

  defp config_value(mask, bits, _width, r) when (mask &&& bits) == 0, do: {nil, r}

  defp config_value(_mask, _bits, width, r) do
    <<value::little-size(width), rest::binary>> = r
    {value, rest}
  end

  defp counted(bin, min, fun) do
    {n, r} = compact(bin)
    if n > div(byte_size(r), min), do: fail("count exceeds input")

    Enum.reduce(List.duplicate(nil, n), {[], r}, fn _, {acc, r} ->
      {v, r} = fun.(r)
      {[v | acc], r}
    end)
    |> then(fn {acc, r} -> {Enum.reverse(acc), r} end)
  end

  defp bytes_vec(bin) do
    {n, r} = compact(bin)

    case r do
      <<b::binary-size(n), r::binary>> -> {b, r}
      _ -> fail("truncated byte vector")
    end
  end

  @doc "CompiledInstruction: `{program_id_index, accounts, data}`."
  def instruction(<<p, r::binary>>) do
    {accounts, r} = bytes_vec(r)
    {data, r} = bytes_vec(r)
    {{p, accounts, data}, r}
  end

  def instruction(_), do: fail("truncated instruction")

  defp lookup(<<key::binary-size(32), r::binary>>) do
    {writable, r} = bytes_vec(r)
    {readonly, r} = bytes_vec(r)
    {{key, writable, readonly}, r}
  end

  defp lookup(_), do: fail("truncated address table lookup")
end
