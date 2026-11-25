defmodule OnlyBlocks.Zstd do
  @moduledoc """
  RFC 8878 Zstandard decoder (decode only), ported from docs/ZSTD_MINI_SPEC.md.

  Headers are destructured with binary patterns, and every backward bitstream
  (Huffman, FSE weights, sequences) is byte-reversed once so that "read N bits
  from the top" becomes a plain big-endian match: `<<_::size(c), v::size(n), _::bits>>`.
  """
  import Bitwise

  @max_out 512 * 1024 * 1024
  @block_max 128 * 1024
  @m64 0xFFFFFFFFFFFFFFFF

  defmodule Error do
    defexception [:message]
  end

  defp fail(why), do: raise(Error, message: "zstd: #{why}")

  # ---------------------------------------------------------------- frames

  def decompress(data) when is_binary(data), do: data |> frames([], 0) |> IO.iodata_to_binary()

  defp frames(<<>>, acc, _total), do: Enum.reverse(acc)

  defp frames(<<magic::little-32, size::little-32, rest::binary>>, acc, total)
       when (magic &&& 0xFFFFFFF0) == 0x184D2A50 do
    case rest do
      <<_::binary-size(size), next::binary>> -> frames(next, acc, total)
      _ -> fail("truncated skippable frame")
    end
  end

  defp frames(<<0xFD2FB528::little-32, rest::binary>>, acc, total) do
    {out, next} = frame(rest, total)
    frames(next, [out | acc], total + byte_size(out))
  end

  defp frames(_, _, _), do: fail("unknown frame magic")

  defp frame(<<fcs::2, single::1, _unused::1, reserved::1, chk::1, did::2, r0::binary>>, total) do
    if reserved != 0, do: fail("reserved frame header bit")

    r1 =
      case {single, r0} do
        {0, <<_window, x::binary>>} -> x
        {1, x} -> x
        _ -> fail("truncated frame header")
      end

    did_bits = elem({0, 8, 16, 32}, did)

    r2 =
      case r1 do
        <<0::little-size(did_bits), x::binary>> -> x
        <<_::little-size(did_bits), _::binary>> -> fail("dictionaries are not supported")
        _ -> fail("truncated frame header")
      end

    fcs_bits = elem({single * 8, 16, 32, 64}, fcs)

    {content, r3} =
      case r2 do
        <<_::size(0), x::binary>> when fcs_bits == 0 -> {nil, x}
        <<c::little-size(fcs_bits), x::binary>> when fcs_bits == 16 -> {c + 256, x}
        <<c::little-size(fcs_bits), x::binary>> -> {c, x}
        _ -> fail("truncated frame content size")
      end

    {out, r4} = blocks(r3, <<>>, %{rep: {1, 4, 8}, huf: nil, ll: nil, off: nil, ml: nil}, total)
    if content != nil and content != byte_size(out), do: fail("frame content size mismatch")

    case {chk, r4} do
      {0, _} ->
        {out, r4}

      {1, <<expected::little-32, r5::binary>>} ->
        if (xxh64(out) &&& 0xFFFFFFFF) != expected, do: fail("content checksum mismatch")
        {out, r5}

      _ ->
        fail("truncated checksum")
    end
  end

  defp frame(_, _), do: fail("truncated frame header")

  defp blocks(<<header::little-24, rest::binary>>, out, st, total) do
    last = header &&& 1
    size = header >>> 3
    if size > @block_max, do: fail("block too large")

    {out, st, next} =
      case {header >>> 1 &&& 3, rest} do
        {0, <<raw::binary-size(size), r::binary>>} ->
          {out <> raw, st, r}

        {1, <<byte, r::binary>>} ->
          {out <> :binary.copy(<<byte>>, size), st, r}

        {2, <<block::binary-size(size), r::binary>>} ->
          {literals, seq_data, st} = literals(block, st)
          {seqs, st} = sequences(seq_data, st)
          {out, rep} = execute(seqs, literals, out, st.rep, total)
          {out, %{st | rep: rep}, r}

        {3, _} ->
          fail("reserved block type")

        _ ->
          fail("truncated block")
      end

    if total + byte_size(out) > @max_out, do: fail("decompressed size limit exceeded")
    if last == 1, do: {out, next}, else: blocks(next, out, st, total)
  end

  defp blocks(_, _, _, _), do: fail("truncated block header")

  # ---------------------------------------------------------------- literals

  defp literals(<<b0, _::binary>> = block, st) when (b0 &&& 3) < 2 do
    {size, r} =
      case {b0 >>> 2 &&& 3, block} do
        {sf, <<_, x::binary>>} when sf in [0, 2] -> {b0 >>> 3, x}
        {1, <<_, b1, x::binary>>} -> {(b0 >>> 4) + (b1 <<< 4), x}
        {3, <<_, b1, b2, x::binary>>} -> {(b0 >>> 4) + (b1 <<< 4) + (b2 <<< 12), x}
        _ -> fail("truncated literals header")
      end

    case {b0 &&& 3, r} do
      {0, <<lit::binary-size(size), r2::binary>>} -> {lit, r2, st}
      {1, <<byte, r2::binary>>} -> {:binary.copy(<<byte>>, size), r2, st}
      _ -> fail("literals overrun block")
    end
  end

  defp literals(<<b0, _::binary>> = block, st) do
    {streams, header_bytes, width} =
      elem({{1, 3, 10}, {4, 3, 10}, {4, 4, 14}, {4, 5, 18}}, b0 >>> 2 &&& 3)

    with <<h::little-size(header_bytes * 8), r::binary>> <- block,
         mask = (1 <<< width) - 1,
         regen = h >>> 4 &&& mask,
         comp = h >>> (4 + width) &&& mask,
         <<lit_data::binary-size(comp), r2::binary>> <- r do
      {huf, stream_data} =
        case {b0 &&& 3, st.huf} do
          {2, _} -> huffman_description(lit_data)
          {3, nil} -> fail("treeless literals without a previous Huffman table")
          {3, huf} -> {huf, lit_data}
        end

      {huffman_streams(streams, stream_data, huf, regen), r2, %{st | huf: huf}}
    else
      _ -> fail("compressed literals overrun block")
    end
  end

  defp literals(_, _), do: fail("missing literals section")

  defp huffman_streams(1, data, huf, regen), do: data |> huffman_stream(huf, regen) |> :erlang.list_to_binary()

  defp huffman_streams(4, <<s1::little-16, s2::little-16, s3::little-16, data::binary>>, huf, regen) do
    s4 = byte_size(data) - s1 - s2 - s3
    quarter = div(regen + 3, 4)
    c4 = regen - 3 * quarter
    if s4 < 1 or c4 < 0, do: fail("corrupt 4-stream literals")
    <<d1::binary-size(s1), d2::binary-size(s2), d3::binary-size(s3), d4::binary>> = data

    [{d1, quarter}, {d2, quarter}, {d3, quarter}, {d4, c4}]
    |> Enum.map(fn {d, count} -> huffman_stream(d, huf, count) end)
    |> :erlang.list_to_binary()
  end

  defp huffman_streams(_, _, _, _), do: fail("corrupt 4-stream literals")

  defp huffman_stream(data, {table, max_bits}, count) do
    {rev, total, c0} = backward(data)
    huffman_loop(rev, total, c0, table, max_bits, count, [])
  end

  defp huffman_loop(_rev, total, c, _table, _max_bits, 0, acc) do
    if c != total, do: fail("Huffman stream not fully consumed")
    Enum.reverse(acc)
  end

  defp huffman_loop(rev, total, c, table, max_bits, n, acc) do
    {sym, nb} = elem(table, peek(rev, total, c, max_bits))
    huffman_loop(rev, total, c + nb, table, max_bits, n - 1, [sym | acc])
  end

  # ---------------------------------------------------------------- Huffman tables

  defp huffman_description(<<h, rest::binary>>) when h < 128 do
    case rest do
      <<desc::binary-size(h), after_desc::binary>> ->
        {probs, log, p} = fse_description(desc, 255, 6)
        table = fse_table(probs, log)
        <<_::binary-size(p), stream::binary>> = desc
        {rev, total, c0} = backward(stream)
        {s1, c1} = read(rev, total, c0, log)
        {s2, c2} = read(rev, total, c1, log)
        {fse_weights(rev, total, c2, table, s1, s2, []) |> huffman_table(), after_desc}

      _ ->
        fail("Huffman description overruns literals")
    end
  end

  defp huffman_description(<<h, rest::binary>>) do
    n = h - 127
    bytes = div(n + 1, 2)

    case rest do
      <<packed::binary-size(bytes), after_desc::binary>> ->
        weights = for <<w::4 <- packed>>, do: w
        {weights |> Enum.take(n) |> huffman_table(), after_desc}

      _ ->
        fail("Huffman description overruns literals")
    end
  end

  defp huffman_description(_), do: fail("missing Huffman description")

  defp fse_weights(_, _, _, _, _, _, acc) when length(acc) > 255, do: fail("too many Huffman weights")

  defp fse_weights(rev, total, c, table, s1, s2, acc) do
    {sym1, nb1, base1} = elem(table, s1)
    {v1, c1} = read(rev, total, c, nb1)
    n1 = base1 + v1

    if c1 > total do
      Enum.reverse([elem(elem(table, s2), 0), sym1 | acc])
    else
      {sym2, nb2, base2} = elem(table, s2)
      {v2, c2} = read(rev, total, c1, nb2)

      if c2 > total do
        Enum.reverse([elem(elem(table, n1), 0), sym2, sym1 | acc])
      else
        fse_weights(rev, total, c2, table, n1, base2 + v2, [sym2, sym1 | acc])
      end
    end
  end

  defp huffman_table(weights) do
    if length(weights) > 255, do: fail("too many Huffman weights")

    sum =
      Enum.reduce(weights, 0, fn
        w, _ when w > 11 -> fail("Huffman weight too large")
        0, acc -> acc
        w, acc -> acc + (1 <<< (w - 1))
      end)

    if sum == 0, do: fail("empty Huffman table")
    max_bits = highbit(sum) + 1
    if max_bits > 11, do: fail("Huffman code too long")
    rest = (1 <<< max_bits) - sum
    if (rest &&& rest - 1) != 0, do: fail("corrupt Huffman weights")

    # Longest codes (lowest weights) first; equal weights in symbol order.
    cells =
      (weights ++ [highbit(rest) + 1])
      |> Enum.with_index()
      |> Enum.filter(fn {w, _} -> w > 0 end)
      |> Enum.sort()
      |> Enum.flat_map(fn {w, s} -> List.duplicate({s, max_bits + 1 - w}, 1 <<< (w - 1)) end)

    {List.to_tuple(cells), max_bits}
  end

  # ---------------------------------------------------------------- FSE

  defp fse_description(data, max_symbol, max_log) do
    log = fpeek(data, 0, 4) + 5
    if log > max_log, do: fail("FSE accuracy log too large")
    {probs, bitpos, remaining} = fse_probs(data, 4, (1 <<< log) + 1, 1 <<< log, log + 1, [], 0, max_symbol)

    if remaining != 1 or length(probs) > max_symbol + 1, do: fail("corrupt FSE description")
    finish = (bitpos + 7) >>> 3
    if finish > byte_size(data), do: fail("FSE description overruns its section")
    {probs, log, finish}
  end

  defp fse_probs(_data, bitpos, remaining, _thr, _nbits, acc, _count, _max) when remaining <= 1,
    do: {Enum.reverse(acc), bitpos, remaining}

  defp fse_probs(_, _, _, _, _, _, count, max) when count > max, do: fail("FSE description has too many symbols")

  defp fse_probs(data, bitpos, remaining, threshold, nbits, acc, count, max) do
    biggest = 2 * threshold - 1 - remaining
    low = fpeek(data, bitpos, nbits - 1)

    {value, pos} =
      if low < biggest do
        {low, bitpos + nbits - 1}
      else
        v = fpeek(data, bitpos, nbits)
        {if(v >= threshold, do: v - biggest, else: v), bitpos + nbits}
      end

    prob = value - 1
    remaining = remaining - abs(prob)

    {acc, count, pos} =
      if prob == 0, do: zero_repeats(data, pos, [0 | acc], count + 1), else: {[prob | acc], count + 1, pos}

    {nbits, threshold} = shrink(remaining, nbits, threshold)
    fse_probs(data, pos, remaining, threshold, nbits, acc, count, max)
  end

  defp zero_repeats(data, pos, acc, count) do
    case fpeek(data, pos, 2) do
      3 -> zero_repeats(data, pos + 2, [0, 0, 0 | acc], count + 3)
      repeat -> {List.duplicate(0, repeat) ++ acc, count + repeat, pos + 2}
    end
  end

  defp shrink(remaining, nbits, threshold) when remaining < threshold and threshold > 1,
    do: shrink(remaining, nbits - 1, threshold >>> 1)

  defp shrink(_, nbits, threshold), do: {nbits, threshold}

  # Forward (LSB-first) bit reader with zero padding past the end.
  defp fpeek(_data, _bitpos, 0), do: 0

  defp fpeek(data, bitpos, n) do
    byte = bitpos >>> 3
    chunk = binary_part(data, min(byte, byte_size(data)), max(0, min(4, byte_size(data) - byte)))
    (:binary.decode_unsigned(chunk, :little) >>> (bitpos &&& 7)) &&& (1 <<< n) - 1
  end

  defp fse_table(probs, log) do
    size = 1 <<< log
    indexed = Enum.with_index(probs)
    mask = size - 1
    step = (size >>> 1) + (size >>> 3) + 3

    {cells, high} =
      indexed
      |> Enum.filter(fn {p, _} -> p == -1 end)
      |> Enum.reduce({%{}, size - 1}, fn {_, s}, {cells, high} -> {Map.put(cells, high, s), high - 1} end)

    {cells, pos} =
      Enum.reduce(indexed, {cells, 0}, fn
        {p, s}, acc when p > 0 ->
          Enum.reduce(1..p, acc, fn _, {cells, pos} ->
            {Map.put(cells, pos, s), advance(pos + step &&& mask, step, mask, high)}
          end)

        _, acc ->
          acc
      end)

    if pos != 0, do: fail("corrupt FSE distribution")
    counters = Map.new(indexed, fn {p, s} -> {s, if(p == -1, do: 1, else: p)} end)

    {rows, _} =
      Enum.map_reduce(0..(size - 1), counters, fn cell, counters ->
        s = Map.get(cells, cell, 0)
        x = Map.fetch!(counters, s)
        nb = log - highbit(x)
        {{s, nb, (x <<< nb) - size}, Map.put(counters, s, x + 1)}
      end)

    List.to_tuple(rows)
  end

  defp advance(pos, step, mask, high) when pos > high, do: advance(pos + step &&& mask, step, mask, high)
  defp advance(pos, _, _, _), do: pos

  # ---------------------------------------------------------------- sequences

  @ll_base {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
            128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}
  @ll_bits {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
            12, 13, 14, 15, 16}
  @ml_base {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
            28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
            2051, 4099, 8195, 16387, 32771, 65539}
  @ml_bits {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

  # kind -> {default distribution, default accuracy log, max symbol, max accuracy log}
  @kinds %{
    ll:
      {[4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1,
        -1, -1, -1], 6, 35, 9},
    ml:
      {[1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1], 6, 52, 9},
    off: {[1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1], 5, 31, 8}
  }

  defp predefined(kind) do
    key = {__MODULE__, kind}

    case :persistent_term.get(key, nil) do
      nil ->
        {probs, log, _, _} = @kinds[kind]
        table = {fse_table(probs, log), log}
        :persistent_term.put(key, table)
        table

      table ->
        table
    end
  end

  defp sequences(<<0>>, st), do: {[], st}
  defp sequences(<<0, _::binary>>, _), do: fail("data after empty sequences section")
  defp sequences(<<b0, r::binary>>, st) when b0 < 128, do: seq_modes(b0, r, st)
  defp sequences(<<b0, b1, r::binary>>, st) when b0 < 255, do: seq_modes((b0 - 128 <<< 8) + b1, r, st)
  defp sequences(<<255, n::little-16, r::binary>>, st), do: seq_modes(n + 0x7F00, r, st)
  defp sequences(_, _), do: fail("missing sequences section")

  defp seq_modes(count, <<llm::2, ofm::2, mlm::2, 0::2, r::binary>>, st) do
    {{llt, lllog}, r, st} = seq_table(llm, :ll, r, st)
    {{oft, oflog}, r, st} = seq_table(ofm, :off, r, st)
    {{mlt, mllog}, r, st} = seq_table(mlm, :ml, r, st)
    {rev, total, c} = backward(r)
    {lls, c} = read(rev, total, c, lllog)
    {ofs, c} = read(rev, total, c, oflog)
    {mls, c} = read(rev, total, c, mllog)
    {seq_loop(rev, total, c, count, {llt, oft, mlt}, lls, ofs, mls, []), st}
  end

  defp seq_modes(_, <<_::6, _::2, _::binary>>, _), do: fail("reserved compression-mode bits set")
  defp seq_modes(_, _, _), do: fail("missing compression modes")

  defp seq_table(0, kind, r, st), do: remember(kind, predefined(kind), r, st)

  defp seq_table(1, kind, <<sym, r::binary>>, st) do
    {_, _, max_sym, _} = @kinds[kind]
    if sym > max_sym, do: fail("bad RLE sequence symbol")
    remember(kind, {{{sym, 0, 0}}, 0}, r, st)
  end

  defp seq_table(1, _, _, _), do: fail("bad RLE sequence symbol")

  defp seq_table(2, kind, r, st) do
    {_, _, max_sym, max_log} = @kinds[kind]
    {probs, log, finish} = fse_description(r, max_sym, max_log)
    <<_::binary-size(finish), r::binary>> = r
    remember(kind, {fse_table(probs, log), log}, r, st)
  end

  defp seq_table(3, kind, r, st) do
    case Map.fetch!(st, kind) do
      nil -> fail("repeat mode without a previous table")
      table -> {table, r, st}
    end
  end

  defp remember(kind, table, r, st), do: {table, r, Map.put(st, kind, table)}

  defp seq_loop(_rev, total, c, 0, _tables, _lls, _ofs, _mls, acc) do
    if c != total, do: fail("sequence bitstream not fully consumed")
    Enum.reverse(acc)
  end

  defp seq_loop(rev, total, c, n, {llt, oft, mlt} = tables, lls, ofs, mls, acc) do
    {ofc, ofnb, ofbase} = elem(oft, ofs)
    {mlc, mlnb, mlbase} = elem(mlt, mls)
    {llc, llnb, llbase} = elem(llt, lls)
    {ov, c} = read(rev, total, c, ofc)
    {mlx, c} = read(rev, total, c, elem(@ml_bits, mlc))
    {llx, c} = read(rev, total, c, elem(@ll_bits, llc))
    seq = {elem(@ll_base, llc) + llx, (1 <<< ofc) + ov, elem(@ml_base, mlc) + mlx}

    if n == 1 do
      seq_loop(rev, total, c, 0, tables, lls, ofs, mls, [seq | acc])
    else
      {a, c} = read(rev, total, c, llnb)
      {b, c} = read(rev, total, c, mlnb)
      {d, c} = read(rev, total, c, ofnb)
      seq_loop(rev, total, c, n - 1, tables, llbase + a, ofbase + d, mlbase + b, [seq | acc])
    end
  end

  defp execute([], lit, out, rep, _total), do: {out <> lit, rep}

  defp execute([{ll, ov, ml} | seqs], lit, out, {r0, r1, r2} = rep, total) do
    case lit do
      <<l::binary-size(ll), lit::binary>> ->
        out = out <> l

        {offset, rep} =
          cond do
            ov > 3 ->
              {ov - 3, {ov - 3, r0, r1}}

            true ->
              case ov - 1 + if(ll == 0, do: 1, else: 0) do
                0 -> {r0, rep}
                1 -> {r1, {r1, r0, r2}}
                2 -> {r2, {r2, r0, r1}}
                3 -> {r0 - 1, {r0 - 1, r0, r1}}
              end
          end

        size = byte_size(out)
        if offset <= 0 or offset > size, do: fail("match offset out of range")
        if total + size + ml > @max_out, do: fail("decompressed size limit exceeded")
        execute(seqs, lit, copy_match(out, size, offset, ml), rep, total)

      _ ->
        fail("sequence consumes more literals than available")
    end
  end

  defp copy_match(out, size, offset, ml) when offset >= ml, do: out <> binary_part(out, size - offset, ml)

  defp copy_match(out, size, offset, ml) do
    # Overlapping copy: the last `offset` bytes repeat as a pattern.
    pattern = binary_part(out, size - offset, offset)
    out <> :binary.copy(pattern, div(ml, offset)) <> binary_part(pattern, 0, rem(ml, offset))
  end

  # ---------------------------------------------------------------- backward bits

  # {reversed bytes, total bits, consumed}; bits remaining = total - consumed.
  defp backward(<<>>), do: fail("empty bitstream")

  defp backward(data) do
    last = :binary.last(data)
    if last == 0, do: fail("bitstream end marker missing")
    rev = data |> :binary.bin_to_list() |> Enum.reverse() |> :erlang.list_to_binary()
    {rev, byte_size(data) * 8, 8 - highbit(last)}
  end

  defp read(rev, total, c, n), do: {peek(rev, total, c, n), c + n}

  defp peek(_rev, _total, _c, 0), do: 0

  defp peek(rev, total, c, n) when c + n <= total do
    <<_::size(c), v::size(n), _::bits>> = rev
    v
  end

  defp peek(_rev, total, c, _n) when c >= total, do: 0

  defp peek(rev, total, c, n) do
    avail = total - c
    <<_::size(c), v::size(avail)>> = rev
    v <<< (n - avail)
  end

  defp highbit(x), do: highbit(x, -1)
  defp highbit(0, n), do: n
  defp highbit(x, n), do: highbit(x >>> 1, n + 1)

  # ---------------------------------------------------------------- XXH64

  @p1 0x9E3779B185EBCA87
  @p2 0xC2B2AE3D27D4EB4F
  @p3 0x165667B19E3779F9
  @p4 0x85EBCA77C2B2AE63
  @p5 0x27D4EB2F165667C5

  defp rotl(x, r), do: (x <<< r ||| x >>> (64 - r)) &&& @m64
  defp xround(acc, lane), do: rotl(acc + lane * @p2 &&& @m64, 31) * @p1 &&& @m64
  defp merge(h, v), do: (bxor(h, xround(0, v)) * @p1 + @p4) &&& @m64

  def xxh64(data) do
    n = byte_size(data)

    {h, tail} =
      if n >= 32 do
        {v1, v2, v3, v4, tail} = stripes(data, @p1 + @p2 &&& @m64, @p2, 0, 0 - @p1 &&& @m64)
        h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18) &&& @m64
        {h |> merge(v1) |> merge(v2) |> merge(v3) |> merge(v4), tail}
      else
        {@p5, data}
      end

    (h + n &&& @m64) |> tail(tail) |> avalanche()
  end

  defp stripes(<<a::little-64, b::little-64, c::little-64, d::little-64, r::binary>>, v1, v2, v3, v4),
    do: stripes(r, xround(v1, a), xround(v2, b), xround(v3, c), xround(v4, d))

  defp stripes(r, v1, v2, v3, v4), do: {v1, v2, v3, v4, r}

  defp tail(h, <<l::little-64, r::binary>>), do: tail(rotl(bxor(h, xround(0, l)), 27) * @p1 + @p4 &&& @m64, r)
  defp tail(h, <<l::little-32, r::binary>>), do: tail(rotl(bxor(h, l * @p1 &&& @m64), 23) * @p2 + @p3 &&& @m64, r)
  defp tail(h, <<b, r::binary>>), do: tail(rotl(bxor(h, b * @p5 &&& @m64), 11) * @p1 &&& @m64, r)
  defp tail(h, <<>>), do: h

  defp avalanche(h) do
    h = bxor(h, h >>> 33) * @p2 &&& @m64
    h = bxor(h, h >>> 29) * @p3 &&& @m64
    bxor(h, h >>> 32)
  end
end
