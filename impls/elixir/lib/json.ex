defmodule OnlyBlocks.JSON do
  @moduledoc """
  A small RFC 8259 JSON reader/writer.

  Decoded values: `{:obj, [{key, value}]}` | list | binary | `{:num, text}` |
  `true` | `false` | `nil`. Numbers keep their source text so slot literals can
  be validated exactly and ids are echoed byte for byte. Depth is capped at
  128, so a 1 MiB body of nested arrays is a clean parse error.

  Encodable values: maps (atom or binary keys) | lists | binaries | integers |
  floats | booleans | `nil` | `{:raw, iodata}`.
  """

  @max_depth 128
  @ws [?\s, ?\t, ?\n, ?\r]

  # ---------------------------------------------------------------- decode

  def decode(bin) do
    {value, rest} = bin |> ws() |> value(0)
    if ws(rest) == "", do: {:ok, value}, else: :error
  catch
    _, _ -> :error
  end

  defp ws(<<c, r::binary>>) when c in @ws, do: ws(r)
  defp ws(bin), do: bin

  defp value(_, depth) when depth > @max_depth, do: throw(:too_deep)
  defp value("{" <> r, d), do: object(ws(r), d + 1, [])
  defp value("[" <> r, d), do: array(ws(r), d + 1, [])
  defp value(~s(") <> r, _), do: string(r, [])
  defp value("true" <> r, _), do: {true, r}
  defp value("false" <> r, _), do: {false, r}
  defp value("null" <> r, _), do: {nil, r}
  defp value(<<c, _::binary>> = bin, _) when c == ?- or c in ?0..?9, do: number(bin)
  defp value(_, _), do: throw(:syntax)

  defp object("}" <> r, _, []), do: {{:obj, []}, r}

  defp object(~s(") <> r, d, acc) do
    {key, r} = string(r, [])
    ":" <> r = ws(r)
    {value, r} = value(ws(r), d)

    case ws(r) do
      "," <> r -> object(ws(r), d, [{key, value} | acc])
      "}" <> r -> {{:obj, Enum.reverse([{key, value} | acc])}, r}
    end
  end

  defp array("]" <> r, _, []), do: {[], r}

  defp array(bin, d, acc) do
    {value, r} = value(bin, d)

    case ws(r) do
      "," <> r -> array(ws(r), d, [value | acc])
      "]" <> r -> {Enum.reverse([value | acc]), r}
    end
  end

  defp string(~s(") <> r, acc) do
    text = acc |> Enum.reverse() |> IO.iodata_to_binary()
    if String.valid?(text), do: {text, r}, else: throw(:invalid_utf8)
  end

  defp string(<<?\\, e, r::binary>>, acc) do
    case e do
      ?" -> string(r, [?" | acc])
      ?\\ -> string(r, [?\\ | acc])
      ?/ -> string(r, [?/ | acc])
      ?b -> string(r, [8 | acc])
      ?f -> string(r, [12 | acc])
      ?n -> string(r, [10 | acc])
      ?r -> string(r, [13 | acc])
      ?t -> string(r, [9 | acc])
      ?u -> unicode_escape(r, acc)
    end
  end

  defp string(<<c, _::binary>> = bin, acc) when c >= 0x20 do
    n = plain(bin, 0)
    <<chunk::binary-size(n), r::binary>> = bin
    string(r, [chunk | acc])
  end

  defp plain(<<c, r::binary>>, n) when c >= 0x20 and c != ?" and c != ?\\, do: plain(r, n + 1)
  defp plain(_, n), do: n

  defp unicode_escape(<<hex::binary-size(4), r::binary>>, acc) do
    case String.to_integer(hex, 16) do
      high when high in 0xD800..0xDBFF ->
        <<"\\u", low_hex::binary-size(4), r::binary>> = r
        low = String.to_integer(low_hex, 16)
        unless low in 0xDC00..0xDFFF, do: throw(:lone_surrogate)
        string(r, [<<0x10000 + (high - 0xD800) * 1024 + (low - 0xDC00)::utf8>> | acc])

      code when code in 0xDC00..0xDFFF ->
        throw(:lone_surrogate)

      code ->
        string(r, [<<code::utf8>> | acc])
    end
  end

  defp number(bin) do
    n = number_length(bin, 0)
    <<text::binary-size(n), r::binary>> = bin
    if text =~ ~r/\A-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?\z/, do: {{:num, text}, r}, else: throw(:number)
  end

  defp number_length(<<c, r::binary>>, n) when c in ?0..?9 or c in [?-, ?+, ?., ?e, ?E],
    do: number_length(r, n + 1)

  defp number_length(_, n), do: n

  # ---------------------------------------------------------------- encode

  def encode(value), do: value |> enc() |> IO.iodata_to_binary()

  defp enc(nil), do: "null"
  defp enc(true), do: "true"
  defp enc(false), do: "false"
  defp enc({:raw, raw}), do: raw
  defp enc(i) when is_integer(i), do: Integer.to_string(i)
  defp enc(f) when is_float(f), do: :erlang.float_to_binary(f, [:short])
  defp enc(b) when is_binary(b), do: [?", escape(b), ?"]
  defp enc(a) when is_atom(a), do: enc(Atom.to_string(a))
  defp enc(list) when is_list(list), do: [?[, list |> Enum.map(&enc/1) |> Enum.intersperse(?,), ?]]

  defp enc(map) when is_map(map) do
    pairs = Enum.map(map, fn {k, v} -> [enc(to_string(k)), ?:, enc(v)] end)
    [?{, Enum.intersperse(pairs, ?,), ?}]
  end

  defp escape(bin) do
    if bin =~ ~r/[\x00-\x1f"\\]/ do
      for <<c <- bin>>, do: esc(c)
    else
      bin
    end
  end

  defp esc(?"), do: "\\\""
  defp esc(?\\), do: "\\\\"
  defp esc(?\n), do: "\\n"
  defp esc(?\r), do: "\\r"
  defp esc(?\t), do: "\\t"
  defp esc(c) when c < 0x20, do: "\\u" <> String.pad_leading(Integer.to_string(c, 16), 4, "0")
  defp esc(c), do: c
end
