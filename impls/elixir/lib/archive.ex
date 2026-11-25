defmodule OnlyBlocks.Archive do
  @moduledoc """
  Old Faithful transport (two HTTP Range reads per block) over `:gen_tcp` or
  `:ssl`, the retry policy, the bounded caches and the getBlock pipeline.
  """
  import OnlyBlocks.Wire, only: [fail: 1]
  alias OnlyBlocks.{LRU, Meta, Rpc, Wire}

  @epoch_slots 432_000
  @max_slice 128 * 1024 * 1024
  @u64 0xFFFFFFFFFFFFFFFF
  @zero_hash "11111111111111111111111111111111"
  @max_inflight 32

  defp rpc_error(code, message), do: throw({:rpc, code, message})

  # ---------------------------------------------------------------- setup

  def start(base) do
    :persistent_term.put({__MODULE__, :base}, base)
    {:ok, _} = LRU.start_link(:ob_ranges, 100_000)
    {:ok, _} = LRU.start_link(:ob_hashes, 100_000)
    :persistent_term.put({__MODULE__, :inflight}, :atomics.new(1, signed: true))

    if base.scheme == :https do
      {:ok, _} = Application.ensure_all_started(:ssl)
      :persistent_term.put({__MODULE__, :cacerts}, load_cacerts())
    end

    :ok
  end

  # The OS trust store, read from a PEM file (no child processes).
  defp load_cacerts do
    ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"]
    |> Enum.find_value(fn file ->
      with {:ok, pem} <- File.read(file),
           [_ | _] = ders <- for({:Certificate, der, :not_encrypted} <- :public_key.pem_decode(pem), do: der) do
        ders
      else
        _ -> nil
      end
    end)
    |> Kernel.||(:public_key.cacerts_get())
  end

  # ---------------------------------------------------------------- getBlock

  def get_block(slot, encoding, details, rewards?, max_version) do
    {index, block} = load_block(slot)
    if Wire.u64(Wire.at(block, 1)) != slot, do: fail("Block slot differs from requested slot")
    entries = Wire.links(Wire.at(block, 3))
    info = if is_list(Wire.at(block, 4)), do: Wire.at(block, 4), else: []
    parent = Wire.u64(Wire.at(info, 0)) || 0
    hash = blockhash(slot, index, entries)

    result = %{
      previousBlockhash: previous_hash(slot, parent),
      blockhash: hash,
      parentSlot: parent,
      blockTime: (case Wire.i64(Wire.at(info, 1)) do
                    0 -> nil
                    t -> t
                  end),
      blockHeight: Wire.u64(Wire.at(info, 2))
    }

    result =
      case details do
        "none" ->
          result

        _ ->
          items =
            for entry <- entries, tx <- entry_transactions(index, entry) do
              transaction_item(slot, index, tx, encoding, details, rewards?, max_version)
            end

          Map.put(result, if(details == "signatures", do: :signatures, else: :transactions), items)
      end

    if rewards?, do: Map.merge(result, Meta.rewards(slot, rewards_payload(index, Wire.at(block, 5)))), else: result
  end

  defp entry_transactions(index, key) do
    entry = Wire.indexed(index, key, 1)
    unless match?(<<_::binary-size(32)>>, Wire.at(entry, 2)), do: fail("Invalid Entry hash")
    Wire.links(Wire.at(entry, 3))
  end

  defp transaction_item(slot, index, key, encoding, details, rewards?, max_version) do
    node = Wire.indexed(index, key, 0)
    tx = index |> Wire.frame_payload(Wire.at(node, 1)) |> Wire.transaction()

    case details do
      "signatures" ->
        case tx.signatures do
          [first | _] -> Wire.base58(first)
          [] -> fail("Transaction has no signature")
        end

      _ ->
        meta =
          case Wire.at(node, 2) do
            frame when is_list(frame) -> Meta.metadata(slot, Wire.frame_payload(index, frame))
            _ -> :none
          end

        Rpc.transaction_json(tx, meta, encoding, details, rewards?, max_version)
    end
  end

  defp rewards_payload(index, value) when is_binary(value) do
    case Wire.link(value) do
      {key, false} when is_map_key(index, key) ->
        case Wire.indexed(index, key, 5) do
          [_, _, frame | _] -> Wire.frame_payload(index, frame)
          _ -> <<>>
        end

      _ ->
        <<>>
    end
  end

  defp rewards_payload(_, _), do: <<>>

  defp blockhash(slot, index, entries) do
    hash =
      case entries do
        [] -> @zero_hash
        _ -> index |> Wire.indexed(List.last(entries), 1) |> Wire.at(2) |> Wire.pubkey()
      end

    LRU.put(:ob_hashes, slot, hash)
    hash
  end

  defp previous_hash(0, _parent), do: @zero_hash

  defp previous_hash(_slot, parent) do
    case LRU.get(:ob_hashes, parent) do
      {:ok, hash} ->
        hash

      :miss ->
        {index, block} = load_block(parent)
        blockhash(parent, index, Wire.links(Wire.at(block, 3)))
    end
  end

  defp load_block(slot) do
    {offset, length} =
      case LRU.get(:ob_ranges, slot) do
        {:ok, record} ->
          record

        :miss ->
          <<offset::little-64, length::little-32>> =
            read_range(slot, "-slot-ranges.raw", rem(slot, @epoch_slots) * 12, 12, 12)

          LRU.put(:ob_ranges, slot, {offset, length})
          {offset, length}
      end

    if length == 0, do: rpc_error(-32007, "Slot #{slot} was skipped, or missing in long-term storage")
    if length > @max_slice, do: fail("Archive slice exceeds 128 MiB")
    slot |> read_range(".car", offset, length, @max_slice) |> Wire.index_car()
  end

  # ---------------------------------------------------------------- range reads

  defp read_range(slot, suffix, start, size, cap) do
    finish = start + size - 1
    if finish > @u64, do: fail("Archive range end overflows u64")
    base = :persistent_term.get({__MODULE__, :base})
    epoch = div(slot, @epoch_slots)
    path = "#{base.path}/#{epoch}/epoch-#{epoch}#{suffix}"
    attempts(0, slot, base, path, "bytes=#{start}-#{finish}", size, cap)
  end

  defp attempts(attempt, slot, base, path, range, size, cap) do
    outcome =
      with_slot(fn ->
        try do
          attempt(base, path, range, size, cap)
        rescue
          e in OnlyBlocks.DecodeError -> reraise e, __STACKTRACE__
          _ -> :transport
        catch
          :exit, _ -> :transport
        end
      end)

    case outcome do
      {206, body} ->
        body

      {404, _} ->
        rpc_error(
          -32004,
          "Block not available for slot #{slot}: epoch #{div(slot, @epoch_slots)} is not archived " <>
            "in Old Faithful (historical-only server)"
        )

      {status, _} when status != 429 and status not in 500..599 ->
        fail("Unexpected archive HTTP status #{status}")

      _ when attempt >= 4 ->
        fail("Archive range retries exhausted")

      _ ->
        retry_after = with {_, header} <- outcome, do: header
        Process.sleep(retry_delay(retry_after, attempt))
        attempts(attempt + 1, slot, base, path, range, size, cap)
    end
  end

  # Hold one of @max_inflight upstream slots only while an attempt runs.
  defp with_slot(fun) do
    counter = :persistent_term.get({__MODULE__, :inflight})

    if :atomics.add_get(counter, 1, 1) > @max_inflight do
      :atomics.sub(counter, 1, 1)
      Process.sleep(5)
      with_slot(fun)
    else
      try do
        fun.()
      after
        :atomics.sub(counter, 1, 1)
      end
    end
  end

  defp retry_delay(header, attempt) when is_binary(header) do
    header = String.trim(header)

    cond do
      header =~ ~r/\A[0-9]+\z/ ->
        min(10, String.to_integer(header)) * 1000

      date = http_date(header) ->
        now = :calendar.datetime_to_gregorian_seconds(:calendar.universal_time())
        (date - now) |> min(10) |> max(0) |> Kernel.*(1000)

      true ->
        backoff(attempt)
    end
  end

  defp retry_delay(_, attempt), do: backoff(attempt)

  defp http_date(text) do
    case :httpd_util.convert_request_date(String.to_charlist(text)) do
      {{_, _, _}, {_, _, _}} = date -> :calendar.datetime_to_gregorian_seconds(date)
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp backoff(attempt) do
    base = min(10_000, 200 * Bitwise.bsl(1, min(attempt, 30)))
    round(base * (0.5 + :rand.uniform() * 0.5))
  end

  defp now_ms, do: System.monotonic_time(:millisecond)

  defp attempt(%{scheme: scheme, host: host, port: port}, path, range, size, cap) do
    deadline = now_ms() + 60_000
    host_chars = String.to_charlist(host)
    opts = [:binary, active: false, packet: :raw]

    {:ok, sock} =
      case scheme do
        :http ->
          :gen_tcp.connect(host_chars, port, opts, 10_000)

        :https ->
          :ssl.connect(
            host_chars,
            port,
            opts ++
              [
                verify: :verify_peer,
                cacerts: :persistent_term.get({__MODULE__, :cacerts}),
                server_name_indication: host_chars,
                customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
              ],
            10_000
          )
      end

    transport = if scheme == :https, do: :ssl, else: :gen_tcp

    try do
      host_header = if {scheme, port} in [{:http, 80}, {:https, 443}], do: host, else: "#{host}:#{port}"

      :ok =
        transport.send(sock, [
          "GET #{path} HTTP/1.1\r\nHost: #{host_header}\r\nRange: #{range}\r\n",
          "User-Agent: onlyblocks/elixir\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ])

      recv = fn timeout -> transport.recv(sock, 0, timeout) end
      {{:response, status}, headers, rest} = read_head(recv, deadline, :response)

      case status do
        206 -> {206, body(recv, deadline, headers, rest, size, cap)}
        _ -> {status, header(headers, "retry-after")}
      end
    after
      transport.close(sock)
    end
  end

  defp header(headers, name) do
    case List.keyfind(headers, name, 0) do
      {_, value} -> value
      nil -> nil
    end
  end

  defp remaining(deadline) do
    case deadline - now_ms() do
      left when left > 0 -> left
      _ -> exit(:timeout)
    end
  end

  defp recv!(recv, deadline) do
    case recv.(remaining(deadline)) do
      {:ok, more} -> more
      {:error, why} -> exit(why)
    end
  end

  @doc """
  Read an HTTP/1.x head with the VM's built-in `:erlang.decode_packet/3` parser.
  Returns `{{:request, method, path} | {:response, status}, [{lower_name, value}], rest}`.
  """
  def read_head(recv, deadline, kind, buf \\ <<>>) do
    cond do
      :binary.match(buf, "\r\n\r\n") != :nomatch ->
        {:ok, start, r} = :erlang.decode_packet(:http_bin, buf, [])

        line =
          case {kind, start} do
            {:response, {:http_response, _, status, _}} -> {:response, status}
            {:request, {:http_request, method, {:abs_path, path}, _}} -> {:request, method, path}
            {:request, {:http_request, method, _, _}} -> {:request, method, :other}
            _ -> exit(:bad_start_line)
          end

        {headers, rest} = headers(r, [])
        {line, headers, rest}

      byte_size(buf) > 65_536 ->
        exit(:head_too_large)

      true ->
        read_head(recv, deadline, kind, buf <> recv!(recv, deadline))
    end
  end

  defp headers(buf, acc) do
    case :erlang.decode_packet(:httph_bin, buf, []) do
      {:ok, {:http_header, _, _, name, value}, r} -> headers(r, [{String.downcase(name), value} | acc])
      {:ok, :http_eoh, r} -> {Enum.reverse(acc), r}
      _ -> exit(:bad_header)
    end
  end

  # A 206 body: Content-Length, chunked, or until close; never above the cap.
  defp body(recv, deadline, headers, rest, size, cap) do
    lengths = for {"content-length", v} <- headers, do: v

    body =
      case {header(headers, "transfer-encoding"), lengths} do
        {nil, []} ->
          until_close(recv, deadline, [rest], byte_size(rest), cap)

        {nil, [text]} ->
          unless text =~ ~r/\A[0-9]{1,12}\z/, do: fail("Invalid archive Content-Length")
          n = String.to_integer(text)
          if n > cap, do: fail("Archive Content-Length exceeds range cap")
          exactly(recv, deadline, rest, n)

        {nil, _} ->
          fail("Multiple archive Content-Length headers")

        {te, _} ->
          if String.downcase(String.trim(te)) != "chunked", do: fail("Unsupported Transfer-Encoding")
          chunked(recv, deadline, rest, cap, [], 0)
      end

    if byte_size(body) != size, do: fail("Archive range body has wrong length")
    body
  end

  defp exactly(recv, deadline, buf, n) do
    Stream.unfold(byte_size(buf), fn
      have when have >= n -> nil
      have -> with more <- recv!(recv, deadline), do: {more, have + byte_size(more)}
    end)
    |> Enum.reduce([buf], &[&1 | &2])
    |> Enum.reverse()
    |> IO.iodata_to_binary()
    |> binary_part(0, n)
  end

  defp until_close(recv, deadline, acc, have, cap) do
    if have > cap, do: fail("Archive body exceeds range cap")

    case recv.(remaining(deadline)) do
      {:ok, more} -> until_close(recv, deadline, [more | acc], have + byte_size(more), cap)
      {:error, :closed} -> acc |> Enum.reverse() |> IO.iodata_to_binary()
      {:error, why} -> exit(why)
    end
  end

  @doc "Decode a chunked body from a growing buffer, failing once it exceeds `cap`."
  def chunked(recv, deadline, buf, cap, acc, have, on_cap \\ fn -> fail("Archive body exceeds range cap") end) do
    case :binary.split(buf, "\r\n") do
      [line, r] ->
        [size_text | _] = :binary.split(line, ";")
        size = size_text |> String.trim() |> String.to_integer(16)
        if have + size > cap, do: on_cap.()

        if size == 0 do
          acc |> Enum.reverse() |> IO.iodata_to_binary()
        else
          <<chunk::binary-size(size), "\r\n", r::binary>> = fill(recv, deadline, r, size + 2)
          chunked(recv, deadline, r, cap, [chunk | acc], have + size, on_cap)
        end

      [_] when byte_size(buf) > 4096 ->
        exit(:bad_chunk)

      [_] ->
        chunked(recv, deadline, fill(recv, deadline, buf, byte_size(buf) + 1), cap, acc, have, on_cap)
    end
  end

  defp fill(_recv, _deadline, buf, n) when byte_size(buf) >= n, do: buf
  defp fill(recv, deadline, buf, n), do: fill(recv, deadline, buf <> recv!(recv, deadline), n)
end
