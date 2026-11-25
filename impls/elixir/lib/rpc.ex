defmodule OnlyBlocks.Rpc do
  @moduledoc """
  JSON-RPC 2.0 envelope, getBlock parameter validation and the transaction
  JSON shapes of WIRE_FORMATS.md section 13.
  """
  alias OnlyBlocks.{Archive, JSON, Meta, Wire}

  @u64 0xFFFFFFFFFFFFFFFF
  @upgradeable "BPFLoaderUpgradeab1e11111111111111111111111"
  @reserved MapSet.new(~w(
    AddressLookupTab1e1111111111111111111111111 BPFLoader2111111111111111111111111111111111
    BPFLoader1111111111111111111111111111111111 BPFLoaderUpgradeab1e11111111111111111111111
    ComputeBudget111111111111111111111111111111 Config1111111111111111111111111111111111111
    Ed25519SigVerify111111111111111111111111111 Feature111111111111111111111111111111111111
    LoaderV411111111111111111111111111111111111 KeccakSecp256k11111111111111111111111111111
    Secp256r1SigVerify1111111111111111111111111 StakeConfig11111111111111111111111111111111
    Stake11111111111111111111111111111111111111 11111111111111111111111111111111
    Vote111111111111111111111111111111111111111 ZkE1Gama1Proof11111111111111111111111111111
    ZkTokenProof1111111111111111111111111111111 SysvarC1ock11111111111111111111111111111111
    SysvarEpochRewards1111111111111111111111111 SysvarEpochSchedu1e111111111111111111111111
    SysvarFees111111111111111111111111111111111 Sysvar1nstructions1111111111111111111111111
    SysvarLastRestartS1ot1111111111111111111111 SysvarRecentB1ockHashes11111111111111111111
    SysvarRent111111111111111111111111111111111 SysvarRewards111111111111111111111111111111
    SysvarS1otHashes111111111111111111111111111 SysvarS1otHistory11111111111111111111111111
    SysvarStakeHistory1111111111111111111111111 NativeLoader1111111111111111111111111111111
    Sysvar1111111111111111111111111111111111111))

  @unsupported_version "Transaction version (0) is not supported by the requesting client. " <>
                         "Please try the request again with the following configuration parameter: " <>
                         ~s("maxSupportedTransactionVersion": 0)

  # ---------------------------------------------------------------- envelope

  @doc "Raw request body in, response JSON out."
  def handle(body) do
    case JSON.decode(body) do
      :error -> error_response(nil, -32700, "Parse error")
      {:ok, [_ | _] = batch} when length(batch) <= 100 -> ["[", batch |> Enum.map(&dispatch/1) |> Enum.intersperse(","), "]"]
      {:ok, batch} when is_list(batch) -> error_response(nil, -32600, "Invalid batch size")
      {:ok, request} -> dispatch(request)
    end
    |> IO.iodata_to_binary()
  end

  defp response(id, key, value), do: JSON.encode(%{:jsonrpc => "2.0", key => value, :id => id_json(id)})

  defp id_json({:num, text}), do: {:raw, text}
  defp id_json(id), do: id

  defp error_response(id, code, message), do: response(id, :error, %{code: code, message: message})

  defp text_or_nil?(v), do: is_binary(v) or is_nil(v)

  defp dispatch({:obj, pairs}) do
    # Duplicate keys: the last occurrence wins.
    request = Map.new(pairs)
    {version, method, id} = {request["jsonrpc"], request["method"], request["id"]}

    cond do
      not (text_or_nil?(version) and text_or_nil?(method) and (text_or_nil?(id) or match?({:num, _}, id))) ->
        error_response(nil, -32600, "Invalid Request")

      version != "2.0" or is_nil(method) ->
        error_response(id, -32600, "Invalid Request")

      true ->
        try do
          response(id, :result, call(method, request["params"]))
        catch
          {:rpc, code, message} -> error_response(id, code, message)
          kind, reason -> error_response(id, -32603, "Internal error: " <> Exception.format_banner(kind, reason))
        end
    end
  end

  defp dispatch(_), do: error_response(nil, -32600, "Invalid Request")

  defp call("getHealth", params) when params in [nil, []], do: "ok"
  defp call("getHealth", _), do: throw({:rpc, -32602, "Invalid getHealth params"})

  defp call("getBlock", params) do
    {slot, encoding, details, rewards?, max_version} = block_params(params)
    Archive.get_block(slot, encoding, details, rewards?, max_version)
  end

  defp call(method, _), do: throw({:rpc, -32601, "Method not found: #{method}"})

  # ---------------------------------------------------------------- params

  defp invalid!, do: throw({:rpc, -32602, "Invalid params"})

  # Validate the number's *source text*: `1.0` and `1e3` are not slots.
  defp uint_param({:num, text}, max) do
    with true <- text =~ ~r/\A(0|[1-9][0-9]{0,19})\z/,
         value when value <= max <- String.to_integer(text) do
      value
    else
      _ -> invalid!()
    end
  end

  defp uint_param(_, _), do: invalid!()

  defp block_params([slot | rest]) when length(rest) <= 1 do
    slot = uint_param(slot, @u64)

    config =
      case rest do
        [] -> %{}
        [nil] -> %{}
        [encoding] when is_binary(encoding) -> %{"encoding" => encoding}
        [{:obj, pairs}] -> Map.new(pairs)
        _ -> invalid!()
      end

    option = fn name, default -> if is_nil(config[name]), do: default, else: config[name] end
    encoding = option.("encoding", "json")
    details = option.("transactionDetails", "full")
    rewards? = option.("rewards", true)

    unless encoding in ~w(json jsonParsed base64 base58) and details in ~w(full accounts signatures none) and
             (details != "accounts" or encoding == "json") and is_boolean(rewards?) and
             option.("commitment", "finalized") in ~w(finalized confirmed),
           do: invalid!()

    max_version =
      case config["maxSupportedTransactionVersion"] do
        nil -> :none
        value -> uint_param(value, 255)
      end

    {slot, encoding, details, rewards?, max_version}
  end

  defp block_params(_), do: invalid!()

  # ---------------------------------------------------------------- transactions

  def transaction_json(%{version: 0}, _meta, _encoding, _details, _rewards?, :none),
    do: throw({:rpc, -32015, @unsupported_version})

  def transaction_json(%{version: version} = tx, meta, encoding, details, rewards?, max_version) do
    meta = if version == 0 and meta == :none, do: Meta.empty_meta(), else: meta
    parsed? = encoding == "jsonParsed"
    accounts_only? = details == "accounts"
    static = Enum.map(tx.keys, &Wire.base58/1)
    loaded = if meta == :none, do: %{writable: [], readonly: []}, else: meta.loadedAddresses
    accounts = if parsed? or accounts_only?, do: account_objects(tx, static, loaded), else: static
    keys = if parsed?, do: accounts |> Enum.map(& &1.pubkey) |> List.to_tuple(), else: :none

    transaction =
      case encoding do
        "base64" -> [Wire.base64(tx.raw), encoding]
        "base58" -> [Wire.base58(tx.raw), encoding]
        _ when accounts_only? -> %{signatures: Enum.map(tx.signatures, &Wire.base58/1), accountKeys: accounts}
        _ -> %{signatures: Enum.map(tx.signatures, &Wire.base58/1), message: message_json(tx, accounts, keys, parsed?)}
      end

    item = %{transaction: transaction, meta: if(meta == :none, do: nil, else: meta_json(meta, keys, parsed?, accounts_only?, rewards?))}
    if meta != :none and max_version != :none, do: Map.put(item, :version, version), else: item
  end

  defp message_json(tx, accounts, keys, parsed?) do
    {nrs, nros, nrou} = tx.header

    %{
      accountKeys: accounts,
      recentBlockhash: Wire.base58(tx.recent),
      instructions: for({p, a, d} <- tx.instructions, do: instruction_json(p, a, d, 1, keys))
    }
    |> then(fn m ->
      if parsed?,
        do: m,
        else: Map.put(m, :header, %{numRequiredSignatures: nrs, numReadonlySignedAccounts: nros, numReadonlyUnsignedAccounts: nrou})
    end)
    |> then(fn m ->
      case tx.lookups do
        nil ->
          m

        lookups ->
          Map.put(
            m,
            :addressTableLookups,
            for({key, w, r} <- lookups,
              do: %{accountKey: Wire.base58(key), writableIndexes: :binary.bin_to_list(w), readonlyIndexes: :binary.bin_to_list(r)}
            )
          )
      end
    end)
  end

  defp instruction_json(p, accounts, data, height, :none),
    do: %{programIdIndex: p, accounts: :binary.bin_to_list(accounts), data: Wire.base58(data), stackHeight: height}

  defp instruction_json(p, accounts, data, height, keys) do
    address = fn
      i when i < tuple_size(keys) -> elem(keys, i)
      _ -> Wire.fail("Instruction account index out of range")
    end

    %{programId: address.(p), accounts: for(<<i <- accounts>>, do: address.(i)), data: Wire.base58(data), stackHeight: height}
  end

  # WIRE_FORMATS.md section 14: signer / writable flags.
  defp account_objects(%{version: version, header: {nrs, nros, nrou}, instructions: ixs}, static, loaded) do
    {writable, readonly} = if version == 0, do: {loaded.writable, loaded.readonly}, else: {[], []}
    s = length(static)
    w = length(writable)
    all = static ++ writable ++ readonly
    programs = MapSet.new(ixs, fn {p, _, _} -> p end)
    upgradeable? = @upgradeable in all

    all
    |> Enum.with_index()
    |> Enum.map(fn {key, i} ->
      lookup? = i >= s

      can_write? =
        cond do
          lookup? -> i - s < w
          i < nrs -> i < nrs - nros
          true -> i < s - nrou
        end

      %{
        pubkey: key,
        signer: i < nrs,
        writable: can_write? and key not in @reserved and (upgradeable? or i not in programs),
        source: if(lookup?, do: "lookupTable", else: "transaction")
      }
    end)
  end

  defp meta_json(meta, keys, parsed?, accounts_only?, rewards?) do
    meta = Map.put(meta, :status, if(is_nil(meta.err), do: %{"Ok" => nil}, else: %{"Err" => meta.err}))
    meta = if rewards?, do: meta, else: %{meta | rewards: nil}

    if accounts_only? do
      meta = Map.drop(meta, [:innerInstructions, :logMessages, :loadedAddresses, :returnData, :computeUnitsConsumed, :costUnits])
      if rewards?, do: meta, else: Map.delete(meta, :rewards)
    else
      meta = if parsed?, do: Map.delete(meta, :loadedAddresses), else: meta

      case meta.innerInstructions do
        nil ->
          meta

        groups ->
          %{
            meta
            | innerInstructions:
                for {index, ixs} <- groups do
                  %{index: index, instructions: for({p, a, d, h} <- ixs, do: instruction_json(p, a, d, h, keys))}
                end
          }
      end
    end
  end
end
