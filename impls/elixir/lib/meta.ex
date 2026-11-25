defmodule OnlyBlocks.Meta do
  @moduledoc """
  Transaction metadata and block rewards: protobuf (modern), bincode
  (pre-epoch-157), zstd unwrapping and the epoch-157 codec split.
  """
  import Bitwise
  import OnlyBlocks.Wire, only: [fail: 1, utf8: 1, pubkey: 1, base64: 1]
  alias OnlyBlocks.{Wire, Zstd}

  @cutoff 157 * 432_000
  @u64 0xFFFFFFFFFFFFFFFF
  @epsilon 2.220446049250313e-16

  @instruction_errors ~w(GenericError InvalidArgument InvalidInstructionData InvalidAccountData
    AccountDataTooSmall InsufficientFunds IncorrectProgramId MissingRequiredSignature
    AccountAlreadyInitialized UninitializedAccount UnbalancedInstruction ModifiedProgramId
    ExternalAccountLamportSpend ExternalAccountDataModified ReadonlyLamportChange ReadonlyDataModified
    DuplicateAccountIndex ExecutableModified RentEpochModified NotEnoughAccountKeys
    AccountDataSizeChanged AccountNotExecutable AccountBorrowFailed AccountBorrowOutstanding
    DuplicateAccountOutOfSync Custom InvalidError ExecutableDataModified ExecutableLamportChange
    ExecutableAccountNotRentExempt UnsupportedProgramId CallDepth MissingAccount ReentrancyNotAllowed
    MaxSeedLengthExceeded InvalidSeeds InvalidRealloc ComputationalBudgetExceeded PrivilegeEscalation
    ProgramEnvironmentSetupFailure ProgramFailedToComplete ProgramFailedToCompile Immutable
    IncorrectAuthority BorshIoError AccountNotRentExempt InvalidAccountOwner ArithmeticOverflow
    UnsupportedSysvar IllegalOwner MaxAccountsDataAllocationsExceeded MaxAccountsExceeded
    MaxInstructionTraceLengthExceeded BuiltinProgramsMustConsumeComputeUnits)
                       |> List.to_tuple()

  @transaction_errors ~w(AccountInUse AccountLoadedTwice AccountNotFound ProgramAccountNotFound
    InsufficientFundsForFee InvalidAccountForFee AlreadyProcessed BlockhashNotFound InstructionError
    CallChainTooDeep MissingSignatureForFee InvalidAccountIndex SignatureFailure
    InvalidProgramForExecution SanitizeFailure ClusterMaintenance AccountBorrowOutstanding
    WouldExceedMaxBlockCostLimit UnsupportedVersion InvalidWritableAccount WouldExceedMaxAccountCostLimit
    WouldExceedAccountDataBlockLimit TooManyAccountLocks AddressLookupTableNotFound
    InvalidAddressLookupTableOwner InvalidAddressLookupTableData InvalidAddressLookupTableIndex
    InvalidRentPayingAccount WouldExceedMaxVoteCostLimit WouldExceedAccountDataTotalLimit
    DuplicateInstruction InsufficientFundsForRent MaxLoadedAccountsDataSizeExceeded
    InvalidLoadedAccountsDataSizeLimit ResanitizationNeeded ProgramExecutionTemporarilyRestricted
    UnbalancedTransaction ProgramCacheHitMaxLimit CommitCancelled)
                       |> List.to_tuple()

  @reward_types {"Fee", "Rent", "Staking", "Voting"}

  # ---------------------------------------------------------------- entry points

  def metadata(_slot, <<>>), do: :none
  def metadata(slot, data), do: unwrap(slot, data, &pb_meta/1, &meta_from_pb/1, &bincode_meta/1)

  def rewards(_slot, <<>>), do: %{rewards: []}
  def rewards(slot, data), do: unwrap(slot, data, &pb_rewards/1, &rewards_from_pb/1, &bincode_rewards/1)

  def empty_meta do
    %{
      err: nil,
      fee: 0,
      preBalances: [],
      postBalances: [],
      innerInstructions: nil,
      logMessages: nil,
      preTokenBalances: nil,
      postTokenBalances: nil,
      rewards: nil,
      loadedAddresses: %{writable: [], readonly: []}
    }
  end

  # WIRE_FORMATS.md 9.1: zstd first when the magic is present, otherwise raw
  # first with zstd as the fallback.
  defp unwrap(slot, <<0x28, 0xB5, 0x2F, 0xFD, _::binary>> = data, parse, convert, stored) do
    plain =
      try do
        Zstd.decompress(data)
      rescue
        _ -> data
      end

    payload(slot, plain, parse, convert, stored)
  end

  defp unwrap(slot, data, parse, convert, stored) do
    payload(slot, data, parse, convert, stored)
  rescue
    original ->
      case attempt(fn -> Zstd.decompress(data) end) do
        {:ok, plain} -> payload(slot, plain, parse, convert, stored)
        :error -> reraise original, __STACKTRACE__
      end
  end

  defp attempt(fun) do
    {:ok, fun.()}
  rescue
    _ -> :error
  end

  defp payload(slot, data, parse, convert, stored) when slot < @cutoff do
    stored.(data)
  rescue
    _ -> data |> parse.() |> convert.()
  end

  defp payload(_slot, data, parse, convert, stored) do
    case attempt(fn -> parse.(data) end) do
      {:ok, parsed} -> convert.(parsed)
      :error -> stored.(data)
    end
  end

  # ---------------------------------------------------------------- protobuf wire

  # A whole message as [{field, wire_type, value}] in wire order.
  defp fields(bin, acc \\ [])
  defp fields(<<>>, acc), do: Enum.reverse(acc)

  defp fields(bin, acc) do
    case key(bin) do
      {field, 3, r} ->
        fields(skip_group(r, field, 0), acc)

      {field, wire, r} ->
        {value, r} = value(wire, r)
        fields(r, [{field, wire, value} | acc])
    end
  end

  defp key(bin) do
    {k, r} = Wire.uvarint(bin)
    if k < 8 or k > 0xFFFFFFFF, do: fail("invalid protobuf key")
    {k >>> 3, k &&& 7, r}
  end

  defp value(0, r), do: Wire.uvarint(r)
  defp value(1, <<v::binary-size(8), r::binary>>), do: {v, r}

  defp value(2, r) do
    {n, r} = Wire.uvarint(r)

    case r do
      <<v::binary-size(n), r::binary>> -> {v, r}
      _ -> fail("truncated protobuf field")
    end
  end

  defp value(5, <<v::binary-size(4), r::binary>>), do: {v, r}
  defp value(_, _), do: fail("invalid protobuf wire type")

  defp skip_group(_, _, depth) when depth >= 100, do: fail("protobuf group nesting limit")

  defp skip_group(bin, field, depth) do
    case key(bin) do
      {^field, 4, r} -> r
      {_, 4, _} -> fail("mismatched protobuf group")
      {f, 3, r} -> r |> skip_group(f, depth + 1) |> skip_group(field, depth)
      {_, wire, r} -> wire |> value(r) |> elem(1) |> skip_group(field, depth)
    end
  end

  defp packed(<<>>, acc), do: acc

  defp packed(bin, acc) do
    {v, r} = Wire.uvarint(bin)
    packed(r, [v | acc])
  end

  # Fold a message; each schema callback rejects known fields with the wrong
  # wire type and ignores unknown fields.
  defp fold(bin, acc, fun), do: bin |> fields() |> Enum.reduce(acc, fn {f, w, v}, acc -> fun.(f, w, v, acc) end)

  defp push(m, key, v), do: Map.update(m, key, [v], &[v | &1])
  # A non-repeated message seen twice is merged: concatenation is a merge.
  defp concat(m, key, v), do: Map.update(m, key, v, &(&1 <> v))
  defp rev(m, key), do: m |> Map.get(key, []) |> Enum.reverse()

  defp wrong_wire, do: fail("wrong protobuf wire type")

  # NaN and the infinities do not match a float segment: they become null.
  defp double(<<f::float-little-64>>), do: f
  defp double(_), do: nil

  defp int64(v) when v >= 1 <<< 63, do: v - (1 <<< 64)
  defp int64(v), do: v

  # ---------------------------------------------------------------- protobuf schemas
  # Parsing is eager: any failure here is a protobuf *parse* failure. Errors in
  # meta_from_pb/1 and rewards_from_pb/1 (conversion) are final.

  defp pb_meta(bin) do
    m = fold(bin, %{}, &meta_field/4)
    m = if Map.has_key?(m, :err), do: Map.update!(m, :err, &pb_error/1), else: m
    if Map.has_key?(m, :rd), do: Map.update!(m, :rd, &pb_return_data/1), else: m
  end

  defp meta_field(1, 2, v, m), do: concat(m, :err, v)
  defp meta_field(2, 0, v, m), do: Map.put(m, :fee, v)
  defp meta_field(f, 0, v, m) when f in [3, 4], do: push(m, f, v)
  defp meta_field(f, 2, v, m) when f in [3, 4], do: Map.put(m, f, packed(v, Map.get(m, f, [])))
  defp meta_field(5, 2, v, m), do: push(m, :inner, pb_inner(v))
  defp meta_field(6, 2, v, m), do: push(m, :logs, utf8(v))
  defp meta_field(7, 2, v, m), do: push(m, :pre_tb, pb_token(v))
  defp meta_field(8, 2, v, m), do: push(m, :post_tb, pb_token(v))
  defp meta_field(9, 2, v, m), do: push(m, :rewards, pb_reward(v))
  defp meta_field(10, 0, v, m), do: Map.put(m, :inner_none, v != 0)
  defp meta_field(11, 0, v, m), do: Map.put(m, :logs_none, v != 0)
  defp meta_field(12, 2, v, m), do: push(m, :lw, v)
  defp meta_field(13, 2, v, m), do: push(m, :lr, v)
  defp meta_field(14, 2, v, m), do: concat(m, :rd, v)
  defp meta_field(15, 0, v, m), do: Map.put(m, :rd_none, v != 0)
  defp meta_field(16, 0, v, m), do: Map.put(m, :cuc, v)
  defp meta_field(17, 0, v, m), do: Map.put(m, :cost, v)
  defp meta_field(f, _, _, _) when f in 1..17, do: wrong_wire()
  defp meta_field(_, _, _, m), do: m

  defp pb_error(bin) do
    fold(bin, <<>>, fn
      1, 2, v, _ -> v
      1, _, _, _ -> wrong_wire()
      _, _, _, acc -> acc
    end)
  end

  defp pb_return_data(bin) do
    fold(bin, %{}, fn
      1, 2, v, m -> Map.put(m, :program, v)
      2, 2, v, m -> Map.put(m, :data, v)
      f, _, _, _ when f in [1, 2] -> wrong_wire()
      _, _, _, m -> m
    end)
  end

  defp pb_inner(bin) do
    m =
      fold(bin, %{}, fn
        1, 0, v, m -> Map.put(m, :index, v)
        2, 2, v, m -> push(m, :ixs, pb_instruction(v))
        f, _, _, _ when f in [1, 2] -> wrong_wire()
        _, _, _, m -> m
      end)

    {Map.get(m, :index, 0) &&& 255, rev(m, :ixs)}
  end

  defp pb_instruction(bin) do
    m =
      fold(bin, %{}, fn
        1, 0, v, m -> Map.put(m, :p, v)
        2, 2, v, m -> Map.put(m, :accounts, v)
        3, 2, v, m -> Map.put(m, :data, v)
        4, 0, v, m -> Map.put(m, :height, v &&& 0xFFFFFFFF)
        f, _, _, _ when f in 1..4 -> wrong_wire()
        _, _, _, m -> m
      end)

    {Map.get(m, :p, 0) &&& 255, Map.get(m, :accounts, <<>>), Map.get(m, :data, <<>>), Map.get(m, :height)}
  end

  defp pb_token(bin) do
    m =
      fold(bin, %{}, fn
        1, 0, v, m -> Map.put(m, :index, v)
        2, 2, v, m -> Map.put(m, :mint, utf8(v))
        3, 2, v, m -> concat(m, :amount, v)
        4, 2, v, m -> Map.put(m, :owner, utf8(v))
        5, 2, v, m -> Map.put(m, :program, utf8(v))
        f, _, _, _ when f in 1..5 -> wrong_wire()
        _, _, _, m -> m
      end)

    amount =
      m
      |> Map.get(:amount, <<>>)
      |> fold(%{}, fn
        1, 1, v, a -> Map.put(a, :ui, double(v))
        2, 0, v, a -> Map.put(a, :decimals, v)
        3, 2, v, a -> Map.put(a, :amount, utf8(v))
        4, 2, v, a -> Map.put(a, :display, utf8(v))
        f, _, _, _ when f in 1..4 -> wrong_wire()
        _, _, _, a -> a
      end)

    ui =
      case Map.get(amount, :ui, 0.0) do
        u when is_float(u) and abs(u) > @epsilon -> u
        _ -> nil
      end

    token_balance(
      Map.get(m, :index, 0) &&& 255,
      Map.get(m, :mint, ""),
      ui,
      Map.get(amount, :decimals, 0) &&& 255,
      Map.get(amount, :amount, ""),
      Map.get(m, :owner, ""),
      Map.get(m, :program, ""),
      Map.get(amount, :display, "")
    )
  end

  defp pb_reward(bin) do
    m =
      fold(bin, %{}, fn
        1, 2, v, m -> Map.put(m, :pubkey, utf8(v))
        2, 0, v, m -> Map.put(m, :lamports, int64(v))
        3, 0, v, m -> Map.put(m, :post, v)
        4, 0, v, m -> Map.put(m, :type, v &&& 0xFFFFFFFF)
        5, 2, v, m -> Map.put(m, :commission, utf8(v))
        6, 2, v, m -> Map.put(m, :bps, utf8(v))
        f, _, _, _ when f in 1..6 -> wrong_wire()
        _, _, _, m -> m
      end)

    commission =
      case unsigned_text(Map.get(m, :commission, ""), 255) do
        nil ->
          case unsigned_text(Map.get(m, :bps, ""), 65535) do
            bps when is_integer(bps) and div(bps, 100) <= 255 -> div(bps, 100)
            _ -> nil
          end

        c ->
          c
      end

    type =
      case Map.get(m, :type, 0) do
        t when t in 1..4 -> elem(@reward_types, t - 1)
        _ -> nil
      end

    %{
      pubkey: Map.get(m, :pubkey, ""),
      lamports: Map.get(m, :lamports, 0),
      postBalance: Map.get(m, :post, 0),
      rewardType: type,
      commission: commission
    }
  end

  defp pb_rewards(bin) do
    m =
      fold(bin, %{}, fn
        1, 2, v, m -> push(m, :rewards, pb_reward(v))
        2, 2, v, m -> concat(m, :parts, v)
        f, _, _, _ when f in [1, 2] -> wrong_wire()
        _, _, _, m -> m
      end)

    case m do
      %{parts: parts} ->
        count =
          fold(parts, 0, fn
            1, 0, v, _ -> v
            1, _, _, _ -> wrong_wire()
            _, _, _, acc -> acc
          end)

        %{m | parts: count}

      _ ->
        m
    end
  end

  defp rewards_from_pb(m) do
    result = %{rewards: rev(m, :rewards)}
    if Map.has_key?(m, :parts), do: Map.put(result, :numRewardPartitions, m.parts), else: result
  end

  defp meta_from_pb(m) do
    base = %{
      empty_meta()
      | err: if(Map.has_key?(m, :err), do: transaction_error(m.err), else: nil),
        fee: Map.get(m, :fee, 0),
        preBalances: rev(m, 3),
        postBalances: rev(m, 4),
        preTokenBalances: rev(m, :pre_tb),
        postTokenBalances: rev(m, :post_tb),
        rewards: rev(m, :rewards),
        loadedAddresses: %{writable: Enum.map(rev(m, :lw), &pubkey/1), readonly: Enum.map(rev(m, :lr), &pubkey/1)}
    }

    base
    |> then(&if(Map.get(m, :inner_none, false), do: &1, else: %{&1 | innerInstructions: rev(m, :inner)}))
    |> then(&if(Map.get(m, :logs_none, false), do: &1, else: %{&1 | logMessages: rev(m, :logs)}))
    |> then(fn meta ->
      case {m, Map.get(m, :rd_none, false)} do
        {%{rd: rd}, false} ->
          Map.put(meta, :returnData, %{
            programId: pubkey(Map.get(rd, :program, <<>>)),
            data: [base64(Map.get(rd, :data, <<>>)), "base64"]
          })

        _ ->
          meta
      end
    end)
    |> then(&if(Map.has_key?(m, :cuc), do: Map.put(&1, :computeUnitsConsumed, m.cuc), else: &1))
    |> then(&if(Map.has_key?(m, :cost), do: Map.put(&1, :costUnits, m.cost), else: &1))
  end

  # ---------------------------------------------------------------- shared helpers

  # Rust `from_str` for unsigned types: optional '+', ASCII digits, must fit.
  defp unsigned_text("+" <> digits, max) when digits != "", do: digits(digits, max)
  defp unsigned_text(digits, max) when digits != "", do: digits(digits, max)
  defp unsigned_text(_, _), do: nil

  defp digits(text, max) do
    if text =~ ~r/\A[0-9]+\z/ do
      case String.to_integer(text) do
        v when v <= max -> v
        _ -> nil
      end
    end
  end

  defp token_balance(index, mint, ui, decimals, amount, owner, program, display) do
    display =
      if display == "", do: real_number(unsigned_text(amount, @u64) || 0, decimals), else: display

    %{
      accountIndex: index,
      mint: mint,
      uiTokenAmount: %{uiAmount: ui, decimals: decimals, amount: amount, uiAmountString: display}
    }
    |> then(&if(owner == "", do: &1, else: Map.put(&1, :owner, owner)))
    |> then(&if(program == "", do: &1, else: Map.put(&1, :programId, program)))
  end

  # real_number_string_trimmed (WIRE_FORMATS.md 15.4)
  defp real_number(amount, 0), do: Integer.to_string(amount)

  defp real_number(amount, decimals) do
    padded = amount |> Integer.to_string() |> String.pad_leading(decimals + 1, "0")
    {int, frac} = String.split_at(padded, -decimals)

    case String.trim_trailing(frac, "0") do
      "" -> int
      frac -> int <> "." <> frac
    end
  end

  # ---------------------------------------------------------------- bincode

  defp u8(<<v, r::binary>>), do: {v, r}
  defp u8(_), do: fail("truncated bincode")
  defp u32(<<v::little-32, r::binary>>), do: {v, r}
  defp u32(_), do: fail("truncated bincode")
  defp u64(<<v::little-64, r::binary>>), do: {v, r}
  defp u64(_), do: fail("truncated bincode")
  defp i64(<<v::little-signed-64, r::binary>>), do: {v, r}
  defp i64(_), do: fail("truncated bincode")
  defp f64(<<v::float-little-64, r::binary>>), do: {v, r}
  defp f64(<<_::binary-size(8), r::binary>>), do: {nil, r}
  defp f64(_), do: fail("truncated bincode")

  defp string(bin) do
    {n, r} = u64(bin)

    case r do
      <<s::binary-size(n), r::binary>> -> {utf8(s), r}
      _ -> fail("truncated bincode string")
    end
  end

  defp vec(bin, min, fun) do
    {n, r} = u64(bin)
    if n > div(byte_size(r), min), do: fail("count exceeds enclosing field")
    vec_loop(n, r, fun, [])
  end

  defp vec_loop(0, r, _fun, acc), do: {Enum.reverse(acc), r}

  defp vec_loop(n, r, fun, acc) do
    {v, r} = fun.(r)
    vec_loop(n - 1, r, fun, [v | acc])
  end

  defp option(<<0, r::binary>>, _fun), do: {nil, r}
  defp option(<<1, r::binary>>, fun), do: fun.(r)
  defp option(_, _), do: fail("invalid bincode option")

  @doc "Bincode TransactionError (trailing bytes allowed)."
  def transaction_error(bin), do: bin |> tx_error() |> elem(0)

  defp tx_error(bin) do
    {variant, r} = u32(bin)
    if variant >= tuple_size(@transaction_errors), do: fail("unknown TransactionError variant")
    name = elem(@transaction_errors, variant)

    case variant do
      8 ->
        {index, r} = u8(r)
        {kind, r} = u32(r)
        if kind >= tuple_size(@instruction_errors), do: fail("unknown InstructionError variant")

        if kind == 25 do
          {code, r} = u32(r)
          {%{name => [index, %{"Custom" => code}]}, r}
        else
          {%{name => [index, elem(@instruction_errors, kind)]}, r}
        end

      30 ->
        {i, r} = u8(r)
        {%{name => i}, r}

      v when v in [31, 35] ->
        {i, r} = u8(r)
        {%{name => %{account_index: i}}, r}

      _ ->
        {name, r}
    end
  end

  defp reward_type(bin) do
    {t, r} = u32(bin)
    if t >= 4, do: fail("unknown RewardType")
    {elem(@reward_types, t), r}
  end

  defp stored_reward(bin, extended) do
    {key, r} = string(bin)
    {lamports, r} = i64(r)
    {post, r} = if r != <<>> or not extended, do: u64(r), else: {0, r}
    {type, r} = if r != <<>> or not extended, do: option(r, &reward_type/1), else: {nil, r}
    {commission, r} = if r != <<>> and extended, do: option(r, &u8/1), else: {nil, r}
    {%{pubkey: key, lamports: lamports, postBalance: post, rewardType: type, commission: commission}, r}
  end

  defp stored_token(bin, layout) do
    {index, r} = u8(bin)
    {mint, r} = string(r)
    {ui, r} = f64(r)
    {decimals, r} = u8(r)
    {amount, r} = string(r)
    {owner, r} = if layout >= 2 and r != <<>>, do: string(r), else: {"", r}
    {program, r} = if layout >= 3 and r != <<>>, do: string(r), else: {"", r}
    {token_balance(index, mint, ui, decimals, amount, owner, program, ""), r}
  end

  defp return_data(<<program::binary-size(32), r::binary>>) do
    {n, r} = u64(r)

    case r do
      <<data::binary-size(n), r::binary>> -> {%{programId: pubkey(program), data: [base64(data), "base64"]}, r}
      _ -> fail("truncated return data")
    end
  end

  defp return_data(_), do: fail("truncated return data")

  defp stored_meta(bin, legacy, layout) do
    {status, r} = u32(bin)
    if status > 1, do: fail("invalid bincode result tag")
    {err, r} = if status == 1, do: tx_error(r), else: {nil, r}
    {fee, r} = u64(r)
    {pre, r} = vec(r, 8, &u64/1)
    {post, r} = vec(r, 8, &u64/1)

    inner_ix = fn b ->
      {{p, a, d}, r} = Wire.instruction(b)

      if legacy do
        {{p, a, d, nil}, r}
      else
        {height, r} = option(r, &u32/1)
        {{p, a, d, height}, r}
      end
    end

    inner = fn b ->
      {index, r} = u8(b)
      {ixs, r} = vec(r, if(legacy, do: 3, else: 4), inner_ix)
      {{index, ixs}, r}
    end

    token = &stored_token(&1, layout)

    fields = [
      innerInstructions: &vec(&1, 9, inner),
      logMessages: &vec(&1, 8, fn b -> string(b) end),
      preTokenBalances: &vec(&1, 26, token),
      postTokenBalances: &vec(&1, 26, token),
      rewards: &vec(&1, 16, fn b -> stored_reward(b, true) end),
      returnData: &return_data/1,
      computeUnitsConsumed: &u64/1,
      costUnits: &u64/1
    ]

    optional_fields(fields, r, %{empty_meta() | err: err, fee: fee, preBalances: pre, postBalances: post})
  end

  # EOF-default fields: once the input is exhausted, every later field defaults.
  defp optional_fields([], r, meta), do: {meta, r}
  defp optional_fields(_, <<>>, meta), do: {meta, <<>>}

  defp optional_fields([{name, fun} | rest], bin, meta) do
    case option(bin, fun) do
      {nil, r} -> optional_fields(rest, r, meta)
      {v, r} -> optional_fields(rest, r, Map.put(meta, name, v))
    end
  end

  # Strict layouts first (whole input consumed); then the first layout in
  # lenient mode, whose failure is final.
  defp bincode(data, [first | _] = layouts) do
    Enum.find_value(layouts, fn layout ->
      case attempt(fn -> layout.(data) end) do
        {:ok, {value, <<>>}} -> {:ok, value}
        _ -> nil
      end
    end)
    |> case do
      {:ok, value} -> value
      nil -> data |> first.() |> elem(0)
    end
  end

  defp bincode_meta(data) do
    bincode(data, [
      &stored_meta(&1, false, 3),
      &stored_meta(&1, true, 1),
      &stored_meta(&1, true, 2),
      &stored_meta(&1, true, 3)
    ])
  end

  defp bincode_rewards(data) do
    %{
      rewards:
        bincode(data, [
          &vec(&1, 16, fn b -> stored_reward(b, true) end),
          &vec(&1, 25, fn b -> stored_reward(b, false) end)
        ])
    }
  end
end
