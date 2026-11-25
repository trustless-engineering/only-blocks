%% Transaction metadata and block rewards: protobuf (modern), bincode
%% (pre-epoch-157), zstd unwrapping and the epoch-157 codec split.
-module(ob_meta).
-export([metadata/2, rewards/2, empty_meta/0, transaction_error/1]).

-import(ob_wire, [fail/1, utf8/1, pubkey/1, base64/1]).

-define(CUTOFF, (157 * 432000)).
-define(U64, 16#FFFFFFFFFFFFFFFF).
-define(EPSILON, 2.220446049250313e-16).

-define(INSTRUCTION_ERRORS, {
    <<"GenericError">>, <<"InvalidArgument">>, <<"InvalidInstructionData">>, <<"InvalidAccountData">>,
    <<"AccountDataTooSmall">>, <<"InsufficientFunds">>, <<"IncorrectProgramId">>,
    <<"MissingRequiredSignature">>, <<"AccountAlreadyInitialized">>, <<"UninitializedAccount">>,
    <<"UnbalancedInstruction">>, <<"ModifiedProgramId">>, <<"ExternalAccountLamportSpend">>,
    <<"ExternalAccountDataModified">>, <<"ReadonlyLamportChange">>, <<"ReadonlyDataModified">>,
    <<"DuplicateAccountIndex">>, <<"ExecutableModified">>, <<"RentEpochModified">>,
    <<"NotEnoughAccountKeys">>, <<"AccountDataSizeChanged">>, <<"AccountNotExecutable">>,
    <<"AccountBorrowFailed">>, <<"AccountBorrowOutstanding">>, <<"DuplicateAccountOutOfSync">>,
    <<"Custom">>, <<"InvalidError">>, <<"ExecutableDataModified">>, <<"ExecutableLamportChange">>,
    <<"ExecutableAccountNotRentExempt">>, <<"UnsupportedProgramId">>, <<"CallDepth">>,
    <<"MissingAccount">>, <<"ReentrancyNotAllowed">>, <<"MaxSeedLengthExceeded">>, <<"InvalidSeeds">>,
    <<"InvalidRealloc">>, <<"ComputationalBudgetExceeded">>, <<"PrivilegeEscalation">>,
    <<"ProgramEnvironmentSetupFailure">>, <<"ProgramFailedToComplete">>, <<"ProgramFailedToCompile">>,
    <<"Immutable">>, <<"IncorrectAuthority">>, <<"BorshIoError">>, <<"AccountNotRentExempt">>,
    <<"InvalidAccountOwner">>, <<"ArithmeticOverflow">>, <<"UnsupportedSysvar">>, <<"IllegalOwner">>,
    <<"MaxAccountsDataAllocationsExceeded">>, <<"MaxAccountsExceeded">>,
    <<"MaxInstructionTraceLengthExceeded">>, <<"BuiltinProgramsMustConsumeComputeUnits">>}).

-define(TRANSACTION_ERRORS, {
    <<"AccountInUse">>, <<"AccountLoadedTwice">>, <<"AccountNotFound">>, <<"ProgramAccountNotFound">>,
    <<"InsufficientFundsForFee">>, <<"InvalidAccountForFee">>, <<"AlreadyProcessed">>,
    <<"BlockhashNotFound">>, <<"InstructionError">>, <<"CallChainTooDeep">>, <<"MissingSignatureForFee">>,
    <<"InvalidAccountIndex">>, <<"SignatureFailure">>, <<"InvalidProgramForExecution">>,
    <<"SanitizeFailure">>, <<"ClusterMaintenance">>, <<"AccountBorrowOutstanding">>,
    <<"WouldExceedMaxBlockCostLimit">>, <<"UnsupportedVersion">>, <<"InvalidWritableAccount">>,
    <<"WouldExceedMaxAccountCostLimit">>, <<"WouldExceedAccountDataBlockLimit">>,
    <<"TooManyAccountLocks">>, <<"AddressLookupTableNotFound">>, <<"InvalidAddressLookupTableOwner">>,
    <<"InvalidAddressLookupTableData">>, <<"InvalidAddressLookupTableIndex">>,
    <<"InvalidRentPayingAccount">>, <<"WouldExceedMaxVoteCostLimit">>,
    <<"WouldExceedAccountDataTotalLimit">>, <<"DuplicateInstruction">>, <<"InsufficientFundsForRent">>,
    <<"MaxLoadedAccountsDataSizeExceeded">>, <<"InvalidLoadedAccountsDataSizeLimit">>,
    <<"ResanitizationNeeded">>, <<"ProgramExecutionTemporarilyRestricted">>, <<"UnbalancedTransaction">>,
    <<"ProgramCacheHitMaxLimit">>, <<"CommitCancelled">>}).

-define(REWARD_TYPES, {<<"Fee">>, <<"Rent">>, <<"Staking">>, <<"Voting">>}).

%% ---------------------------------------------------------------- entry points

metadata(_Slot, <<>>) -> none;
metadata(Slot, Data) -> unwrap(Slot, Data, fun pb_meta/1, fun meta_from_pb/1, fun bincode_meta/1).

rewards(_Slot, <<>>) -> #{rewards => []};
rewards(Slot, Data) -> unwrap(Slot, Data, fun pb_rewards/1, fun rewards_from_pb/1, fun bincode_rewards/1).

empty_meta() ->
    #{err => null, fee => 0, preBalances => [], postBalances => [], innerInstructions => null,
      logMessages => null, preTokenBalances => null, postTokenBalances => null, rewards => null,
      loadedAddresses => #{writable => [], readonly => []}}.

%% WIRE_FORMATS.md section 9.1: zstd first when the magic is present,
%% otherwise raw first with zstd as the fallback.
unwrap(Slot, <<16#28, 16#B5, 16#2F, 16#FD, _/binary>> = Data, Parse, Convert, Stored) ->
    Plain = try ob_zstd:decompress(Data) catch error:_ -> Data end,
    payload(Slot, Plain, Parse, Convert, Stored);
unwrap(Slot, Data, Parse, Convert, Stored) ->
    try payload(Slot, Data, Parse, Convert, Stored)
    catch error:Original ->
            case try {ok, ob_zstd:decompress(Data)} catch error:_ -> failed end of
                {ok, Plain} -> payload(Slot, Plain, Parse, Convert, Stored);
                failed -> erlang:error(Original)
            end
    end.

payload(Slot, Data, Parse, Convert, Stored) when Slot < ?CUTOFF ->
    try Stored(Data)
    catch error:_ -> Convert(Parse(Data))
    end;
payload(_Slot, Data, Parse, Convert, Stored) ->
    case try {ok, Parse(Data)} catch error:_ -> failed end of
        {ok, Parsed} -> Convert(Parsed);
        failed -> Stored(Data)
    end.

%% ---------------------------------------------------------------- protobuf wire

%% Decode a whole message into [{Field, WireType, Value}] in wire order.
fields(Bin) -> fields(Bin, []).
fields(<<>>, Acc) -> lists:reverse(Acc);
fields(Bin, Acc) ->
    {Field, Wire, R} = key(Bin),
    case Wire of
        3 -> fields(skip_group(R, Field, 0), Acc);
        _ -> {V, R2} = value(Wire, R), fields(R2, [{Field, Wire, V} | Acc])
    end.

key(Bin) ->
    {K, R} = ob_wire:uvarint(Bin),
    (K >= 8 andalso K =< 16#FFFFFFFF) orelse fail(bad_protobuf_key),
    {K bsr 3, K band 7, R}.

value(0, R) -> ob_wire:uvarint(R);
value(1, <<V:8/binary, R/binary>>) -> {V, R};
value(2, R0) ->
    {N, R} = ob_wire:uvarint(R0),
    case R of
        <<V:N/binary, R2/binary>> -> {V, R2};
        _ -> fail(truncated_protobuf)
    end;
value(5, <<V:4/binary, R/binary>>) -> {V, R};
value(_, _) -> fail(bad_protobuf_wire).

skip_group(_, _, Depth) when Depth >= 100 -> fail(protobuf_group_nesting);
skip_group(Bin, Field, Depth) ->
    case key(Bin) of
        {Field, 4, R} -> R;
        {_, 4, _} -> fail(mismatched_group);
        {F, 3, R} -> skip_group(skip_group(R, F, Depth + 1), Field, Depth);
        {_, W, R} -> {_, R2} = value(W, R), skip_group(R2, Field, Depth)
    end.

packed(<<>>, Acc) -> Acc;
packed(Bin, Acc) -> {V, R} = ob_wire:uvarint(Bin), packed(R, [V | Acc]).

%% Fold a message with Fun(Field, Wire, Value, Acc). Unknown fields are
%% skipped by the callbacks' catch-all clause; wrong wire types fail.
fold(Bin, Fun, Acc0) -> lists:foldl(fun({F, W, V}, A) -> Fun(F, W, V, A) end, Acc0, fields(Bin)).

append(Key, V, M) -> M#{Key => [V | maps:get(Key, M, [])]}.
%% Non-repeated message fields merge: concatenating occurrences is a merge.
concat(Key, V, M) -> M#{Key => <<(maps:get(Key, M, <<>>))/binary, V/binary>>}.
rev(Key, M) -> lists:reverse(maps:get(Key, M, [])).

double(<<F:64/float-little>>) -> F;
double(_) -> null.  % NaN and infinities

int64(V) when V >= 1 bsl 63 -> V - (1 bsl 64);
int64(V) -> V.

%% ---------------------------------------------------------------- protobuf schemas
%% Parsing is eager (any failure here is a protobuf *parse* failure);
%% conversion (meta_from_pb/1, rewards_from_pb/1) errors are final.

pb_meta(Bin) ->
    M = fold(Bin, fun meta_field/4, #{}),
    M1 = case M of #{err := E} -> M#{err := pb_bytes_field(E)}; _ -> M end,
    case M1 of #{rd := RD} -> M1#{rd := pb_return_data(RD)}; _ -> M1 end.

meta_field(1, 2, V, M) -> concat(err, V, M);
meta_field(2, 0, V, M) -> M#{fee => V};
meta_field(F, 0, V, M) when F =:= 3; F =:= 4 -> append(F, V, M);
meta_field(F, 2, V, M) when F =:= 3; F =:= 4 -> M#{F => packed(V, maps:get(F, M, []))};
meta_field(5, 2, V, M) -> append(inner, pb_inner(V), M);
meta_field(6, 2, V, M) -> append(logs, utf8(V), M);
meta_field(7, 2, V, M) -> append(pre_tb, pb_token(V), M);
meta_field(8, 2, V, M) -> append(post_tb, pb_token(V), M);
meta_field(9, 2, V, M) -> append(rewards, pb_reward(V), M);
meta_field(10, 0, V, M) -> M#{inner_none => V =/= 0};
meta_field(11, 0, V, M) -> M#{logs_none => V =/= 0};
meta_field(12, 2, V, M) -> append(lw, V, M);
meta_field(13, 2, V, M) -> append(lr, V, M);
meta_field(14, 2, V, M) -> concat(rd, V, M);
meta_field(15, 0, V, M) -> M#{rd_none => V =/= 0};
meta_field(16, 0, V, M) -> M#{cuc => V};
meta_field(17, 0, V, M) -> M#{cost => V};
meta_field(F, _, _, _) when F >= 1, F =< 17 -> fail(wrong_protobuf_wire_type);
meta_field(_, _, _, M) -> M.

pb_bytes_field(Bin) ->
    fold(Bin, fun(1, 2, V, _) -> V; (1, _, _, _) -> fail(wrong_protobuf_wire_type); (_, _, _, A) -> A end,
         <<>>).

pb_return_data(Bin) ->
    fold(Bin, fun(1, 2, V, M) -> M#{program => V};
                 (2, 2, V, M) -> M#{data => V};
                 (F, _, _, _) when F =:= 1; F =:= 2 -> fail(wrong_protobuf_wire_type);
                 (_, _, _, M) -> M
              end, #{}).

pb_inner(Bin) ->
    M = fold(Bin, fun(1, 0, V, A) -> A#{index => V};
                     (2, 2, V, A) -> append(ixs, pb_instruction(V), A);
                     (F, _, _, _) when F =:= 1; F =:= 2 -> fail(wrong_protobuf_wire_type);
                     (_, _, _, A) -> A
                  end, #{}),
    {maps:get(index, M, 0) band 255, rev(ixs, M)}.

pb_instruction(Bin) ->
    M = fold(Bin, fun(1, 0, V, A) -> A#{p => V};
                     (2, 2, V, A) -> A#{acc => V};
                     (3, 2, V, A) -> A#{data => V};
                     (4, 0, V, A) -> A#{height => V band 16#FFFFFFFF};
                     (F, _, _, _) when F >= 1, F =< 4 -> fail(wrong_protobuf_wire_type);
                     (_, _, _, A) -> A
                  end, #{}),
    {maps:get(p, M, 0) band 255, maps:get(acc, M, <<>>), maps:get(data, M, <<>>),
     maps:get(height, M, null)}.

pb_token(Bin) ->
    M = fold(Bin, fun(1, 0, V, A) -> A#{index => V};
                     (2, 2, V, A) -> A#{mint => utf8(V)};
                     (3, 2, V, A) -> concat(amount, V, A);
                     (4, 2, V, A) -> A#{owner => utf8(V)};
                     (5, 2, V, A) -> A#{program => utf8(V)};
                     (F, _, _, _) when F >= 1, F =< 5 -> fail(wrong_protobuf_wire_type);
                     (_, _, _, A) -> A
                  end, #{}),
    Amount = fold(maps:get(amount, M, <<>>),
                  fun(1, 1, V, A) -> A#{ui => double(V)};
                     (2, 0, V, A) -> A#{decimals => V};
                     (3, 2, V, A) -> A#{amount => utf8(V)};
                     (4, 2, V, A) -> A#{display => utf8(V)};
                     (F, _, _, _) when F >= 1, F =< 4 -> fail(wrong_protobuf_wire_type);
                     (_, _, _, A) -> A
                  end, #{}),
    Ui = case maps:get(ui, Amount, 0.0) of
             U when is_float(U), abs(U) > ?EPSILON -> U;
             _ -> null
         end,
    token_balance(maps:get(index, M, 0) band 255, maps:get(mint, M, <<>>), Ui,
                  maps:get(decimals, Amount, 0) band 255, maps:get(amount, Amount, <<>>),
                  maps:get(owner, M, <<>>), maps:get(program, M, <<>>), maps:get(display, Amount, <<>>)).

pb_reward(Bin) ->
    M = fold(Bin, fun(1, 2, V, A) -> A#{pubkey => utf8(V)};
                     (2, 0, V, A) -> A#{lamports => int64(V)};
                     (3, 0, V, A) -> A#{post => V};
                     (4, 0, V, A) -> A#{type => V band 16#FFFFFFFF};
                     (5, 2, V, A) -> A#{commission => utf8(V)};
                     (6, 2, V, A) -> A#{bps => utf8(V)};
                     (F, _, _, _) when F >= 1, F =< 6 -> fail(wrong_protobuf_wire_type);
                     (_, _, _, A) -> A
                  end, #{}),
    Commission = case unsigned_text(maps:get(commission, M, <<>>), 255) of
                     undefined ->
                         case unsigned_text(maps:get(bps, M, <<>>), 65535) of
                             Bps when is_integer(Bps), Bps div 100 =< 255 -> Bps div 100;
                             _ -> null
                         end;
                     C -> C
                 end,
    Type = case maps:get(type, M, 0) of
               T when T >= 1, T =< 4 -> element(T, ?REWARD_TYPES);
               _ -> null
           end,
    #{pubkey => maps:get(pubkey, M, <<>>), lamports => maps:get(lamports, M, 0),
      postBalance => maps:get(post, M, 0), rewardType => Type, commission => Commission}.

pb_rewards(Bin) ->
    M = fold(Bin, fun(1, 2, V, A) -> append(rewards, pb_reward(V), A);
                     (2, 2, V, A) -> concat(parts, V, A);
                     (F, _, _, _) when F =:= 1; F =:= 2 -> fail(wrong_protobuf_wire_type);
                     (_, _, _, A) -> A
                  end, #{}),
    case M of
        #{parts := P} ->
            Count = fold(P, fun(1, 0, V, _) -> V; (1, _, _, _) -> fail(wrong_protobuf_wire_type);
                               (_, _, _, A) -> A end, 0),
            M#{parts := Count};
        _ -> M
    end.

rewards_from_pb(M) ->
    R = #{rewards => rev(rewards, M)},
    case M of
        #{parts := P} -> R#{numRewardPartitions => P};
        _ -> R
    end.

meta_from_pb(M) ->
    Err = case M of
              #{err := E} -> transaction_error(E);
              _ -> null
          end,
    Base = (empty_meta())#{
             err := Err,
             fee := maps:get(fee, M, 0),
             preBalances := lists:reverse(maps:get(3, M, [])),
             postBalances := lists:reverse(maps:get(4, M, [])),
             preTokenBalances := rev(pre_tb, M),
             postTokenBalances := rev(post_tb, M),
             rewards := rev(rewards, M),
             loadedAddresses := #{writable => [pubkey(K) || K <- rev(lw, M)],
                                  readonly => [pubkey(K) || K <- rev(lr, M)]}},
    B1 = case maps:get(inner_none, M, false) of
             true -> Base;
             false -> Base#{innerInstructions := rev(inner, M)}
         end,
    B2 = case maps:get(logs_none, M, false) of
             true -> B1;
             false -> B1#{logMessages := rev(logs, M)}
         end,
    B3 = case {M, maps:get(rd_none, M, false)} of
             {#{rd := RD}, false} ->
                 B2#{returnData => #{programId => pubkey(maps:get(program, RD, <<>>)),
                                     data => [base64(maps:get(data, RD, <<>>)), <<"base64">>]}};
             _ -> B2
         end,
    B4 = case M of #{cuc := Cu} -> B3#{computeUnitsConsumed => Cu}; _ -> B3 end,
    case M of #{cost := Co} -> B4#{costUnits => Co}; _ -> B4 end.

%% ---------------------------------------------------------------- shared helpers

%% Rust `u64::from_str`-style: optional '+', ASCII digits, must fit Max.
unsigned_text(<<"+", Digits/binary>>, Max) when Digits =/= <<>> -> digits(Digits, Max);
unsigned_text(Digits, Max) when Digits =/= <<>> -> digits(Digits, Max);
unsigned_text(_, _) -> undefined.

digits(Bin, Max) ->
    case lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(Bin)) of
        true ->
            V = binary_to_integer(Bin),
            if V =< Max -> V; true -> undefined end;
        false -> undefined
    end.

token_balance(Index, Mint, Ui, Decimals, Amount, Owner, Program, Display0) ->
    Display = case Display0 of
                  <<>> -> real_number(case unsigned_text(Amount, ?U64) of undefined -> 0; V -> V end,
                                      Decimals);
                  _ -> Display0
              end,
    B = #{accountIndex => Index, mint => Mint,
          uiTokenAmount => #{uiAmount => Ui, decimals => Decimals, amount => Amount,
                             uiAmountString => Display}},
    B1 = case Owner of <<>> -> B; _ -> B#{owner => Owner} end,
    case Program of <<>> -> B1; _ -> B1#{programId => Program} end.

%% real_number_string_trimmed (WIRE_FORMATS.md section 15.4)
real_number(Amount, 0) -> integer_to_binary(Amount);
real_number(Amount, Decimals) ->
    S = integer_to_binary(Amount),
    Padded = case byte_size(S) =< Decimals of
                 true -> <<(binary:copy(<<"0">>, Decimals + 1 - byte_size(S)))/binary, S/binary>>;
                 false -> S
             end,
    IntLen = byte_size(Padded) - Decimals,
    <<Int:IntLen/binary, Frac/binary>> = Padded,
    case string:trim(Frac, trailing, "0") of
        <<>> -> Int;
        F -> <<Int/binary, ".", (iolist_to_binary(F))/binary>>
    end.

%% ---------------------------------------------------------------- bincode

u8(<<V, R/binary>>) -> {V, R};
u8(_) -> fail(truncated).
u32(<<V:32/little, R/binary>>) -> {V, R};
u32(_) -> fail(truncated).
u64(<<V:64/little, R/binary>>) -> {V, R};
u64(_) -> fail(truncated).
i64(<<V:64/little-signed, R/binary>>) -> {V, R};
i64(_) -> fail(truncated).
f64(<<V:64/float-little, R/binary>>) -> {V, R};
f64(<<_:8/binary, R/binary>>) -> {null, R};
f64(_) -> fail(truncated).

string(Bin) ->
    {N, R} = u64(Bin),
    case R of
        <<S:N/binary, R2/binary>> -> {utf8(S), R2};
        _ -> fail(truncated_string)
    end.

vec(Bin, Min, Fun) ->
    {N, R} = u64(Bin),
    N =< byte_size(R) div Min orelse fail(count_exceeds_input),
    vec_loop(N, R, Fun, []).

vec_loop(0, R, _Fun, Acc) -> {lists:reverse(Acc), R};
vec_loop(N, R, Fun, Acc) -> {V, R2} = Fun(R), vec_loop(N - 1, R2, Fun, [V | Acc]).

option(<<0, R/binary>>, _Fun) -> {null, R};
option(<<1, R/binary>>, Fun) -> Fun(R);
option(_, _) -> fail(bad_option).

%% TransactionError (lenient: returns the JSON value and the rest).
transaction_error(Bin) -> element(1, tx_error(Bin)).

tx_error(Bin) ->
    {Variant, R} = u32(Bin),
    Variant < tuple_size(?TRANSACTION_ERRORS) orelse fail(unknown_transaction_error),
    Name = element(Variant + 1, ?TRANSACTION_ERRORS),
    case Variant of
        8 ->
            {Index, R1} = u8(R),
            {Kind, R2} = u32(R1),
            Kind < tuple_size(?INSTRUCTION_ERRORS) orelse fail(unknown_instruction_error),
            case Kind of
                25 -> {Code, R3} = u32(R2), {#{Name => [Index, #{<<"Custom">> => Code}]}, R3};
                _ -> {#{Name => [Index, element(Kind + 1, ?INSTRUCTION_ERRORS)]}, R2}
            end;
        30 -> {I, R1} = u8(R), {#{Name => I}, R1};
        V when V =:= 31; V =:= 35 -> {I, R1} = u8(R), {#{Name => #{account_index => I}}, R1};
        _ -> {Name, R}
    end.

stored_reward(Bin, Extended) ->
    {Key, R1} = string(Bin),
    {Lamports, R2} = i64(R1),
    {Post, R3} = case R2 =/= <<>> orelse not Extended of
                     true -> u64(R2);
                     false -> {0, R2}
                 end,
    TypeFun = fun(B) ->
                      {T, Rx} = u32(B),
                      T < 4 orelse fail(unknown_reward_type),
                      {element(T + 1, ?REWARD_TYPES), Rx}
              end,
    {Type, R4} = case R3 =/= <<>> orelse not Extended of
                     true -> option(R3, TypeFun);
                     false -> {null, R3}
                 end,
    {Commission, R5} = case R4 =/= <<>> andalso Extended of
                           true -> option(R4, fun u8/1);
                           false -> {null, R4}
                       end,
    {#{pubkey => Key, lamports => Lamports, postBalance => Post, rewardType => Type,
       commission => Commission}, R5}.

stored_token(Bin, Layout) ->
    {Index, R1} = u8(Bin),
    {Mint, R2} = string(R1),
    {Ui, R3} = f64(R2),
    {Decimals, R4} = u8(R3),
    {Amount, R5} = string(R4),
    {Owner, R6} = if Layout >= 2, R5 =/= <<>> -> string(R5); true -> {<<>>, R5} end,
    {Program, R7} = if Layout >= 3, R6 =/= <<>> -> string(R6); true -> {<<>>, R6} end,
    {token_balance(Index, Mint, Ui, Decimals, Amount, Owner, Program, <<>>), R7}.

stored_meta(Bin, Legacy, Layout) ->
    {Status, R0} = u32(Bin),
    Status =< 1 orelse fail(bad_result_tag),
    {Err, R1} = case Status of 0 -> {null, R0}; 1 -> tx_error(R0) end,
    {Fee, R2} = u64(R1),
    {Pre, R3} = vec(R2, 8, fun u64/1),
    {Post, R4} = vec(R3, 8, fun u64/1),
    InnerIx = fun(B) ->
                      {{P, A, D}, Rx} = ob_wire:instruction(B),
                      case Legacy of
                          true -> {{P, A, D, null}, Rx};
                          false -> {H, Ry} = option(Rx, fun u32/1), {{P, A, D, H}, Ry}
                      end
              end,
    Inner = fun(B) ->
                    {Index, Rx} = u8(B),
                    {Ixs, Ry} = vec(Rx, if Legacy -> 3; true -> 4 end, InnerIx),
                    {{Index, Ixs}, Ry}
            end,
    Token = fun(B) -> stored_token(B, Layout) end,
    Fields = [{innerInstructions, fun(B) -> vec(B, 9, Inner) end},
              {logMessages, fun(B) -> vec(B, 8, fun string/1) end},
              {preTokenBalances, fun(B) -> vec(B, 26, Token) end},
              {postTokenBalances, fun(B) -> vec(B, 26, Token) end},
              {rewards, fun(B) -> vec(B, 16, fun(X) -> stored_reward(X, true) end) end},
              {returnData, fun(B) ->
                                   case B of
                                       <<Pid:32/binary, Rx/binary>> ->
                                           {N, Ry} = u64(Rx),
                                           case Ry of
                                               <<D:N/binary, Rz/binary>> ->
                                                   {#{programId => pubkey(Pid),
                                                      data => [base64(D), <<"base64">>]}, Rz};
                                               _ -> fail(truncated)
                                           end;
                                       _ -> fail(truncated)
                                   end
                           end},
              {computeUnitsConsumed, fun u64/1},
              {costUnits, fun u64/1}],
    Meta0 = (empty_meta())#{err := Err, fee := Fee, preBalances := Pre, postBalances := Post},
    optional_fields(Fields, R4, Meta0).

optional_fields([], R, Meta) -> {Meta, R};
optional_fields(_, <<>>, Meta) -> {Meta, <<>>};
optional_fields([{Name, Fun} | Rest], Bin, Meta) ->
    case option(Bin, Fun) of
        {null, R} -> optional_fields(Rest, R, Meta);
        {V, R} -> optional_fields(Rest, R, Meta#{Name => V})
    end.

%% Try each layout strictly (whole input consumed); fall back to the first
%% layout in lenient mode, whose failure is final.
bincode(Data, [First | _] = Layouts) ->
    Strict = lists:foldl(fun(_, {ok, _} = Done) -> Done;
                            (Layout, none) ->
                                 try Layout(Data) of
                                     {V, <<>>} -> {ok, V};
                                     _ -> none
                                 catch error:_ -> none
                                 end
                         end, none, Layouts),
    case Strict of
        {ok, V} -> V;
        none -> element(1, First(Data))
    end.

bincode_meta(Data) ->
    bincode(Data, [fun(B) -> stored_meta(B, false, 3) end,
                   fun(B) -> stored_meta(B, true, 1) end,
                   fun(B) -> stored_meta(B, true, 2) end,
                   fun(B) -> stored_meta(B, true, 3) end]).

bincode_rewards(Data) ->
    #{rewards => bincode(Data, [fun(B) -> vec(B, 16, fun(X) -> stored_reward(X, true) end) end,
                                fun(B) -> vec(B, 25, fun(X) -> stored_reward(X, false) end) end])}.
