%% JSON-RPC 2.0 envelope, getBlock parameter validation and the
%% transaction JSON shapes of WIRE_FORMATS.md section 13.
-module(ob_rpc).
-export([handle/1, transaction_json/6]).

-define(U64, 16#FFFFFFFFFFFFFFFF).
-define(UPGRADEABLE, <<"BPFLoaderUpgradeab1e11111111111111111111111">>).
-define(RESERVED, [
    <<"AddressLookupTab1e1111111111111111111111111">>, <<"BPFLoader2111111111111111111111111111111111">>,
    <<"BPFLoader1111111111111111111111111111111111">>, <<"BPFLoaderUpgradeab1e11111111111111111111111">>,
    <<"ComputeBudget111111111111111111111111111111">>, <<"Config1111111111111111111111111111111111111">>,
    <<"Ed25519SigVerify111111111111111111111111111">>, <<"Feature111111111111111111111111111111111111">>,
    <<"LoaderV411111111111111111111111111111111111">>, <<"KeccakSecp256k11111111111111111111111111111">>,
    <<"Secp256r1SigVerify1111111111111111111111111">>, <<"StakeConfig11111111111111111111111111111111">>,
    <<"Stake11111111111111111111111111111111111111">>, <<"11111111111111111111111111111111">>,
    <<"Vote111111111111111111111111111111111111111">>, <<"ZkE1Gama1Proof11111111111111111111111111111">>,
    <<"ZkTokenProof1111111111111111111111111111111">>, <<"SysvarC1ock11111111111111111111111111111111">>,
    <<"SysvarEpochRewards1111111111111111111111111">>, <<"SysvarEpochSchedu1e111111111111111111111111">>,
    <<"SysvarFees111111111111111111111111111111111">>, <<"Sysvar1nstructions1111111111111111111111111">>,
    <<"SysvarLastRestartS1ot1111111111111111111111">>, <<"SysvarRecentB1ockHashes11111111111111111111">>,
    <<"SysvarRent111111111111111111111111111111111">>, <<"SysvarRewards111111111111111111111111111111">>,
    <<"SysvarS1otHashes111111111111111111111111111">>, <<"SysvarS1otHistory11111111111111111111111111">>,
    <<"SysvarStakeHistory1111111111111111111111111">>, <<"NativeLoader1111111111111111111111111111111">>,
    <<"Sysvar1111111111111111111111111111111111111">>]).

%% ---------------------------------------------------------------- envelope

%% Raw request body -> response JSON (binary).
handle(Body) ->
    case ob_json:decode(Body) of
        error -> error_response(null, -32700, <<"Parse error">>);
        {ok, Items} when is_list(Items), length(Items) >= 1, length(Items) =< 100 ->
            iolist_to_binary([$[, lists:join($,, [dispatch(I) || I <- Items]), $]]);
        {ok, Items} when is_list(Items) -> error_response(null, -32600, <<"Invalid batch size">>);
        {ok, Request} -> dispatch(Request)
    end.

response(Id, Key, Value) ->
    ob_json:encode(#{jsonrpc => <<"2.0">>, Key => Value, id => id_json(Id)}).

id_json({num, Text}) -> {raw, Text};
id_json(Id) -> Id.

error_response(Id, Code, Message) ->
    response(Id, error, #{code => Code, message => Message}).

dispatch({obj, Pairs}) ->
    Req = maps:from_list(Pairs),  % duplicate keys: the last one wins
    Version = maps:get(<<"jsonrpc">>, Req, null),
    Method = maps:get(<<"method">>, Req, null),
    Id = maps:get(<<"id">>, Req, null),
    TextOrNull = fun(V) -> is_binary(V) orelse V =:= null end,
    ValidId = TextOrNull(Id) orelse is_tuple(Id) andalso element(1, Id) =:= num,
    WellTyped = TextOrNull(Version) andalso TextOrNull(Method) andalso ValidId,
    if
        not WellTyped ->
            error_response(null, -32600, <<"Invalid Request">>);
        Version =/= <<"2.0">> orelse Method =:= null ->
            error_response(Id, -32600, <<"Invalid Request">>);
        true ->
            Params = maps:get(<<"params">>, Req, null),
            try call(Method, Params) of
                Result -> response(Id, result, Result)
            catch
                throw:{rpc, Code, Message} -> error_response(Id, Code, Message);
                Class:Reason ->
                    error_response(Id, -32603, iolist_to_binary(
                                                 io_lib:format("Internal error: ~0p", [{Class, Reason}])))
            end
    end;
dispatch(_) ->
    error_response(null, -32600, <<"Invalid Request">>).

call(<<"getHealth">>, Params) when Params =:= null; Params =:= [] -> <<"ok">>;
call(<<"getHealth">>, _) -> throw({rpc, -32602, <<"Invalid getHealth params">>});
call(<<"getBlock">>, Params) ->
    {Slot, Encoding, Details, Rewards, MaxVersion} = block_params(Params),
    ob_archive:get_block(Slot, Encoding, Details, Rewards, MaxVersion);
call(Method, _) ->
    throw({rpc, -32601, <<"Method not found: ", Method/binary>>}).

%% ---------------------------------------------------------------- params

invalid() -> throw({rpc, -32602, <<"Invalid params">>}).

uint_param({num, Text}, Max) ->
    case re:run(Text, "^(0|[1-9][0-9]{0,19})$", [{capture, none}]) of
        match ->
            case binary_to_integer(Text) of
                V when V =< Max -> V;
                _ -> invalid()
            end;
        nomatch -> invalid()
    end;
uint_param(_, _) -> invalid().

block_params([SlotValue | Rest]) when length(Rest) =< 1 ->
    Slot = uint_param(SlotValue, ?U64),
    Config = case Rest of
                 [] -> #{};
                 [null] -> #{};
                 [Enc] when is_binary(Enc) -> #{<<"encoding">> => Enc};
                 [{obj, Pairs}] -> maps:from_list(Pairs);
                 _ -> invalid()
             end,
    Option = fun(Name, Default) ->
                     case maps:get(Name, Config, null) of
                         null -> Default;
                         V -> V
                     end
             end,
    Encoding = Option(<<"encoding">>, <<"json">>),
    Details = Option(<<"transactionDetails">>, <<"full">>),
    Rewards = Option(<<"rewards">>, true),
    Commitment = Option(<<"commitment">>, <<"finalized">>),
    lists:member(Encoding, [<<"json">>, <<"jsonParsed">>, <<"base64">>, <<"base58">>]) orelse invalid(),
    lists:member(Details, [<<"full">>, <<"accounts">>, <<"signatures">>, <<"none">>]) orelse invalid(),
    (Details =/= <<"accounts">> orelse Encoding =:= <<"json">>) orelse invalid(),
    is_boolean(Rewards) orelse invalid(),
    lists:member(Commitment, [<<"finalized">>, <<"confirmed">>]) orelse invalid(),
    MaxVersion = case Option(<<"maxSupportedTransactionVersion">>, none) of
                     none -> none;
                     V -> uint_param(V, 255)
                 end,
    {Slot, Encoding, Details, Rewards, MaxVersion};
block_params(_) -> invalid().

%% ---------------------------------------------------------------- transactions

transaction_json(#{version := 0}, _Meta, _Enc, _Details, _Rewards, none) ->
    throw({rpc, -32015, <<"Transaction version (0) is not supported by the requesting client. "
                          "Please try the request again with the following configuration parameter: "
                          "\"maxSupportedTransactionVersion\": 0">>});
transaction_json(#{version := Version} = Tx, Meta0, Encoding, Details, Rewards, MaxVersion) ->
    Meta = case {Version, Meta0} of
               {0, none} -> ob_meta:empty_meta();
               _ -> Meta0
           end,
    Parsed = Encoding =:= <<"jsonParsed">>,
    AccountsOnly = Details =:= <<"accounts">>,
    StaticKeys = [ob_wire:base58(K) || K <- maps:get(keys, Tx)],
    Loaded = case Meta of
                 none -> #{writable => [], readonly => []};
                 _ -> maps:get(loadedAddresses, Meta)
             end,
    Accounts = case Parsed orelse AccountsOnly of
                   true -> account_objects(Tx, StaticKeys, Loaded);
                   false -> StaticKeys
               end,
    Keys = case Parsed of
               true -> list_to_tuple([maps:get(pubkey, A) || A <- Accounts]);
               false -> none
           end,
    Transaction =
        case Encoding of
            <<"base64">> -> [ob_wire:base64(maps:get(raw, Tx)), Encoding];
            <<"base58">> -> [ob_wire:base58(maps:get(raw, Tx)), Encoding];
            _ ->
                Sigs = [ob_wire:base58(S) || S <- maps:get(signatures, Tx)],
                case AccountsOnly of
                    true -> #{signatures => Sigs, accountKeys => Accounts};
                    false -> #{signatures => Sigs, message => message_json(Tx, Accounts, Keys, Parsed)}
                end
        end,
    MetaJson = case Meta of
                   none -> null;
                   _ -> meta_json(Meta, Keys, Parsed, AccountsOnly, Rewards)
               end,
    Item = #{transaction => Transaction, meta => MetaJson},
    case {Meta, MaxVersion} of
        {none, _} -> Item;
        {_, none} -> Item;
        _ -> Item#{version => Version}
    end.

message_json(Tx, Accounts, Keys, Parsed) ->
    {Nrs, Nros, Nrou} = maps:get(header, Tx),
    M0 = #{accountKeys => Accounts,
           recentBlockhash => ob_wire:base58(maps:get(recent, Tx)),
           instructions => [instruction_json(P, A, D, 1, Keys) || {P, A, D} <- maps:get(instructions, Tx)]},
    M1 = case Parsed of
             true -> M0;
             false -> M0#{header => #{numRequiredSignatures => Nrs, numReadonlySignedAccounts => Nros,
                                      numReadonlyUnsignedAccounts => Nrou}}
         end,
    case maps:get(lookups, Tx) of
        undefined -> M1;
        Lookups ->
            M1#{addressTableLookups =>
                    [#{accountKey => ob_wire:base58(K), writableIndexes => binary_to_list(W),
                       readonlyIndexes => binary_to_list(R)} || {K, W, R} <- Lookups]}
    end.

instruction_json(P, Accounts, Data, Height, none) ->
    #{programIdIndex => P, accounts => binary_to_list(Accounts), data => ob_wire:base58(Data),
      stackHeight => Height};
instruction_json(P, Accounts, Data, Height, Keys) ->
    Address = fun(I) when I < tuple_size(Keys) -> element(I + 1, Keys);
                 (_) -> ob_wire:fail(instruction_account_index_out_of_range)
              end,
    #{programId => Address(P), accounts => [Address(I) || <<I>> <= Accounts],
      data => ob_wire:base58(Data), stackHeight => Height}.

%% WIRE_FORMATS.md section 14.
account_objects(#{version := Version, header := {Nrs, Nros, Nrou}, instructions := Ixs},
                Static, Loaded) ->
    {W, R} = case Version of
                 0 -> {maps:get(writable, Loaded), maps:get(readonly, Loaded)};
                 legacy -> {[], []}
             end,
    S = length(Static),
    NW = length(W),
    All = Static ++ W ++ R,
    Programs = maps:from_list([{P, true} || {P, _, _} <- Ixs]),
    Upgradeable = lists:member(?UPGRADEABLE, All),
    {Objects, _} =
        lists:mapfoldl(
          fun(Key, I) ->
                  Lookup = I >= S,
                  CanWrite = if
                                 Lookup -> I - S < NW;
                                 I < Nrs -> I < Nrs - Nros;
                                 true -> I < S - Nrou
                             end,
                  Writable = CanWrite andalso not lists:member(Key, ?RESERVED)
                      andalso (Upgradeable orelse not is_map_key(I, Programs)),
                  {#{pubkey => Key, signer => I < Nrs, writable => Writable,
                     source => case Lookup of true -> <<"lookupTable">>; false -> <<"transaction">> end},
                   I + 1}
          end, 0, All),
    Objects.

meta_json(Meta, Keys, Parsed, AccountsOnly, Rewards) ->
    M0 = Meta#{status => case maps:get(err, Meta) of
                             null -> #{'Ok' => null};
                             Err -> #{'Err' => Err}
                         end},
    M1 = case Rewards of true -> M0; false -> M0#{rewards := null} end,
    case AccountsOnly of
        true ->
            M2 = maps:without([innerInstructions, logMessages, loadedAddresses, returnData,
                               computeUnitsConsumed, costUnits], M1),
            case Rewards of true -> M2; false -> maps:remove(rewards, M2) end;
        false ->
            M2 = case Parsed of true -> maps:remove(loadedAddresses, M1); false -> M1 end,
            case maps:get(innerInstructions, M2) of
                null -> M2;
                Groups ->
                    M2#{innerInstructions :=
                            [#{index => Index,
                               instructions => [instruction_json(P, A, D, H, Keys) || {P, A, D, H} <- Ixs]}
                             || {Index, Ixs} <- Groups]}
            end
    end.
