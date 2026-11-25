%% Old Faithful transport (two HTTP Range reads per block), retry policy,
%% bounded caches and the getBlock pipeline.
-module(ob_archive).
-export([start/1, get_block/5, read_head/3]).

-define(EPOCH_SLOTS, 432000).
-define(MAX_SLICE, (128 * 1024 * 1024)).
-define(U64, 16#FFFFFFFFFFFFFFFF).
-define(ZERO_HASH, <<"11111111111111111111111111111111">>).
-define(MAX_INFLIGHT, 32).

rpc_error(Code, Msg) -> throw({rpc, Code, iolist_to_binary(Msg)}).
fail(Why) -> erlang:error({decode, Why}).

%% ---------------------------------------------------------------- setup

start(Base) ->
    persistent_term:put({?MODULE, base}, Base),
    ob_lru:start(ob_ranges, 100000),
    ob_lru:start(ob_hashes, 100000),
    %% Concurrency slots for upstream attempts: a shared atomic counter.
    persistent_term:put({?MODULE, inflight}, atomics:new(1, [{signed, true}])),
    case maps:get(scheme, Base) of
        https ->
            {ok, _} = application:ensure_all_started(ssl),
            persistent_term:put({?MODULE, cacerts}, load_cacerts());
        http -> ok
    end,
    ok.

%% Read the OS trust store from a PEM file (no child processes).
load_cacerts() ->
    Files = ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
             "/etc/pki/tls/certs/ca-bundle.crt", "/opt/homebrew/etc/ca-certificates/cert.pem"],
    Loaded = lists:foldl(
               fun(_, {ok, _} = Done) -> Done;
                  (File, none) ->
                       case file:read_file(File) of
                           {ok, Pem} ->
                               Ders = [Der || {'Certificate', Der, not_encrypted}
                                                  <- public_key:pem_decode(Pem)],
                               case Ders of [] -> none; _ -> {ok, Ders} end;
                           _ -> none
                       end
               end, none, Files),
    case Loaded of
        {ok, Certs} -> Certs;
        none -> public_key:cacerts_get()
    end.

%% ---------------------------------------------------------------- getBlock

get_block(Slot, Encoding, Details, Rewards, MaxVersion) ->
    {Index, Block} = load_block(Slot),
    ob_wire:u64(ob_wire:at(Block, 1)) =:= Slot orelse fail(block_slot_mismatch),
    Entries = ob_wire:links(ob_wire:at(Block, 3)),
    Info = case ob_wire:at(Block, 4) of L when is_list(L) -> L; _ -> [] end,
    Parent = case ob_wire:u64(ob_wire:at(Info, 0)) of undefined -> 0; P -> P end,
    BlockTime = case ob_wire:i64(ob_wire:at(Info, 1)) of undefined -> null; 0 -> null; T -> T end,
    Height = case ob_wire:u64(ob_wire:at(Info, 2)) of undefined -> null; H -> H end,
    Hash = blockhash(Slot, Index, Entries),
    Result0 = #{previousBlockhash => previous_hash(Slot, Parent), blockhash => Hash,
                parentSlot => Parent, blockTime => BlockTime, blockHeight => Height},
    Result1 = case Details of
                  <<"none">> -> Result0;
                  _ ->
                      Items = [transaction_item(Slot, Index, TxKey, Encoding, Details, Rewards, MaxVersion)
                               || EntryKey <- Entries,
                                  TxKey <- entry_transactions(Index, EntryKey)],
                      case Details of
                          <<"signatures">> -> Result0#{signatures => Items};
                          _ -> Result0#{transactions => Items}
                      end
              end,
    case Rewards of
        false -> Result1;
        true -> maps:merge(Result1, ob_meta:rewards(Slot, rewards_payload(Index, ob_wire:at(Block, 5))))
    end.

entry_transactions(Index, Key) ->
    Entry = ob_wire:indexed(Index, Key, 1),
    case ob_wire:at(Entry, 2) of
        <<_:32/binary>> -> ok;
        _ -> fail(invalid_entry_hash)
    end,
    ob_wire:links(ob_wire:at(Entry, 3)).

transaction_item(Slot, Index, Key, Encoding, Details, Rewards, MaxVersion) ->
    Node = ob_wire:indexed(Index, Key, 0),
    Tx = ob_wire:transaction(ob_wire:frame_payload(Index, ob_wire:at(Node, 1))),
    case Details of
        <<"signatures">> ->
            case maps:get(signatures, Tx) of
                [First | _] -> ob_wire:base58(First);
                [] -> fail(transaction_without_signature)
            end;
        _ ->
            Meta = case ob_wire:at(Node, 2) of
                       Frame when is_list(Frame) ->
                           ob_meta:metadata(Slot, ob_wire:frame_payload(Index, Frame));
                       _ -> none
                   end,
            ob_rpc:transaction_json(Tx, Meta, Encoding, Details, Rewards, MaxVersion)
    end.

rewards_payload(Index, Value) when is_binary(Value) ->
    case ob_wire:link(Value) of
        {_, true} -> <<>>;
        {Key, false} when is_map_key(Key, Index) ->
            Node = ob_wire:indexed(Index, Key, 5),
            case length(Node) > 2 of
                true -> ob_wire:frame_payload(Index, lists:nth(3, Node));
                false -> <<>>
            end;
        _ -> <<>>
    end;
rewards_payload(_, _) -> <<>>.

blockhash(Slot, Index, Entries) ->
    Hash = case Entries of
               [] -> ?ZERO_HASH;
               _ -> ob_wire:pubkey(ob_wire:at(ob_wire:indexed(Index, lists:last(Entries), 1), 2))
           end,
    ob_lru:put(ob_hashes, Slot, Hash),
    Hash.

previous_hash(0, _Parent) -> ?ZERO_HASH;
previous_hash(_Slot, Parent) ->
    case ob_lru:get(ob_hashes, Parent) of
        {ok, Hash} -> Hash;
        undefined ->
            {Index, Block} = load_block(Parent),
            blockhash(Parent, Index, ob_wire:links(ob_wire:at(Block, 3)))
    end.

load_block(Slot) ->
    {Offset, Length} =
        case ob_lru:get(ob_ranges, Slot) of
            {ok, Record} -> Record;
            undefined ->
                <<Off:64/little, Len:32/little>> =
                    read_range(Slot, "-slot-ranges.raw", (Slot rem ?EPOCH_SLOTS) * 12, 12, 12),
                ob_lru:put(ob_ranges, Slot, {Off, Len}),
                {Off, Len}
        end,
    Length =:= 0 andalso
        rpc_error(-32007, io_lib:format("Slot ~B was skipped, or missing in long-term storage", [Slot])),
    Length =< ?MAX_SLICE orelse fail(oversize_slice),
    ob_wire:index_car(read_range(Slot, ".car", Offset, Length, ?MAX_SLICE)).

%% ---------------------------------------------------------------- range reads

read_range(Slot, Suffix, Start, Size, Cap) ->
    End = Start + Size - 1,
    End =< ?U64 orelse fail(range_overflow),
    Base = persistent_term:get({?MODULE, base}),
    Epoch = integer_to_list(Slot div ?EPOCH_SLOTS),
    Path = [maps:get(path, Base), "/", Epoch, "/epoch-", Epoch, Suffix],
    Range = io_lib:format("bytes=~B-~B", [Start, End]),
    attempts(0, Slot, Base, Path, Range, Size, Cap).

attempts(Attempt, Slot, Base, Path, Range, Size, Cap) ->
    Outcome = with_slot(fun() ->
                                try attempt(Base, Path, Range, Size, Cap)
                                catch
                                    error:{decode, _} = E -> erlang:error(E);
                                    _:_ -> transport
                                end
                        end),
    case Outcome of
        {206, Body} -> Body;
        {404, _} ->
            rpc_error(-32004, io_lib:format("Block not available for slot ~B: epoch ~B is not archived "
                                            "in Old Faithful (historical-only server)",
                                            [Slot, Slot div ?EPOCH_SLOTS]));
        {Status, _} when Status =/= 429, (Status < 500 orelse Status > 599) ->
            fail({unexpected_status, Status});
        _ when Attempt >= 4 ->
            fail(retries_exhausted);
        _ ->
            RetryAfter = case Outcome of {_, H} -> H; transport -> undefined end,
            timer:sleep(retry_delay(RetryAfter, Attempt)),
            attempts(Attempt + 1, Slot, Base, Path, Range, Size, Cap)
    end.

%% Hold one of MAX_INFLIGHT upstream slots only while an attempt runs.
with_slot(Fun) ->
    Counter = persistent_term:get({?MODULE, inflight}),
    case atomics:add_get(Counter, 1, 1) > ?MAX_INFLIGHT of
        true ->
            atomics:sub(Counter, 1, 1),
            timer:sleep(5),
            with_slot(Fun);
        false ->
            try Fun() after atomics:sub(Counter, 1, 1) end
    end.

retry_delay(Header, Attempt) when is_binary(Header) ->
    Trimmed = string:trim(Header),
    case re:run(Trimmed, "^[0-9]+$", [{capture, none}]) of
        match -> min(10, binary_to_integer(Trimmed)) * 1000;
        nomatch ->
            case catch httpd_util:convert_request_date(binary_to_list(Trimmed)) of
                {{_, _, _}, {_, _, _}} = Date ->
                    Target = calendar:datetime_to_gregorian_seconds(Date),
                    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
                    max(0, min(10, Target - Now)) * 1000;
                _ -> backoff(Attempt)
            end
    end;
retry_delay(_, Attempt) -> backoff(Attempt).

backoff(Attempt) ->
    Base = min(10000, 200 * (1 bsl min(Attempt, 30))),
    round(Base * (0.5 + rand:uniform() * 0.5)).

now_ms() -> erlang:monotonic_time(millisecond).

attempt(#{scheme := Scheme, host := Host, port := Port}, Path, Range, Size, Cap) ->
    Deadline = now_ms() + 60000,
    Opts = [binary, {active, false}, {packet, raw}],
    {ok, Sock} = case Scheme of
                     http -> gen_tcp:connect(Host, Port, Opts, 10000);
                     https ->
                         ssl:connect(Host, Port,
                                     Opts ++ [{verify, verify_peer},
                                              {cacerts, persistent_term:get({?MODULE, cacerts})},
                                              {server_name_indication, Host},
                                              {customize_hostname_check,
                                               [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}],
                                     10000)
                 end,
    T = transport(Scheme),
    try
        HostHeader = case {Scheme, Port} of
                         {http, 80} -> Host;
                         {https, 443} -> Host;
                         _ -> [Host, ":", integer_to_list(Port)]
                     end,
        ok = T:send(Sock, ["GET ", Path, " HTTP/1.1\r\nHost: ", HostHeader,
                           "\r\nRange: ", Range,
                           "\r\nUser-Agent: onlyblocks/erlang\r\nAccept-Encoding: identity"
                           "\r\nConnection: close\r\n\r\n"]),
        Recv = fun(Timeout) -> T:recv(Sock, 0, Timeout) end,
        {{response, Status}, Headers, Rest} = read_head(Recv, Deadline, response),
        case Status of
            206 -> {206, body(Recv, Deadline, Headers, Rest, Size, Cap)};
            _ -> {Status, header(<<"retry-after">>, Headers)}
        end
    after
        T:close(Sock)
    end.

transport(http) -> gen_tcp;
transport(https) -> ssl.

header(Name, Headers) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, V} -> V;
        false -> undefined
    end.

remaining(Deadline) ->
    case Deadline - now_ms() of
        Left when Left > 0 -> Left;
        _ -> exit(timeout)
    end.

%% Parse an HTTP/1.x head with the built-in erlang:decode_packet/3 parser.
%% Returns {{request, Method, Path} | {response, Status}, [{LowerName, Value}], Rest}.
read_head(Recv, Deadline, Kind) -> read_head(Recv, Deadline, Kind, <<>>).

read_head(Recv, Deadline, Kind, Buf) ->
    case binary:match(Buf, <<"\r\n\r\n">>) of
        nomatch when byte_size(Buf) > 65536 -> exit(head_too_large);
        nomatch ->
            case Recv(remaining(Deadline)) of
                {ok, More} -> read_head(Recv, Deadline, Kind, <<Buf/binary, More/binary>>);
                {error, Why} -> exit(Why)
            end;
        _ ->
            {ok, Start, R} = erlang:decode_packet(http_bin, Buf, []),
            Line = case {Kind, Start} of
                       {response, {http_response, _, Status, _}} -> {response, Status};
                       {request, {http_request, Method, {abs_path, P}, _}} -> {request, Method, P};
                       {request, {http_request, Method, _, _}} -> {request, Method, other};
                       _ -> exit(bad_start_line)
                   end,
            {Headers, Rest} = headers(R, []),
            {Line, Headers, Rest}
    end.

headers(Buf, Acc) ->
    case erlang:decode_packet(httph_bin, Buf, []) of
        {ok, {http_header, _, _, Name, Value}, R} ->
            headers(R, [{string:lowercase(Name), Value} | Acc]);
        {ok, http_eoh, R} -> {lists:reverse(Acc), R};
        _ -> exit(bad_header)
    end.

%% A 206 body: Content-Length, chunked, or until close; never above Cap.
body(Recv, Deadline, Headers, Rest, Size, Cap) ->
    Body = case {header(<<"transfer-encoding">>, Headers),
                 [V || {<<"content-length">>, V} <- Headers]} of
               {TE, _} when TE =/= undefined ->
                   string:lowercase(string:trim(TE)) =:= <<"chunked">> orelse fail(bad_transfer_encoding),
                   chunked(Recv, Deadline, Rest, Cap, [], 0);
               {undefined, [Len]} ->
                   case re:run(Len, "^[0-9]{1,12}$", [{capture, none}]) of
                       match -> ok;
                       nomatch -> fail(bad_content_length)
                   end,
                   N = binary_to_integer(Len),
                   N =< Cap orelse fail(content_length_exceeds_cap),
                   exactly(Recv, Deadline, Rest, N);
               {undefined, []} -> until_close(Recv, Deadline, [Rest], byte_size(Rest), Cap);
               _ -> fail(multiple_content_length)
           end,
    byte_size(Body) =:= Size orelse fail(range_length_mismatch),
    Body.

exactly(Recv, Deadline, Buf, N) -> exactly(Recv, Deadline, [Buf], byte_size(Buf), N).
exactly(_Recv, _Deadline, Acc, Have, N) when Have >= N ->
    binary:part(iolist_to_binary(lists:reverse(Acc)), 0, N);
exactly(Recv, Deadline, Acc, Have, N) ->
    case Recv(remaining(Deadline)) of
        {ok, More} -> exactly(Recv, Deadline, [More | Acc], Have + byte_size(More), N);
        {error, Why} -> exit(Why)
    end.

until_close(Recv, Deadline, Acc, Have, Cap) ->
    Have =< Cap orelse fail(body_exceeds_cap),
    case Recv(remaining(Deadline)) of
        {ok, More} -> until_close(Recv, Deadline, [More | Acc], Have + byte_size(More), Cap);
        {error, closed} -> iolist_to_binary(lists:reverse(Acc));
        {error, Why} -> exit(Why)
    end.

%% Chunked transfer decoding over a growing buffer.
chunked(Recv, Deadline, Buf, Cap, Acc, Have) ->
    case binary:split(Buf, <<"\r\n">>) of
        [Line, R] ->
            [SizeText | _] = binary:split(Line, <<";">>),
            Size = binary_to_integer(string:trim(SizeText), 16),
            Have + Size =< Cap orelse fail(body_exceeds_cap),
            case Size of
                0 -> iolist_to_binary(lists:reverse(Acc));
                _ ->
                    R2 = fill(Recv, Deadline, R, Size + 2),
                    <<Chunk:Size/binary, "\r\n", R3/binary>> = R2,
                    chunked(Recv, Deadline, R3, Cap, [Chunk | Acc], Have + Size)
            end;
        [_] ->
            byte_size(Buf) > 4096 andalso exit(bad_chunk),
            chunked(Recv, Deadline, fill(Recv, Deadline, Buf, byte_size(Buf) + 1), Cap, Acc, Have)
    end.

fill(_Recv, _Deadline, Buf, N) when byte_size(Buf) >= N -> Buf;
fill(Recv, Deadline, Buf, N) ->
    case Recv(remaining(Deadline)) of
        {ok, More} -> fill(Recv, Deadline, <<Buf/binary, More/binary>>, N);
        {error, Why} -> exit(Why)
    end.
