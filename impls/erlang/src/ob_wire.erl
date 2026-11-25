%% CARv1, DAG-CBOR, CIDs, DataFrames, checksums, Base58/64 and the Solana
%% VersionedTransaction wire format, all decoded with binary pattern matching.
-module(ob_wire).
-compile({no_auto_import, [link/1]}).
-export([uvarint/1, compact/1, cbor/1, cid/1, link/1, links/1, index_car/1, indexed/3,
         frame_payload/2, crc64/1, fnv1a/1, base58/1, base64/1, pubkey/1, transaction/1,
         at/2, u64/1, i64/1, fail/1, utf8/1, instruction/1]).

-define(U64, 16#FFFFFFFFFFFFFFFF).

fail(Why) -> erlang:error({decode, Why}).

%% ---------------------------------------------------------------- varints

%% Unsigned LEB128, at most 10 bytes (the 10th byte must be 0 or 1).
uvarint(Bin) -> uvarint(Bin, 0, 0).
uvarint(<<0:1, X:7, R/binary>>, Shift, Acc) when Shift < 63; X =< 1 -> {Acc bor (X bsl Shift), R};
uvarint(<<1:1, X:7, R/binary>>, Shift, Acc) when Shift < 63 -> uvarint(R, Shift + 7, Acc bor (X bsl Shift));
uvarint(<<>>, _, _) -> fail(truncated_varint);
uvarint(_, _, _) -> fail(varint_overflow).

%% Solana short_vec length: canonical 1..3 bytes, at most 0xFFFF.
compact(<<0:1, A:7, R/binary>>) -> {A, R};
compact(<<1:1, A:7, 0:1, B:7, R/binary>>) when B =/= 0 -> {A bor (B bsl 7), R};
compact(<<1:1, A:7, 1:1, B:7, C, R/binary>>) when C =/= 0, C =< 3 -> {A bor (B bsl 7) bor (C bsl 14), R};
compact(_) -> fail(bad_compact_u16).

%% ---------------------------------------------------------------- DAG-CBOR
%% Values: integer | binary (bytes) | {text, Bin} | [Item] | {map, [{K, V}]}
%%         | true | false | null | float

cbor(Bin) ->
    case item(Bin, 0) of
        {V, <<>>} -> V;
        _ -> fail(trailing_cbor_bytes)
    end.

utf8(Bin) ->
    case unicode:characters_to_binary(Bin, utf8, utf8) of
        Out when is_binary(Out) -> Out;
        _ -> fail(invalid_utf8)
    end.

arg(Info, R) when Info < 24 -> {Info, R};
arg(24, <<V:8, R/binary>>) -> {V, R};
arg(25, <<V:16, R/binary>>) -> {V, R};
arg(26, <<V:32, R/binary>>) -> {V, R};
arg(27, <<V:64, R/binary>>) -> {V, R};
arg(31, R) -> {indefinite, R};
arg(_, _) -> fail(bad_cbor_argument).

item(_, Depth) when Depth > 128 -> fail(cbor_nesting);
item(<<7:3, Info:5, R/binary>>, _) ->
    case {Info, R} of
        {20, _} -> {false, R};
        {21, _} -> {true, R};
        {22, _} -> {null, R};
        {23, _} -> {null, R};
        {25, <<_:16, R2/binary>>} -> {float, R2};
        {26, <<_:32, R2/binary>>} -> {float, R2};
        {27, <<_:64, R2/binary>>} -> {float, R2};
        _ -> fail(unsupported_cbor_simple)
    end;
item(<<Major:3, Info:5, R0/binary>>, Depth) ->
    {Arg, R} = arg(Info, R0),
    (Arg =/= indefinite orelse (Major >= 2 andalso Major =< 5)) orelse fail(bad_indefinite),
    case Major of
        0 -> {Arg, R};
        1 -> {-1 - Arg, R};
        6 -> item(R, Depth + 1);
        2 -> string(Arg, R, 2);
        3 -> {S, R2} = string(Arg, R, 3), {{text, S}, R2};
        4 -> sequence(Arg, R, Depth, array, []);
        5 -> sequence(Arg, R, Depth, map, [])
    end;
item(<<>>, _) -> fail(truncated_cbor).

string(indefinite, R, Major) -> chunks(R, Major, []);
string(N, R, Major) ->
    case R of
        <<S:N/binary, R2/binary>> when Major =:= 2 -> {S, R2};
        <<S:N/binary, R2/binary>> -> {utf8(S), R2};
        _ -> fail(truncated_cbor_string)
    end.

chunks(<<16#FF, R/binary>>, _Major, Acc) -> {iolist_to_binary(lists:reverse(Acc)), R};
chunks(<<Major:3, Info:5, R/binary>>, Major, Acc) when Info =/= 31 ->
    {N, R1} = arg(Info, R),
    {S, R2} = string(N, R1, Major),
    chunks(R2, Major, [S | Acc]);
chunks(_, _, _) -> fail(bad_cbor_chunk).

sequence(indefinite, <<16#FF, R/binary>>, _Depth, Kind, Acc) -> finish(Kind, Acc, R);
sequence(indefinite, R, Depth, Kind, Acc) -> element_of(indefinite, R, Depth, Kind, Acc);
sequence(0, R, _Depth, Kind, Acc) -> finish(Kind, Acc, R);
sequence(N, R, Depth, Kind, Acc) when Acc =:= [] ->
    Min = case Kind of array -> 1; map -> 2 end,
    N =< byte_size(R) div Min orelse fail(cbor_count_exceeds_input),
    element_of(N, R, Depth, Kind, Acc);
sequence(N, R, Depth, Kind, Acc) -> element_of(N, R, Depth, Kind, Acc).

element_of(N, R, Depth, array, Acc) ->
    {V, R2} = item(R, Depth + 1),
    sequence(dec(N), R2, Depth, array, [V | Acc]);
element_of(N, R, Depth, map, Acc) ->
    {K, R2} = item(R, Depth + 1),
    {V, R3} = item(R2, Depth + 1),
    sequence(dec(N), R3, Depth, map, [{K, V} | Acc]).

dec(indefinite) -> indefinite;
dec(N) -> N - 1.

finish(array, Acc, R) -> {lists:reverse(Acc), R};
finish(map, Acc, R) -> {{map, lists:reverse(Acc)}, R}.

%% ---------------------------------------------------------------- CIDs

%% Returns {CidBytes, Absent, Rest}.
cid(Bin) ->
    {A, R1} = uvarint(Bin),
    {B, R2} = uvarint(R1),
    case {A, B} of
        {16#12, 16#20} ->
            case R2 of
                <<_:32/binary, R3/binary>> -> {take(Bin, R3), false, R3};
                _ -> fail(truncated_cid)
            end;
        {1, _} ->
            {Code, R3} = uvarint(R2),
            {Len, R4} = uvarint(R3),
            Len =< 64 orelse fail(cid_digest_too_long),
            case R4 of
                <<_:Len/binary, R5/binary>> -> {take(Bin, R5), Code =:= 0 andalso Len =:= 0, R5};
                _ -> fail(truncated_cid)
            end;
        _ -> fail(unsupported_cid_version)
    end.

take(Whole, Rest) -> binary:part(Whole, 0, byte_size(Whole) - byte_size(Rest)).

%% A DAG-CBOR link: (tag 42 discarded) byte string 0x00 ++ CID.
link(<<0, Cid/binary>>) -> {Key, Absent, _} = cid(Cid), {Key, Absent};
link(_) -> fail(invalid_cid_link).

links(Items) when is_list(Items) -> [element(1, link(I)) || I <- Items];
links(_) -> [].

%% ---------------------------------------------------------------- CAR

at(List, I) when is_list(List) ->
    try lists:nth(I + 1, List) catch error:_ -> null end;
at(_, _) -> null.

u64(V) when is_integer(V), V >= 0, V =< ?U64 -> V;
u64(_) -> undefined.

i64(V) when is_integer(V), V >= -(1 bsl 63), V < (1 bsl 63) -> V;
i64(_) -> undefined.

kind(Node, Kind) ->
    case is_list(Node) andalso u64(at(Node, 0)) =:= Kind of
        true -> Node;
        false -> fail({expected_node_kind, Kind})
    end.

indexed(Index, Key, Kind) ->
    case Index of
        #{Key := Bytes} -> kind(cbor(Bytes), Kind);
        _ -> fail(cid_missing_from_car)
    end.

%% Returns {Index, BlockNode}.
index_car(Data) -> sections(Data, #{}, undefined, true).

sections(<<>>, _Index, undefined, _) -> fail(no_block_node);
sections(<<>>, Index, Block, _) -> {Index, kind(cbor(Block), 2)};
sections(Data, Index, Block, First) ->
    case uvarint(Data) of
        {0, R} -> sections(R, Index, Block, First);
        {Size, _} when Size > 32 * 1024 * 1024 -> fail(oversize_car_section);
        {Size, R} ->
            case R of
                <<Section:Size/binary, Rest/binary>> ->
                    case First andalso car_header(Section) of
                        true -> sections(Rest, Index, Block, false);
                        _ ->
                            {Key, _, Node} = cid(Section),
                            sections(Rest, Index#{Key => Node}, block_candidate(Node, Block), false)
                    end;
                _ -> fail(truncated_car_section)
            end
    end.

car_header(<<5:3, _:5, _/binary>> = Section) ->
    try cbor(Section) of
        {map, Pairs} -> lists:keymember({text, <<"version">>}, 1, Pairs);
        _ -> false
    catch error:_ -> false
    end;
car_header(_) -> false.

%% A section whose node is an array header followed by the kind byte 2.
block_candidate(<<4:3, Info:5, R/binary>> = Node, Block) when Info < 28; Info =:= 31 ->
    Skip = if Info < 24; Info =:= 31 -> 0; true -> 1 bsl (Info - 24) end,
    case R of
        <<_:Skip/binary, 2, _/binary>> -> Node;
        _ -> Block
    end;
block_candidate(_, Block) -> Block.

%% ---------------------------------------------------------------- DataFrames

frame_data(Frame) ->
    case at(Frame, 4) of
        B when is_binary(B) -> B;
        _ -> <<>>
    end.

frame_next(Frame) ->
    case at(Frame, 5) of
        [_ | _] = L -> links(L);
        _ -> []
    end.

frame_payload(Index, Root) ->
    kind(Root, 6),
    First = frame_data(Root),
    Chunks = reassemble(Index, frame_next(Root), #{}, byte_size(First), [First]),
    Payload = iolist_to_binary(Chunks),
    case u64(at(Root, 1)) of
        undefined -> Payload;
        Expected ->
            (crc64(Payload) =:= Expected orelse fnv1a(Payload) =:= Expected)
                orelse fail(dataframe_hash_mismatch),
            Payload
    end.

reassemble(_Index, [], _Seen, _Size, Acc) -> lists:reverse(Acc);
reassemble(Index, [Key | Stack], Seen, Size, Acc) ->
    is_map_key(Key, Seen) andalso fail(cyclic_dataframe),
    Frame = indexed(Index, Key, 6),
    Data = frame_data(Frame),
    Size1 = Size + byte_size(Data),
    Size1 =< 128 * 1024 * 1024 orelse fail(oversize_dataframe),
    reassemble(Index, frame_next(Frame) ++ Stack, Seen#{Key => true}, Size1, [Data | Acc]).

%% ---------------------------------------------------------------- checksums

crc_table() ->
    case persistent_term:get({?MODULE, crc}, undefined) of
        undefined ->
            T = list_to_tuple([crc_entry(I, 8) || I <- lists:seq(0, 255)]),
            persistent_term:put({?MODULE, crc}, T),
            T;
        T -> T
    end.

crc_entry(V, 0) -> V;
crc_entry(V, N) when V band 1 =:= 1 -> crc_entry((V bsr 1) bxor 16#D800000000000000, N - 1);
crc_entry(V, N) -> crc_entry(V bsr 1, N - 1).

crc64(Data) -> crc64(Data, crc_table(), ?U64) bxor ?U64.
crc64(<<B, R/binary>>, T, C) -> crc64(R, T, (C bsr 8) bxor element(((C band 255) bxor B) + 1, T));
crc64(<<>>, _, C) -> C.

fnv1a(Data) -> fnv1a(Data, 16#CBF29CE484222325).
fnv1a(<<B, R/binary>>, H) -> fnv1a(R, ((H bxor B) * 16#100000001B3) band ?U64);
fnv1a(<<>>, H) -> H.

%% ---------------------------------------------------------------- Base58/64

-define(B58, <<"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz">>).

base58(Bin) ->
    Zeros = zeros(Bin, 0),
    Digits = b58_digits(binary:decode_unsigned(Bin), []),
    iolist_to_binary([binary:copy(<<"1">>, Zeros), Digits]).

zeros(<<0, R/binary>>, N) -> zeros(R, N + 1);
zeros(_, N) -> N.

b58_digits(0, Acc) -> Acc;
b58_digits(V, Acc) -> b58_digits(V div 58, [binary:at(?B58, V rem 58) | Acc]).

base64(Bin) -> base64:encode(Bin).

pubkey(<<_:32/binary>> = B) -> base58(B);
pubkey(_) -> fail(expected_32_bytes).

%% ---------------------------------------------------------------- transactions

transaction(Data) ->
    {Tx, Rest} =
        case Data of
            <<16#81, R/binary>> -> transaction_v1(R);
            <<NSig, R/binary>> when NSig < 16#80 -> transaction_legacy_or_v0(NSig, R);
            _ -> fail(invalid_transaction_discriminator)
        end,
    Tx#{raw => take(Data, Rest)}.

transaction_legacy_or_v0(NSig, R0) ->
    NSig =< byte_size(R0) div 64 orelse fail(signature_count),
    <<SigBytes:(NSig * 64)/binary, R1/binary>> = R0,
    Sigs = [S || <<S:64/binary>> <= SigBytes],
    {Version, Header, R2} =
        case R1 of
            <<1:1, 0:7, A, B, C, X/binary>> -> {0, {A, B, C}, X};
            <<A, B, C, X/binary>> when A < 16#80 -> {legacy, {A, B, C}, X};
            <<1:1, _:7, _/binary>> -> fail(unsupported_transaction_version);
            _ -> fail(truncated_transaction)
        end,
    {Keys, R3} = counted(R2, 32, fun(<<K:32/binary, X/binary>>) -> {K, X} end),
    <<Recent:32/binary, R4/binary>> = R3,
    {Instrs, R5} = counted(R4, 3, fun instruction/1),
    {Lookups, R6} =
        case Version of
            0 -> counted(R5, 34, fun lookup/1);
            legacy -> {undefined, R5}
        end,
    {#{version => Version, signatures => Sigs, header => Header, keys => Keys, recent => Recent,
       instructions => Instrs, lookups => Lookups}, R6}.

transaction_v1(<<A, B, C, Mask:32/little, Recent:32/binary, NIx, NKeys, R0/binary>>) ->
    FeeBits = Mask band 3,
    (Mask =< 16#1F andalso (FeeBits =:= 0 orelse FeeBits =:= 3)) orelse fail(invalid_config_mask),
    <<KeyBytes:(NKeys * 32)/binary, R1/binary>> = R0,
    Keys = [K || <<K:32/binary>> <= KeyBytes],
    {PriorityFee, R2} = config_value(Mask, 3, 64, R1),
    {ComputeLimit, R3} = config_value(Mask, 4, 32, R2),
    {LoadedDataLimit, R4} = config_value(Mask, 8, 32, R3),
    {HeapSize, R5} = config_value(Mask, 16, 32, R4),
    Config = #{priorityFee => PriorityFee, computeUnitLimit => ComputeLimit,
               loadedAccountsDataSizeLimit => LoadedDataLimit, heapSize => HeapSize},
    <<HeaderBytes:(NIx * 4)/binary, R6/binary>> = R5,
    Headers = [{P, NA, ND} || <<P, NA, ND:16/little>> <= HeaderBytes],
    {Instrs, R7} = lists:mapfoldl(
                     fun({P, NA, ND}, Payload) ->
                             <<Accounts:NA/binary, Data:ND/binary, Rest/binary>> = Payload,
                             {{P, Accounts, Data}, Rest}
                     end, R6, Headers),
    <<SigBytes:(A * 64)/binary, Rest/binary>> = R7,
    Sigs = [S || <<S:64/binary>> <= SigBytes],
    {#{version => 1, signatures => Sigs, header => {A, B, C}, keys => Keys, recent => Recent,
       instructions => Instrs, config => Config}, Rest};
transaction_v1(_) -> fail(truncated_transaction).

config_value(Mask, Bits, _Width, R) when (Mask band Bits) =:= 0 -> {null, R};
config_value(_Mask, _Bits, Width, R) ->
    <<Value:Width/little, Rest/binary>> = R,
    {Value, Rest}.

counted(Bin, Min, Fun) ->
    {N, R} = compact(Bin),
    N =< byte_size(R) div Min orelse fail(count_exceeds_input),
    repeat(N, R, Fun, []).

repeat(0, R, _Fun, Acc) -> {lists:reverse(Acc), R};
repeat(N, R, Fun, Acc) ->
    {V, R2} = Fun(R),
    repeat(N - 1, R2, Fun, [V | Acc]).

bytes_vec(Bin) ->
    {N, R} = compact(Bin),
    case R of
        <<B:N/binary, R2/binary>> -> {B, R2};
        _ -> fail(truncated_bytes)
    end.

%% {ProgramIdIndex, Accounts, Data}
instruction(<<P, R0/binary>>) ->
    {Accounts, R1} = bytes_vec(R0),
    {Data, R2} = bytes_vec(R1),
    {{P, Accounts, Data}, R2};
instruction(_) -> fail(truncated_instruction).

lookup(<<Key:32/binary, R0/binary>>) ->
    {W, R1} = bytes_vec(R0),
    {Ro, R2} = bytes_vec(R1),
    {{Key, W, Ro}, R2};
lookup(_) -> fail(truncated_lookup).
