%% RFC 8878 Zstandard decoder (decode only), ported from docs/ZSTD_MINI_SPEC.md.
%%
%% Bit-syntax tricks used throughout:
%%   * frame and block headers are matched straight out of the binary
%%     (`<<Fcs:2, Single:1, _:1, 0:1, Chk:1, Did:2, ...>>`);
%%   * backward bitstreams (Huffman, FSE weights, sequences) are byte-reversed
%%     once, after which "read N bits from the top" is simply
%%     `<<_:Consumed, V:N, _/bits>>`: a big-endian bit read.
-module(ob_zstd).
-export([decompress/1, xxh64/1]).

-define(MAX_OUT, (512 * 1024 * 1024)).
-define(BLOCK_MAX, (128 * 1024)).
-define(M64, 16#FFFFFFFFFFFFFFFF).

-record(st, {rep = {1, 4, 8}, huf = undefined, ll = undefined, off = undefined, ml = undefined}).

fail(Why) -> erlang:error({zstd, Why}).

%% ---------------------------------------------------------------- frames

decompress(Data) when is_binary(Data) ->
    iolist_to_binary(frames(Data, [], 0)).

frames(<<>>, Acc, _Total) ->
    lists:reverse(Acc);
frames(<<Magic:32/little, Size:32/little, Rest/binary>>, Acc, Total)
  when Magic band 16#FFFFFFF0 =:= 16#184D2A50 ->
    case Rest of
        <<_:Size/binary, Next/binary>> -> frames(Next, Acc, Total);
        _ -> fail(truncated_skippable_frame)
    end;
frames(<<16#FD2FB528:32/little, Rest/binary>>, Acc, Total) ->
    {Out, Next} = frame(Rest, Total),
    frames(Next, [Out | Acc], Total + byte_size(Out));
frames(_, _, _) ->
    fail(unknown_frame_magic).

frame(<<Fcs:2, Single:1, _Unused:1, Reserved:1, Chk:1, Did:2, R0/binary>>, Total) ->
    Reserved =:= 0 orelse fail(reserved_header_bit),
    R1 = case Single of
             0 -> case R0 of <<_Window, X/binary>> -> X; _ -> fail(truncated) end;
             1 -> R0
         end,
    DidBits = element(Did + 1, {0, 8, 16, 32}),
    R2 = case R1 of
             <<0:DidBits/little, X2/binary>> -> X2;
             <<_:DidBits/little, _/binary>> -> fail(dictionaries_not_supported);
             _ -> fail(truncated)
         end,
    FcsBytes = element(Fcs + 1, {Single, 2, 4, 8}),
    {Content, R3} = case R2 of
                        <<C:FcsBytes/unit:8-little, X3/binary>> when FcsBytes =:= 2 -> {C + 256, X3};
                        <<_:0, X3/binary>> when FcsBytes =:= 0 -> {undefined, X3};
                        <<C:FcsBytes/unit:8-little, X3/binary>> -> {C, X3};
                        _ -> fail(truncated)
                    end,
    {Out, R4} = blocks(R3, <<>>, #st{}, Total),
    Content =:= undefined orelse Content =:= byte_size(Out) orelse fail(content_size_mismatch),
    case Chk of
        0 -> {Out, R4};
        1 ->
            case R4 of
                <<Expected:32/little, R5/binary>> ->
                    (xxh64(Out) band 16#FFFFFFFF) =:= Expected orelse fail(checksum_mismatch),
                    {Out, R5};
                _ -> fail(truncated_checksum)
            end
    end;
frame(_, _) ->
    fail(truncated_frame_header).

blocks(<<Header:24/little, Rest/binary>>, Out, St, Total) ->
    Last = Header band 1,
    Type = (Header bsr 1) band 3,
    Size = Header bsr 3,
    Size =< ?BLOCK_MAX orelse fail(block_too_large),
    {Out2, St2, Next} =
        case {Type, Rest} of
            {0, <<Raw:Size/binary, R/binary>>} ->
                {<<Out/binary, Raw/binary>>, St, R};
            {1, <<Byte, R/binary>>} ->
                {<<Out/binary, (binary:copy(<<Byte>>, Size))/binary>>, St, R};
            {2, <<Block:Size/binary, R/binary>>} ->
                {Literals, SeqData, St1} = literals(Block, St),
                {Seqs, St3} = sequences(SeqData, St1),
                {O, Rep} = execute(Seqs, Literals, Out, St3#st.rep, Total),
                {O, St3#st{rep = Rep}, R};
            {3, _} -> fail(reserved_block_type);
            _ -> fail(truncated_block)
        end,
    Total + byte_size(Out2) =< ?MAX_OUT orelse fail(output_limit),
    case Last of
        1 -> {Out2, Next};
        0 -> blocks(Next, Out2, St2, Total)
    end;
blocks(_, _, _, _) ->
    fail(truncated_block_header).

%% ---------------------------------------------------------------- literals

literals(<<B0, _/binary>> = Block, St) ->
    LType = B0 band 3,
    SizeFormat = (B0 bsr 2) band 3,
    if
        LType < 2 ->
            {Size, R} = case {SizeFormat, Block} of
                            {SF, <<_, X/binary>>} when SF =:= 0; SF =:= 2 -> {B0 bsr 3, X};
                            {1, <<_, B1, X/binary>>} -> {(B0 bsr 4) + (B1 bsl 4), X};
                            {3, <<_, B1, B2, X/binary>>} -> {(B0 bsr 4) + (B1 bsl 4) + (B2 bsl 12), X};
                            _ -> fail(truncated_literals_header)
                        end,
            case {LType, R} of
                {0, <<Lit:Size/binary, R2/binary>>} -> {Lit, R2, St};
                {1, <<Byte, R2/binary>>} -> {binary:copy(<<Byte>>, Size), R2, St};
                _ -> fail(literals_overrun)
            end;
        true ->
            {Streams, HeaderBytes, Width} = element(SizeFormat + 1,
                                                    {{1, 3, 10}, {4, 3, 10}, {4, 4, 14}, {4, 5, 18}}),
            case Block of
                <<H:HeaderBytes/unit:8-little, R/binary>> ->
                    Mask = (1 bsl Width) - 1,
                    Regen = (H bsr 4) band Mask,
                    Comp = (H bsr (4 + Width)) band Mask,
                    case R of
                        <<LitData:Comp/binary, R2/binary>> ->
                            {Huf, StreamData} =
                                case LType of
                                    2 -> huffman_description(LitData);
                                    3 when St#st.huf =/= undefined -> {St#st.huf, LitData};
                                    3 -> fail(treeless_without_table)
                                end,
                            Lit = huffman_streams(Streams, StreamData, Huf, Regen),
                            {Lit, R2, St#st{huf = Huf}};
                        _ -> fail(literals_overrun)
                    end;
                _ -> fail(truncated_literals_header)
            end
    end;
literals(_, _) ->
    fail(missing_literals).

huffman_streams(1, Data, Huf, Regen) ->
    list_to_binary(huffman_stream(Data, Huf, Regen));
huffman_streams(4, <<S1:16/little, S2:16/little, S3:16/little, Data/binary>>, Huf, Regen) ->
    S4 = byte_size(Data) - S1 - S2 - S3,
    Quarter = (Regen + 3) div 4,
    C4 = Regen - 3 * Quarter,
    (S4 >= 1 andalso C4 >= 0) orelse fail(corrupt_4_stream_literals),
    <<D1:S1/binary, D2:S2/binary, D3:S3/binary, D4/binary>> = Data,
    list_to_binary([huffman_stream(D1, Huf, Quarter), huffman_stream(D2, Huf, Quarter),
                    huffman_stream(D3, Huf, Quarter), huffman_stream(D4, Huf, C4)]);
huffman_streams(_, _, _, _) ->
    fail(corrupt_4_stream_literals).

huffman_stream(Data, {Table, MaxBits}, Count) ->
    {Rev, Total, C0} = backward(Data),
    huffman_loop(Rev, Total, C0, Table, MaxBits, Count, []).

huffman_loop(_Rev, Total, C, _Table, _MaxBits, 0, Acc) ->
    C =:= Total orelse fail(huffman_stream_not_consumed),
    lists:reverse(Acc);
huffman_loop(Rev, Total, C, Table, MaxBits, N, Acc) ->
    {Sym, Nb} = element(peek(Rev, Total, C, MaxBits) + 1, Table),
    huffman_loop(Rev, Total, C + Nb, Table, MaxBits, N - 1, [Sym | Acc]).

%% ---------------------------------------------------------------- huffman tables

huffman_description(<<H, Rest/binary>>) when H < 128 ->
    case Rest of
        <<Desc:H/binary, After/binary>> ->
            {Probs, Log, P} = fse_description(Desc, 255, 6),
            Table = fse_table(Probs, Log),
            <<_:P/binary, Stream/binary>> = Desc,
            {Rev, Total, C0} = backward(Stream),
            {S1, C1} = read(Rev, Total, C0, Log),
            {S2, C2} = read(Rev, Total, C1, Log),
            Weights = fse_weights(Rev, Total, C2, Table, S1, S2, []),
            {huffman_table(Weights), After};
        _ -> fail(huffman_description_overrun)
    end;
huffman_description(<<H, Rest/binary>>) ->
    N = H - 127,
    Bytes = (N + 1) div 2,
    case Rest of
        <<Packed:Bytes/binary, After/binary>> ->
            Nibbles = [W || <<W:4>> <= Packed],
            {huffman_table(lists:sublist(Nibbles, N)), After};
        _ -> fail(huffman_description_overrun)
    end;
huffman_description(_) ->
    fail(missing_huffman_description).

fse_weights(_, _, _, _, _, _, Acc) when length(Acc) > 255 ->
    fail(too_many_huffman_weights);
fse_weights(Rev, Total, C, Table, S1, S2, Acc) ->
    {Sym1, Nb1, Base1} = element(S1 + 1, Table),
    {V1, C1} = read(Rev, Total, C, Nb1),
    N1 = Base1 + V1,
    if
        C1 > Total ->
            lists:reverse([element(1, element(S2 + 1, Table)), Sym1 | Acc]);
        true ->
            {Sym2, Nb2, Base2} = element(S2 + 1, Table),
            {V2, C2} = read(Rev, Total, C1, Nb2),
            N2 = Base2 + V2,
            if
                C2 > Total ->
                    lists:reverse([element(1, element(N1 + 1, Table)), Sym2, Sym1 | Acc]);
                true ->
                    fse_weights(Rev, Total, C2, Table, N1, N2, [Sym2, Sym1 | Acc])
            end
    end.

huffman_table(Weights) ->
    length(Weights) =< 255 orelse fail(too_many_huffman_weights),
    Sum = lists:foldl(fun(W, _) when W > 11 -> fail(huffman_weight_too_large);
                         (0, A) -> A;
                         (W, A) -> A + (1 bsl (W - 1))
                      end, 0, Weights),
    Sum > 0 orelse fail(empty_huffman_table),
    MaxBits = highbit(Sum) + 1,
    MaxBits =< 11 orelse fail(huffman_code_too_long),
    Rest = (1 bsl MaxBits) - Sum,
    Rest band (Rest - 1) =:= 0 orelse fail(corrupt_huffman_weights),
    All = Weights ++ [highbit(Rest) + 1],
    Indexed = lists:zip(lists:seq(0, length(All) - 1), All),
    %% Longest codes (lowest weights) first; equal weights in symbol order.
    Sorted = lists:sort([{W, S} || {S, W} <- Indexed, W > 0]),
    Cells = lists:append([lists:duplicate(1 bsl (W - 1), {S, MaxBits + 1 - W}) || {W, S} <- Sorted]),
    {list_to_tuple(Cells), MaxBits}.

%% ---------------------------------------------------------------- FSE

%% Forward (LSB-first) reader over Data; returns probabilities, accuracy log
%% and the byte length consumed.
fse_description(Data, MaxSymbol, MaxLog) ->
    Log = fpeek(Data, 0, 4) + 5,
    Log =< MaxLog orelse fail(fse_accuracy_log_too_large),
    {Probs, BitPos, Remaining} =
        fse_probs(Data, 4, (1 bsl Log) + 1, 1 bsl Log, Log + 1, [], 0, MaxSymbol),
    (Remaining =:= 1 andalso length(Probs) =< MaxSymbol + 1) orelse fail(corrupt_fse_description),
    End = (BitPos + 7) bsr 3,
    End =< byte_size(Data) orelse fail(fse_description_overrun),
    {Probs, Log, End}.

fse_probs(_Data, BitPos, Remaining, _Threshold, _NBits, Acc, _Count, _Max) when Remaining =< 1 ->
    {lists:reverse(Acc), BitPos, Remaining};
fse_probs(_, _, _, _, _, _, Count, Max) when Count > Max ->
    fail(fse_too_many_symbols);
fse_probs(Data, BitPos, Remaining, Threshold, NBits, Acc, Count, Max) ->
    Biggest = 2 * Threshold - 1 - Remaining,
    Low = fpeek(Data, BitPos, NBits - 1),
    {Value, Pos1} =
        if
            Low < Biggest -> {Low, BitPos + NBits - 1};
            true ->
                V = fpeek(Data, BitPos, NBits),
                {if V >= Threshold -> V - Biggest; true -> V end, BitPos + NBits}
        end,
    Prob = Value - 1,
    Remaining1 = Remaining - abs(Prob),
    {Acc1, Count1, Pos2} =
        case Prob of
            0 -> zero_repeats(Data, Pos1, [0 | Acc], Count + 1);
            _ -> {[Prob | Acc], Count + 1, Pos1}
        end,
    {NBits1, Threshold1} = shrink(Remaining1, NBits, Threshold),
    fse_probs(Data, Pos2, Remaining1, Threshold1, NBits1, Acc1, Count1, Max).

zero_repeats(Data, Pos, Acc, Count) ->
    Repeat = fpeek(Data, Pos, 2),
    Acc1 = lists:duplicate(Repeat, 0) ++ Acc,
    case Repeat of
        3 -> zero_repeats(Data, Pos + 2, Acc1, Count + 3);
        _ -> {Acc1, Count + Repeat, Pos + 2}
    end.

shrink(Remaining, NBits, Threshold) when Remaining < Threshold, Threshold > 1 ->
    shrink(Remaining, NBits - 1, Threshold bsr 1);
shrink(_, NBits, Threshold) ->
    {NBits, Threshold}.

fpeek(_Data, _BitPos, 0) -> 0;
fpeek(Data, BitPos, N) ->
    Byte = BitPos bsr 3,
    Avail = byte_size(Data) - Byte,
    Word = if
               Avail >= 4 -> binary:decode_unsigned(binary:part(Data, Byte, 4), little);
               Avail > 0 -> binary:decode_unsigned(binary:part(Data, Byte, Avail), little);
               true -> 0
           end,
    (Word bsr (BitPos band 7)) band ((1 bsl N) - 1).

fse_table(Probs, Log) ->
    Size = 1 bsl Log,
    Indexed = lists:zip(lists:seq(0, length(Probs) - 1), Probs),
    Less = [S || {S, -1} <- Indexed],
    High0 = Size - 1,
    {Cells0, High} = lists:foldl(fun(S, {M, H}) -> {M#{H => S}, H - 1} end, {#{}, High0}, Less),
    Step = (Size bsr 1) + (Size bsr 3) + 3,
    Mask = Size - 1,
    {Cells, Pos} = lists:foldl(
                     fun({S, P}, Acc) when P > 0 -> spread(S, P, Acc, Step, Mask, High);
                        (_, Acc) -> Acc
                     end, {Cells0, 0}, Indexed),
    Pos =:= 0 orelse fail(corrupt_fse_distribution),
    Counters0 = maps:from_list([{S, if P =:= -1 -> 1; true -> P end} || {S, P} <- Indexed]),
    {Rows, _} = lists:mapfoldl(
                  fun(Cell, Counters) ->
                          S = maps:get(Cell, Cells, 0),
                          X = maps:get(S, Counters),
                          Nb = Log - highbit(X),
                          {{S, Nb, (X bsl Nb) - Size}, Counters#{S := X + 1}}
                  end, Counters0, lists:seq(0, Size - 1)),
    list_to_tuple(Rows).

spread(_S, 0, Acc, _Step, _Mask, _High) -> Acc;
spread(S, N, {Cells, Pos}, Step, Mask, High) ->
    spread(S, N - 1, {Cells#{Pos => S}, advance((Pos + Step) band Mask, Step, Mask, High)},
           Step, Mask, High).

advance(Pos, Step, Mask, High) when Pos > High -> advance((Pos + Step) band Mask, Step, Mask, High);
advance(Pos, _, _, _) -> Pos.

%% ---------------------------------------------------------------- sequences

-define(LL_BASE, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                  16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
                  8192, 16384, 32768, 65536}).
-define(LL_BITS, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
                  13, 14, 15, 16}).
-define(ML_BASE, {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                  19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
                  35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
                  4099, 8195, 16387, 32771, 65539}).
-define(ML_BITS, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
                  12, 13, 14, 15, 16}).

kind(ll) -> {[4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
              2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
              -1, -1, -1, -1], 6, 35, 9};
kind(ml) -> {[1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
              -1, -1, -1, -1, -1], 6, 52, 9};
kind(off) -> {[1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1], 5, 31, 8}.

predefined(Kind) ->
    Key = {?MODULE, Kind},
    try persistent_term:get(Key)
    catch error:badarg ->
            {Probs, Log, _, _} = kind(Kind),
            T = {fse_table(Probs, Log), Log},
            persistent_term:put(Key, T),
            T
    end.

sequences(<<0>>, St) -> {[], St};
sequences(<<0, _/binary>>, _) -> fail(data_after_empty_sequences);
sequences(<<B0, R/binary>>, St) when B0 < 128 -> seq_modes(B0, R, St);
sequences(<<B0, B1, R/binary>>, St) when B0 < 255 -> seq_modes(((B0 - 128) bsl 8) + B1, R, St);
sequences(<<255, N:16/little, R/binary>>, St) -> seq_modes(N + 16#7F00, R, St);
sequences(_, _) -> fail(missing_sequences).

seq_modes(Count, <<LLm:2, OFm:2, MLm:2, 0:2, R0/binary>>, St0) ->
    {LL, R1, St1} = seq_table(LLm, ll, R0, St0),
    {OF, R2, St2} = seq_table(OFm, off, R1, St1),
    {ML, R3, St3} = seq_table(MLm, ml, R2, St2),
    {Rev, Total, C0} = backward(R3),
    {LLt, LLlog} = LL, {OFt, OFlog} = OF, {MLt, MLlog} = ML,
    {LLs, C1} = read(Rev, Total, C0, LLlog),
    {OFs, C2} = read(Rev, Total, C1, OFlog),
    {MLs, C3} = read(Rev, Total, C2, MLlog),
    Seqs = seq_loop(Rev, Total, C3, Count, LLt, OFt, MLt, LLs, OFs, MLs, []),
    {Seqs, St3};
seq_modes(_, <<_:6, _:2, _/binary>>, _) -> fail(reserved_mode_bits);
seq_modes(_, _, _) -> fail(missing_compression_modes).

seq_table(0, Kind, R, St) -> remember(Kind, predefined(Kind), R, St);
seq_table(1, Kind, <<Sym, R/binary>>, St) ->
    {_, _, MaxSym, _} = kind(Kind),
    Sym =< MaxSym orelse fail(bad_rle_symbol),
    remember(Kind, {{{Sym, 0, 0}}, 0}, R, St);
seq_table(1, _, _, _) -> fail(bad_rle_symbol);
seq_table(2, Kind, R, St) ->
    {_, _, MaxSym, MaxLog} = kind(Kind),
    {Probs, Log, End} = fse_description(R, MaxSym, MaxLog),
    <<_:End/binary, R2/binary>> = R,
    remember(Kind, {fse_table(Probs, Log), Log}, R2, St);
seq_table(3, Kind, R, St) ->
    T = case Kind of ll -> St#st.ll; off -> St#st.off; ml -> St#st.ml end,
    T =/= undefined orelse fail(repeat_without_table),
    {T, R, St}.

remember(ll, T, R, St) -> {T, R, St#st{ll = T}};
remember(off, T, R, St) -> {T, R, St#st{off = T}};
remember(ml, T, R, St) -> {T, R, St#st{ml = T}}.

seq_loop(_Rev, Total, C, 0, _, _, _, _, _, _, Acc) ->
    C =:= Total orelse fail(sequence_stream_not_consumed),
    lists:reverse(Acc);
seq_loop(Rev, Total, C, N, LLt, OFt, MLt, LLs, OFs, MLs, Acc) ->
    {OFc, OFnb, OFbase} = element(OFs + 1, OFt),
    {MLc, MLnb, MLbase} = element(MLs + 1, MLt),
    {LLc, LLnb, LLbase} = element(LLs + 1, LLt),
    {OV, C1} = read(Rev, Total, C, OFc),
    {MLx, C2} = read(Rev, Total, C1, element(MLc + 1, ?ML_BITS)),
    {LLx, C3} = read(Rev, Total, C2, element(LLc + 1, ?LL_BITS)),
    Seq = {element(LLc + 1, ?LL_BASE) + LLx, (1 bsl OFc) + OV, element(MLc + 1, ?ML_BASE) + MLx},
    case N of
        1 ->
            seq_loop(Rev, Total, C3, 0, LLt, OFt, MLt, LLs, OFs, MLs, [Seq | Acc]);
        _ ->
            {A, C4} = read(Rev, Total, C3, LLnb),
            {B, C5} = read(Rev, Total, C4, MLnb),
            {D, C6} = read(Rev, Total, C5, OFnb),
            seq_loop(Rev, Total, C6, N - 1, LLt, OFt, MLt, LLbase + A, OFbase + D, MLbase + B,
                     [Seq | Acc])
    end.

execute([], Lit, Out, Rep, _Total) ->
    {<<Out/binary, Lit/binary>>, Rep};
execute([{LL, OV, ML} | Seqs], Lit, Out, {R0, R1, R2} = Rep, Total) ->
    case Lit of
        <<L:LL/binary, Lit2/binary>> ->
            Out1 = <<Out/binary, L/binary>>,
            {Off, Rep2} =
                if
                    OV > 3 -> {OV - 3, {OV - 3, R0, R1}};
                    true ->
                        case OV - 1 + (if LL =:= 0 -> 1; true -> 0 end) of
                            0 -> {R0, Rep};
                            1 -> {R1, {R1, R0, R2}};
                            2 -> {R2, {R2, R0, R1}};
                            3 -> {R0 - 1, {R0 - 1, R0, R1}}
                        end
                end,
            Size = byte_size(Out1),
            (Off > 0 andalso Off =< Size) orelse fail(match_offset_out_of_range),
            Total + Size + ML =< ?MAX_OUT orelse fail(output_limit),
            execute(Seqs, Lit2, copy_match(Out1, Size, Off, ML), Rep2, Total);
        _ -> fail(not_enough_literals)
    end.

copy_match(Out, Size, Off, ML) when Off >= ML ->
    <<Out/binary, (binary:part(Out, Size - Off, ML))/binary>>;
copy_match(Out, Size, Off, ML) ->
    %% Overlapping copy: the last Off bytes repeat as a pattern.
    Pattern = binary:part(Out, Size - Off, Off),
    <<Out/binary, (binary:copy(Pattern, ML div Off))/binary,
      (binary:part(Pattern, 0, ML rem Off))/binary>>.

%% ---------------------------------------------------------------- backward bits

%% Returns {ReversedBytes, TotalBits, Consumed}. Bits remaining = Total - Consumed.
backward(<<>>) -> fail(empty_bitstream);
backward(Data) ->
    Size = byte_size(Data),
    Last = binary:last(Data),
    Last =/= 0 orelse fail(missing_end_marker),
    Rev = list_to_binary(lists:reverse(binary_to_list(Data))),
    {Rev, Size * 8, 8 - highbit(Last)}.

read(Rev, Total, C, N) -> {peek(Rev, Total, C, N), C + N}.

peek(_Rev, _Total, _C, 0) -> 0;
peek(Rev, Total, C, N) when C + N =< Total ->
    <<_:C, V:N, _/bits>> = Rev,
    V;
peek(_Rev, Total, C, _N) when C >= Total -> 0;
peek(Rev, Total, C, N) ->
    Avail = Total - C,
    <<_:C, V:Avail>> = Rev,
    V bsl (N - Avail).

highbit(X) -> highbit(X, -1).
highbit(0, N) -> N;
highbit(X, N) -> highbit(X bsr 1, N + 1).

%% ---------------------------------------------------------------- XXH64

-define(P1, 16#9E3779B185EBCA87).
-define(P2, 16#C2B2AE3D27D4EB4F).
-define(P3, 16#165667B19E3779F9).
-define(P4, 16#85EBCA77C2B2AE63).
-define(P5, 16#27D4EB2F165667C5).

rotl(X, R) -> ((X bsl R) bor (X bsr (64 - R))) band ?M64.
xround(Acc, Lane) -> (rotl((Acc + Lane * ?P2) band ?M64, 31) * ?P1) band ?M64.
merge(H, V) -> (((H bxor xround(0, V)) * ?P1) + ?P4) band ?M64.

xxh64(Data) ->
    N = byte_size(Data),
    {H0, Tail} =
        if
            N >= 32 ->
                {V1, V2, V3, V4, T} = stripes(Data, (?P1 + ?P2) band ?M64, ?P2, 0,
                                              (0 - ?P1) band ?M64),
                H = (rotl(V1, 1) + rotl(V2, 7) + rotl(V3, 12) + rotl(V4, 18)) band ?M64,
                {merge(merge(merge(merge(H, V1), V2), V3), V4), T};
            true -> {?P5, Data}
        end,
    avalanche(tail((H0 + N) band ?M64, Tail)).

stripes(<<A:64/little, B:64/little, C:64/little, D:64/little, R/binary>>, V1, V2, V3, V4) ->
    stripes(R, xround(V1, A), xround(V2, B), xround(V3, C), xround(V4, D));
stripes(R, V1, V2, V3, V4) -> {V1, V2, V3, V4, R}.

tail(H, <<L:64/little, R/binary>>) ->
    tail((rotl(H bxor xround(0, L), 27) * ?P1 + ?P4) band ?M64, R);
tail(H, <<L:32/little, R/binary>>) ->
    tail((rotl(H bxor ((L * ?P1) band ?M64), 23) * ?P2 + ?P3) band ?M64, R);
tail(H, <<B, R/binary>>) ->
    tail((rotl(H bxor ((B * ?P5) band ?M64), 11) * ?P1) band ?M64, R);
tail(H, <<>>) -> H.

avalanche(H0) ->
    H1 = ((H0 bxor (H0 bsr 33)) * ?P2) band ?M64,
    H2 = ((H1 bxor (H1 bsr 29)) * ?P3) band ?M64,
    H2 bxor (H2 bsr 32).
