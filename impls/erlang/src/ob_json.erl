%% Minimal RFC 8259 JSON for OTP 26 (which predates the OTP 27 `json` module).
%%
%% Decoded values: {obj, [{Key, Value}]} | [Value] | binary() | {num, Text}
%%                 | true | false | null.  Numbers keep their source text so
%% slot literals can be validated and ids echoed byte for byte.
%% Encoded values: maps (atom or binary keys) | lists | binaries | integers
%%                 | floats | true | false | null | {raw, iodata()}.
-module(ob_json).
-export([decode/1, encode/1]).

-define(MAX_DEPTH, 128).

%% ---------------------------------------------------------------- decode

decode(Bin) ->
    try
        {V, R} = value(ws(Bin), 0),
        <<>> = ws(R),
        {ok, V}
    catch _:_ -> error
    end.

ws(<<C, R/binary>>) when C =:= $\s; C =:= $\t; C =:= $\n; C =:= $\r -> ws(R);
ws(B) -> B.

value(_, Depth) when Depth > ?MAX_DEPTH -> throw(too_deep);
value(<<${, R/binary>>, D) -> object(ws(R), D + 1, []);
value(<<$[, R/binary>>, D) -> array(ws(R), D + 1, []);
value(<<$", R/binary>>, _) -> string(R, []);
value(<<"true", R/binary>>, _) -> {true, R};
value(<<"false", R/binary>>, _) -> {false, R};
value(<<"null", R/binary>>, _) -> {null, R};
value(<<C, _/binary>> = B, _) when C =:= $-; C >= $0, C =< $9 -> number(B);
value(_, _) -> throw(syntax).

object(<<$}, R/binary>>, _, []) -> {{obj, []}, R};
object(<<$", R/binary>>, D, Acc) ->
    {K, R1} = string(R, []),
    <<$:, R2/binary>> = ws(R1),
    {V, R3} = value(ws(R2), D),
    case ws(R3) of
        <<$,, R4/binary>> -> object(ws(R4), D, [{K, V} | Acc]);
        <<$}, R4/binary>> -> {{obj, lists:reverse([{K, V} | Acc])}, R4}
    end.

array(<<$], R/binary>>, _, []) -> {[], R};
array(B, D, Acc) ->
    {V, R} = value(B, D),
    case ws(R) of
        <<$,, R2/binary>> -> array(ws(R2), D, [V | Acc]);
        <<$], R2/binary>> -> {lists:reverse([V | Acc]), R2}
    end.

string(<<$", R/binary>>, Acc) ->
    Bin = iolist_to_binary(lists:reverse(Acc)),
    true = is_binary(unicode:characters_to_binary(Bin)),  % reject invalid UTF-8
    {Bin, R};
string(<<$\\, E, R/binary>>, Acc) ->
    case E of
        $" -> string(R, [$" | Acc]);
        $\\ -> string(R, [$\\ | Acc]);
        $/ -> string(R, [$/ | Acc]);
        $b -> string(R, [8 | Acc]);
        $f -> string(R, [12 | Acc]);
        $n -> string(R, [10 | Acc]);
        $r -> string(R, [13 | Acc]);
        $t -> string(R, [9 | Acc]);
        $u -> unicode_escape(R, Acc)
    end;
string(<<C, R/binary>>, Acc) when C >= 16#20 ->
    %% Copy a run of plain bytes in one go.
    {Run, Rest} = plain(R, 1),
    Len = Run,
    <<Chunk:Len/binary, _/binary>> = <<C, R/binary>>,
    string(Rest, [Chunk | Acc]).

plain(<<C, R/binary>>, N) when C >= 16#20, C =/= $", C =/= $\\ -> plain(R, N + 1);
plain(R, N) -> {N, R}.

unicode_escape(<<H:4/binary, R/binary>>, Acc) ->
    Code = binary_to_integer(H, 16),
    if
        Code >= 16#D800, Code =< 16#DBFF ->
            <<"\\u", L:4/binary, R2/binary>> = R,
            Low = binary_to_integer(L, 16),
            true = Low >= 16#DC00 andalso Low =< 16#DFFF,
            Cp = 16#10000 + ((Code - 16#D800) bsl 10) + (Low - 16#DC00),
            string(R2, [<<Cp/utf8>> | Acc]);
        Code >= 16#DC00, Code =< 16#DFFF -> throw(lone_surrogate);
        true -> string(R, [<<Code/utf8>> | Acc])
    end.

number(B) ->
    {Len, R} = num_end(B, 0),
    <<Text:Len/binary, _/binary>> = B,
    true = valid_number(Text),
    {{num, Text}, R}.

num_end(<<C, R/binary>>, N) when C >= $0, C =< $9; C =:= $-; C =:= $+; C =:= $.; C =:= $e; C =:= $E ->
    num_end(R, N + 1);
num_end(R, N) -> {N, R}.

valid_number(Text) ->
    re:run(Text, "^-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][-+]?[0-9]+)?$", [{capture, none}]) =:= match.

%% ---------------------------------------------------------------- encode

encode(V) -> iolist_to_binary(enc(V)).

enc(null) -> <<"null">>;
enc(true) -> <<"true">>;
enc(false) -> <<"false">>;
enc({raw, Raw}) -> Raw;
enc(I) when is_integer(I) -> integer_to_binary(I);
enc(F) when is_float(F) -> float_to_binary(F, [short]);
enc(B) when is_binary(B) -> [$", escape(B), $"];
enc(A) when is_atom(A) -> enc(atom_to_binary(A));
enc(L) when is_list(L) -> [$[, join([enc(X) || X <- L]), $]];
enc(M) when is_map(M) ->
    [${, join([[enc(key(K)), $:, enc(V)] || {K, V} <- maps:to_list(M)]), $}].

key(K) when is_atom(K) -> atom_to_binary(K);
key(K) -> K.

join([]) -> [];
join([H | T]) -> [H | [[$, | X] || X <- T]].

escape(B) ->
    case needs_escape(B) of
        false -> B;
        true -> [esc(C) || <<C>> <= B]
    end.

needs_escape(<<C, _/binary>>) when C < 16#20; C =:= $"; C =:= $\\ -> true;
needs_escape(<<_, R/binary>>) -> needs_escape(R);
needs_escape(<<>>) -> false.

esc($") -> <<"\\\"">>;
esc($\\) -> <<"\\\\">>;
esc($\n) -> <<"\\n">>;
esc($\r) -> <<"\\r">>;
esc($\t) -> <<"\\t">>;
esc(C) when C < 16#20 -> io_lib:format("\\u~4.16.0b", [C]);
esc(C) -> C.
