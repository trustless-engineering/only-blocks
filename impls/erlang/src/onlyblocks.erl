%% OnlyBlocks entry point: argument handling and the inbound HTTP/1.1 server.
%% One lightweight BEAM process per connection; a slow upstream fetch never
%% blocks getHealth.
-module(onlyblocks).
-export([main/1, start/0]).

-define(MAX_BODY, 1048576).
-define(ACCEPTORS, 16).

%% Called from `erl -eval`: run the server in its own process so that
%% init finishes booting and handles SIGTERM with a clean init:stop().
start() ->
    Args = init:get_plain_arguments(),
    spawn(fun() -> main(Args) end),
    ok.

main(Args) ->
    try
        {Bind, BaseUrl} = parse_args(Args, os:getenv("ONLYBLOCKS_BIND", "127.0.0.1:8899"),
                                     os:getenv("OLD_FAITHFUL_BASE_URL", "https://files.old-faithful.net")),
        Base = parse_base(BaseUrl),
        {Ip, Port} = parse_bind(Bind),
        ok = ob_archive:start(Base),
        {ok, Listen} = gen_tcp:listen(Port, [binary, {ip, Ip}, {active, false}, {reuseaddr, true},
                                             {backlog, 1024}, {packet, raw}, {nodelay, true}]),
        [spawn_link(fun() -> accept(Listen) end) || _ <- lists:seq(1, ?ACCEPTORS)],
        io:format("onlyblocks/erlang listening on ~s (upstream ~s)~n", [Bind, BaseUrl]),
        receive stop -> ok end
    catch
        throw:{usage, Message} ->
            io:format(standard_error, "onlyblocks: ~s~n", [Message]),
            erlang:halt(2);
        Class:Reason ->
            io:format(standard_error, "onlyblocks: startup failed: ~p~n", [{Class, Reason}]),
            erlang:halt(1)
    end.

parse_args([], Bind, Base) -> {Bind, Base};
parse_args(["--bind", V | R], _, Base) -> parse_args(R, V, Base);
parse_args(["--base-url", V | R], Bind, _) -> parse_args(R, Bind, V);
parse_args(["--bind=" ++ V | R], _, Base) -> parse_args(R, V, Base);
parse_args(["--base-url=" ++ V | R], Bind, _) -> parse_args(R, Bind, V);
parse_args([Other | _], _, _) -> throw({usage, "unknown argument " ++ Other}).

parse_base(Url0) ->
    Url = string:trim(string:trim(Url0), trailing, "/"),
    case uri_string:parse(Url) of
        #{scheme := Scheme, host := Host} = U when Host =/= "" ->
            S = case string:lowercase(Scheme) of
                    "http" -> http;
                    "https" -> https;
                    _ -> throw({usage, "--base-url must be http:// or https://"})
                end,
            Port = maps:get(port, U, case S of http -> 80; https -> 443 end),
            #{scheme => S, host => Host, port => Port, path => maps:get(path, U, "")};
        _ -> throw({usage, "--base-url must be an http:// or https:// URL"})
    end.

parse_bind(Bind) ->
    case string:split(Bind, ":", trailing) of
        [Host0, PortText] ->
            Host = string:trim(Host0, both, "[]"),
            Port = try list_to_integer(PortText) catch _:_ -> throw({usage, "bad --bind port"}) end,
            case inet:parse_address(Host) of
                {ok, Ip} -> {Ip, Port};
                _ ->
                    case inet:getaddr(Host, inet) of
                        {ok, Ip} -> {Ip, Port};
                        _ -> throw({usage, "bad --bind host"})
                    end
            end;
        _ -> throw({usage, "--bind must be HOST:PORT"})
    end.

accept(Listen) ->
    case gen_tcp:accept(Listen) of
        {ok, Sock} ->
            Pid = spawn(fun() -> receive go -> serve(Sock) end end),
            ok = gen_tcp:controlling_process(Sock, Pid),
            Pid ! go,
            accept(Listen);
        {error, closed} -> ok;
        {error, _} -> accept(Listen)
    end.

serve(Sock) ->
    try
        Deadline = erlang:monotonic_time(millisecond) + 30000,
        Recv = fun(T) -> gen_tcp:recv(Sock, 0, T) end,
        {Line, Headers, Rest} = ob_archive:read_head(Recv, Deadline, request),
        case Line of
            {request, 'POST', <<"/">>} ->
                case request_body(Recv, Deadline, Headers, Rest) of
                    {ok, Body} -> reply(Sock, 200, ob_rpc:handle(Body));
                    too_large -> reply(Sock, 413, <<>>);
                    bad -> reply(Sock, 400, <<>>)
                end;
            {request, 'POST', _} -> reply(Sock, 404, <<>>);
            {request, _, _} -> reply(Sock, 405, <<>>)
        end
    catch _:_ -> ok
    after
        gen_tcp:close(Sock)
    end.

request_body(Recv, Deadline, Headers, Rest) ->
    Lengths = [V || {<<"content-length">>, V} <- Headers],
    case {lists:keyfind(<<"transfer-encoding">>, 1, Headers), Lengths} of
        {{_, TE}, []} ->
            case string:lowercase(string:trim(TE)) of
                <<"chunked">> ->
                    try {ok, chunks(Recv, Deadline, Rest, [], 0)}
                    catch throw:too_large -> too_large; _:_ -> bad
                    end;
                _ -> bad
            end;
        {{_, _}, _} -> bad;
        {false, []} -> {ok, <<>>};
        {false, [Text]} ->
            case re:run(Text, "^[0-9]+$", [{capture, none}]) of
                nomatch -> bad;
                match ->
                    case binary_to_integer(Text) of
                        N when N > ?MAX_BODY -> too_large;
                        N -> {ok, read_exactly(Recv, Deadline, Rest, N)}
                    end
            end;
        _ -> bad
    end.

read_exactly(_Recv, _Deadline, Buf, N) when byte_size(Buf) >= N -> binary:part(Buf, 0, N);
read_exactly(Recv, Deadline, Buf, N) ->
    {ok, More} = Recv(max(1, Deadline - erlang:monotonic_time(millisecond))),
    read_exactly(Recv, Deadline, <<Buf/binary, More/binary>>, N).

chunks(Recv, Deadline, Buf, Acc, Have) ->
    case binary:split(Buf, <<"\r\n">>) of
        [Line, R] ->
            [SizeText | _] = binary:split(Line, <<";">>),
            Size = binary_to_integer(string:trim(SizeText), 16),
            Have + Size =< ?MAX_BODY orelse throw(too_large),
            case Size of
                0 -> iolist_to_binary(lists:reverse(Acc));
                _ ->
                    R2 = read_at_least(Recv, Deadline, R, Size + 2),
                    <<Chunk:Size/binary, "\r\n", R3/binary>> = R2,
                    chunks(Recv, Deadline, R3, [Chunk | Acc], Have + Size)
            end;
        [_] when byte_size(Buf) > 4096 -> error(bad_chunk);
        [_] -> chunks(Recv, Deadline, read_at_least(Recv, Deadline, Buf, byte_size(Buf) + 1), Acc, Have)
    end.

read_at_least(_Recv, _Deadline, Buf, N) when byte_size(Buf) >= N -> Buf;
read_at_least(Recv, Deadline, Buf, N) ->
    {ok, More} = Recv(max(1, Deadline - erlang:monotonic_time(millisecond))),
    read_at_least(Recv, Deadline, <<Buf/binary, More/binary>>, N).

reply(Sock, Status, Body) ->
    Reason = case Status of
                 200 -> "OK"; 400 -> "Bad Request"; 404 -> "Not Found";
                 405 -> "Method Not Allowed"; 413 -> "Payload Too Large"
             end,
    Type = case Status of 200 -> "Content-Type: application/json\r\n"; _ -> "" end,
    gen_tcp:send(Sock, [io_lib:format("HTTP/1.1 ~B ~s\r\n", [Status, Reason]), Type,
                        "Content-Length: ", integer_to_list(byte_size(Body)),
                        "\r\nConnection: close\r\n\r\n", Body]).
