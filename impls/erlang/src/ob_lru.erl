%% A bounded, RAM-only LRU owned by one process: an ETS set for lookups
%% plus an ordered_set keyed by a monotonically increasing tick for recency.
%% Reads go through the owner too, because a hit must refresh recency.
-module(ob_lru).
-export([start/2, get/2, put/3]).

start(Name, Capacity) ->
    Parent = self(),
    Pid = spawn_link(fun() ->
                             register(Name, self()),
                             Values = ets:new(values, [set, private]),
                             Ages = ets:new(ages, [ordered_set, private]),
                             Parent ! {self(), ready},
                             loop(Values, Ages, Capacity, 0)
                     end),
    receive {Pid, ready} -> Pid end.

get(Name, Key) -> call(Name, {get, Key}).
put(Name, Key, Value) -> call(Name, {put, Key, Value}).

call(Name, Msg) ->
    Ref = make_ref(),
    Name ! {self(), Ref, Msg},
    receive {Ref, Reply} -> Reply after 5000 -> undefined end.

loop(Values, Ages, Capacity, Tick) ->
    receive
        {From, Ref, {get, Key}} ->
            case ets:lookup(Values, Key) of
                [{Key, Value, Old}] ->
                    ets:delete(Ages, Old),
                    ets:insert(Ages, {Tick, Key}),
                    ets:insert(Values, {Key, Value, Tick}),
                    From ! {Ref, {ok, Value}};
                [] ->
                    From ! {Ref, undefined}
            end,
            loop(Values, Ages, Capacity, Tick + 1);
        {From, Ref, {put, Key, Value}} ->
            case ets:lookup(Values, Key) of
                [{Key, _, Old}] -> ets:delete(Ages, Old);
                [] -> ok
            end,
            ets:insert(Ages, {Tick, Key}),
            ets:insert(Values, {Key, Value, Tick}),
            case ets:info(Values, size) > Capacity of
                true ->
                    Oldest = ets:first(Ages),
                    [{_, Victim}] = ets:lookup(Ages, Oldest),
                    ets:delete(Ages, Oldest),
                    ets:delete(Values, Victim);
                false -> ok
            end,
            From ! {Ref, ok},
            loop(Values, Ages, Capacity, Tick + 1)
    end.
