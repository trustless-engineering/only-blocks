defmodule OnlyBlocks.LRU do
  @moduledoc """
  A bounded, RAM-only LRU cache owned by one GenServer: an ETS `:set` maps
  keys to `{value, tick}` and an `:ordered_set` keyed by tick tracks recency.
  Reads also go through the server, because a hit must refresh recency.
  """
  use GenServer

  def start_link(name, capacity), do: GenServer.start_link(__MODULE__, capacity, name: name)

  def get(name, key), do: GenServer.call(name, {:get, key})
  def put(name, key, value), do: GenServer.call(name, {:put, key, value})

  @impl true
  def init(capacity) do
    {:ok, %{values: :ets.new(:values, [:set, :private]), ages: :ets.new(:ages, [:ordered_set, :private]),
            capacity: capacity, tick: 0}}
  end

  @impl true
  def handle_call({:get, key}, _from, %{values: values} = st) do
    case :ets.lookup(values, key) do
      [{^key, value, _old}] -> {:reply, {:ok, value}, touch(st, key, value)}
      [] -> {:reply, :miss, st}
    end
  end

  def handle_call({:put, key, value}, _from, st) do
    st = touch(st, key, value)

    if :ets.info(st.values, :size) > st.capacity do
      oldest = :ets.first(st.ages)
      [{_, victim}] = :ets.lookup(st.ages, oldest)
      :ets.delete(st.ages, oldest)
      :ets.delete(st.values, victim)
    end

    {:reply, :ok, st}
  end

  defp touch(%{values: values, ages: ages, tick: tick} = st, key, value) do
    with [{^key, _, old}] <- :ets.lookup(values, key), do: :ets.delete(ages, old)
    :ets.insert(ages, {tick, key})
    :ets.insert(values, {key, value, tick})
    %{st | tick: tick + 1}
  end
end
