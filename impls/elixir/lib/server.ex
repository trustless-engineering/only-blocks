defmodule OnlyBlocks.Server do
  @moduledoc """
  Inbound HTTP/1.1 over `:gen_tcp`: a pool of acceptors, one process per
  connection, so a slow upstream fetch never blocks `getHealth`.
  """
  alias OnlyBlocks.{Archive, Rpc}

  @max_body 1_048_576
  @acceptors 16

  def listen(ip, port) do
    {:ok, listen} =
      :gen_tcp.listen(port, [:binary, ip: ip, active: false, reuseaddr: true, backlog: 1024, packet: :raw, nodelay: true])

    for _ <- 1..@acceptors, do: spawn_link(fn -> accept(listen) end)
    :ok
  end

  defp accept(listen) do
    case :gen_tcp.accept(listen) do
      {:ok, sock} ->
        pid = spawn(fn -> receive(do: (:go -> serve(sock))) end)
        :ok = :gen_tcp.controlling_process(sock, pid)
        send(pid, :go)
        accept(listen)

      {:error, :closed} ->
        :ok

      {:error, _} ->
        accept(listen)
    end
  end

  defp serve(sock) do
    deadline = System.monotonic_time(:millisecond) + 30_000
    recv = fn timeout -> :gen_tcp.recv(sock, 0, timeout) end

    case Archive.read_head(recv, deadline, :request) do
      {{:request, :POST, "/"}, headers, rest} ->
        case request_body(recv, deadline, headers, rest) do
          {:ok, body} -> reply(sock, 200, Rpc.handle(body))
          :too_large -> reply(sock, 413, "")
          :bad -> reply(sock, 400, "")
        end

      {{:request, :POST, _}, _, _} ->
        reply(sock, 404, "")

      {{:request, _, _}, _, _} ->
        reply(sock, 405, "")
    end
  catch
    _, _ -> :ok
  after
    :gen_tcp.close(sock)
  end

  defp request_body(recv, deadline, headers, rest) do
    lengths = for {"content-length", v} <- headers, do: v

    case {List.keyfind(headers, "transfer-encoding", 0), lengths} do
      {nil, []} ->
        {:ok, ""}

      {nil, [text]} ->
        cond do
          not (text =~ ~r/\A[0-9]+\z/) -> :bad
          String.to_integer(text) > @max_body -> :too_large
          true -> {:ok, read_exactly(recv, deadline, rest, String.to_integer(text))}
        end

      {{_, te}, []} ->
        if String.downcase(String.trim(te)) == "chunked" do
          try do
            {:ok, Archive.chunked(recv, deadline, rest, @max_body, [], 0, fn -> throw(:too_large) end)}
          catch
            :too_large -> :too_large
            _, _ -> :bad
          end
        else
          :bad
        end

      _ ->
        :bad
    end
  end

  defp read_exactly(_recv, _deadline, buf, n) when byte_size(buf) >= n, do: binary_part(buf, 0, n)

  defp read_exactly(recv, deadline, buf, n) do
    {:ok, more} = recv.(max(1, deadline - System.monotonic_time(:millisecond)))
    read_exactly(recv, deadline, buf <> more, n)
  end

  @reasons %{200 => "OK", 400 => "Bad Request", 404 => "Not Found", 405 => "Method Not Allowed", 413 => "Payload Too Large"}

  defp reply(sock, status, body) do
    type = if status == 200, do: "Content-Type: application/json\r\n", else: ""

    :gen_tcp.send(sock, [
      "HTTP/1.1 #{status} #{@reasons[status]}\r\n",
      type,
      "Content-Length: #{byte_size(body)}\r\nConnection: close\r\n\r\n",
      body
    ])
  end
end

defmodule OnlyBlocks.CLI do
  @moduledoc "Argument handling: flag > environment > default."
  alias OnlyBlocks.{Archive, Server}

  @doc "Entry point for `elixir -e`: boot the server in its own process and return."
  def start(argv) do
    spawn(fn -> main(argv) end)
    :ok
  end

  def main(argv) do
    {bind, base_url} =
      parse(argv, System.get_env("ONLYBLOCKS_BIND", "127.0.0.1:8899"),
        System.get_env("OLD_FAITHFUL_BASE_URL", "https://files.old-faithful.net"))

    base = parse_base!(base_url)
    {ip, port} = parse_bind!(bind)
    :ok = Archive.start(base)
    :ok = Server.listen(ip, port)
    IO.puts("onlyblocks/elixir listening on #{bind} (upstream #{base_url})")
    Process.sleep(:infinity)
  catch
    {:usage, message} ->
      IO.puts(:stderr, "onlyblocks: #{message}")
      System.halt(2)

    kind, reason ->
      IO.puts(:stderr, "onlyblocks: startup failed: " <> Exception.format_banner(kind, reason))
      System.halt(1)
  end

  defp parse([], bind, base), do: {bind, base}
  defp parse(["--bind", v | rest], _, base), do: parse(rest, v, base)
  defp parse(["--base-url", v | rest], bind, _), do: parse(rest, bind, v)
  defp parse(["--bind=" <> v | rest], _, base), do: parse(rest, v, base)
  defp parse(["--base-url=" <> v | rest], bind, _), do: parse(rest, bind, v)
  defp parse([other | _], _, _), do: throw({:usage, "unknown argument #{other}"})

  defp parse_base!(url) do
    url = url |> String.trim() |> String.trim_trailing("/")

    case URI.parse(url) do
      %URI{scheme: scheme, host: host} = uri when scheme in ["http", "https"] and host not in [nil, ""] ->
        %{scheme: String.to_atom(scheme), host: host, port: uri.port, path: uri.path || ""}

      _ ->
        throw({:usage, "--base-url must be an http:// or https:// URL"})
    end
  end

  defp parse_bind!(bind) do
    with [host, port_text] <- String.split(bind, ~r/:(?=[^:]*$)/),
         {port, ""} <- Integer.parse(port_text),
         host = host |> String.trim_leading("[") |> String.trim_trailing("]") |> String.to_charlist(),
         {:ok, ip} <- :inet.getaddr(host, if(:inet.parse_ipv6strict_address(host) |> elem(0) == :ok, do: :inet6, else: :inet)) do
      {ip, port}
    else
      _ -> throw({:usage, "--bind must be HOST:PORT"})
    end
  end
end
