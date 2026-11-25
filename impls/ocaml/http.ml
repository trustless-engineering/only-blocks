(* HTTP/1.1 over Unix sockets: the inbound request reader and the outbound
   Range client (plain sockets for http://, the OS curl binary for https://). *)

exception Transport of string   (* retryable: connect/timeout/reset/short body *)
exception Fatal of string       (* -32603, never retried *)

let now = Unix.gettimeofday

let rec restart f = try f () with Unix.Unix_error (Unix.EINTR, _, _) -> restart f

(* Wait until [fd] is readable or [deadline] passes. *)
let wait_readable fd deadline =
  let rec go () =
    let left = deadline -. now () in
    if left <= 0. then false
    else match Unix.select [ fd ] [] [] left with
      | [], _, _ -> go ()
      | _ -> true
      | exception Unix.Unix_error (Unix.EINTR, _, _) -> go () in
  go ()

(* A buffered byte source over a file descriptor with an absolute deadline. *)
type source = { fd : Unix.file_descr; deadline : float; buf : Bytes.t; mutable lo : int; mutable hi : int; on_timeout : string -> exn }

let source ?(on_timeout = fun m -> Transport m) fd deadline =
  { fd; deadline; buf = Bytes.create 65536; lo = 0; hi = 0; on_timeout }

(* Refill; returns false at EOF. *)
let fill s =
  if not (wait_readable s.fd s.deadline) then raise (s.on_timeout "timed out");
  let n = try restart (fun () -> Unix.read s.fd s.buf 0 (Bytes.length s.buf))
    with Unix.Unix_error (e, _, _) -> raise (Transport (Unix.error_message e)) in
  s.lo <- 0; s.hi <- n; n > 0

(* Read the header block (up to and including CRLFCRLF). *)
let read_head s limit =
  let b = Buffer.create 1024 in
  let rec go () =
    if s.lo >= s.hi && not (fill s) then raise (Transport "connection closed in headers");
    let c = Bytes.get s.buf s.lo in
    s.lo <- s.lo + 1;
    Buffer.add_char b c;
    let l = Buffer.length b in
    if l > limit then raise (Fatal "header block too large");
    if c = '\n' && l >= 4 && Buffer.sub b (l - 4) 4 = "\r\n\r\n" then Buffer.contents b
    else if c = '\n' && l >= 2 && Buffer.sub b (l - 2) 2 = "\n\n" then Buffer.contents b
    else go () in
  go ()

(* Read up to n bytes into [out]; returns the number actually read (short at EOF). *)
let read_into s out n =
  let got = ref 0 and eof = ref false in
  while !got < n && not !eof do
    if s.lo >= s.hi && not (fill s) then eof := true
    else begin
      let k = min (n - !got) (s.hi - s.lo) in
      Buffer.add_subbytes out s.buf s.lo k;
      s.lo <- s.lo + k; got := !got + k
    end
  done;
  !got

let read_line s limit =
  let b = Buffer.create 32 in
  let rec go () =
    if s.lo >= s.hi && not (fill s) then raise (Transport "connection closed in chunk header");
    let c = Bytes.get s.buf s.lo in
    s.lo <- s.lo + 1;
    if c = '\n' then Buffer.contents b
    else begin
      Buffer.add_char b c;
      if Buffer.length b > limit then raise (Fatal "line too long");
      go ()
    end in
  let l = go () in
  if String.length l > 0 && l.[String.length l - 1] = '\r' then String.sub l 0 (String.length l - 1) else l

let lower = String.lowercase_ascii

(* Split a header block into the first line and lowercase (name, value) pairs. *)
let parse_head head =
  let lines = String.split_on_char '\n' head |> List.map (fun l ->
      if String.length l > 0 && l.[String.length l - 1] = '\r' then String.sub l 0 (String.length l - 1) else l)
              |> List.filter (( <> ) "") in
  match lines with
  | [] -> ("", [])
  | first :: rest ->
    (first, List.filter_map (fun l ->
         match String.index_opt l ':' with
         | None -> None
         | Some i -> Some (lower (String.trim (String.sub l 0 i)),
                           String.trim (String.sub l (i + 1) (String.length l - i - 1)))) rest)

let header hs name = List.assoc_opt name hs
let headers hs name = List.filter_map (fun (k, v) -> if k = name then Some v else None) hs

let all_digits s = s <> "" && String.for_all (fun c -> c >= '0' && c <= '9') s

(* Bounded decimal parse: None when not digits, max_int when huge. *)
let parse_length s =
  if not (all_digits s) then None
  else begin
    let v = ref 0 in
    String.iter (fun c -> if !v < 1 lsl 40 then v := !v * 10 + Char.code c - 48) s;
    Some !v
  end

let hex_value s =
  let s = String.trim (match String.index_opt s ';' with Some i -> String.sub s 0 i | None -> s) in
  if s = "" || String.length s > 12 then None
  else
    let ok = String.for_all (function '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true | _ -> false) s in
    if ok then Some (int_of_string ("0x" ^ s)) else None

(* Decode a chunked body; [too_big] is raised as soon as more than [cap] bytes arrive. *)
let read_chunked s cap too_big =
  let out = Buffer.create 4096 in
  let rec go () =
    match hex_value (read_line s 4096) with
    | None -> raise (Transport "invalid chunk header")
    | Some 0 ->
      let rec trailers n = if n > 100 then raise (Transport "too many trailers")
        else if read_line s 4096 <> "" then trailers (n + 1) in
      trailers 0
    | Some size ->
      if Buffer.length out + size > cap then raise too_big;
      if read_into s out size < size then raise (Transport "connection closed in chunk");
      if read_line s 2 <> "" then raise (Transport "bad chunk terminator");
      go () in
  go ();
  Buffer.contents out

(* ---- outbound -------------------------------------------------------- *)

type base = { scheme : string; host : string; port : int; prefix : string; url : string }

let parse_base_url raw =
  let s = String.trim raw in
  let n = ref (String.length s) in
  while !n > 0 && s.[!n - 1] = '/' do decr n done;
  let s = String.sub s 0 !n in
  let scheme, rest =
    match String.index_opt s ':' with
    | Some i when i + 3 <= String.length s && String.sub s i 3 = "://" ->
      (lower (String.sub s 0 i), String.sub s (i + 3) (String.length s - i - 3))
    | _ -> failwith "base URL needs an http:// or https:// scheme" in
  if scheme <> "http" && scheme <> "https" then failwith "base URL scheme must be http or https";
  let authority, prefix =
    match String.index_opt rest '/' with
    | Some i -> (String.sub rest 0 i, String.sub rest i (String.length rest - i))
    | None -> (rest, "") in
  let authority = match String.rindex_opt authority '@' with
    | Some i -> String.sub authority (i + 1) (String.length authority - i - 1) | None -> authority in
  let default_port = if scheme = "https" then 443 else 80 in
  let host, port =
    if String.length authority > 0 && authority.[0] = '[' then
      match String.index_opt authority ']' with
      | None -> failwith "bad IPv6 host"
      | Some j ->
        let h = String.sub authority 1 (j - 1) in
        let tail = String.sub authority (j + 1) (String.length authority - j - 1) in
        if tail = "" then (h, default_port)
        else if tail.[0] = ':' then (h, int_of_string (String.sub tail 1 (String.length tail - 1)))
        else failwith "bad authority"
    else match String.rindex_opt authority ':' with
      | Some i -> (String.sub authority 0 i,
                   (match int_of_string_opt (String.sub authority (i + 1) (String.length authority - i - 1)) with
                    | Some p -> p | None -> failwith "bad port"))
      | None -> (authority, default_port) in
  if host = "" then failwith "base URL has no host";
  if port <= 0 || port > 65535 then failwith "bad port";
  { scheme; host; port; prefix; url = s }

let resolve host port =
  match Unix.getaddrinfo host (string_of_int port) [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ] with
  | [] -> raise (Transport ("cannot resolve " ^ host))
  | addrs ->
    (match List.find_opt (fun a -> a.Unix.ai_family = Unix.PF_INET) addrs with
     | Some a -> a | None -> List.hd addrs)

let connect_with_timeout host port timeout =
  let ai = try resolve host port with Not_found -> raise (Transport "resolve failed") in
  let fd = Unix.socket ai.Unix.ai_family Unix.SOCK_STREAM 0 in
  (try
     Unix.set_nonblock fd;
     (try Unix.connect fd ai.Unix.ai_addr with
      | Unix.Unix_error ((Unix.EINPROGRESS | Unix.EWOULDBLOCK | Unix.EAGAIN | Unix.EINTR), _, _) ->
        let deadline = now () +. timeout in
        let rec wait () =
          let left = deadline -. now () in
          if left <= 0. then raise (Transport "connect timed out");
          match Unix.select [] [ fd ] [] left with
          | _, [], _ -> wait ()
          | _ -> ()
          | exception Unix.Unix_error (Unix.EINTR, _, _) -> wait () in
        wait ();
        (match Unix.getsockopt_error fd with
         | None -> ()
         | Some e -> raise (Transport (Unix.error_message e))));
     Unix.clear_nonblock fd;
     fd
   with e -> Unix.close fd; raise e)

let write_all fd s =
  let b = Bytes.unsafe_of_string s in
  let rec go off =
    if off < Bytes.length b then
      go (off + restart (fun () -> Unix.write fd b off (Bytes.length b - off))) in
  go 0

type reply = Partial of string | Status of int * string option

(* Parse an upstream response from [s]: status, then a bounded 206 body. *)
let read_response s ~size ~cap =
  let head = read_head s 65536 in
  let first, hs = parse_head head in
  let status =
    match String.split_on_char ' ' first with
    | v :: code :: _ when String.length v >= 5 && String.sub v 0 5 = "HTTP/" ->
      (match int_of_string_opt code with Some c -> c | None -> raise (Transport "bad status line"))
    | _ -> raise (Transport "bad status line") in
  if status <> 206 then Status (status, header hs "retry-after")
  else begin
    let too_big = Fatal "archive body exceeds range cap" in
    let chunked = match header hs "transfer-encoding" with
      | Some te -> List.mem "chunked" (List.map (fun x -> lower (String.trim x)) (String.split_on_char ',' te))
      | None -> false in
    let body =
      if chunked then read_chunked s cap too_big
      else match headers hs "content-length" with
        | [] ->
          let out = Buffer.create 4096 in
          let rec go () =
            if Buffer.length out > cap then raise too_big;
            if read_into s out (min 65536 (cap + 1 - Buffer.length out)) > 0 then go () in
          go ();
          if Buffer.length out > cap then raise too_big;
          Buffer.contents out
        | [ cl ] ->
          (match parse_length cl with
           | None -> raise (Fatal "invalid Content-Length")
           | Some n when n > cap -> raise too_big
           | Some n ->
             let out = Buffer.create n in
             if read_into s out n < n then raise (Transport "connection closed before body complete");
             Buffer.contents out)
        | _ -> raise (Fatal "duplicate Content-Length") in
    if String.length body <> size then raise (Fatal "archive range body has wrong length");
    Partial body
  end

let user_agent = "onlyblocks/ocaml"

let attempt_http base path range ~size ~cap =
  let deadline = now () +. 60. in
  let fd = connect_with_timeout base.host base.port 10. in
  Fun.protect ~finally:(fun () -> try Unix.close fd with _ -> ()) (fun () ->
      let host = if base.port = 80 then base.host else Printf.sprintf "%s:%d" base.host base.port in
      let req = Printf.sprintf
          "GET %s HTTP/1.1\r\nHost: %s\r\nRange: %s\r\nUser-Agent: %s\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
          path host range user_agent in
      (try write_all fd req with Unix.Unix_error (e, _, _) -> raise (Transport (Unix.error_message e)));
      read_response (source fd deadline) ~size ~cap)

(* HTTPS: the OS curl binary performs only the TLS transport; its raw HTTP/1.1
   response (headers + undecoded body) streams over a pipe into the same parser. *)
(* SPEC 3.3 permits only the OS-provided curl; prefer it over any PATH copy. *)
let os_curl = if Sys.file_exists "/usr/bin/curl" then "/usr/bin/curl" else "curl"

let attempt_curl base path range ~size ~cap =
  let deadline = now () +. 62. in
  let host = if String.contains base.host ':' then "[" ^ base.host ^ "]" else base.host in
  let url = if base.port = 443 then Printf.sprintf "https://%s%s" host path
    else Printf.sprintf "https://%s:%d%s" host base.port path in
  let r, w = Unix.pipe ~cloexec:true () in
  let devnull = Unix.openfile "/dev/null" [ Unix.O_RDONLY; Unix.O_CLOEXEC ] 0 in
  let args = [| os_curl; "-sS"; "--http1.1"; "--raw"; "-i"; "--suppress-connect-headers";
                "--connect-timeout"; "10"; "--max-time"; "60";
                "-H"; "Range: " ^ range; "-H"; "User-Agent: " ^ user_agent;
                "-H"; "Accept-Encoding: identity"; "-H"; "Connection: close"; "--"; url |] in
  let pid =
    try Unix.create_process os_curl args devnull w Unix.stderr
    with e -> Unix.close r; Unix.close w; Unix.close devnull; raise (Transport (Printexc.to_string e)) in
  Unix.close w; Unix.close devnull;
  Fun.protect
    ~finally:(fun () ->
        (try Unix.close r with _ -> ());
        (try Unix.kill pid Sys.sigkill with _ -> ());
        ignore (restart (fun () -> Unix.waitpid [] pid)))
    (fun () -> read_response (source r deadline) ~size ~cap)

let attempt base path range ~size ~cap =
  if base.scheme = "https" then attempt_curl base path range ~size ~cap
  else attempt_http base path range ~size ~cap

(* ---- Retry-After ----------------------------------------------------- *)

let days_from_civil y m d =
  let y = if m <= 2 then y - 1 else y in
  let era = (if y >= 0 then y else y - 399) / 400 in
  let yoe = y - era * 400 in
  let mp = (m + 9) mod 12 in
  let doy = (153 * mp + 2) / 5 + d - 1 in
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy in
  era * 146097 + doe - 719468

let months = [ "jan"; "feb"; "mar"; "apr"; "may"; "jun"; "jul"; "aug"; "sep"; "oct"; "nov"; "dec" ]

(* IMF-fixdate "Sun, 06 Nov 1994 08:49:37 GMT" -> Unix seconds. *)
let http_date s =
  try
    let parts = String.split_on_char ' ' (String.trim s) |> List.filter (( <> ) "") in
    match parts with
    | [ _; d; mon; y; hms; _ ] ->
      let rec idx i = function [] -> raise Not_found | x :: r -> if x = lower mon then i else idx (i + 1) r in
      let m = idx 1 months in
      (match String.split_on_char ':' hms with
       | [ hh; mm; ss ] ->
         let days = days_from_civil (int_of_string y) m (int_of_string d) in
         Some (float_of_int (days * 86400 + int_of_string hh * 3600 + int_of_string mm * 60 + int_of_string ss))
       | _ -> None)
    | _ -> None
  with _ -> None

let retry_delay retry_after attempt =
  let backoff () = Float.min 10. (0.2 *. Float.pow 2. (float_of_int (min attempt 30))) *. (0.5 +. Random.float 0.5) in
  match retry_after with
  | Some v when all_digits (String.trim v) ->
    let v = String.trim v in
    if String.length v > 4 then 10. else Float.min 10. (float_of_string v)
  | Some v -> (match http_date v with Some t -> Float.max 0. (Float.min 10. (t -. now ())) | None -> backoff ())
  | None -> backoff ()

(* ---- inbound ---------------------------------------------------------- *)

exception Too_large
exception Bad_request

let max_body = 1 lsl 20

(* Returns (method, target, body). *)
let read_request fd =
  let s = source ~on_timeout:(fun _ -> Bad_request) fd (now () +. 10.) in
  let head = try read_head s 65536 with Transport _ | Fatal _ -> raise Bad_request in
  let first, hs = parse_head head in
  let meth, target =
    match String.split_on_char ' ' first with
    | m :: t :: _ -> (m, t)
    | _ -> raise Bad_request in
  let body =
    if meth <> "POST" then ""
    else match header hs "transfer-encoding" with
      | Some te ->
        if lower (String.trim te) <> "chunked" || headers hs "content-length" <> [] then raise Bad_request;
        (try read_chunked s max_body Too_large with Transport _ | Fatal _ -> raise Bad_request)
      | None ->
        match headers hs "content-length" with
        | [] -> ""
        | [ cl ] ->
          (match parse_length (String.trim cl) with
           | None -> raise Bad_request
           | Some n when n > max_body -> raise Too_large
           | Some n ->
             let out = Buffer.create n in
             if (try read_into s out n with Transport _ -> -1) < n then raise Bad_request;
             Buffer.contents out)
        | _ -> raise Bad_request in
  (meth, target, body)

let respond fd status reason ?(content_type = true) body =
  let head = Printf.sprintf "HTTP/1.1 %d %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n"
      status reason (if content_type then "Content-Type: application/json\r\n" else "") (String.length body) in
  write_all fd (head ^ body)

(* After an early error response, read and discard what the client still
   sends (briefly) so the close does not reset the reply away. *)
let drain fd =
  (try Unix.shutdown fd Unix.SHUTDOWN_SEND with _ -> ());
  let deadline = now () +. 1.0 and buf = Bytes.create 65536 and total = ref 0 in
  try
    while !total < 4 * max_body && wait_readable fd deadline
          && (let n = Unix.read fd buf 0 65536 in total := !total + n; n > 0) do () done
  with _ -> ()
