(* OnlyBlocks in OCaml: a zero-dependency historical Solana getBlock JSON-RPC
   server over Old Faithful HTTP Range reads.  Stdlib + unix + threads only. *)

open Wire
open Json

exception Rpc of int * string

let internal m = raise (Rpc (-32603, m))

(* ---- bounded LRU (hash table + intrusive doubly linked list) ------------ *)

type ('k, 'v) cell = { key : 'k; mutable value : 'v; mutable prev : ('k, 'v) cell option; mutable next : ('k, 'v) cell option }

type ('k, 'v) lru = {
  cap : int; tbl : ('k, ('k, 'v) cell) Hashtbl.t; lock : Mutex.t;
  mutable head : ('k, 'v) cell option; mutable tail : ('k, 'v) cell option;
}

let lru cap = { cap; tbl = Hashtbl.create 1024; lock = Mutex.create (); head = None; tail = None }

let unlink t c =
  (match c.prev with Some p -> p.next <- c.next | None -> t.head <- c.next);
  (match c.next with Some n -> n.prev <- c.prev | None -> t.tail <- c.prev);
  c.prev <- None; c.next <- None

let push_front t c =
  c.next <- t.head; c.prev <- None;
  (match t.head with Some h -> h.prev <- Some c | None -> t.tail <- Some c);
  t.head <- Some c

let lru_get t k =
  Mutex.protect t.lock (fun () ->
      match Hashtbl.find_opt t.tbl k with
      | None -> None
      | Some c -> unlink t c; push_front t c; Some c.value)

let lru_put t k v =
  Mutex.protect t.lock (fun () ->
      (match Hashtbl.find_opt t.tbl k with
       | Some c -> c.value <- v; unlink t c; push_front t c
       | None ->
         let c = { key = k; value = v; prev = None; next = None } in
         Hashtbl.replace t.tbl k c; push_front t c);
      if Hashtbl.length t.tbl > t.cap then
        match t.tail with
        | Some old -> unlink t old; Hashtbl.remove t.tbl old.key
        | None -> ())

(* ---- Old Faithful: the 2-range-read protocol ---------------------------- *)

type slot_range = Present of int64 * int | Skipped

let epoch_slots = 432000L
let max_slice = 128 lsl 20
let ranges : (int64, slot_range) lru = lru 100_000
let hashes : (int64, string) lru = lru 100_000
let upstream = Semaphore.Counting.make 32
let base = ref (Http.parse_base_url "https://files.old-faithful.net")

let not_archived slot =
  Rpc (-32004, Printf.sprintf
         "Block not available for slot %Lu: epoch %Lu is not archived in Old Faithful (historical-only server)"
         slot (Int64.unsigned_div slot epoch_slots))

let read_range slot suffix start size cap =
  let stop = Int64.add start (Int64.of_int (size - 1)) in
  if ucmp stop start < 0 then internal "archive range end overflows u64";
  let epoch = Int64.unsigned_div slot epoch_slots in
  let path = Printf.sprintf "%s/%Lu/epoch-%Lu%s" !base.Http.prefix epoch epoch suffix in
  let range = Printf.sprintf "bytes=%Lu-%Lu" start stop in
  let rec go attempt =
    let outcome =
      Semaphore.Counting.acquire upstream;
      Fun.protect ~finally:(fun () -> Semaphore.Counting.release upstream) (fun () ->
          try Ok (Http.attempt !base path range ~size ~cap) with
          | Http.Transport _ | Unix.Unix_error _ | Sys_error _ | End_of_file -> Error ()
          | Http.Fatal m -> internal m) in
    match outcome with
    | Ok (Http.Partial body) -> body
    | Ok (Http.Status (404, _)) -> raise (not_archived slot)
    | Ok (Http.Status (s, ra)) when s = 429 || (s >= 500 && s < 600) -> retry attempt ra
    | Ok (Http.Status (s, _)) -> internal (Printf.sprintf "unexpected archive HTTP status %d" s)
    | Error () -> retry attempt None
  and retry attempt ra =
    if attempt >= 4 then internal "archive range retries exhausted";
    Thread.delay (Http.retry_delay ra attempt);
    go (attempt + 1) in
  go 0

let load_block slot : car =
  let record =
    match lru_get ranges slot with
    | Some r -> r
    | None ->
      let idx = Int64.unsigned_rem slot epoch_slots in
      let raw = read_range slot "-slot-ranges.raw" (Int64.mul idx 12L) 12 12 in
      let offset = String.get_int64_le raw 0 in
      let length = Int32.to_int (String.get_int32_le raw 8) land 0xFFFFFFFF in
      let r = if length = 0 then Skipped else Present (offset, length) in
      lru_put ranges slot r; r in
  match record with
  | Skipped -> raise (Rpc (-32007, Printf.sprintf "Slot %Lu was skipped, or missing in long-term storage" slot))
  | Present (offset, length) ->
    if length > max_slice then internal "archive slice exceeds 128 MiB";
    index_car (read_range slot ".car" offset length max_slice)

let entry_hash car key =
  match at (node car key 1) 2 with
  | Some (B h) when String.length h = 32 -> h
  | _ -> fail "invalid Entry hash"

let block_hash slot car entries =
  let h = match List.rev entries with [] -> zero_hash | last :: _ -> base58 (entry_hash car last) in
  lru_put hashes slot h; h

let previous_hash slot parent =
  if slot = 0L then zero_hash
  else match lru_get hashes parent with
    | Some h -> h
    | None ->
      let car = load_block parent in
      if as_u64 (at car.block 1) = None then fail "missing parent Block slot";
      block_hash parent car (links (at car.block 3))

(* ---- JSON rendering (WIRE_FORMATS.md section 13) ------------------------ *)

let upgradeable = "BPFLoaderUpgradeab1e11111111111111111111111"

let reserved =
  let t = Hashtbl.create 64 in
  List.iter (fun k -> Hashtbl.replace t k ())
    [ "AddressLookupTab1e1111111111111111111111111"; "BPFLoader2111111111111111111111111111111111";
      "BPFLoader1111111111111111111111111111111111"; "BPFLoaderUpgradeab1e11111111111111111111111";
      "ComputeBudget111111111111111111111111111111"; "Config1111111111111111111111111111111111111";
      "Ed25519SigVerify111111111111111111111111111"; "Feature111111111111111111111111111111111111";
      "LoaderV411111111111111111111111111111111111"; "KeccakSecp256k11111111111111111111111111111";
      "Secp256r1SigVerify1111111111111111111111111"; "StakeConfig11111111111111111111111111111111";
      "Stake11111111111111111111111111111111111111"; "11111111111111111111111111111111";
      "Vote111111111111111111111111111111111111111"; "ZkE1Gama1Proof11111111111111111111111111111";
      "ZkTokenProof1111111111111111111111111111111"; "SysvarC1ock11111111111111111111111111111111";
      "SysvarEpochRewards1111111111111111111111111"; "SysvarEpochSchedu1e111111111111111111111111";
      "SysvarFees111111111111111111111111111111111"; "Sysvar1nstructions1111111111111111111111111";
      "SysvarLastRestartS1ot1111111111111111111111"; "SysvarRecentB1ockHashes11111111111111111111";
      "SysvarRent111111111111111111111111111111111"; "SysvarRewards111111111111111111111111111111";
      "SysvarS1otHashes111111111111111111111111111"; "SysvarS1otHistory11111111111111111111111111";
      "SysvarStakeHistory1111111111111111111111111"; "NativeLoader1111111111111111111111111111111";
      "Sysvar1111111111111111111111111111111111111" ];
  t

let str s = OStr s
let byte_list s = OArr (List.init (String.length s) (fun i -> int (Char.code s.[i])))

let rec err_json = function
  | Meta.EStr s -> OStr s
  | Meta.EInt n -> int n
  | Meta.EArr l -> OArr (List.map err_json l)
  | Meta.EObj (k, v) -> OObj [ (k, err_json v) ]

let reward_json (r : Meta.reward) =
  OObj [ ("pubkey", str r.pubkey); ("lamports", i64 r.lamports); ("postBalance", u64 r.post_balance);
         ("rewardType", opt str r.reward_type); ("commission", opt int r.commission) ]

let token_json (t : Meta.token_balance) =
  let ui = match t.ui_amount with Some f when Float.is_finite f -> OFloat f | _ -> ONull in
  OObj ([ ("accountIndex", int t.account_index); ("mint", str t.mint);
          ("uiTokenAmount", OObj [ ("uiAmount", ui); ("decimals", int t.decimals); ("amount", str t.amount);
                                   ("uiAmountString", str t.ui_amount_string) ]) ]
        @ (if t.owner <> "" then [ ("owner", str t.owner) ] else [])
        @ (if t.program_id <> "" then [ ("programId", str t.program_id) ] else []))

(* Compiled form when [keys] is None, partially decoded (jsonParsed) otherwise. *)
let instruction_json (ix : instruction) keys =
  let common = [ ("data", str (base58 ix.data)); ("stackHeight", opt int ix.height) ] in
  match keys with
  | None -> OObj (("programIdIndex", int ix.program) :: ("accounts", byte_list ix.accounts) :: common)
  | Some ks ->
    let addr i = if i < Array.length ks then str ks.(i) else fail "instruction account index out of range" in
    let program = addr ix.program in
    let accounts = List.init (String.length ix.accounts) (fun i -> addr (Char.code ix.accounts.[i])) in
    OObj (("programId", program) :: ("accounts", OArr accounts) :: common)

let account_objects (tx : tx) (lw, lr) =
  let w, r = if tx.version = V0 then (lw, lr) else ([], []) in
  let keys = tx.keys @ w @ r in
  let ns = List.length tx.keys and nw = List.length w in
  let programs = List.map (fun (ix : instruction) -> ix.program) tx.instructions in
  let upg = List.mem upgradeable keys in
  List.mapi (fun i key ->
      let lookup = i >= ns in
      let can_write =
        if lookup then i - ns < nw else if i < tx.nrs then i < tx.nrs - tx.nros else i < ns - tx.nrou in
      let writable = can_write && not (Hashtbl.mem reserved key) && (upg || not (List.mem i programs)) in
      (key, OObj [ ("pubkey", str key); ("writable", OBool writable); ("signer", OBool (i < tx.nrs));
                   ("source", str (if lookup then "lookupTable" else "transaction")) ])) keys

type opts = { encoding : string; details : string; rewards_on : bool; max_version : int option }

let meta_json (m : Meta.meta) o keys =
  let parsed = o.encoding = "jsonParsed" and accounts_only = o.details = "accounts" in
  let tokens = opt (fun l -> OArr (List.map token_json l)) in
  let base = [
    ("err", opt err_json m.err);
    ("status", match m.err with None -> OObj [ ("Ok", ONull) ] | Some e -> OObj [ ("Err", err_json e) ]);
    ("fee", u64 m.fee);
    ("preBalances", OArr (List.map u64 m.pre_balances));
    ("postBalances", OArr (List.map u64 m.post_balances));
    ("preTokenBalances", tokens m.pre_tokens);
    ("postTokenBalances", tokens m.post_tokens) ] in
  let rewards =
    if o.rewards_on then [ ("rewards", opt (fun l -> OArr (List.map reward_json l)) m.rewards) ]
    else if accounts_only then [] else [ ("rewards", ONull) ] in
  let extra =
    if accounts_only then []
    else
      [ ("innerInstructions", opt (fun groups ->
            OArr (List.map (fun (index, ixs) ->
                OObj [ ("index", int index); ("instructions", OArr (List.map (fun ix -> instruction_json ix keys) ixs)) ])
                groups)) m.inner);
        ("logMessages", opt (fun l -> OArr (List.map str l)) m.logs) ]
      @ (if parsed then []
         else [ ("loadedAddresses", OObj [ ("writable", OArr (List.map str m.loaded_writable));
                                            ("readonly", OArr (List.map str m.loaded_readonly)) ]) ])
      @ (match m.return_data with
          | Some (p, d) -> [ ("returnData", OObj [ ("programId", str p); ("data", OArr [ str (base64 d); str "base64" ]) ]) ]
          | None -> [])
      @ (match m.compute_units with Some v -> [ ("computeUnitsConsumed", u64 v) ] | None -> [])
      @ (match m.cost_units with Some v -> [ ("costUnits", u64 v) ] | None -> []) in
  OObj (base @ rewards @ extra)

let unsupported_version v =
  Rpc (-32015, Printf.sprintf "Transaction version (%d) is not supported by the requesting client. Please try the request again with the following configuration parameter: \"maxSupportedTransactionVersion\": %d" v v)

let transaction_json (tx : tx) (meta : Meta.meta option) o =
  let numeric_version = match tx.version with Legacy -> None | V0 -> Some 0 | V1 _ -> Some 1 in
  let meta = match numeric_version with
    | None -> meta
    | Some v ->
        if Option.value o.max_version ~default:(-1) < v then raise (unsupported_version v);
        Some (Option.value meta ~default:Meta.empty_meta) in
  let parsed = o.encoding = "jsonParsed" and accounts_only = o.details = "accounts" in
  let loaded = match meta with Some m -> (m.loaded_writable, m.loaded_readonly) | None -> ([], []) in
  let keys = ref None in
  let transaction =
    match o.encoding with
    | "base64" -> OArr [ str (base64 tx.raw); str "base64" ]
    | "base58" -> OArr [ str (base58 tx.raw); str "base58" ]
    | _ ->
      let signatures = ("signatures", OArr (List.map (fun s -> str (base58 s)) tx.signatures)) in
      let objects = if parsed || accounts_only then Some (account_objects tx loaded) else None in
      if parsed then keys := Option.map (fun l -> Array.of_list (List.map fst l)) objects;
      let account_keys = match objects with
        | Some l -> OArr (List.map snd l)
        | None -> OArr (List.map str tx.keys) in
      if accounts_only then OObj [ signatures; ("accountKeys", account_keys) ]
      else begin
        let header =
          if parsed then []
          else [ ("header", OObj [ ("numRequiredSignatures", int tx.nrs); ("numReadonlySignedAccounts", int tx.nros);
                                   ("numReadonlyUnsignedAccounts", int tx.nrou) ]) ] in
        let instructions = List.map (fun ix -> instruction_json ix !keys) tx.instructions in
        let version_fields =
          match tx.version with
          | V0 ->
            [ ("addressTableLookups", OArr (List.map (fun l ->
                  OObj [ ("accountKey", str (base58 l.table)); ("writableIndexes", byte_list l.writable);
                         ("readonlyIndexes", byte_list l.readonly) ]) tx.lookups)) ]
          | V1 config ->
            [ ("transactionConfig", OObj [
                ("priorityFee", opt Json.u64 config.priority_fee);
                ("computeUnitLimit", opt int config.compute_unit_limit);
                ("loadedAccountsDataSizeLimit", opt int config.loaded_accounts_data_size_limit);
                ("heapSize", opt int config.heap_size) ]) ]
          | Legacy -> [] in
        OObj [ signatures; ("message", OObj (header @ [ ("accountKeys", account_keys); ("recentBlockhash", str tx.recent);
                                                        ("instructions", OArr instructions) ] @ version_fields)) ]
      end in
  let meta_out = match meta with None -> ONull | Some m -> meta_json m o !keys in
  let version =
    match meta, o.max_version with
    | Some _, Some _ -> [ ("version", match numeric_version with None -> str "legacy" | Some v -> int v) ]
    | _ -> [] in
  OObj ([ ("transaction", transaction); ("meta", meta_out) ] @ version)

let get_block slot o =
  let car = load_block slot in
  if as_u64 (at car.block 1) <> Some slot then fail "Block slot differs from requested slot";
  let entries = links (at car.block 3) in
  let info = match at car.block 4 with Some (A a) -> a | _ -> [||] in
  let parent = Option.value (as_u64 (at info 0)) ~default:0L in
  let blockhash = block_hash slot car entries in
  let previous = previous_hash slot parent in
  let details =
    if o.details = "none" then []
    else begin
      let items = List.concat_map (fun key ->
          let entry = node car key 1 in
          (match at entry 2 with Some (B h) when String.length h = 32 -> () | _ -> fail "invalid Entry hash");
          List.map (fun tx_key ->
              let n = node car tx_key 0 in
              let data = match at n 1 with Some v -> v | None -> fail "transaction node has no data frame" in
              let tx = transaction (frame_payload car data) in
              if o.details = "signatures" then
                (match tx.signatures with s :: _ -> str (base58 s) | [] -> fail "transaction has no signature")
              else begin
                let meta = match at n 2 with
                  | Some (A _ as frame) -> Meta.metadata slot (frame_payload car frame)
                  | _ -> None in
                transaction_json tx meta o
              end) (links (at entry 3))) entries in
      [ ((if o.details = "signatures" then "signatures" else "transactions"), OArr items) ]
    end in
  let rewards =
    if not o.rewards_on then []
    else begin
      let data =
        match at car.block 5 with
        | Some (B _ as v) ->
          let key, absent = link v in
          if absent || not (mem car key) then ""
          else (match at (node car key 5) 2 with Some f -> frame_payload car f | None -> "")
        | _ -> "" in
      let list, partitions = Meta.rewards slot data in
      ("rewards", OArr (List.map reward_json list))
      :: (match partitions with Some p -> [ ("numRewardPartitions", u64 p) ] | None -> [])
    end in
  let block_time = match as_i64 (at info 1) with None | Some 0L -> ONull | Some t -> i64 t in
  OObj ([ ("previousBlockhash", str previous); ("blockhash", str blockhash); ("parentSlot", u64 parent) ]
        @ details @ rewards
        @ [ ("blockTime", block_time); ("blockHeight", opt u64 (as_u64 (at info 2))) ])

(* ---- JSON-RPC 2.0 ------------------------------------------------------- *)

let invalid_params () = raise (Rpc (-32602, "Invalid params"))

(* A JSON integer literal 0|[1-9][0-9]* within 0..max (unsigned). *)
let uint_param v max =
  match v with
  | Num t when (t = "0" || (t.[0] >= '1' && t.[0] <= '9' && String.length t <= 20
                             && String.for_all (fun c -> c >= '0' && c <= '9') t)) ->
    (match Meta.unsigned_text ~max t with Some n -> n | None -> invalid_params ())
  | _ -> invalid_params ()

let block_params params =
  let items = match params with Some (Arr l) when List.length l >= 1 && List.length l <= 2 -> l | _ -> invalid_params () in
  let slot = uint_param (List.hd items) (-1L) in
  let config =
    match List.nth_opt items 1 with
    | None | Some Null -> []
    | Some (Str s) -> [ ("encoding", Str s) ]
    | Some (Obj kvs) -> kvs
    | Some _ -> invalid_params () in
  let field k = match List.assoc_opt k config with None | Some Null -> None | Some v -> Some v in
  let choice k default allowed =
    match field k with
    | None -> default
    | Some (Str s) when List.mem s allowed -> s
    | Some _ -> invalid_params () in
  let encoding = choice "encoding" "json" [ "json"; "jsonParsed"; "base64"; "base58" ] in
  let details = choice "transactionDetails" "full" [ "full"; "accounts"; "signatures"; "none" ] in
  let rewards_on = match field "rewards" with None -> true | Some (Bool b) -> b | Some _ -> invalid_params () in
  ignore (choice "commitment" "finalized" [ "finalized"; "confirmed" ]);
  let max_version = Option.map (fun v -> Int64.to_int (uint_param v 255L)) (field "maxSupportedTransactionVersion") in
  if encoding = "base58" && Option.value max_version ~default:0 >= 1 then
    raise (Rpc (-32602, "base58 encoding is not supported with maxSupportedTransactionVersion >= 1"));
  if details = "accounts" && encoding <> "json" then invalid_params ();
  (slot, { encoding; details; rewards_on; max_version })

let id_json = function Some (Num t) -> ORaw t | Some (Str s) -> OStr s | _ -> ONull

let render v = let b = Buffer.create 4096 in write b v; Buffer.contents b

let response id field value = render (OObj [ ("jsonrpc", str "2.0"); (field, value); ("id", id_json id) ])
let error id code message = response id "error" (OObj [ ("code", int code); ("message", str message) ])

let dispatch request =
  match request with
  | Obj kvs ->
    let get k = List.assoc_opt k kvs in
    let version = get "jsonrpc" and meth = get "method" and id = get "id" in
    let text_or_null = function None | Some Null | Some (Str _) -> true | _ -> false in
    if not (text_or_null version && text_or_null meth
            && (match id with None | Some Null | Some (Str _) | Some (Num _) -> true | _ -> false)) then
      error None (-32600) "Invalid Request"
    else if version <> Some (Str "2.0") then error id (-32600) "Invalid Request"
    else begin
      match meth with
      | None | Some Null -> error id (-32600) "Invalid Request"
      | Some m ->
        let m = match m with Str s -> s | _ -> "" in
        (try
           match m with
           | "getHealth" ->
             (match get "params" with
              | None | Some Null | Some (Arr []) -> response id "result" (str "ok")
              | Some _ -> raise (Rpc (-32602, "Invalid params: getHealth takes no parameters")))
           | "getBlock" ->
             let slot, o = block_params (get "params") in
             response id "result" (get_block slot o)
           | _ -> raise (Rpc (-32601, "Method not found: " ^ m))
         with
         | Rpc (code, message) -> error id code message
         | Decode message | Http.Fatal message | Zstd.Error message -> error id (-32603) ("Internal error: " ^ message)
         | Stack_overflow | Out_of_memory -> error id (-32603) "Internal error: resource limit"
         | e -> error id (-32603) ("Internal error: " ^ Printexc.to_string e))
    end
  | _ -> error None (-32600) "Invalid Request"

let rpc body =
  match Json.parse body with
  | exception (Parse_error | Stack_overflow) -> error None (-32700) "Parse error"
  | Arr items ->
    let n = List.length items in
    if n = 0 || n > 100 then error None (-32600) "Invalid Request: batch must hold 1 to 100 requests"
    else "[" ^ String.concat "," (List.map dispatch items) ^ "]"
  | v -> dispatch v

(* ---- server --------------------------------------------------------------- *)

let handle fd =
  (try
     match Http.read_request fd with
     | "POST", "/", body -> Http.respond fd 200 "OK" (rpc body)
     | "POST", _, _ -> Http.respond fd 404 "Not Found" ~content_type:false ""
     | _ -> Http.respond fd 405 "Method Not Allowed" ~content_type:false ""
   with
   | Http.Too_large -> (try Http.respond fd 413 "Payload Too Large" ~content_type:false ""; Http.drain fd with _ -> ())
   | Http.Bad_request -> (try Http.respond fd 400 "Bad Request" ~content_type:false "" with _ -> ())
   | _ -> ());
  try Unix.close fd with _ -> ()

let usage () = prerr_endline "usage: onlyblocks [--bind HOST:PORT] [--base-url URL]"; exit 2

let () =
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  Random.self_init ();
  let bind = ref (Option.value (Sys.getenv_opt "ONLYBLOCKS_BIND") ~default:"127.0.0.1:8899") in
  let url = ref (Option.value (Sys.getenv_opt "OLD_FAITHFUL_BASE_URL") ~default:"https://files.old-faithful.net") in
  let rec args = function
    | [] -> ()
    | ("--bind" | "--base-url") :: [] -> usage ()
    | "--bind" :: v :: rest -> bind := v; args rest
    | "--base-url" :: v :: rest -> url := v; args rest
    | a :: rest when String.starts_with ~prefix:"--bind=" a -> bind := String.sub a 7 (String.length a - 7); args rest
    | a :: rest when String.starts_with ~prefix:"--base-url=" a -> url := String.sub a 11 (String.length a - 11); args rest
    | a :: _ -> Printf.eprintf "unknown argument: %s\n" a; usage () in
  args (List.tl (Array.to_list Sys.argv));
  (try base := Http.parse_base_url !url
   with Failure m -> Printf.eprintf "invalid --base-url %S: %s\n" !url m; exit 2);
  let host, port =
    match String.rindex_opt !bind ':' with
    | Some i ->
      let h = String.sub !bind 0 i and p = String.sub !bind (i + 1) (String.length !bind - i - 1) in
      let h = if String.length h >= 2 && h.[0] = '[' && h.[String.length h - 1] = ']'
        then String.sub h 1 (String.length h - 2) else h in
      (h, p)
    | None -> Printf.eprintf "invalid --bind %S\n" !bind; exit 2 in
  let ai =
    match Unix.getaddrinfo host port [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM; Unix.AI_PASSIVE ] with
    | a :: _ -> a
    | [] -> Printf.eprintf "cannot resolve bind address %S\n" !bind; exit 2 in
  let sock = Unix.socket ~cloexec:true ai.Unix.ai_family Unix.SOCK_STREAM 0 in
  Unix.setsockopt sock Unix.SO_REUSEADDR true;
  (try Unix.bind sock ai.Unix.ai_addr; Unix.listen sock 1024
   with Unix.Unix_error (e, _, _) -> Printf.eprintf "cannot listen on %s: %s\n" !bind (Unix.error_message e); exit 1);
  (* Signals are taken synchronously by one dedicated thread.  A background
     job may inherit SIGINT as ignored, which would hide it from sigwait. *)
  List.iter (fun s -> Sys.set_signal s (Sys.Signal_handle (fun _ -> exit 0))) [ Sys.sigint; Sys.sigterm ];
  ignore (Thread.sigmask Unix.SIG_BLOCK [ Sys.sigint; Sys.sigterm ]);
  ignore (Thread.create (fun () ->
      ignore (Thread.wait_signal [ Sys.sigint; Sys.sigterm ]);
      (try Unix.close sock with _ -> ());
      exit 0) ());
  Printf.printf "onlyblocks/ocaml listening on %s (archive %s)\n%!" !bind !base.Http.url;
  while true do
    match Unix.accept ~cloexec:true sock with
    | fd, _ -> ignore (Thread.create handle fd)
    | exception Unix.Unix_error ((Unix.EINTR | Unix.ECONNABORTED | Unix.EAGAIN), _, _) -> ()
    | exception Unix.Unix_error ((Unix.EMFILE | Unix.ENFILE | Unix.ENOBUFS | Unix.ENOMEM), _, _) -> Thread.delay 0.05
    | exception Unix.Unix_error (Unix.EBADF, _, _) -> Thread.delay 1.0
  done
