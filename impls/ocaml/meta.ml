(* Transaction metadata and block rewards: protobuf (modern), bincode
   (pre-epoch-157), TransactionError, and the zstd/epoch-157 frame unwrapping. *)

open Wire

(* ---- internal data model (WIRE_FORMATS.md section 12) ------------------- *)

type reward = {
  pubkey : string; lamports : int64; post_balance : int64;
  reward_type : string option; commission : int option;
}

type token_balance = {
  account_index : int; mint : string; owner : string; program_id : string;
  ui_amount : float option; decimals : int; amount : string; ui_amount_string : string;
}

(* A TransactionError already rendered as a tiny JSON tree. *)
type err = EStr of string | EObj of string * err | EArr of err list | EInt of int

type meta = {
  err : err option;
  fee : int64;
  pre_balances : int64 list; post_balances : int64 list;
  inner : (int * instruction list) list option;
  logs : string list option;
  pre_tokens : token_balance list option; post_tokens : token_balance list option;
  rewards : reward list option;
  loaded_writable : string list; loaded_readonly : string list;   (* Base58 *)
  return_data : (string * string) option;                          (* Base58 program, raw data *)
  compute_units : int64 option; cost_units : int64 option;
}

let empty_meta = {
  err = None; fee = 0L; pre_balances = []; post_balances = []; inner = None; logs = None;
  pre_tokens = None; post_tokens = None; rewards = None; loaded_writable = []; loaded_readonly = [];
  return_data = None; compute_units = None; cost_units = None;
}

let cutoff = Int64.of_int (157 * 432000)

(* ---- TransactionError (bincode enum) ------------------------------------ *)

let instruction_errors = [|
  "GenericError"; "InvalidArgument"; "InvalidInstructionData"; "InvalidAccountData"; "AccountDataTooSmall";
  "InsufficientFunds"; "IncorrectProgramId"; "MissingRequiredSignature"; "AccountAlreadyInitialized";
  "UninitializedAccount"; "UnbalancedInstruction"; "ModifiedProgramId"; "ExternalAccountLamportSpend";
  "ExternalAccountDataModified"; "ReadonlyLamportChange"; "ReadonlyDataModified"; "DuplicateAccountIndex";
  "ExecutableModified"; "RentEpochModified"; "NotEnoughAccountKeys"; "AccountDataSizeChanged";
  "AccountNotExecutable"; "AccountBorrowFailed"; "AccountBorrowOutstanding"; "DuplicateAccountOutOfSync";
  "Custom"; "InvalidError"; "ExecutableDataModified"; "ExecutableLamportChange";
  "ExecutableAccountNotRentExempt"; "UnsupportedProgramId"; "CallDepth"; "MissingAccount";
  "ReentrancyNotAllowed"; "MaxSeedLengthExceeded"; "InvalidSeeds"; "InvalidRealloc";
  "ComputationalBudgetExceeded"; "PrivilegeEscalation"; "ProgramEnvironmentSetupFailure";
  "ProgramFailedToComplete"; "ProgramFailedToCompile"; "Immutable"; "IncorrectAuthority"; "BorshIoError";
  "AccountNotRentExempt"; "InvalidAccountOwner"; "ArithmeticOverflow"; "UnsupportedSysvar"; "IllegalOwner";
  "MaxAccountsDataAllocationsExceeded"; "MaxAccountsExceeded"; "MaxInstructionTraceLengthExceeded";
  "BuiltinProgramsMustConsumeComputeUnits" |]

let transaction_errors = [|
  "AccountInUse"; "AccountLoadedTwice"; "AccountNotFound"; "ProgramAccountNotFound"; "InsufficientFundsForFee";
  "InvalidAccountForFee"; "AlreadyProcessed"; "BlockhashNotFound"; "InstructionError"; "CallChainTooDeep";
  "MissingSignatureForFee"; "InvalidAccountIndex"; "SignatureFailure"; "InvalidProgramForExecution";
  "SanitizeFailure"; "ClusterMaintenance"; "AccountBorrowOutstanding"; "WouldExceedMaxBlockCostLimit";
  "UnsupportedVersion"; "InvalidWritableAccount"; "WouldExceedMaxAccountCostLimit";
  "WouldExceedAccountDataBlockLimit"; "TooManyAccountLocks"; "AddressLookupTableNotFound";
  "InvalidAddressLookupTableOwner"; "InvalidAddressLookupTableData"; "InvalidAddressLookupTableIndex";
  "InvalidRentPayingAccount"; "WouldExceedMaxVoteCostLimit"; "WouldExceedAccountDataTotalLimit";
  "DuplicateInstruction"; "InsufficientFundsForRent"; "MaxLoadedAccountsDataSizeExceeded";
  "InvalidLoadedAccountsDataSizeLimit"; "ResanitizationNeeded"; "ProgramExecutionTemporarilyRestricted";
  "UnbalancedTransaction"; "ProgramCacheHitMaxLimit"; "CommitCancelled" |]

let transaction_error r =
  let variant = u32 r in
  if variant >= Array.length transaction_errors then fail "unknown TransactionError variant";
  let name = transaction_errors.(variant) in
  match variant with
  | 8 ->
    let index = u8 r in
    let k = u32 r in
    if k >= Array.length instruction_errors then fail "unknown InstructionError variant";
    let inner = if k = 25 then EObj ("Custom", EInt (u32 r)) else EStr instruction_errors.(k) in
    EObj (name, EArr [ EInt index; inner ])
  | 30 -> EObj (name, EInt (u8 r))
  | 31 | 35 -> EObj (name, EObj ("account_index", EInt (u8 r)))
  | _ -> EStr name

(* ---- shared helpers ----------------------------------------------------- *)

(* Rust u64::from_str-style: optional '+', ASCII digits, must fit [max]. *)
let unsigned_text ?(max = -1L) text =
  let n = String.length text in
  let start = if n > 0 && text.[0] = '+' then 1 else 0 in
  if n = start then None
  else begin
    let ok = ref true and v = ref 0L and overflow = ref false in
    for i = start to n - 1 do
      let c = text.[i] in
      if c < '0' || c > '9' then ok := false
      else begin
        let d = Int64.of_int (Char.code c - 48) in
        (* v * 10 + d must not exceed 2^64-1 *)
        if ucmp !v (Int64.unsigned_div (Int64.sub (-1L) d) 10L) > 0 then overflow := true;
        v := Int64.add (Int64.mul !v 10L) d
      end
    done;
    if not !ok || !overflow || ucmp !v max > 0 then None else Some !v
  end

(* real_number_string_trimmed *)
let ui_amount_string amount decimals =
  let digits = u64_string (match unsigned_text amount with Some v -> v | None -> 0L) in
  if decimals = 0 then digits
  else begin
    let padded =
      if String.length digits <= decimals then String.make (decimals + 1 - String.length digits) '0' ^ digits
      else digits in
    let cut = String.length padded - decimals in
    let s = String.sub padded 0 cut ^ "." ^ String.sub padded cut decimals in
    let e = ref (String.length s) in
    while !e > 0 && s.[!e - 1] = '0' do decr e done;
    if !e > 0 && s.[!e - 1] = '.' then decr e;
    String.sub s 0 !e
  end

let token_balance ?(owner = "") ?(program_id = "") ?(display = "") account_index mint ui decimals amount =
  let ui_amount_string = if display <> "" then display else ui_amount_string amount decimals in
  { account_index; mint; owner; program_id; ui_amount = ui; decimals; amount; ui_amount_string }

let reward_types = [| "Fee"; "Rent"; "Staking"; "Voting" |]

(* ---- protobuf wire format ----------------------------------------------- *)

type wv = Varint of int64 | Fixed64 of int64 | Len of string | Fixed32

let proto_key r =
  let key = uvarint r in
  if ucmp key 8L < 0 || ucmp key 0xFFFFFFFFL > 0 then fail "invalid protobuf key";
  let key = Int64.to_int key in
  (key lsr 3, key land 7)

let rec skip_group r field depth =
  if depth > 100 then fail "protobuf group nesting limit";
  let tag, wire = proto_key r in
  if wire = 4 then (if tag <> field then fail "mismatched protobuf group")
  else (skip_value r tag wire depth; skip_group r field depth)

and skip_value r tag wire depth =
  match wire with
  | 0 -> ignore (uvarint r)
  | 1 -> skip r 8
  | 2 -> skip r (small (uvarint r))
  | 3 -> skip_group r tag (depth + 1)
  | 5 -> skip r 4
  | _ -> fail "invalid protobuf wire type"

(* Field descriptors: V varint, D double, L length-delimited, P repeated varint
   (packed or not).  Unknown fields are skipped; known fields must match. *)
type fk = V | D | L | P

let fields (schema : (int * fk) list) (data : string) : (int * wv) list =
  let r = reader data in
  let out = ref [] in
  while left r > 0 do
    let field, wire = proto_key r in
    match List.assoc_opt field schema with
    | None -> skip_value r field wire 0
    | Some k ->
      let v =
        match k, wire with
        | (V | P), 0 -> Varint (uvarint r)
        | D, 1 -> Fixed64 (u64 r)
        | (L | P), 2 -> Len (take r (small (uvarint r)))
        | _ -> fail "wrong protobuf wire type" in
      out := (field, v) :: !out
  done;
  List.rev !out

let last_varint fs n =
  List.fold_left (fun acc (f, v) -> match v with Varint x when f = n -> Some x | _ -> acc) None fs
let last_double fs n =
  List.fold_left (fun acc (f, v) -> match v with Fixed64 x when f = n -> Some (Int64.float_of_bits x) | _ -> acc) None fs
let all_len fs n = List.filter_map (fun (f, v) -> match v with Len s when f = n -> Some s | _ -> None) fs
let last_len fs n = List.fold_left (fun _ s -> Some s) None (all_len fs n)
let utf8 s = if String.is_valid_utf_8 s then s else fail "invalid UTF-8 in protobuf string"
let strings fs n = List.map utf8 (all_len fs n)
let last_string fs n = List.fold_left (fun _ s -> s) "" (strings fs n)
(* A non-repeated message seen several times merges: concatenation does exactly that. *)
let message fs n = match all_len fs n with [] -> None | parts -> Some (String.concat "" parts)
let packed fs n =
  List.concat_map (fun (f, v) ->
    if f <> n then []
    else match v with
      | Varint x -> [ x ]
      | Len s -> let r = reader s in let l = ref [] in while left r > 0 do l := uvarint r :: !l done; List.rev !l
      | _ -> []) fs
let bool_field fs n = match last_varint fs n with Some v -> v <> 0L | None -> false

(* ---- protobuf parse (pure wire level; conversion errors happen later) ---- *)

type p_reward = { pk : string; lam : int64; post : int64; rtype : int64; comm : string; bps : string }

let p_reward data =
  let fs = fields [ (1, L); (2, V); (3, V); (4, V); (5, L); (6, L) ] data in
  { pk = last_string fs 1; lam = Option.value (last_varint fs 2) ~default:0L;
    post = Option.value (last_varint fs 3) ~default:0L; rtype = Option.value (last_varint fs 4) ~default:0L;
    comm = last_string fs 5; bps = last_string fs 6 }

let convert_reward p =
  let commission =
    match unsigned_text ~max:255L p.comm with
    | Some c -> Some (Int64.to_int c)
    | None ->
      match unsigned_text ~max:65535L p.bps with
      | Some b when Int64.to_int b / 100 <= 255 -> Some (Int64.to_int b / 100)
      | _ -> None in
  let k = Int64.to_int (Int64.logand p.rtype 0xFFFFFFFFL) in
  { pubkey = p.pk; lamports = p.lam; post_balance = p.post;
    reward_type = (if k >= 1 && k <= 4 then Some reward_types.(k - 1) else None); commission }

let p_token data =
  let fs = fields [ (1, V); (2, L); (3, L); (4, L); (5, L) ] data in
  let amount_fs = match message fs 3 with Some m -> fields [ (1, D); (2, V); (3, L); (4, L) ] m | None -> [] in
  let ui = Option.value (last_double amount_fs 1) ~default:0.0 in
  let decimals = Int64.to_int (Int64.logand (Option.value (last_varint amount_fs 2) ~default:0L) 0xFFL) in
  token_balance
    (Int64.to_int (Int64.logand (Option.value (last_varint fs 1) ~default:0L) 0xFFL))
    (last_string fs 2)
    (if Float.abs ui > epsilon_float then Some ui else None)
    decimals (last_string amount_fs 3)
    ~owner:(last_string fs 4) ~program_id:(last_string fs 5) ~display:(last_string amount_fs 4)

let p_inner_instruction data =
  let fs = fields [ (1, V); (2, L); (3, L); (4, V) ] data in
  { program = Int64.to_int (Int64.logand (Option.value (last_varint fs 1) ~default:0L) 0xFFL);
    accounts = Option.value (last_len fs 2) ~default:"";
    data = Option.value (last_len fs 3) ~default:"";
    height = Option.map (fun h -> Int64.to_int (Int64.logand h 0xFFFFFFFFL)) (last_varint fs 4) }

let p_inner data =
  let fs = fields [ (1, V); (2, L) ] data in
  (Int64.to_int (Int64.logand (Option.value (last_varint fs 1) ~default:0L) 0xFFL),
   List.map p_inner_instruction (all_len fs 2))

let meta_schema =
  [ (1, L); (2, V); (3, P); (4, P); (5, L); (6, L); (7, L); (8, L); (9, L); (10, V); (11, V);
    (12, L); (13, L); (14, L); (15, V); (16, V); (17, V) ]

(* Parse fully (raising on any wire-level problem) and return a thunk that
   performs the conversion, whose errors are final. *)
let proto_meta data : unit -> meta =
  let fs = fields meta_schema data in
  let err_bytes = Option.map (fun m -> Option.value (last_len (fields [ (1, L) ] m) 1) ~default:"") (message fs 1) in
  let inner = List.map p_inner (all_len fs 5) in
  let logs = strings fs 6 in
  let pre = List.map p_token (all_len fs 7) and post = List.map p_token (all_len fs 8) in
  let rewards = List.map p_reward (all_len fs 9) in
  let ret = Option.map (fun m -> let f = fields [ (1, L); (2, L) ] m in
                         (Option.value (last_len f 1) ~default:"", Option.value (last_len f 2) ~default:""))
      (message fs 14) in
  fun () ->
    { err = Option.map (fun b -> transaction_error (reader b)) err_bytes;
      fee = Option.value (last_varint fs 2) ~default:0L;
      pre_balances = packed fs 3; post_balances = packed fs 4;
      inner = (if bool_field fs 10 then None else Some inner);
      logs = (if bool_field fs 11 then None else Some logs);
      pre_tokens = Some pre; post_tokens = Some post;
      rewards = Some (List.map convert_reward rewards);
      loaded_writable = List.map pubkey (all_len fs 12);
      loaded_readonly = List.map pubkey (all_len fs 13);
      return_data = (if bool_field fs 15 then None
                     else Option.map (fun (p, d) -> (pubkey p, d)) ret);
      compute_units = last_varint fs 16; cost_units = last_varint fs 17 }

let proto_rewards data : unit -> reward list * int64 option =
  let fs = fields [ (1, L); (2, L) ] data in
  let rewards = List.map p_reward (all_len fs 1) in
  let parts = Option.map (fun m -> Option.value (last_varint (fields [ (1, V) ] m) 1) ~default:0L) (message fs 2) in
  fun () -> (List.map convert_reward rewards, parts)

(* ---- bincode (pre-epoch-157) -------------------------------------------- *)

let b_string r = let n = small (u64 r) in let s = take r n in if String.is_valid_utf_8 s then s else fail "invalid UTF-8"
let b_vec r minimum read = let n = u64 r in
  if ucmp n (Int64.of_int (left r / minimum)) > 0 then fail "count exceeds enclosing field";
  List.init (Int64.to_int n) (fun _ -> read ())
let b_option r read = match u8 r with 0 -> None | 1 -> Some (read ()) | _ -> fail "invalid bincode option"

let b_reward ?(extended = true) r =
  let pubkey = b_string r in
  let lamports = u64 r in
  let post_balance = if left r > 0 || not extended then u64 r else 0L in
  let reward_type =
    if left r > 0 || not extended then
      b_option r (fun () -> let i = u32 r in
                   if i >= 4 then fail "unknown RewardType" else reward_types.(i))
    else None in
  let commission = if left r > 0 && extended then b_option r (fun () -> u8 r) else None in
  { pubkey; lamports; post_balance; reward_type; commission }

(* layout: 1 = V1 (no owner/program), 2 = V2 (owner), 3 = StoredTokenBalance *)
let b_token r layout =
  let index = u8 r in
  let mint = b_string r in
  let ui = f64 r in
  let decimals = u8 r in
  let amount = b_string r in
  let owner = if layout >= 2 && left r > 0 then b_string r else "" in
  let program_id = if layout >= 3 && left r > 0 then b_string r else "" in
  token_balance index mint (Some ui) decimals amount ~owner ~program_id

let b_meta ?(legacy = false) ?(layout = 3) r =
  let status = u32 r in
  if status > 1 then fail "invalid bincode result tag";
  let err = if status = 1 then Some (transaction_error r) else None in
  let fee = u64 r in
  let pre_balances = b_vec r 8 (fun () -> u64 r) in
  let post_balances = b_vec r 8 (fun () -> u64 r) in
  (* EOF-default fields: once the input is exhausted, every later field is None. *)
  let eof_opt read = if left r = 0 then None else b_option r read in
  let inner_ix () =
    let ix = compiled r None in
    if legacy then ix else { ix with height = b_option r (fun () -> u32 r) } in
  let inner = eof_opt (fun () ->
      b_vec r 9 (fun () -> let index = u8 r in (index, b_vec r (if legacy then 3 else 4) inner_ix))) in
  let logs = eof_opt (fun () -> b_vec r 8 (fun () -> b_string r)) in
  let pre_tokens = eof_opt (fun () -> b_vec r 26 (fun () -> b_token r layout)) in
  let post_tokens = eof_opt (fun () -> b_vec r 26 (fun () -> b_token r layout)) in
  let rewards = eof_opt (fun () -> b_vec r 16 (fun () -> b_reward r)) in
  let return_data = eof_opt (fun () -> let p = pubkey (take r 32) in let d = take r (small (u64 r)) in (p, d)) in
  let compute_units = eof_opt (fun () -> u64 r) in
  let cost_units = eof_opt (fun () -> u64 r) in
  { empty_meta with err; fee; pre_balances; post_balances; inner; logs; pre_tokens; post_tokens; rewards;
                    return_data; compute_units; cost_units }

(* Try strict layouts in order, then fall back to the lenient first layout. *)
let bincode data (layouts : (reader -> 'a) list) =
  let rec go = function
    | [] -> (List.hd layouts) (reader data)
    | f :: rest ->
      let r = reader data in
      (match f r with
       | v when left r = 0 -> v
       | _ -> go rest
       | exception Decode _ -> go rest) in
  go layouts

let bincode_meta data =
  bincode data [ (fun r -> b_meta r); (fun r -> b_meta ~legacy:true ~layout:1 r);
                 (fun r -> b_meta ~legacy:true ~layout:2 r); (fun r -> b_meta ~legacy:true ~layout:3 r) ]

let bincode_rewards data =
  (bincode data [ (fun r -> b_vec r 16 (fun () -> b_reward r));
                  (fun r -> b_vec r 25 (fun () -> b_reward ~extended:false r)) ], None)

(* ---- frame unwrapping (WIRE_FORMATS.md section 9) ------------------------ *)

let decode_payload slot data proto stored =
  let pre157 = ucmp slot cutoff < 0 in
  let stored_ok = if pre157 then (try Some (stored data) with Decode _ -> None) else None in
  match stored_ok with
  | Some v -> v
  | None ->
    match proto data with
    | convert -> convert ()
    | exception (Decode _ as e) -> if pre157 then raise e else stored data

let unwrap slot data proto stored =
  let decode payload = decode_payload slot payload proto stored in
  if Zstd.is_frame data then
    decode (try Zstd.decompress data with Zstd.Error _ -> data)
  else
    try decode data
    with Decode _ as original ->
      match Zstd.decompress data with
      | plain -> decode plain
      | exception Zstd.Error _ -> raise original

let metadata slot data = if data = "" then None else Some (unwrap slot data proto_meta bincode_meta)
let rewards slot data = if data = "" then ([], None) else unwrap slot data proto_rewards bincode_rewards
