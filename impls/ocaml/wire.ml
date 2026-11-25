(* Byte-level decoders: CARv1, DAG-CBOR, CIDs, DataFrames (CRC-64/GO-ISO,
   FNV-1a), Base58/Base64 and the Solana VersionedTransaction wire format. *)

exception Decode of string

let fail m = raise (Decode m)

(* ---- a bounds-checked cursor over an immutable string ------------------- *)

type reader = { s : string; mutable pos : int; lim : int }

let reader ?(pos = 0) ?len s =
  let lim = match len with None -> String.length s | Some l -> pos + l in
  if pos < 0 || lim > String.length s || lim < pos then fail "bad slice";
  { s; pos; lim }

let left r = r.lim - r.pos
let need r n = if n < 0 || n > left r then fail "truncated binary value"
let u8 r = need r 1; let v = Char.code (String.unsafe_get r.s r.pos) in r.pos <- r.pos + 1; v
let skip r n = need r n; r.pos <- r.pos + n
let take r n = need r n; let v = String.sub r.s r.pos n in r.pos <- r.pos + n; v
let u32 r = need r 4; let v = Int32.to_int (String.get_int32_le r.s r.pos) land 0xFFFFFFFF in r.pos <- r.pos + 4; v
let u64 r = need r 8; let v = String.get_int64_le r.s r.pos in r.pos <- r.pos + 8; v
let f64 r = Int64.float_of_bits (u64 r)

(* Unsigned LEB128, at most 10 bytes, the 10th byte <= 1. *)
let uvarint r =
  let rec go i shift acc =
    let b = u8 r in
    if b < 0x80 then begin
      if i = 9 && b > 1 then fail "varint overflow";
      Int64.logor acc (Int64.shift_left (Int64.of_int b) shift)
    end else if i = 9 then fail "varint overflow"
    else go (i + 1) (shift + 7) (Int64.logor acc (Int64.shift_left (Int64.of_int (b land 0x7f)) shift))
  in
  go 0 0 0L

(* An unsigned 64-bit value as a non-negative OCaml int (lengths, counts). *)
let small v = if Int64.compare v 0L < 0 || Int64.compare v 0x3FFFFFFFFFFFFFFFL > 0 then fail "length too large" else Int64.to_int v

(* Solana compact-u16 (short_vec), strict canonical form. *)
let compact r =
  let b0 = u8 r in
  if b0 < 0x80 then b0
  else begin
    let b1 = u8 r in
    if b1 = 0 then fail "noncanonical compact-u16";
    if b1 < 0x80 then (b0 land 0x7f) lor (b1 lsl 7)
    else begin
      let b2 = u8 r in
      if b2 = 0 then fail "noncanonical compact-u16";
      if b2 > 3 then fail "compact-u16 overflow";
      (b0 land 0x7f) lor ((b1 land 0x7f) lsl 7) lor (b2 lsl 14)
    end
  end

(* Read [count] items, each at least [minimum] bytes long. *)
let items r count minimum read =
  if count > left r / minimum then fail "count exceeds enclosing field";
  List.init count (fun _ -> read ())

let ucmp = Int64.unsigned_compare
let u64_string v = Printf.sprintf "%Lu" v

(* ---- DAG-CBOR ----------------------------------------------------------- *)

type cbor =
  | U of int64                (* unsigned 0..2^64-1 *)
  | N of int64                (* negative: the value is -1 - n (n unsigned) *)
  | B of string
  | T of string
  | A of cbor array
  | M of (cbor * cbor) list
  | Bool of bool
  | Null
  | F of float

let half_to_float h =
  let s = if h land 0x8000 <> 0 then -1.0 else 1.0 in
  let e = (h lsr 10) land 0x1f and m = h land 0x3ff in
  if e = 0 then s *. Float.ldexp (float_of_int m) (-24)
  else if e = 31 then (if m = 0 then s *. Float.infinity else Float.nan)
  else s *. Float.ldexp (float_of_int (m + 1024)) (e - 25)

let cbor_argument r info =
  if info < 24 then Some (Int64.of_int info)
  else if info = 31 then None
  else if info > 27 then fail "reserved CBOR argument"
  else begin
    let n = 1 lsl (info - 24) in
    need r n;
    let v = ref 0L in
    for i = 0 to n - 1 do
      v := Int64.logor (Int64.shift_left !v 8) (Int64.of_int (Char.code r.s.[r.pos + i]))
    done;
    r.pos <- r.pos + n;
    Some !v
  end

let rec cbor_item r depth =
  if depth > 128 then fail "CBOR nesting limit";
  let head = u8 r in
  let major = head lsr 5 and info = head land 31 in
  if major = 7 then begin
    match info with
    | 20 -> Bool false | 21 -> Bool true | 22 | 23 -> Null
    | 25 -> need r 2; let v = String.get_uint16_be r.s r.pos in r.pos <- r.pos + 2; F (half_to_float v)
    | 26 -> need r 4; let v = String.get_int32_be r.s r.pos in r.pos <- r.pos + 4; F (Int32.float_of_bits v)
    | 27 -> need r 8; let v = String.get_int64_be r.s r.pos in r.pos <- r.pos + 8; F (Int64.float_of_bits v)
    | _ -> fail "unsupported CBOR simple value"
  end else begin
    let arg = cbor_argument r info in
    let definite () = match arg with Some a -> a | None -> fail "invalid indefinite CBOR item" in
    let more () = need r 1; Char.code r.s.[r.pos] <> 0xFF in
    match major with
    | 0 -> U (definite ())
    | 1 -> N (definite ())
    | 6 -> ignore (definite ()); cbor_item r (depth + 1)
    | 2 | 3 ->
      let str =
        match arg with
        | Some n -> take r (small n)
        | None ->
          let b = Buffer.create 64 in
          while more () do
            let h = u8 r in
            if h lsr 5 <> major || h land 31 = 31 then fail "invalid CBOR string chunk";
            match cbor_argument r (h land 31) with
            | Some n -> Buffer.add_string b (take r (small n))
            | None -> fail "invalid CBOR string chunk"
          done;
          skip r 1;
          Buffer.contents b in
      if major = 2 then B str
      else if String.is_valid_utf_8 str then T str
      else fail "invalid UTF-8 in CBOR text"
    | 4 ->
      (match arg with
       | Some n ->
         if ucmp n (Int64.of_int (left r)) > 0 then fail "CBOR count exceeds enclosing field";
         let n = Int64.to_int n in
         let a = Array.make n Null in
         for i = 0 to n - 1 do a.(i) <- cbor_item r (depth + 1) done;
         A a
       | None ->
         let l = ref [] in
         while more () do l := cbor_item r (depth + 1) :: !l done;
         skip r 1;
         A (Array.of_list (List.rev !l)))
    | _ ->
      (match arg with
       | Some n ->
         if ucmp n (Int64.of_int (left r / 2)) > 0 then fail "CBOR count exceeds enclosing field";
         M (List.init (Int64.to_int n) (fun _ ->
             let k = cbor_item r (depth + 1) in
             let v = cbor_item r (depth + 1) in (k, v)))
       | None ->
         let l = ref [] in
         while more () do
           let k = cbor_item r (depth + 1) in
           let v = cbor_item r (depth + 1) in
           l := (k, v) :: !l
         done;
         skip r 1;
         M (List.rev !l))
  end

(* Exactly one CBOR data item, no trailing bytes. *)
let cbor_of ?(pos = 0) ?len s =
  let r = reader ~pos ?len s in
  let v = cbor_item r 0 in
  if left r <> 0 then fail "trailing CBOR bytes";
  v

let at (a : cbor array) i = if i < Array.length a then Some a.(i) else None
let as_u64 = function Some (U n) -> Some n | _ -> None
let as_i64 = function
  | Some (U n) when Int64.compare n 0L >= 0 -> Some n
  | Some (N n) when Int64.compare n 0L >= 0 -> Some (Int64.sub (-1L) n)
  | _ -> None

(* ---- CIDs and links ----------------------------------------------------- *)

(* Parse a CID at the reader; returns (raw CID bytes, is-empty-identity). *)
let cid r =
  let start = r.pos in
  let a = uvarint r in
  let b = uvarint r in
  if a = 0x12L && b = 0x20L then (skip r 32; (String.sub r.s start (r.pos - start), false))
  else begin
    if a <> 1L then fail "unsupported CID version";
    let code = uvarint r in
    let len = uvarint r in
    if ucmp len 64L > 0 then fail "CID digest too long";
    skip r (Int64.to_int len);
    (String.sub r.s start (r.pos - start), code = 0L && len = 0L)
  end

let link = function
  | B s when String.length s > 0 && s.[0] = '\000' -> cid (reader ~pos:1 s)
  | _ -> fail "invalid CID link"

let links = function
  | Some (A items) -> Array.to_list (Array.map (fun v -> fst (link v)) items)
  | _ -> []

(* ---- CARv1 section stream ----------------------------------------------- *)

type car = { slice : string; index : (string, int * int) Hashtbl.t; block : cbor array }

let kind n = function
  | A a when Array.length a > 0 && as_u64 (Some a.(0)) = Some (Int64.of_int n) -> a
  | _ -> fail (Printf.sprintf "expected IPLD node kind %d" n)

let mem car key = Hashtbl.mem car.index key

let node car key n =
  match Hashtbl.find_opt car.index key with
  | None -> fail "CID missing from CAR slice"
  | Some (pos, len) -> kind n (cbor_of ~pos ~len car.slice)

let is_version_header s pos len =
  match cbor_of ~pos ~len s with
  | M kvs -> List.exists (fun (k, _) -> k = T "version") kvs
  | _ -> false
  | exception Decode _ -> false

let index_car (slice : string) : car =
  let r = reader slice in
  let index = Hashtbl.create 64 in
  let block = ref None and first = ref true in
  while left r > 0 do
    let size = uvarint r in
    if size <> 0L then begin
      if ucmp size 33554432L > 0 then fail "oversize CAR section";
      let size = Int64.to_int size in
      need r size;
      let start = r.pos in
      r.pos <- r.pos + size;
      let header = !first && Char.code slice.[start] lsr 5 = 5 && is_version_header slice start size in
      first := false;
      if not header then begin
        let sr = reader ~pos:start ~len:size slice in
        let key, _ = cid sr in
        let npos = sr.pos and nlen = sr.lim - sr.pos in
        Hashtbl.replace index key (npos, nlen);
        if nlen > 0 then begin
          let b = Char.code slice.[npos] in
          let info = b land 31 in
          if b lsr 5 = 4 && (info < 28 || info = 31) then begin
            let head = if info < 24 || info = 31 then 1 else 1 + (1 lsl (info - 24)) in
            if head < nlen && slice.[npos + head] = '\002' then block := Some (npos, nlen)
          end
        end
      end
    end
  done;
  match !block with
  | None -> fail "no Block node in CAR slice"
  | Some (pos, len) -> { slice; index; block = kind 2 (cbor_of ~pos ~len slice) }

(* ---- DataFrames --------------------------------------------------------- *)

let crc_table =
  Array.init 256 (fun i ->
    let v = ref (Int64.of_int i) in
    for _ = 1 to 8 do
      v := if Int64.logand !v 1L = 1L then Int64.logxor (Int64.shift_right_logical !v 1) 0xD800000000000000L
           else Int64.shift_right_logical !v 1
    done; !v)

let crc64 s =
  let c = ref (-1L) in
  String.iter (fun ch ->
    let i = (Int64.to_int (Int64.logand !c 0xFFL)) lxor Char.code ch in
    c := Int64.logxor (Int64.shift_right_logical !c 8) crc_table.(i)) s;
  Int64.lognot !c

let fnv1a s =
  let h = ref 0xCBF29CE484222325L in
  String.iter (fun ch -> h := Int64.mul (Int64.logxor !h (Int64.of_int (Char.code ch))) 0x100000001B3L) s;
  !h

let frame_data a = match at a 4 with Some (B s) -> s | _ -> ""

(* Iterative DFS reassembly of a DataFrame chain; verifies the first hash. *)
let frame_payload car (root : cbor) =
  let root = kind 6 root in
  let b = Buffer.create (String.length (frame_data root)) in
  Buffer.add_string b (frame_data root);
  let seen = Hashtbl.create 8 in
  let stack = ref (links (at root 5)) in
  while !stack <> [] do
    let key = List.hd !stack in
    stack := List.tl !stack;
    if Hashtbl.mem seen key then fail "repeated DataFrame CID";
    Hashtbl.add seen key ();
    let f = node car key 6 in
    Buffer.add_string b (frame_data f);
    if Buffer.length b > 128 lsl 20 then fail "oversize reassembled DataFrame";
    stack := links (at f 5) @ !stack
  done;
  let payload = Buffer.contents b in
  (match as_u64 (at root 1) with
   | Some h when crc64 payload <> h && fnv1a payload <> h -> fail "DataFrame hash mismatch"
   | _ -> ());
  payload

(* ---- Base58 / Base64 ---------------------------------------------------- *)

let b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

let base58 (s : string) =
  let n = String.length s in
  let zeros = ref 0 in
  while !zeros < n && s.[!zeros] = '\000' do incr zeros done;
  let digits = Array.make (n * 138 / 100 + 1) 0 in
  let len = ref 0 in
  for i = !zeros to n - 1 do
    let carry = ref (Char.code s.[i]) in
    for j = 0 to !len - 1 do
      carry := !carry + (digits.(j) lsl 8);
      digits.(j) <- !carry mod 58;
      carry := !carry / 58
    done;
    while !carry > 0 do digits.(!len) <- !carry mod 58; incr len; carry := !carry / 58 done
  done;
  let b = Bytes.make (!zeros + !len) '1' in
  for j = 0 to !len - 1 do Bytes.set b (!zeros + j) b58_alphabet.[digits.(!len - 1 - j)] done;
  Bytes.to_string b

let b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

let base64 (s : string) =
  let n = String.length s in
  let b = Buffer.create ((n + 2) / 3 * 4) in
  let c i = Char.code s.[i] in
  let i = ref 0 in
  while !i + 3 <= n do
    let v = (c !i lsl 16) lor (c (!i + 1) lsl 8) lor c (!i + 2) in
    List.iter (fun sh -> Buffer.add_char b b64_alphabet.[(v lsr sh) land 63]) [ 18; 12; 6; 0 ];
    i := !i + 3
  done;
  (match n - !i with
   | 1 -> let v = c !i lsl 16 in
     Buffer.add_char b b64_alphabet.[v lsr 18]; Buffer.add_char b b64_alphabet.[(v lsr 12) land 63];
     Buffer.add_string b "=="
   | 2 -> let v = (c !i lsl 16) lor (c (!i + 1) lsl 8) in
     Buffer.add_char b b64_alphabet.[v lsr 18]; Buffer.add_char b b64_alphabet.[(v lsr 12) land 63];
     Buffer.add_char b b64_alphabet.[(v lsr 6) land 63]; Buffer.add_char b '='
   | _ -> ());
  Buffer.contents b

let zero_hash = String.make 32 '1'

let pubkey s = if String.length s <> 32 then fail "expected 32-byte hash or public key" else base58 s

(* ---- Solana VersionedTransaction ---------------------------------------- *)

type instruction = { program : int; accounts : string; data : string; height : int option }

type lookup = { table : string; writable : string; readonly : string }

type tx = {
  v0 : bool;
  signatures : string list;          (* raw 64-byte signatures *)
  nrs : int; nros : int; nrou : int;
  keys : string list;                (* Base58 static account keys *)
  recent : string;                   (* Base58 recent blockhash *)
  instructions : instruction list;
  lookups : lookup list;
  raw : string;                      (* consumed wire prefix *)
}

let compiled r height =
  let program = u8 r in
  let accounts = take r (compact r) in
  let data = take r (compact r) in
  { program; accounts; data; height }

let transaction (data : string) : tx =
  let r = reader data in
  let signatures = items r (compact r) 64 (fun () -> take r 64) in
  let p = u8 r in
  let v0, nrs =
    if p land 0x80 = 0 then (false, p)
    else if p land 0x7f = 0 then (true, u8 r)
    else if p land 0x7f = 127 then fail "off-chain messages are not accepted"
    else fail "unsupported transaction version" in
  let nros = u8 r in
  let nrou = u8 r in
  let keys = items r (compact r) 32 (fun () -> base58 (take r 32)) in
  let recent = base58 (take r 32) in
  let instructions = items r (compact r) 3 (fun () -> compiled r (Some 1)) in
  let lookups =
    if v0 then
      items r (compact r) 34 (fun () ->
        let table = take r 32 in
        let writable = take r (compact r) in
        let readonly = take r (compact r) in
        { table; writable; readonly })
    else [] in
  { v0; signatures; nrs; nros; nrou; keys; recent; instructions; lookups; raw = String.sub data 0 r.pos }
