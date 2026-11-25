(* RFC 8259 JSON: a depth-limited recursive-descent parser that keeps number
   tokens as source text, and a Buffer-based printer. *)

exception Parse_error

(* Objects keep their members in reverse order so [List.assoc] finds the
   last duplicate key, as the reference does. *)
type value =
  | Null
  | Bool of bool
  | Num of string
  | Str of string
  | Arr of value list
  | Obj of (string * value) list

let max_depth = 128

let parse (s : string) : value =
  if not (String.is_valid_utf_8 s) then raise Parse_error;
  let n = String.length s in
  let pos = ref 0 in
  let peek () = if !pos < n then s.[!pos] else '\000' in
  let ws () = while !pos < n && (match s.[!pos] with ' ' | '\t' | '\n' | '\r' -> true | _ -> false) do incr pos done in
  let expect c = if peek () = c && !pos < n then incr pos else raise Parse_error in
  let literal word v =
    let l = String.length word in
    if !pos + l <= n && String.sub s !pos l = word then (pos := !pos + l; v) else raise Parse_error in
  let digits () =
    let start = !pos in
    while !pos < n && s.[!pos] >= '0' && s.[!pos] <= '9' do incr pos done;
    if !pos = start then raise Parse_error in
  let number () =
    let start = !pos in
    if peek () = '-' then incr pos;
    (match peek () with
     | '0' -> incr pos
     | '1' .. '9' -> digits ()
     | _ -> raise Parse_error);
    if peek () = '.' then (incr pos; digits ());
    if peek () = 'e' || peek () = 'E' then begin
      incr pos;
      if peek () = '+' || peek () = '-' then incr pos;
      digits ()
    end;
    Num (String.sub s start (!pos - start)) in
  let hex4 () =
    if !pos + 4 > n then raise Parse_error;
    let v = ref 0 in
    for i = 0 to 3 do
      let d = match s.[!pos + i] with
        | '0' .. '9' as c -> Char.code c - 48
        | 'a' .. 'f' as c -> Char.code c - 87
        | 'A' .. 'F' as c -> Char.code c - 55
        | _ -> raise Parse_error in
      v := (!v lsl 4) lor d
    done;
    pos := !pos + 4; !v in
  let string () =
    expect '"';
    let b = Buffer.create 16 in
    let fin = ref false in
    while not !fin do
      if !pos >= n then raise Parse_error;
      let c = s.[!pos] in
      incr pos;
      match c with
      | '"' -> fin := true
      | '\\' ->
        if !pos >= n then raise Parse_error;
        let e = s.[!pos] in
        incr pos;
        (match e with
         | '"' -> Buffer.add_char b '"' | '\\' -> Buffer.add_char b '\\' | '/' -> Buffer.add_char b '/'
         | 'b' -> Buffer.add_char b '\b' | 'f' -> Buffer.add_char b '\012' | 'n' -> Buffer.add_char b '\n'
         | 'r' -> Buffer.add_char b '\r' | 't' -> Buffer.add_char b '\t'
         | 'u' ->
           let u = hex4 () in
           let cp =
             if u >= 0xD800 && u <= 0xDBFF then begin
               if !pos + 2 <= n && s.[!pos] = '\\' && s.[!pos + 1] = 'u' then begin
                 pos := !pos + 2;
                 let lo = hex4 () in
                 if lo < 0xDC00 || lo > 0xDFFF then raise Parse_error;
                 0x10000 + ((u - 0xD800) lsl 10) + (lo - 0xDC00)
               end else raise Parse_error
             end else if u >= 0xDC00 && u <= 0xDFFF then raise Parse_error
             else u in
           Buffer.add_utf_8_uchar b (Uchar.of_int cp)
         | _ -> raise Parse_error)
      | c when Char.code c < 0x20 -> raise Parse_error
      | c -> Buffer.add_char b c
    done;
    Buffer.contents b in
  let rec value depth =
    if depth > max_depth then raise Parse_error;
    ws ();
    match peek () with
    | '{' ->
      incr pos; ws ();
      if peek () = '}' then (incr pos; Obj [])
      else begin
        let members = ref [] in
        let fin = ref false in
        while not !fin do
          ws ();
          let k = string () in
          ws (); expect ':';
          let v = value (depth + 1) in
          members := (k, v) :: !members;
          ws ();
          match peek () with
          | ',' -> incr pos
          | '}' -> incr pos; fin := true
          | _ -> raise Parse_error
        done;
        Obj !members
      end
    | '[' ->
      incr pos; ws ();
      if peek () = ']' then (incr pos; Arr [])
      else begin
        let items = ref [] in
        let fin = ref false in
        while not !fin do
          items := value (depth + 1) :: !items;
          ws ();
          match peek () with
          | ',' -> incr pos
          | ']' -> incr pos; fin := true
          | _ -> raise Parse_error
        done;
        Arr (List.rev !items)
      end
    | '"' -> Str (string ())
    | 't' -> literal "true" (Bool true)
    | 'f' -> literal "false" (Bool false)
    | 'n' -> literal "null" Null
    | '-' | '0' .. '9' -> number ()
    | _ -> raise Parse_error in
  let v = value 1 in
  ws ();
  if !pos <> n then raise Parse_error;
  v

let member k = function Obj kvs -> List.assoc_opt k kvs | _ -> None

(* ---- output ------------------------------------------------------------- *)

type out =
  | ONull
  | OBool of bool
  | ORaw of string            (* pre-rendered number text *)
  | OFloat of float
  | OStr of string
  | OArr of out list
  | OObj of (string * out) list

let escape b s =
  Buffer.add_char b '"';
  String.iter (fun c ->
    match c with
    | '"' -> Buffer.add_string b "\\\""
    | '\\' -> Buffer.add_string b "\\\\"
    | '\n' -> Buffer.add_string b "\\n"
    | '\r' -> Buffer.add_string b "\\r"
    | '\t' -> Buffer.add_string b "\\t"
    | c when Char.code c < 0x20 -> Buffer.add_string b (Printf.sprintf "\\u%04x" (Char.code c))
    | c -> Buffer.add_char b c) s;
  Buffer.add_char b '"'

(* Shortest %g form that round-trips. *)
let float_text f =
  if not (Float.is_finite f) then "null"
  else begin
    let rec go p = let t = Printf.sprintf "%.*g" p f in
      if p >= 17 || float_of_string t = f then t else go (p + 1) in
    go 1
  end

let rec write b = function
  | ONull -> Buffer.add_string b "null"
  | OBool v -> Buffer.add_string b (if v then "true" else "false")
  | ORaw t -> Buffer.add_string b t
  | OFloat f -> Buffer.add_string b (float_text f)
  | OStr s -> escape b s
  | OArr items ->
    Buffer.add_char b '[';
    List.iteri (fun i v -> if i > 0 then Buffer.add_char b ','; write b v) items;
    Buffer.add_char b ']'
  | OObj kvs ->
    Buffer.add_char b '{';
    List.iteri (fun i (k, v) -> if i > 0 then Buffer.add_char b ','; escape b k; Buffer.add_char b ':'; write b v) kvs;
    Buffer.add_char b '}'

let int n = ORaw (string_of_int n)
let u64 v = ORaw (Printf.sprintf "%Lu" v)
let i64 v = ORaw (Printf.sprintf "%Ld" v)
let opt f = function None -> ONull | Some v -> f v
