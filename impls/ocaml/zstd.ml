(* RFC 8878 Zstandard decoder: a line-by-line port of docs/ZSTD_MINI_SPEC.md.
   Decode-only, whole-buffer, no dictionaries.  Every violation raises [Error]. *)

exception Error of string

let fail m = raise (Error m)
let max_output = 512 * 1024 * 1024
let block_size_max = 128 * 1024

let byte d i =
  if i < 0 || i >= String.length d then fail "truncated input"
  else Char.code (String.unsafe_get d i)

(* Little-endian unsigned integer of n <= 7 bytes (8 handled by caller). *)
let le d pos n =
  if pos < 0 || pos + n > String.length d then fail "truncated input";
  let v = ref 0 in
  for i = n - 1 downto 0 do v := (!v lsl 8) lor Char.code (String.unsafe_get d (pos + i)) done;
  !v

let highbit x =
  let rec go x n = if x <= 1 then n else go (x lsr 1) (n + 1) in go x 0

(* ---- growable output buffer --------------------------------------------- *)

type out = { mutable buf : Bytes.t; mutable len : int }

let reserve o extra =
  let need = o.len + extra in
  if need > max_output then fail "decompressed size limit exceeded";
  if need > Bytes.length o.buf then begin
    let cap = ref (max 1024 (Bytes.length o.buf)) in
    while !cap < need do cap := !cap * 2 done;
    let nb = Bytes.create (min !cap max_output) in
    Bytes.blit o.buf 0 nb 0 o.len;
    o.buf <- nb
  end

let push o c = reserve o 1; Bytes.unsafe_set o.buf o.len c; o.len <- o.len + 1

let push_sub o s pos n =
  reserve o n; Bytes.blit_string s pos o.buf o.len n; o.len <- o.len + n

let push_fill o n c =
  reserve o n; Bytes.fill o.buf o.len n c; o.len <- o.len + n

(* ---- tables ------------------------------------------------------------- *)

let ll_base = [| 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15; 16; 18; 20; 22; 24; 28; 32; 40;
                 48; 64; 128; 256; 512; 1024; 2048; 4096; 8192; 16384; 32768; 65536 |]
let ll_bits = [| 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 1; 1; 1; 1; 2; 2; 3; 3;
                 4; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15; 16 |]
let ml_base = [| 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15; 16; 17; 18; 19; 20; 21; 22; 23; 24; 25; 26;
                 27; 28; 29; 30; 31; 32; 33; 34; 35; 37; 39; 41; 43; 47; 51; 59; 67; 83; 99; 131; 259;
                 515; 1027; 2051; 4099; 8195; 16387; 32771; 65539 |]
let ml_bits = [| 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0;
                 0; 0; 1; 1; 1; 1; 2; 2; 3; 3; 4; 4; 5; 7; 8; 9; 10; 11; 12; 13; 14; 15; 16 |]
let ll_default = [| 4; 3; 2; 2; 2; 2; 2; 2; 2; 2; 2; 2; 2; 1; 1; 1; 2; 2; 2; 2; 2; 2; 2; 2; 2; 3; 2; 1; 1;
                    1; 1; 1; -1; -1; -1; -1 |]
let ml_default = [| 1; 4; 3; 2; 2; 2; 2; 2; 2; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1;
                    1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; -1; -1; -1; -1; -1; -1; -1 |]
let of_default = [| 1; 1; 1; 1; 1; 1; 2; 2; 2; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; 1; -1; -1; -1;
                    -1; -1 |]

type kind = LL | OF | ML

(* default distribution, default log, max symbol, max log *)
let seq_kind = function
  | LL -> (ll_default, 6, 35, 9)
  | OF -> (of_default, 5, 31, 8)
  | ML -> (ml_default, 6, 52, 9)

(* ---- backward bitstream ------------------------------------------------- *)

type bits = { data : string; start : int; mutable bits : int }

let backward data start end_ =
  if start < 0 || end_ > String.length data || end_ <= start then fail "empty or out-of-range bitstream";
  let last = Char.code data.[end_ - 1] in
  if last = 0 then fail "bitstream end marker missing";
  { data; start; bits = 8 * (end_ - start - 1) + highbit last }

let window br lo hi =
  let first = lo lsr 3 and last = (hi - 1) lsr 3 in
  let w = ref 0 in
  for i = last downto first do w := (!w lsl 8) lor byte br.data (br.start + i) done;
  (!w lsr (lo land 7)) land ((1 lsl (hi - lo)) - 1)

let peek br n =
  let lo = br.bits - n and hi = br.bits in
  if n = 0 || hi <= 0 then 0
  else if lo < 0 then window br 0 hi lsl (-lo)
  else window br lo hi

let read br n = let v = peek br n in br.bits <- br.bits - n; v

(* ---- FSE ---------------------------------------------------------------- *)

let read_fse_description data pos limit max_symbol max_log =
  let bitpos = ref (pos * 8) in
  let peekf n =
    let v = ref 0 in
    for i = 0 to n - 1 do
      let p = !bitpos + i in
      if p lsr 3 < limit then v := !v lor (((byte data (p lsr 3) lsr (p land 7)) land 1) lsl i)
    done; !v in
  let take n = let v = peekf n in bitpos := !bitpos + n; v in
  let accuracy_log = take 4 + 5 in
  if accuracy_log > max_log then fail "FSE accuracy log too large";
  let remaining = ref ((1 lsl accuracy_log) + 1) in
  let threshold = ref (1 lsl accuracy_log) in
  let nbits = ref (accuracy_log + 1) in
  let probs = ref [] and count = ref 0 in
  let add p = probs := p :: !probs; incr count in
  while !remaining > 1 do
    if !count > max_symbol then fail "FSE description has too many symbols";
    let biggest = 2 * !threshold - 1 - !remaining in
    let low = peekf (!nbits - 1) in
    let value =
      if low < biggest then (ignore (take (!nbits - 1)); low)
      else (let v = take !nbits in if v >= !threshold then v - biggest else v) in
    let prob = value - 1 in
    add prob;
    remaining := !remaining - abs prob;
    if prob = 0 then begin
      let continue = ref true in
      while !continue do
        let repeat = take 2 in
        for _ = 1 to repeat do add 0 done;
        if repeat <> 3 then continue := false;
        if !count > 4096 then fail "corrupt FSE description"
      done
    end;
    while !remaining < !threshold do decr nbits; threshold := !threshold lsr 1 done
  done;
  if !remaining <> 1 || !count > max_symbol + 1 then fail "corrupt FSE description";
  let end_ = (!bitpos + 7) lsr 3 in
  if end_ > limit then fail "FSE description overruns its section";
  (Array.of_list (List.rev !probs), accuracy_log, end_)

(* A decoding table cell: symbol, nb_bits, baseline. *)
type fse = { sym : int array; nb : int array; base : int array; log : int }

let build_fse probs accuracy_log =
  let size = 1 lsl accuracy_log in
  let cell = Array.make size 0 in
  let counter = Array.make (Array.length probs) 0 in
  let high = ref (size - 1) in
  Array.iteri (fun s p ->
    if p = -1 then begin
      if !high < 0 then fail "corrupt FSE distribution";
      cell.(!high) <- s; decr high; counter.(s) <- 1
    end else counter.(s) <- p) probs;
  let step = (size lsr 1) + (size lsr 3) + 3 and mask = size - 1 in
  let pos = ref 0 in
  Array.iteri (fun s p ->
    for _ = 1 to max p 0 do
      cell.(!pos) <- s;
      pos := (!pos + step) land mask;
      while !pos > !high do pos := (!pos + step) land mask done
    done) probs;
  if !pos <> 0 then fail "corrupt FSE distribution";
  let sym = Array.make size 0 and nb = Array.make size 0 and base = Array.make size 0 in
  for c = 0 to size - 1 do
    let s = cell.(c) in
    let x = counter.(s) in
    counter.(s) <- x + 1;
    if x <= 0 then fail "corrupt FSE distribution";
    let n = accuracy_log - highbit x in
    sym.(c) <- s; nb.(c) <- n; base.(c) <- (x lsl n) - size
  done;
  { sym; nb; base; log = accuracy_log }

(* ---- Huffman ------------------------------------------------------------ *)

type huff = { hsym : int array; hnb : int array; max_bits : int }

let build_huffman weights =
  let n = Array.length weights in
  if n > 255 then fail "too many Huffman weights";
  let total = ref 0 in
  Array.iter (fun w -> if w > 11 then fail "Huffman weight too large";
               if w > 0 then total := !total + (1 lsl (w - 1))) weights;
  if !total = 0 then fail "empty Huffman table";
  let max_bits = highbit !total + 1 in
  if max_bits > 11 then fail "Huffman code too long";
  let rest = (1 lsl max_bits) - !total in
  if rest land (rest - 1) <> 0 then fail "corrupt Huffman weights";
  let weights = Array.append weights [| highbit rest + 1 |] in
  let next = Array.make (max_bits + 2) 0 in
  let start = ref 0 in
  for w = 1 to max_bits do
    next.(w) <- !start;
    Array.iter (fun x -> if x = w then start := !start + (1 lsl (w - 1))) weights
  done;
  let size = 1 lsl max_bits in
  let hsym = Array.make size 0 and hnb = Array.make size 0 in
  Array.iteri (fun s w ->
    if w > 0 then begin
      if w > max_bits then fail "corrupt Huffman weights";
      for i = next.(w) to next.(w) + (1 lsl (w - 1)) - 1 do
        hsym.(i) <- s; hnb.(i) <- max_bits + 1 - w
      done;
      next.(w) <- next.(w) + (1 lsl (w - 1))
    end) weights;
  { hsym; hnb; max_bits }

let read_huffman_description data pos limit =
  if pos >= limit then fail "missing Huffman description";
  let h = byte data pos in
  let pos = pos + 1 in
  if h < 128 then begin
    let end_ = pos + h in
    if end_ > limit then fail "Huffman description overruns literals";
    let probs, al, p = read_fse_description data pos end_ 255 6 in
    let t = build_fse probs al in
    let br = backward data p end_ in
    let s1 = ref (read br al) and s2 = ref (read br al) in
    let ws = ref [] and count = ref 0 in
    let emit s = ws := s :: !ws; incr count in
    let fin = ref false in
    while not !fin do
      if !count > 255 then fail "too many Huffman weights";
      emit t.sym.(!s1);
      s1 := t.base.(!s1) + read br t.nb.(!s1);
      if br.bits < 0 then (emit t.sym.(!s2); fin := true)
      else begin
        emit t.sym.(!s2);
        s2 := t.base.(!s2) + read br t.nb.(!s2);
        if br.bits < 0 then (emit t.sym.(!s1); fin := true)
      end
    done;
    (build_huffman (Array.of_list (List.rev !ws)), end_)
  end else begin
    let n = h - 127 in
    let end_ = pos + (n + 1) / 2 in
    if end_ > limit then fail "Huffman description overruns literals";
    let ws = Array.init n (fun i ->
      let b = byte data (pos + i / 2) in if i mod 2 = 0 then b lsr 4 else b land 15) in
    (build_huffman ws, end_)
  end

let decode_huffman_stream data start end_ h count out =
  let br = backward data start end_ in
  for _ = 1 to count do
    let i = peek br h.max_bits in
    push out (Char.unsafe_chr h.hsym.(i));
    br.bits <- br.bits - h.hnb.(i)
  done;
  if br.bits <> 0 then fail "Huffman stream not fully consumed"

(* ---- frame state, literals, sequences ----------------------------------- *)

type frame = {
  mutable rep0 : int; mutable rep1 : int; mutable rep2 : int;
  mutable huffman : huff option;
  mutable t_ll : fse option; mutable t_of : fse option; mutable t_ml : fse option;
}

(* Returns (literal bytes as string, position after the literals section). *)
let decode_literals data pos end_ fr =
  if pos >= end_ then fail "missing literals section";
  let b0 = byte data pos in
  let ltype = b0 land 3 and size_format = (b0 lsr 2) land 3 in
  if ltype = 0 || ltype = 1 then begin
    let size, pos =
      match size_format with
      | 0 | 2 -> (b0 lsr 3, pos + 1)
      | 1 -> ((b0 lsr 4) + (byte data (pos + 1) lsl 4), pos + 2)
      | _ -> ((b0 lsr 4) + (byte data (pos + 1) lsl 4) + (byte data (pos + 2) lsl 12), pos + 3) in
    if ltype = 0 then begin
      if pos + size > end_ then fail "raw literals overrun block";
      (String.sub data pos size, pos + size)
    end else begin
      if pos >= end_ then fail "RLE literals overrun block";
      (String.make size data.[pos], pos + 1)
    end
  end else begin
    let streams, header_len, width =
      match size_format with 0 -> (1, 3, 10) | 1 -> (4, 3, 10) | 2 -> (4, 4, 14) | _ -> (4, 5, 18) in
    let h = le data pos header_len in
    let regenerated = (h lsr 4) land ((1 lsl width) - 1) in
    let compressed = (h lsr (4 + width)) land ((1 lsl width) - 1) in
    let pos = pos + header_len in
    let lit_end = pos + compressed in
    if lit_end > end_ then fail "compressed literals overrun block";
    let pos =
      if ltype = 2 then (let hf, p = read_huffman_description data pos lit_end in fr.huffman <- Some hf; p)
      else if fr.huffman = None then fail "treeless literals without a previous Huffman table"
      else pos in
    let hf = match fr.huffman with Some h -> h | None -> fail "no Huffman table" in
    let out = { buf = Bytes.create (max regenerated 1); len = 0 } in
    if streams = 1 then decode_huffman_stream data pos lit_end hf regenerated out
    else begin
      let s1 = le data pos 2 and s2 = le data (pos + 2) 2 and s3 = le data (pos + 4) 2 in
      let pos = pos + 6 in
      let s4 = lit_end - pos - s1 - s2 - s3 in
      let quarter = (regenerated + 3) / 4 in
      let c4 = regenerated - 3 * quarter in
      if s4 < 1 || c4 < 0 then fail "corrupt 4-stream literals";
      let p = ref pos in
      List.iter (fun (size, count) ->
        decode_huffman_stream data !p (!p + size) hf count out; p := !p + size)
        [ (s1, quarter); (s2, quarter); (s3, quarter); (s4, c4) ]
    end;
    (Bytes.sub_string out.buf 0 out.len, lit_end)
  end

let read_sequence_table data pos end_ mode kind fr =
  let default, default_log, max_symbol, max_log = seq_kind kind in
  let t, pos =
    match mode with
    | 0 -> (build_fse default default_log, pos)
    | 1 ->
      if pos >= end_ || byte data pos > max_symbol then fail "bad RLE sequence symbol";
      ({ sym = [| byte data pos |]; nb = [| 0 |]; base = [| 0 |]; log = 0 }, pos + 1)
    | 2 ->
      let probs, al, p = read_fse_description data pos end_ max_symbol max_log in
      (build_fse probs al, p)
    | _ ->
      let prev = match kind with LL -> fr.t_ll | OF -> fr.t_of | ML -> fr.t_ml in
      (match prev with Some t -> (t, pos) | None -> fail "repeat mode without a previous table") in
  (match kind with LL -> fr.t_ll <- Some t | OF -> fr.t_of <- Some t | ML -> fr.t_ml <- Some t);
  (t, pos)

(* Decodes and immediately executes the sequences of one block. *)
let decode_and_execute data pos end_ fr literals out frame_start =
  if pos >= end_ then fail "missing sequences section";
  let b0 = byte data pos in
  let lit = ref 0 in
  let nlit = String.length literals in
  if b0 = 0 then begin
    if pos + 1 <> end_ then fail "data after empty sequences section"
  end else begin
    let count, pos =
      if b0 < 128 then (b0, pos + 1)
      else if b0 < 255 then (((b0 - 128) lsl 8) + byte data (pos + 1), pos + 2)
      else (le data (pos + 1) 2 + 0x7F00, pos + 3) in
    if pos >= end_ then fail "missing compression modes";
    let modes = byte data pos in
    let pos = pos + 1 in
    if modes land 3 <> 0 then fail "reserved compression-mode bits set";
    let llt, pos = read_sequence_table data pos end_ ((modes lsr 6) land 3) LL fr in
    let oft, pos = read_sequence_table data pos end_ ((modes lsr 4) land 3) OF fr in
    let mlt, pos = read_sequence_table data pos end_ ((modes lsr 2) land 3) ML fr in
    let br = backward data pos end_ in
    let ll_s = ref (read br llt.log) in
    let of_s = ref (read br oft.log) in
    let ml_s = ref (read br mlt.log) in
    for i = 0 to count - 1 do
      let of_code = oft.sym.(!of_s) and ml_code = mlt.sym.(!ml_s) and ll_code = llt.sym.(!ll_s) in
      if of_code > 31 || ml_code > 52 || ll_code > 35 then fail "bad sequence code";
      let offset_value = (1 lsl of_code) + read br of_code in
      let ml = ml_base.(ml_code) + read br ml_bits.(ml_code) in
      let ll = ll_base.(ll_code) + read br ll_bits.(ll_code) in
      if i <> count - 1 then begin
        ll_s := llt.base.(!ll_s) + read br llt.nb.(!ll_s);
        ml_s := mlt.base.(!ml_s) + read br mlt.nb.(!ml_s);
        of_s := oft.base.(!of_s) + read br oft.nb.(!of_s)
      end;
      (* execute *)
      if !lit + ll > nlit then fail "sequence consumes more literals than available";
      push_sub out literals !lit ll;
      lit := !lit + ll;
      let offset =
        if offset_value > 3 then begin
          let o = offset_value - 3 in
          fr.rep2 <- fr.rep1; fr.rep1 <- fr.rep0; fr.rep0 <- o; o
        end else begin
          let idx = offset_value - 1 + (if ll = 0 then 1 else 0) in
          match idx with
          | 0 -> fr.rep0
          | 1 -> let o = fr.rep1 in fr.rep1 <- fr.rep0; fr.rep0 <- o; o
          | 2 -> let o = fr.rep2 in fr.rep2 <- fr.rep1; fr.rep1 <- fr.rep0; fr.rep0 <- o; o
          | _ -> let o = fr.rep0 - 1 in fr.rep2 <- fr.rep1; fr.rep1 <- fr.rep0; fr.rep0 <- o; o
        end in
      if offset <= 0 || offset > out.len - frame_start then fail "match offset out of range";
      reserve out ml;
      let src = out.len - offset in
      if offset >= ml then Bytes.blit out.buf src out.buf out.len ml
      else for k = 0 to ml - 1 do Bytes.unsafe_set out.buf (out.len + k) (Bytes.unsafe_get out.buf (src + k)) done;
      out.len <- out.len + ml
    done;
    if br.bits <> 0 then fail "sequence bitstream not fully consumed"
  end;
  push_sub out literals !lit (nlit - !lit)

(* ---- XXH64 -------------------------------------------------------------- *)

let p1 = 0x9E3779B185EBCA87L and p2 = 0xC2B2AE3D27D4EB4FL and p3 = 0x165667B19E3779F9L
let p4 = 0x85EBCA77C2B2AE63L and p5 = 0x27D4EB2F165667C5L
let rotl x r = Int64.logor (Int64.shift_left x r) (Int64.shift_right_logical x (64 - r))
let round acc lane = Int64.mul (rotl (Int64.add acc (Int64.mul lane p2)) 31) p1

let xxh64 (b : Bytes.t) off n =
  let lane i = Bytes.get_int64_le b (off + i) in
  let i = ref 0 in
  let h =
    if n >= 32 then begin
      let v1 = ref (Int64.add p1 p2) and v2 = ref p2 and v3 = ref 0L and v4 = ref (Int64.neg p1) in
      while !i + 32 <= n do
        v1 := round !v1 (lane !i); v2 := round !v2 (lane (!i + 8));
        v3 := round !v3 (lane (!i + 16)); v4 := round !v4 (lane (!i + 24));
        i := !i + 32
      done;
      let h = Int64.(add (add (rotl !v1 1) (rotl !v2 7)) (add (rotl !v3 12) (rotl !v4 18))) in
      List.fold_left (fun h v -> Int64.(add (mul (logxor h (round 0L v)) p1) p4)) h [ !v1; !v2; !v3; !v4 ]
    end else p5 in
  let h = ref (Int64.add h (Int64.of_int n)) in
  while !i + 8 <= n do
    h := Int64.(add (mul (rotl (logxor !h (round 0L (lane !i))) 27) p1) p4); i := !i + 8
  done;
  if !i + 4 <= n then begin
    let w = Int64.logand (Int64.of_int32 (Bytes.get_int32_le b (off + !i))) 0xFFFFFFFFL in
    h := Int64.(add (mul (rotl (logxor !h (mul w p1)) 23) p2) p3); i := !i + 4
  end;
  while !i < n do
    let c = Int64.of_int (Char.code (Bytes.get b (off + !i))) in
    h := Int64.(mul (rotl (logxor !h (mul c p5)) 11) p1); incr i
  done;
  let h = !h in
  let h = Int64.(mul (logxor h (shift_right_logical h 33)) p2) in
  let h = Int64.(mul (logxor h (shift_right_logical h 29)) p3) in
  Int64.(logxor h (shift_right_logical h 32))

(* ---- frames ------------------------------------------------------------- *)

let decode_frame data pos out =
  let fhd = byte data pos in
  let pos = ref (pos + 1) in
  let fcs_flag = fhd lsr 6 and single = (fhd lsr 5) land 1 in
  let has_checksum = (fhd lsr 2) land 1 and did_flag = fhd land 3 in
  if fhd land 0x08 <> 0 then fail "reserved frame header bit set";
  if single = 0 then (ignore (byte data !pos); incr pos);
  let did_size = [| 0; 1; 2; 4 |].(did_flag) in
  if did_size > 0 && le data !pos did_size <> 0 then fail "zstd dictionaries are not supported";
  pos := !pos + did_size;
  let fcs_size = [| (if single = 1 then 1 else 0); 2; 4; 8 |].(fcs_flag) in
  let content_size =
    if fcs_size = 0 then None
    else if fcs_size = 8 then begin
      if !pos + 8 > String.length data then fail "truncated input";
      let v = String.get_int64_le data !pos in
      pos := !pos + 8;
      if Int64.compare v 0L < 0 || Int64.compare v (Int64.of_int max_output) > 0 then
        fail "frame content size too large";
      Some (Int64.to_int v)
    end else begin
      let v = le data !pos fcs_size + (if fcs_size = 2 then 256 else 0) in
      pos := !pos + fcs_size; Some v
    end in
  let frame_start = out.len in
  let fr = { rep0 = 1; rep1 = 4; rep2 = 8; huffman = None; t_ll = None; t_of = None; t_ml = None } in
  let last = ref false in
  while not !last do
    let header = le data !pos 3 in
    pos := !pos + 3;
    last := header land 1 = 1;
    let block_type = (header lsr 1) land 3 and block_size = header lsr 3 in
    if block_size > block_size_max then fail "block too large";
    (match block_type with
     | 0 ->
       if !pos + block_size > String.length data then fail "truncated raw block";
       push_sub out data !pos block_size; pos := !pos + block_size
     | 1 -> push_fill out block_size (Char.chr (byte data !pos)); incr pos
     | 2 ->
       let end_ = !pos + block_size in
       if end_ > String.length data then fail "truncated compressed block";
       let literals, p = decode_literals data !pos end_ fr in
       decode_and_execute data p end_ fr literals out frame_start;
       pos := end_
     | _ -> fail "reserved block type");
    if out.len > max_output then fail "decompressed size limit exceeded"
  done;
  (match content_size with
   | Some n when out.len - frame_start <> n -> fail "frame content size mismatch"
   | _ -> ());
  if has_checksum = 1 then begin
    let expected = le data !pos 4 in
    pos := !pos + 4;
    let h = xxh64 out.buf frame_start (out.len - frame_start) in
    if Int64.to_int (Int64.logand h 0xFFFFFFFFL) <> expected then fail "content checksum mismatch"
  end;
  !pos

let decompress_exn (data : string) : string =
  let out = { buf = Bytes.create (min (16 lsl 20) (max 1024 (3 * String.length data))); len = 0 } in
  let pos = ref 0 in
  let n = String.length data in
  while !pos < n do
    let magic = le data !pos 4 in
    if magic land 0xFFFFFFF0 = 0x184D2A50 then begin
      let size = le data (!pos + 4) 4 in
      if !pos + 8 + size > n then fail "truncated skippable frame";
      pos := !pos + 8 + size
    end else if magic = 0xFD2FB528 then pos := decode_frame data (!pos + 4) out
    else fail "unknown frame magic"
  done;
  Bytes.sub_string out.buf 0 out.len

(* Any stray stdlib exception on hostile input is still just a zstd failure,
   so the caller's raw-bytes fallback (WIRE_FORMATS.md section 9.1) applies. *)
let decompress data =
  try decompress_exn data with
  | Invalid_argument m | Failure m -> fail m
  | Not_found -> fail "corrupt frame"

let is_frame s = String.length s >= 4 && String.sub s 0 4 = "\x28\xb5\x2f\xfd"
