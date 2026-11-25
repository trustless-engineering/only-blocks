! ob_rpc: JSON-RPC 2.0 envelope handling, getBlock parameter validation and
! the two-range-read getBlock pipeline (SPEC.md sections 4 and 5).
module ob_rpc
  use iso_fortran_env, only: error_unit
  use ob_util
  use ob_json
  use ob_http
  use ob_cache
  use ob_car
  use ob_tx
  use ob_meta
  use ob_render
  use ob_codec
  implicit none
  private
  public :: rpc_init, rpc_handle

  integer(int64), parameter :: SLOTS_PER_EPOCH = 432000_int64
  integer(int64), parameter :: MAX_SLICE = 134217728_int64
  integer, parameter :: MAX_BATCH = 100
  integer(int64), parameter :: KEEP_BYTES = 33554432_int64

  type(lru_t), save :: range_cache, hash_cache
  type(jdoc_t), save :: doc
  ! decode buffers reused across requests
  type(bytes_t), save :: slice, pslice, rbuf, txb, mframe, pl, rframe, rpl
  type(car_t), save :: car, pcar
  type(tx_t), save :: tx
  type(meta_t), save :: meta
  type(rewards_t), save :: rws

contains

  subroutine rpc_init()
    call lru_init(range_cache, 100000, .false.)
    call lru_init(hash_cache, 100000, .true.)
    call render_init()
    call meta_default(meta)
  end subroutine rpc_init

  ! ============================================================ envelopes
  subroutine put_error(out, code, msg, idtext)
    type(sb_t), intent(inout) :: out
    integer, intent(in) :: code
    character(len=*), intent(in) :: msg, idtext
    call sb_add(out, '{"jsonrpc":"2.0","error":{"code":')
    call sb_int(out, code)
    call sb_add(out, ',"message":')
    call sb_json_text(out, msg)
    call sb_add(out, '},"id":')
    call sb_add(out, idtext)
    call sb_addc(out, '}')
  end subroutine put_error

  !> Handle one HTTP request body; out receives the complete JSON response.
  subroutine rpc_handle(body, out)
    character(len=*), intent(in) :: body
    type(sb_t), intent(inout) :: out
    integer :: root, n, c, k
    out%n = 0
    call json_parse(body, doc, root)
    if (root == 0) then
      call put_error(out, -32700, 'Parse error', 'null')
      return
    end if
    select case (doc%kind(root))
    case (J_OBJ)
      call handle_request(body, root, out)
    case (J_ARR)
      n = jlen(doc, root)
      if (n == 0 .or. n > MAX_BATCH) then
        call put_error(out, -32600, 'Invalid Request', 'null')
        return
      end if
      call sb_addc(out, '[')
      c = doc%child(root)
      k = 0
      do while (c /= 0)
        k = k + 1
        if (k > 1) call sb_addc(out, ',')
        if (doc%kind(c) == J_OBJ) then
          call handle_request(body, c, out)
        else
          call put_error(out, -32600, 'Invalid Request', 'null')
        end if
        c = doc%next(c)
      end do
      call sb_addc(out, ']')
    case default
      call put_error(out, -32600, 'Invalid Request', 'null')
    end select
  end subroutine rpc_handle

  subroutine handle_request(txt, obj, out)
    character(len=*), intent(in) :: txt
    integer, intent(in) :: obj
    type(sb_t), intent(inout) :: out
    integer :: jr, me, idn, pa, k
    character(len=:), allocatable :: idtext, name
    jr = jget(doc, txt, obj, 'jsonrpc')
    me = jget(doc, txt, obj, 'method')
    idn = jget(doc, txt, obj, 'id')
    pa = jget(doc, txt, obj, 'params')
    if (jr /= 0) then
      k = doc%kind(jr)
      if (k /= J_STR .and. k /= J_NULL) then
        call put_error(out, -32600, 'Invalid Request', 'null')
        return
      end if
    end if
    if (me /= 0) then
      k = doc%kind(me)
      if (k /= J_STR .and. k /= J_NULL) then
        call put_error(out, -32600, 'Invalid Request', 'null')
        return
      end if
    end if
    idtext = 'null'
    if (idn /= 0) then
      k = doc%kind(idn)
      if (k /= J_STR .and. k /= J_NUM .and. k /= J_NULL) then
        call put_error(out, -32600, 'Invalid Request', 'null')
        return
      end if
      idtext = jraw(doc, txt, idn)
    end if
    if (jr == 0) then
      call put_error(out, -32600, 'Invalid Request', idtext)
      return
    end if
    if (.not. jstr_eq(doc, txt, jr, '2.0')) then
      call put_error(out, -32600, 'Invalid Request', idtext)
      return
    end if
    if (me == 0) then
      call put_error(out, -32600, 'Invalid Request', idtext)
      return
    end if
    if (doc%kind(me) /= J_STR) then
      call put_error(out, -32600, 'Invalid Request', idtext)
      return
    end if
    name = jstr(doc, txt, me)
    if (streq(name, 'getHealth')) then
      if (pa /= 0) then
        k = doc%kind(pa)
        if (.not. (k == J_NULL .or. (k == J_ARR .and. doc%child(pa) == 0))) then
          call put_error(out, -32602, 'Invalid params: getHealth takes no parameters', idtext)
          return
        end if
      end if
      call sb_add(out, '{"jsonrpc":"2.0","result":"ok","id":')
      call sb_add(out, idtext)
      call sb_addc(out, '}')
    else if (streq(name, 'getBlock')) then
      call handle_get_block(txt, pa, idtext, out)
    else
      call put_error(out, -32601, 'Method not found: ' // name, idtext)
    end if
  end subroutine handle_request

  ! ============================================================ getBlock params
  logical function is_uint_literal(txt, node)
    character(len=*), intent(in) :: txt
    integer, intent(in) :: node
    is_uint_literal = .false.
    if (doc%kind(node) /= J_NUM) return
    if (.not. doc%isint(node)) return
    if (txt(doc%p(node):doc%p(node)) == '-') return
    is_uint_literal = .true.
  end function is_uint_literal

  subroutine handle_get_block(txt, pa, idtext, out)
    character(len=*), intent(in) :: txt, idtext
    integer, intent(in) :: pa
    type(sb_t), intent(inout) :: out
    integer :: n, p0, p1, m, code
    integer(int64) :: slot, v, mark
    logical :: ok
    type(opts_t) :: o
    character(len=:), allocatable :: s, msg
    if (pa == 0) then
      call put_error(out, -32602, 'Invalid params: expected [slot, config?]', idtext)
      return
    end if
    if (doc%kind(pa) /= J_ARR) then
      call put_error(out, -32602, 'Invalid params: expected [slot, config?]', idtext)
      return
    end if
    n = jlen(doc, pa)
    if (n < 1 .or. n > 2) then
      call put_error(out, -32602, 'Invalid params: expected [slot, config?]', idtext)
      return
    end if
    p0 = doc%child(pa)
    ok = is_uint_literal(txt, p0)
    if (ok) call parse_u64_digits(txt(doc%p(p0):doc%q(p0)), slot, ok)
    if (.not. ok) then
      call put_error(out, -32602, 'Invalid params: slot must be an integer in 0..2^64-1', idtext)
      return
    end if
    o = opts_t()
    if (n == 2) then
      p1 = doc%next(p0)
      select case (doc%kind(p1))
      case (J_NULL)
        continue
      case (J_STR)
        if (.not. set_encoding(jstr(doc, txt, p1), o)) then
          call put_error(out, -32602, 'Invalid params: unknown encoding', idtext)
          return
        end if
      case (J_OBJ)
        m = jget(doc, txt, p1, 'encoding')
        if (m /= 0) then
          if (doc%kind(m) == J_STR) then
            if (.not. set_encoding(jstr(doc, txt, m), o)) then
              call put_error(out, -32602, 'Invalid params: unknown encoding', idtext)
              return
            end if
          else if (doc%kind(m) /= J_NULL) then
            call put_error(out, -32602, 'Invalid params: encoding must be a string', idtext)
            return
          end if
        end if
        m = jget(doc, txt, p1, 'transactionDetails')
        if (m /= 0) then
          if (doc%kind(m) == J_STR) then
            s = jstr(doc, txt, m)
            if (streq(s, 'full')) then
              o%details = DET_FULL
            else if (streq(s, 'accounts')) then
              o%details = DET_ACCOUNTS
            else if (streq(s, 'signatures')) then
              o%details = DET_SIGS
            else if (streq(s, 'none')) then
              o%details = DET_NONE
            else
              call put_error(out, -32602, 'Invalid params: unknown transactionDetails', idtext)
              return
            end if
          else if (doc%kind(m) /= J_NULL) then
            call put_error(out, -32602, 'Invalid params: transactionDetails must be a string', idtext)
            return
          end if
        end if
        m = jget(doc, txt, p1, 'rewards')
        if (m /= 0) then
          if (doc%kind(m) == J_TRUE) then
            o%rewards = .true.
          else if (doc%kind(m) == J_FALSE) then
            o%rewards = .false.
          else if (doc%kind(m) /= J_NULL) then
            call put_error(out, -32602, 'Invalid params: rewards must be a boolean', idtext)
            return
          end if
        end if
        m = jget(doc, txt, p1, 'maxSupportedTransactionVersion')
        if (m /= 0) then
          if (doc%kind(m) /= J_NULL) then
            ok = is_uint_literal(txt, m)
            if (ok) call parse_u64_digits(txt(doc%p(m):doc%q(m)), v, ok)
            if (ok) ok = (v >= 0 .and. v <= 255)
            if (.not. ok) then
              call put_error(out, -32602, 'Invalid params: maxSupportedTransactionVersion must be 0..255', idtext)
              return
            end if
            o%maxv = int(v)
          end if
        end if
        m = jget(doc, txt, p1, 'commitment')
        if (m /= 0) then
          if (doc%kind(m) /= J_NULL) then
            ok = .false.
            if (doc%kind(m) == J_STR) then
              s = jstr(doc, txt, m)
              ok = streq(s, 'finalized') .or. streq(s, 'confirmed')
            end if
            if (.not. ok) then
              call put_error(out, -32602, 'Invalid params: commitment must be "finalized" or "confirmed"', idtext)
              return
            end if
          end if
        end if
      case default
        call put_error(out, -32602, 'Invalid params: config must be an object, a string or null', idtext)
        return
      end select
    end if
    if (o%details == DET_ACCOUNTS .and. o%encoding /= ENC_JSON) then
      call put_error(out, -32602, 'Invalid params: transactionDetails "accounts" requires encoding "json"', idtext)
      return
    end if
    ! The result is written straight into the response; on failure roll back to `mark`.
    mark = out%n
    call sb_add(out, '{"jsonrpc":"2.0","result":')
    call get_block(slot, o, out, code, msg)
    call release_decode_buffers()
    if (code /= 0) then
      out%n = mark
      if (code == -32603) write(error_unit, '(a)') 'getBlock ' // u64_str(slot) // ': ' // msg
      call put_error(out, code, msg, idtext)
      return
    end if
    call sb_add(out, ',"id":')
    call sb_add(out, idtext)
    call sb_addc(out, '}')
  end subroutine handle_get_block

  !> Epoch-boundary blocks need hundreds of MiB of scratch; give it back afterwards.
  subroutine release_decode_buffers()
    call bytes_release(slice, KEEP_BYTES)
    call bytes_release(pslice, KEEP_BYTES)
    call bytes_release(txb, KEEP_BYTES)
    call bytes_release(mframe, KEEP_BYTES)
    call bytes_release(pl, KEEP_BYTES)
    call bytes_release(rframe, KEEP_BYTES)
    call bytes_release(rpl, KEEP_BYTES)
    if (allocated(rws%rw)) then
      if (size(rws%rw) > 65536) deallocate(rws%rw)
    end if
  end subroutine release_decode_buffers

  logical function set_encoding(s, o)
    character(len=*), intent(in) :: s
    type(opts_t), intent(inout) :: o
    set_encoding = .true.
    if (streq(s, 'json')) then
      o%encoding = ENC_JSON
    else if (streq(s, 'jsonParsed')) then
      o%encoding = ENC_PARSED
    else if (streq(s, 'base64')) then
      o%encoding = ENC_B64
    else if (streq(s, 'base58')) then
      o%encoding = ENC_B58
    else
      set_encoding = .false.
    end if
  end function set_encoding

  ! ============================================================ Old Faithful reads
  !> Both range reads for `slot`; the CAR slice lands in sl.
  subroutine fetch_slot(slot, sl, code, msg)
    integer(int64), intent(in) :: slot
    type(bytes_t), intent(inout) :: sl
    integer, intent(out) :: code
    character(len=:), allocatable, intent(out) :: msg
    integer(int64) :: epoch, idx, off, ln, v1, v2
    character(len=:), allocatable :: es, fmsg
    integer :: fc, k
    code = 0
    msg = ''
    call udivmod(slot, SLOTS_PER_EPOCH, epoch, idx)
    es = u64_str(epoch)
    if (lru_get(range_cache, slot, v1, v2)) then
      off = v1
      ln = v2
    else
      call range_fetch('/' // es // '/epoch-' // es // '-slot-ranges.raw', idx * 12, idx * 12 + 11, &
                       12_int64, 12_int64, rbuf, fc, fmsg)
      if (fc == FETCH_NOTFOUND) then
        code = -32004
        msg = 'Block not available for slot ' // u64_str(slot) // ': epoch ' // es // &
              ' is not archived in Old Faithful (historical-only server)'
        return
      else if (fc /= FETCH_OK) then
        code = -32603
        msg = 'slot index read failed: ' // fmsg
        return
      end if
      off = 0
      do k = 7, 0, -1
        off = ior(shiftl(off, 8), int(ub(rbuf%d(k)), int64))
      end do
      ln = 0
      do k = 11, 8, -1
        ln = ior(shiftl(ln, 8), int(ub(rbuf%d(k)), int64))
      end do
      call lru_put(range_cache, slot, off, ln)
    end if
    if (ln == 0) then
      code = -32007
      msg = 'Slot ' // u64_str(slot) // ' was skipped, or missing in long-term storage'
      return
    end if
    if (ln > MAX_SLICE) then
      code = -32603
      msg = 'CAR slice of ' // u64_str(ln) // ' bytes exceeds the 134217728 byte limit'
      return
    end if
    if (bgt(off, not(ln - 1))) then
      code = -32603
      msg = 'CAR range overflows u64'
      return
    end if
    call range_fetch('/' // es // '/epoch-' // es // '.car', off, off + ln - 1, MAX_SLICE, ln, sl, fc, fmsg)
    if (fc == FETCH_NOTFOUND) then
      code = -32004
      msg = 'Block not available for slot ' // u64_str(slot) // ': epoch ' // es // &
            ' is not archived in Old Faithful (historical-only server)'
    else if (fc /= FETCH_OK) then
      code = -32603
      msg = 'CAR read failed: ' // fmsg
    end if
  end subroutine fetch_slot

  !> Hash of the last Entry of an indexed block (32 zero bytes when it has none).
  subroutine last_entry_hash(s, c, blk, h, e)
    type(bytes_t), intent(in) :: s
    type(car_t), intent(in) :: c
    type(block_t), intent(in) :: blk
    integer(int8), intent(out) :: h(32)
    integer, intent(out) :: e
    integer :: idx
    type(entry_t) :: ent
    e = 0
    h = 0
    if (blk%nentries == 0) return
    idx = car_find(s%d, c, blk%entries(blk%nentries))
    if (idx == 0) then
      e = 1
      car_err = 'missing Entry CID'
      return
    end if
    call parse_entry(s%d, c%npos(idx), c%nlen(idx), ent, e)
    if (e /= 0) return
    h = ent%hash
  end subroutine last_entry_hash

  subroutine sb_hash(sb, h)
    type(sb_t), intent(inout) :: sb
    integer(int8), intent(in) :: h(32)
    integer(int8) :: t(0:31)
    t = h
    call sb_addc(sb, '"')
    call sb_b58(sb, t, 0_int64, 32_int64)
    call sb_addc(sb, '"')
  end subroutine sb_hash

  ! ============================================================ getBlock
  subroutine get_block(slot, o, r, code, msg)
    integer(int64), intent(in) :: slot
    type(opts_t), intent(in) :: o
    type(sb_t), intent(inout) :: r
    integer, intent(out) :: code
    character(len=:), allocatable, intent(out) :: msg
    type(block_t) :: blk, pblk
    type(entry_t) :: ent
    type(txnode_t) :: tn
    type(dataframe_t) :: rdf
    integer(int8) :: bh(32), ph(32)
    integer(int64) :: v1, v2
    integer :: e, ei, ti, idx
    logical :: complete, has_meta, gate, first_tx
    code = 0
    msg = ''
    ! 1-3: the block itself
    call fetch_slot(slot, slice, code, msg)
    if (code /= 0) return
    call car_index(slice%d, slice%n, car, e)
    if (e /= 0) then
      call fail_decode('CAR index: ' // trim(car_err))
      return
    end if
    if (.not. car%has_block) then
      call fail_decode('no Block node in the CAR slice')
      return
    end if
    call parse_block(slice%d, car%block_pos, car%block_len, blk, e)
    if (e /= 0) then
      call fail_decode('Block node: ' // trim(car_err))
      return
    end if
    if (blk%slot /= slot) then
      call fail_decode('Block slot ' // u64_str(blk%slot) // ' does not match the request')
      return
    end if
    call last_entry_hash(slice, car, blk, bh, e)
    if (e /= 0) then
      call fail_decode('blockhash: ' // trim(car_err))
      return
    end if
    call lru_put(hash_cache, slot, 0_int64, 0_int64, bh)
    ! 4: previousBlockhash
    if (slot == 0) then
      ph = 0
    else if (.not. lru_get(hash_cache, blk%parent, v1, v2, ph)) then
      call fetch_slot(blk%parent, pslice, code, msg)
      if (code /= 0) return
      call car_index(pslice%d, pslice%n, pcar, e)
      if (e /= 0) then
        call fail_decode('parent CAR index: ' // trim(car_err))
        return
      end if
      if (.not. pcar%has_block) then
        call fail_decode('no Block node in the parent CAR slice')
        return
      end if
      call parse_block(pslice%d, pcar%block_pos, pcar%block_len, pblk, e)
      if (e /= 0) then
        call fail_decode('parent Block node: ' // trim(car_err))
        return
      end if
      call last_entry_hash(pslice, pcar, pblk, ph, e)
      if (e /= 0) then
        call fail_decode('parent blockhash: ' // trim(car_err))
        return
      end if
      call lru_put(hash_cache, blk%parent, 0_int64, 0_int64, ph)
      pslice%n = 0
    end if
    call sb_add(r, '{"previousBlockhash":')
    call sb_hash(r, ph)
    call sb_add(r, ',"blockhash":')
    call sb_hash(r, bh)
    call sb_add(r, ',"parentSlot":')
    call sb_u64(r, blk%parent)
    ! 5: transactions
    gate = .false.
    if (o%details /= DET_NONE) then
      if (o%details == DET_SIGS) then
        call sb_add(r, ',"signatures":[')
      else
        call sb_add(r, ',"transactions":[')
      end if
      first_tx = .true.
      do ei = 1, blk%nentries
        idx = car_find(slice%d, car, blk%entries(ei))
        if (idx == 0) then
          call fail_decode('missing Entry CID')
          return
        end if
        call parse_entry(slice%d, car%npos(idx), car%nlen(idx), ent, e)
        if (e /= 0) then
          call fail_decode('Entry node: ' // trim(car_err))
          return
        end if
        do ti = 1, ent%ntx
          idx = car_find(slice%d, car, ent%txs(ti))
          if (idx == 0) then
            call fail_decode('missing Transaction CID')
            return
          end if
          call parse_txnode(slice%d, car%npos(idx), car%nlen(idx), tn, e)
          if (e /= 0) then
            call fail_decode('Transaction node: ' // trim(car_err))
            return
          end if
          call reassemble(slice%d, car, tn%data, txb, e)
          if (e /= 0) then
            call fail_decode('transaction DataFrame: ' // trim(car_err))
            return
          end if
          call parse_tx(txb%d, txb%n, tx, e)
          if (e /= 0) then
            call fail_decode('undecodable VersionedTransaction')
            return
          end if
          if (o%details == DET_SIGS) then
            if (tx%nsig == 0) then
              call fail_decode('transaction without signatures')
              return
            end if
            if (.not. first_tx) call sb_addc(r, ',')
            first_tx = .false.
            call sb_addc(r, '"')
            call sb_b58(r, txb%d, tx%sig_pos, 64_int64)
            call sb_addc(r, '"')
            cycle
          end if
          call reassemble(slice%d, car, tn%meta, mframe, e)
          if (e /= 0) then
            call fail_decode('metadata DataFrame: ' // trim(car_err))
            return
          end if
          call decode_meta_frame(slot, mframe, pl, meta, has_meta, e)
          if (e /= 0) then
            call fail_decode('transaction metadata: ' // trim(meta_err))
            return
          end if
          complete = has_meta
          if (.not. has_meta .and. tx%v0) then
            call meta_default(meta)
            complete = .true.
          end if
          if (complete .and. tx%v0 .and. o%maxv < 0) then
            gate = .true.
            cycle
          end if
          if (gate) cycle
          if (.not. first_tx) call sb_addc(r, ',')
          first_tx = .false.
          call render_tx_entry(r, txb, tx, complete, meta, pl, o, e)
          if (e /= 0) then
            call fail_decode('account index out of range')
            return
          end if
        end do
      end do
      call sb_addc(r, ']')
    end if
    ! rewards
    if (o%rewards) then
      rws%n = 0
      rws%has_parts = .false.
      if (blk%has_rewards) then
        idx = car_find(slice%d, car, blk%rewards)
        if (idx /= 0) then
          call parse_rewards_node(slice%d, car%npos(idx), car%nlen(idx), rdf, e)
          if (e /= 0) then
            call fail_decode('Rewards node: ' // trim(car_err))
            return
          end if
          call reassemble(slice%d, car, rdf, rframe, e)
          if (e /= 0) then
            call fail_decode('rewards DataFrame: ' // trim(car_err))
            return
          end if
          call decode_rewards_frame(slot, rframe, rpl, rws, e)
          if (e /= 0) then
            call fail_decode('rewards: ' // trim(meta_err))
            return
          end if
        end if
      end if
      if (.not. allocated(rws%rw)) allocate(rws%rw(1))
      call sb_add(r, ',"rewards":')
      call render_reward_list(r, rws%rw, rws%n, rpl)
      if (rws%has_parts) then
        call sb_add(r, ',"numRewardPartitions":')
        call sb_u64(r, rws%parts)
      end if
    end if
    if (gate) then
      code = -32015
      msg = 'Transaction version (0) is not supported by the requesting client. ' // &
            'Please try the request again with the following configuration parameter: ' // &
            '"maxSupportedTransactionVersion": 0'
      return
    end if
    call sb_add(r, ',"blockTime":')
    if (blk%has_blocktime) then
      call sb_i64(r, blk%blocktime)
    else
      call sb_add(r, 'null')
    end if
    call sb_add(r, ',"blockHeight":')
    if (blk%has_height) then
      call sb_u64(r, blk%height)
    else
      call sb_add(r, 'null')
    end if
    call sb_addc(r, '}')
  contains
    subroutine fail_decode(m)
      character(len=*), intent(in) :: m
      code = -32603
      msg = 'Internal error: ' // m
    end subroutine fail_decode
  end subroutine get_block

end module ob_rpc
