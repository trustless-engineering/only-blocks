! ob_car: CARv1 section indexing, CIDs, a validating DAG-CBOR walker, the
! Old Faithful IPLD node schemas and DataFrame reassembly.
module ob_car
  use ob_util
  use ob_hash, only: crc64_go_iso, fnv1a64
  implicit none
  private
  public :: cid_t, car_t, dataframe_t, block_t, entry_t, txnode_t
  public :: car_index, car_find, parse_block, parse_entry, parse_txnode, parse_rewards_node
  public :: reassemble, car_err, uvarint

  integer, parameter :: CID_MAX = 128
  integer(int64), parameter :: MAX_SECTION = 33554432_int64
  integer, parameter :: MAX_DEPTH = 128

  type :: cid_t
    integer :: n = 0
    integer(int8) :: b(0:CID_MAX - 1) = 0_int8
  end type cid_t

  type :: car_t
    integer :: count = 0, nbuckets = 0, cur_stamp = 0
    integer(int64), allocatable :: cpos(:), npos(:), nlen(:)
    integer, allocatable :: clen(:), chain(:), bucket(:), stamp(:)
    logical :: has_block = .false.
    integer(int64) :: block_pos = 0, block_len = 0
  end type car_t

  type :: dataframe_t
    logical :: has_hash = .false.
    integer(int64) :: hash = 0
    integer(int64) :: dpos = -1, lim = 0    ! data item position (-1 = none) and its node end
    integer :: nnext = 0
    type(cid_t), allocatable :: next(:)
  end type dataframe_t

  type :: block_t
    integer(int64) :: slot = 0, parent = 0, blocktime = 0, height = 0
    logical :: has_blocktime = .false., has_height = .false., has_rewards = .false.
    integer :: nentries = 0
    type(cid_t), allocatable :: entries(:)
    type(cid_t) :: rewards
  end type block_t

  type :: entry_t
    integer(int8) :: hash(32) = 0_int8
    integer :: ntx = 0
    type(cid_t), allocatable :: txs(:)
  end type entry_t

  type :: txnode_t
    type(dataframe_t) :: data, meta
  end type txnode_t

  character(len=96), save :: car_err = ''

contains

  subroutine fail(e, msg)
    integer, intent(out) :: e
    character(len=*), intent(in) :: msg
    e = 1
    car_err = msg
  end subroutine fail

  ! ============================================================ varints, CIDs
  subroutine uvarint(d, pos, lim, x, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer(int64), intent(out) :: x
    integer, intent(out) :: e
    integer :: i, b, shift
    e = 0
    x = 0
    shift = 0
    do i = 0, 9
      if (pos >= lim) then
        call fail(e, 'truncated varint')
        return
      end if
      b = ub(d(pos))
      pos = pos + 1
      if (b < 128) then
        if (i == 9 .and. b > 1) then
          call fail(e, 'varint overflow')
          return
        end if
        x = ior(x, shiftl(int(b, int64), shift))
        return
      end if
      x = ior(x, shiftl(int(iand(b, 127), int64), shift))
      shift = shift + 7
    end do
    call fail(e, 'varint overflow')
  end subroutine uvarint

  !> Length of the CID at d(pos:) (bounded by lim), plus its multihash code and digest length.
  subroutine cid_parse(d, pos, lim, clen, hcode, hlen, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: pos, lim
    integer, intent(out) :: clen
    integer(int64), intent(out) :: hcode, hlen
    integer, intent(out) :: e
    integer(int64) :: p, a, b
    clen = 0
    hcode = 0
    hlen = 0
    p = pos
    call uvarint(d, p, lim, a, e)
    if (e /= 0) return
    call uvarint(d, p, lim, b, e)
    if (e /= 0) return
    if (a == 18 .and. b == 32) then
      hcode = 18
      hlen = 32
      if (lim - p < 32) then
        call fail(e, 'truncated CIDv0')
        return
      end if
      p = p + 32
    else
      if (a == 0) then
        call fail(e, 'explicit CIDv0')
        return
      end if
      if (a /= 1) then
        call fail(e, 'unsupported CID version')
        return
      end if
      call uvarint(d, p, lim, hcode, e)
      if (e /= 0) return
      call uvarint(d, p, lim, hlen, e)
      if (e /= 0) return
      if (bgt(hlen, 64_int64)) then
        call fail(e, 'CID digest too long')
        return
      end if
      if (lim - p < hlen) then
        call fail(e, 'truncated CID digest')
        return
      end if
      p = p + hlen
    end if
    if (p - pos > CID_MAX) then
      call fail(e, 'CID too long')
      return
    end if
    clen = int(p - pos)
  end subroutine cid_parse

  ! ============================================================ CBOR walker
  subroutine cb_head(d, pos, lim, major, info, arg, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer, intent(out) :: major, info
    integer(int64), intent(out) :: arg
    integer, intent(out) :: e
    integer :: ib, nb, k
    e = 0
    arg = 0
    major = 0
    info = 0
    if (pos >= lim) then
      call fail(e, 'truncated CBOR')
      return
    end if
    ib = ub(d(pos))
    pos = pos + 1
    major = shiftr(ib, 5)
    info = iand(ib, 31)
    if (info < 24) then
      arg = info
    else if (info <= 27) then
      nb = 2**(info - 24)
      if (lim - pos < nb) then
        call fail(e, 'truncated CBOR argument')
        return
      end if
      do k = 0, nb - 1
        arg = ior(shiftl(arg, 8), int(ub(d(pos + k)), int64))
      end do
      pos = pos + nb
    else if (info == 31) then
      if (major == 0 .or. major == 1 .or. major == 6) call fail(e, 'invalid indefinite length')
    else
      call fail(e, 'reserved CBOR additional info')
    end if
  end subroutine cb_head

  !> Skip (and validate) one CBOR data item.
  recursive subroutine cb_skip(d, pos, lim, depth, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer, intent(in) :: depth
    integer, intent(out) :: e
    integer :: major, info, m2, i2
    integer(int64) :: arg, a2, k, cnt
    if (depth > MAX_DEPTH) then
      call fail(e, 'CBOR nesting too deep')
      return
    end if
    call cb_head(d, pos, lim, major, info, arg, e)
    if (e /= 0) return
    select case (major)
    case (0, 1)
      continue
    case (2, 3)
      if (info == 31) then
        do
          if (pos >= lim) then
            call fail(e, 'unterminated CBOR string')
            return
          end if
          if (ub(d(pos)) == 255) then
            pos = pos + 1
            exit
          end if
          call cb_head(d, pos, lim, m2, i2, a2, e)
          if (e /= 0) return
          if (m2 /= major .or. i2 == 31) then
            call fail(e, 'bad CBOR string chunk')
            return
          end if
          if (bgt(a2, lim - pos)) then
            call fail(e, 'truncated CBOR string')
            return
          end if
          if (major == 3) then
            if (.not. utf8_ok(d, pos, a2)) then
              call fail(e, 'invalid UTF-8 in CBOR text')
              return
            end if
          end if
          pos = pos + a2
        end do
      else
        if (bgt(arg, lim - pos)) then
          call fail(e, 'truncated CBOR string')
          return
        end if
        if (major == 3) then
          if (.not. utf8_ok(d, pos, arg)) then
            call fail(e, 'invalid UTF-8 in CBOR text')
            return
          end if
        end if
        pos = pos + arg
      end if
    case (4, 5)
      if (info == 31) then
        do
          if (pos >= lim) then
            call fail(e, 'unterminated CBOR container')
            return
          end if
          if (ub(d(pos)) == 255) then
            pos = pos + 1
            exit
          end if
          call cb_skip(d, pos, lim, depth + 1, e)
          if (e /= 0) return
          if (major == 5) then
            call cb_skip(d, pos, lim, depth + 1, e)
            if (e /= 0) return
          end if
        end do
      else
        if (bgt(arg, lim - pos)) then
          call fail(e, 'CBOR container longer than its input')
          return
        end if
        cnt = arg
        if (major == 5) cnt = 2 * arg
        do k = 1, cnt
          call cb_skip(d, pos, lim, depth + 1, e)
          if (e /= 0) return
        end do
      end if
    case (6)
      call cb_skip(d, pos, lim, depth + 1, e)
    case default
      if (info == 31) then
        call fail(e, 'unexpected CBOR break')
      else if (info < 20 .or. info == 24) then
        call fail(e, 'unsupported CBOR simple value')
      end if
    end select
  end subroutine cb_skip

  !> The node bytes must hold exactly one CBOR item.
  subroutine node_validate(d, p, n, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer, intent(out) :: e
    integer(int64) :: q
    q = p
    call cb_skip(d, q, p + n, 0, e)
    if (e /= 0) return
    if (q /= p + n) call fail(e, 'trailing bytes after CBOR node')
  end subroutine node_validate

  subroutine cb_untag(d, pos, lim)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer :: major, info, e
    integer(int64) :: arg, q
    do while (pos < lim)
      if (shiftr(ub(d(pos)), 5) /= 6) exit
      q = pos
      call cb_head(d, q, lim, major, info, arg, e)
      if (e /= 0) exit
      pos = q
    end do
  end subroutine cb_untag

  !> Major type (after tags) of the item at p; info is its additional info.
  subroutine item_type(d, p, lim, major, info)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, lim
    integer, intent(out) :: major, info
    integer(int64) :: q
    q = p
    call cb_untag(d, q, lim)
    major = -1
    info = -1
    if (q >= lim) return
    major = shiftr(ub(d(q)), 5)
    info = iand(ub(d(q)), 31)
  end subroutine item_type

  subroutine item_u64(d, p, lim, v, ok)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, lim
    integer(int64), intent(out) :: v
    logical, intent(out) :: ok
    integer(int64) :: q
    integer :: major, info, e
    q = p
    ok = .false.
    v = 0
    call cb_untag(d, q, lim)
    call cb_head(d, q, lim, major, info, v, e)
    if (e /= 0) return
    ok = (major == 0)
    if (.not. ok) v = 0
  end subroutine item_u64

  subroutine item_i64(d, p, lim, v, ok)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, lim
    integer(int64), intent(out) :: v
    logical, intent(out) :: ok
    integer(int64) :: q, arg
    integer :: major, info, e
    q = p
    ok = .false.
    v = 0
    call cb_untag(d, q, lim)
    call cb_head(d, q, lim, major, info, arg, e)
    if (e /= 0) return
    if (major == 0 .and. arg >= 0) then
      v = arg
      ok = .true.
    else if (major == 1 .and. arg >= 0) then
      v = -1_int64 - arg
      ok = .true.
    end if
  end subroutine item_i64

  !> Element start positions of the array at p (after tags). isarr = .false. if not an array.
  subroutine item_array(d, p, lim, st, cnt, isarr, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, lim
    integer(int64), allocatable, intent(inout) :: st(:)
    integer, intent(out) :: cnt
    logical, intent(out) :: isarr
    integer, intent(out) :: e
    integer(int64) :: q, arg, k
    integer :: major, info
    e = 0
    cnt = 0
    isarr = .false.
    q = p
    call cb_untag(d, q, lim)
    if (q >= lim) return
    if (shiftr(ub(d(q)), 5) /= 4) return
    call cb_head(d, q, lim, major, info, arg, e)
    if (e /= 0) return
    isarr = .true.
    if (.not. allocated(st)) allocate(st(16))
    if (info == 31) then
      do
        if (q >= lim) then
          call fail(e, 'unterminated array')
          return
        end if
        if (ub(d(q)) == 255) exit
        call push(q)
        call cb_skip(d, q, lim, 1, e)
        if (e /= 0) return
      end do
    else
      if (bgt(arg, lim - q)) then
        call fail(e, 'array longer than its input')
        return
      end if
      do k = 1, arg
        call push(q)
        call cb_skip(d, q, lim, 1, e)
        if (e /= 0) return
      end do
    end if
  contains
    subroutine push(v)
      integer(int64), intent(in) :: v
      integer(int64), allocatable :: t(:)
      if (cnt >= size(st)) then
        allocate(t(2 * size(st)))
        t(1:cnt) = st(1:cnt)
        call move_alloc(t, st)
      end if
      cnt = cnt + 1
      st(cnt) = v
    end subroutine push
  end subroutine item_array

  !> Append the content of the byte string at p to out. isbytes = .false. if not a byte string.
  subroutine item_bytes_append(d, p, lim, out, isbytes, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, lim
    type(bytes_t), intent(inout) :: out
    logical, intent(out) :: isbytes
    integer, intent(out) :: e
    integer(int64) :: q, arg, a2
    integer :: major, info, m2, i2
    e = 0
    isbytes = .false.
    q = p
    call cb_untag(d, q, lim)
    if (q >= lim) return
    if (shiftr(ub(d(q)), 5) /= 2) return
    isbytes = .true.
    call cb_head(d, q, lim, major, info, arg, e)
    if (e /= 0) return
    if (info /= 31) then
      if (bgt(arg, lim - q)) then
        call fail(e, 'truncated byte string')
        return
      end if
      call bytes_append(out, d, q, arg)
      return
    end if
    do
      if (q >= lim) then
        call fail(e, 'unterminated byte string')
        return
      end if
      if (ub(d(q)) == 255) exit
      call cb_head(d, q, lim, m2, i2, a2, e)
      if (e /= 0) return
      if (bgt(a2, lim - q)) then
        call fail(e, 'truncated byte string')
        return
      end if
      call bytes_append(out, d, q, a2)
      q = q + a2
    end do
  end subroutine item_bytes_append

  !> Decode a CID link: a byte string 00 <cid> (tag 42 already discarded).
  subroutine item_link(d, p, lim, cid, hcode, hlen, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, lim
    type(cid_t), intent(out) :: cid
    integer(int64), intent(out) :: hcode, hlen
    integer, intent(out) :: e
    type(bytes_t) :: tb
    logical :: isb
    integer :: clen
    call bytes_reserve(tb, 64_int64)
    call item_bytes_append(d, p, lim, tb, isb, e)
    if (e /= 0) return
    if (.not. isb) then
      call fail(e, 'link is not a byte string')
      return
    end if
    if (tb%n == 0) then
      call fail(e, 'empty CID link')
      return
    end if
    if (tb%d(0) /= 0) then
      call fail(e, 'CID link without identity multibase prefix')
      return
    end if
    call cid_parse(tb%d, 1_int64, tb%n, clen, hcode, hlen, e)
    if (e /= 0) return
    cid%n = clen
    cid%b(0:clen - 1) = tb%d(1:clen)
  end subroutine item_link

  !> Every element of the array at p must be a link.
  subroutine item_links(d, p, lim, cids, n, isarr, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, lim
    type(cid_t), allocatable, intent(inout) :: cids(:)
    integer, intent(out) :: n
    logical, intent(out) :: isarr
    integer, intent(out) :: e
    integer(int64), allocatable :: st(:)
    integer :: k
    integer(int64) :: hc, hl
    n = 0
    call item_array(d, p, lim, st, n, isarr, e)
    if (e /= 0 .or. .not. isarr) return
    if (allocated(cids)) deallocate(cids)
    allocate(cids(max(n, 1)))
    do k = 1, n
      call item_link(d, st(k), lim, cids(k), hc, hl, e)
      if (e /= 0) return
    end do
  end subroutine item_links

  ! ============================================================ CAR index
  integer function cid_bucket(d, p, n, nb)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p
    integer, intent(in) :: n, nb
    cid_bucket = int(iand(fnv1a64(d, p, int(n, int64)), int(nb - 1, int64)))
  end function cid_bucket

  subroutine car_index(s, sn, car, e)
    integer(int8), intent(in) :: s(0:)
    integer(int64), intent(in) :: sn
    type(car_t), intent(inout) :: car
    integer, intent(out) :: e
    integer(int64) :: pos, l, sec_end, npos, nlen, hc, hl
    integer :: clen, b, info, hlen, nb
    logical :: first
    e = 0
    nb = 1024
    do while (nb < sn / 64 .and. nb < 4194304)
      nb = nb * 2
    end do
    if (allocated(car%bucket)) deallocate(car%bucket)
    allocate(car%bucket(0:nb - 1))
    car%bucket = 0
    car%nbuckets = nb
    car%count = 0
    car%cur_stamp = 0
    car%has_block = .false.
    if (.not. allocated(car%cpos)) then
      allocate(car%cpos(256), car%npos(256), car%nlen(256), car%clen(256), car%chain(256), car%stamp(256))
    end if
    pos = 0
    first = .true.
    do while (pos < sn)
      call uvarint(s, pos, sn, l, e)
      if (e /= 0) return
      if (l == 0) cycle
      if (bgt(l, MAX_SECTION)) then
        call fail(e, 'CAR section too large')
        return
      end if
      if (bgt(l, sn - pos)) then
        call fail(e, 'truncated CAR section')
        return
      end if
      sec_end = pos + l
      if (first) then
        first = .false.
        if (shiftr(ub(s(pos)), 5) == 5) then
          if (is_car_header(s, pos, sec_end)) then
            pos = sec_end
            cycle
          end if
        end if
      end if
      call cid_parse(s, pos, sec_end, clen, hc, hl, e)
      if (e /= 0) return
      npos = pos + clen
      nlen = sec_end - npos
      call insert(pos, clen, npos, nlen)
      if (nlen > 0) then
        b = ub(s(npos))
        if (shiftr(b, 5) == 4) then
          info = iand(b, 31)
          hlen = -1
          if (info < 24 .or. info == 31) then
            hlen = 1
          else if (info == 24) then
            hlen = 2
          else if (info == 25) then
            hlen = 3
          else if (info == 26) then
            hlen = 5
          else if (info == 27) then
            hlen = 9
          end if
          if (hlen > 0) then
            if (npos + hlen < sec_end) then
              if (ub(s(npos + hlen)) == 2) then
                car%has_block = .true.
                car%block_pos = npos
                car%block_len = nlen
              end if
            end if
          end if
        end if
      end if
      pos = sec_end
    end do
  contains
    subroutine insert(cp, cl, np, nl)
      integer(int64), intent(in) :: cp, np, nl
      integer, intent(in) :: cl
      integer :: bk, i
      bk = cid_bucket(s, cp, cl, car%nbuckets)
      i = car%bucket(bk)
      do while (i /= 0)
        if (car%clen(i) == cl) then
          if (all(s(car%cpos(i):car%cpos(i) + cl - 1) == s(cp:cp + cl - 1))) then
            car%npos(i) = np
            car%nlen(i) = nl
            return
          end if
        end if
        i = car%chain(i)
      end do
      if (car%count >= size(car%cpos)) call grow_index()
      car%count = car%count + 1
      i = car%count
      car%cpos(i) = cp
      car%clen(i) = cl
      car%npos(i) = np
      car%nlen(i) = nl
      car%stamp(i) = 0
      car%chain(i) = car%bucket(bk)
      car%bucket(bk) = i
    end subroutine insert
    subroutine grow_index()
      integer :: cap
      integer(int64), allocatable :: t8(:)
      integer, allocatable :: t4(:)
      cap = 2 * size(car%cpos)
      allocate(t8(cap)); t8(1:car%count) = car%cpos(1:car%count); call move_alloc(t8, car%cpos)
      allocate(t8(cap)); t8(1:car%count) = car%npos(1:car%count); call move_alloc(t8, car%npos)
      allocate(t8(cap)); t8(1:car%count) = car%nlen(1:car%count); call move_alloc(t8, car%nlen)
      allocate(t4(cap)); t4(1:car%count) = car%clen(1:car%count); call move_alloc(t4, car%clen)
      allocate(t4(cap)); t4(1:car%count) = car%chain(1:car%count); call move_alloc(t4, car%chain)
      allocate(t4(cap)); t4(1:car%count) = car%stamp(1:car%count); call move_alloc(t4, car%stamp)
    end subroutine grow_index
  end subroutine car_index

  !> A first section that is one CBOR map with a text key "version" is a CARv1 header.
  logical function is_car_header(s, p, lim)
    integer(int8), intent(in) :: s(0:)
    integer(int64), intent(in) :: p, lim
    integer(int64) :: q, arg, k, kq, karg
    integer :: e, major, info, km, ki
    is_car_header = .false.
    q = p
    call cb_skip(s, q, lim, 0, e)
    if (e /= 0 .or. q /= lim) return
    q = p
    call cb_head(s, q, lim, major, info, arg, e)
    if (e /= 0 .or. major /= 5) return
    k = 0
    do
      if (info == 31) then
        if (q >= lim) return
        if (ub(s(q)) == 255) return
      else
        if (k >= arg) return
      end if
      k = k + 1
      kq = q
      call cb_head(s, kq, lim, km, ki, karg, e)
      if (e /= 0) return
      if (km == 3 .and. ki /= 31 .and. karg == 7) then
        if (kq + 7 <= lim) then
          if (all(s(kq:kq + 6) == [118_int8, 101_int8, 114_int8, 115_int8, 105_int8, 111_int8, 110_int8])) then
            is_car_header = .true.
            return
          end if
        end if
      end if
      call cb_skip(s, q, lim, 1, e)
      if (e /= 0) return
      call cb_skip(s, q, lim, 1, e)
      if (e /= 0) return
    end do
  end function is_car_header

  integer function car_find(s, car, cid)
    integer(int8), intent(in) :: s(0:)
    type(car_t), intent(in) :: car
    type(cid_t), intent(in) :: cid
    integer :: bk, i
    car_find = 0
    if (car%nbuckets == 0 .or. cid%n == 0) return
    bk = int(iand(fnv1a64(cid%b, 0_int64, int(cid%n, int64)), int(car%nbuckets - 1, int64)))
    i = car%bucket(bk)
    do while (i /= 0)
      if (car%clen(i) == cid%n) then
        if (all(s(car%cpos(i):car%cpos(i) + cid%n - 1) == cid%b(0:cid%n - 1))) then
          car_find = i
          return
        end if
      end if
      i = car%chain(i)
    end do
  end function car_find

  ! ============================================================ node schemas
  !> Check node kind: array whose [0] is the integer `kind`. Returns element starts.
  subroutine node_elems(d, p, lim, kind, st, cnt, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, lim
    integer, intent(in) :: kind
    integer(int64), allocatable, intent(inout) :: st(:)
    integer, intent(out) :: cnt
    integer, intent(out) :: e
    logical :: isarr, ok
    integer(int64) :: k
    call item_array(d, p, lim, st, cnt, isarr, e)
    if (e /= 0) return
    if (.not. isarr) then
      call fail(e, 'node is not an array')
      return
    end if
    if (cnt < 1) then
      call fail(e, 'node without a kind')
      return
    end if
    call item_u64(d, st(1), lim, k, ok)
    if (.not. ok .or. k /= kind) then
      call fail(e, 'unexpected node kind')
      return
    end if
  end subroutine node_elems

  !> DataFrame at item position p inside a node ending at lim.
  subroutine parse_dataframe_at(d, p, lim, df, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, lim
    type(dataframe_t), intent(inout) :: df
    integer, intent(out) :: e
    integer(int64), allocatable :: st(:)
    integer :: cnt, major, info, n
    logical :: ok, isarr
    df%has_hash = .false.
    df%hash = 0
    df%dpos = -1
    df%lim = lim
    df%nnext = 0
    call node_elems(d, p, lim, 6, st, cnt, e)
    if (e /= 0) return
    if (cnt >= 2) then
      call item_u64(d, st(2), lim, df%hash, ok)
      df%has_hash = ok
    end if
    if (cnt >= 5) then
      call item_type(d, st(5), lim, major, info)
      if (major == 2) df%dpos = st(5)
    end if
    if (cnt >= 6) then
      call item_type(d, st(6), lim, major, info)
      if (major == 4) then
        call item_links(d, st(6), lim, df%next, n, isarr, e)
        if (e /= 0) return
        df%nnext = n
      end if
    end if
  end subroutine parse_dataframe_at

  subroutine empty_dataframe(df)
    type(dataframe_t), intent(inout) :: df
    df%has_hash = .false.
    df%hash = 0
    df%dpos = -1
    df%lim = 0
    df%nnext = 0
  end subroutine empty_dataframe

  subroutine parse_block(s, p, n, blk, e)
    integer(int8), intent(in) :: s(0:)
    integer(int64), intent(in) :: p, n
    type(block_t), intent(inout) :: blk
    integer, intent(out) :: e
    integer(int64), allocatable :: st(:), mt(:)
    integer :: cnt, mcnt, major, info, ne
    integer(int64) :: lim, v, hc, hl
    logical :: ok, isarr
    lim = p + n
    call node_validate(s, p, n, e)
    if (e /= 0) return
    call node_elems(s, p, lim, 2, st, cnt, e)
    if (e /= 0) return
    blk%slot = 0
    ok = .false.
    if (cnt >= 2) call item_u64(s, st(2), lim, blk%slot, ok)
    if (.not. ok) then
      call fail(e, 'block without a slot')
      return
    end if
    blk%nentries = 0
    if (cnt >= 4) then
      call item_type(s, st(4), lim, major, info)
      if (major == 4) then
        call item_links(s, st(4), lim, blk%entries, ne, isarr, e)
        if (e /= 0) return
        blk%nentries = ne
      end if
    end if
    blk%parent = 0
    blk%has_blocktime = .false.
    blk%blocktime = 0
    blk%has_height = .false.
    blk%height = 0
    if (cnt >= 5) then
      call item_array(s, st(5), lim, mt, mcnt, isarr, e)
      if (e /= 0) return
      if (isarr) then
        if (mcnt >= 1) then
          call item_u64(s, mt(1), lim, v, ok)
          if (ok) blk%parent = v
        end if
        if (mcnt >= 2) then
          call item_i64(s, mt(2), lim, v, ok)
          if (ok .and. v /= 0) then
            blk%has_blocktime = .true.
            blk%blocktime = v
          end if
        end if
        if (mcnt >= 3) then
          call item_u64(s, mt(3), lim, v, ok)
          if (ok) then
            blk%has_height = .true.
            blk%height = v
          end if
        end if
      end if
    end if
    blk%has_rewards = .false.
    if (cnt >= 6) then
      call item_type(s, st(6), lim, major, info)
      if (major == 2) then
        call item_link(s, st(6), lim, blk%rewards, hc, hl, e)
        if (e /= 0) return
        blk%has_rewards = .not. (hc == 0 .and. hl == 0)
      end if
    end if
  end subroutine parse_block

  subroutine parse_entry(s, p, n, ent, e)
    integer(int8), intent(in) :: s(0:)
    integer(int64), intent(in) :: p, n
    type(entry_t), intent(inout) :: ent
    integer, intent(out) :: e
    integer(int64), allocatable :: st(:)
    integer :: cnt, major, info, nt
    integer(int64) :: lim
    logical :: isb, isarr
    type(bytes_t) :: hb
    lim = p + n
    call node_validate(s, p, n, e)
    if (e /= 0) return
    call node_elems(s, p, lim, 1, st, cnt, e)
    if (e /= 0) return
    if (cnt < 3) then
      call fail(e, 'entry without a hash')
      return
    end if
    call bytes_reserve(hb, 32_int64)
    call item_bytes_append(s, st(3), lim, hb, isb, e)
    if (e /= 0) return
    if (.not. isb .or. hb%n /= 32) then
      call fail(e, 'entry hash is not 32 bytes')
      return
    end if
    ent%hash = hb%d(0:31)
    ent%ntx = 0
    if (cnt >= 4) then
      call item_type(s, st(4), lim, major, info)
      if (major == 4) then
        call item_links(s, st(4), lim, ent%txs, nt, isarr, e)
        if (e /= 0) return
        ent%ntx = nt
      end if
    end if
  end subroutine parse_entry

  subroutine parse_txnode(s, p, n, tx, e)
    integer(int8), intent(in) :: s(0:)
    integer(int64), intent(in) :: p, n
    type(txnode_t), intent(inout) :: tx
    integer, intent(out) :: e
    integer(int64), allocatable :: st(:)
    integer :: cnt, major, info
    integer(int64) :: lim
    lim = p + n
    call node_validate(s, p, n, e)
    if (e /= 0) return
    call node_elems(s, p, lim, 0, st, cnt, e)
    if (e /= 0) return
    if (cnt < 2) then
      call fail(e, 'transaction without data')
      return
    end if
    call parse_dataframe_at(s, st(2), lim, tx%data, e)
    if (e /= 0) return
    call empty_dataframe(tx%meta)
    if (cnt >= 3) then
      call item_type(s, st(3), lim, major, info)
      if (major == 4) then
        call parse_dataframe_at(s, st(3), lim, tx%meta, e)
        if (e /= 0) return
      end if
    end if
  end subroutine parse_txnode

  subroutine parse_rewards_node(s, p, n, df, e)
    integer(int8), intent(in) :: s(0:)
    integer(int64), intent(in) :: p, n
    type(dataframe_t), intent(inout) :: df
    integer, intent(out) :: e
    integer(int64), allocatable :: st(:)
    integer :: cnt, major, info
    integer(int64) :: lim
    lim = p + n
    call node_validate(s, p, n, e)
    if (e /= 0) return
    call node_elems(s, p, lim, 5, st, cnt, e)
    if (e /= 0) return
    call empty_dataframe(df)
    if (cnt >= 3) then
      call item_type(s, st(3), lim, major, info)
      if (.not. (major == 7 .and. (info == 22 .or. info == 23))) then
        call parse_dataframe_at(s, st(3), lim, df, e)
      end if
    end if
  end subroutine parse_rewards_node

  ! ============================================================ reassembly
  subroutine append_df_data(s, df, out, e)
    integer(int8), intent(in) :: s(0:)
    type(dataframe_t), intent(in) :: df
    type(bytes_t), intent(inout) :: out
    integer, intent(out) :: e
    logical :: isb
    e = 0
    if (df%dpos < 0) return
    call item_bytes_append(s, df%dpos, df%lim, out, isb, e)
  end subroutine append_df_data

  !> Concatenate a DataFrame chain (iterative DFS) and verify the first frame's hash.
  subroutine reassemble(s, car, first, out, e)
    integer(int8), intent(in) :: s(0:)
    type(car_t), intent(inout) :: car
    type(dataframe_t), intent(in) :: first
    type(bytes_t), intent(inout) :: out
    integer, intent(out) :: e
    type(cid_t), allocatable :: stack(:)
    type(dataframe_t) :: fr
    type(cid_t) :: cid
    integer :: sp, k, idx
    out%n = 0
    call bytes_reserve(out, 256_int64)
    call append_df_data(s, first, out, e)
    if (e /= 0) return
    if (first%nnext > 0) then
      car%cur_stamp = car%cur_stamp + 1
      allocate(stack(max(16, 2 * first%nnext)))
      sp = 0
      do k = first%nnext, 1, -1
        call push(first%next(k))
      end do
      do while (sp > 0)
        cid = stack(sp)
        sp = sp - 1
        idx = car_find(s, car, cid)
        if (idx == 0) then
          call fail(e, 'missing DataFrame CID')
          return
        end if
        if (car%stamp(idx) == car%cur_stamp) then
          call fail(e, 'cyclic DataFrame')
          return
        end if
        car%stamp(idx) = car%cur_stamp
        call node_validate(s, car%npos(idx), car%nlen(idx), e)
        if (e /= 0) return
        call parse_dataframe_at(s, car%npos(idx), car%npos(idx) + car%nlen(idx), fr, e)
        if (e /= 0) return
        call append_df_data(s, fr, out, e)
        if (e /= 0) return
        do k = fr%nnext, 1, -1
          call push(fr%next(k))
        end do
      end do
    end if
    if (first%has_hash) then
      if (crc64_go_iso(out%d, 0_int64, out%n) /= first%hash) then
        if (fnv1a64(out%d, 0_int64, out%n) /= first%hash) then
          call fail(e, 'DataFrame hash mismatch')
          return
        end if
      end if
    end if
  contains
    subroutine push(c)
      type(cid_t), intent(in) :: c
      type(cid_t), allocatable :: t(:)
      if (sp >= size(stack)) then
        allocate(t(2 * size(stack)))
        t(1:sp) = stack(1:sp)
        call move_alloc(t, stack)
      end if
      sp = sp + 1
      stack(sp) = c
    end subroutine push
  end subroutine reassemble

end module ob_car
