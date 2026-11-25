! ob_zstd: a decode-only RFC 8878 Zstandard decoder, ported line by line from
! docs/ZSTD_MINI_SPEC.md. Every bounds or format violation returns e /= 0.
module ob_zstd
  use ob_util
  use ob_hash, only: xxh64
  implicit none
  private
  public :: zstd_decompress, ZSTD_MAX_OUT, zstd_err

  integer(int64), parameter :: ZSTD_MAX_OUT = 536870912_int64
  integer(int64), parameter :: BLOCK_SIZE_MAX = 131072_int64

  integer, parameter :: LL_BASE(0:35) = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, &
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, &
    8192, 16384, 32768, 65536]
  integer, parameter :: LL_BITS(0:35) = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, &
    13, 14, 15, 16]
  integer, parameter :: ML_BASE(0:52) = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, &
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, &
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, &
    4099, 8195, 16387, 32771, 65539]
  integer, parameter :: ML_BITS(0:52) = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, &
    12, 13, 14, 15, 16]
  integer, parameter :: LL_DEFAULT(0:35) = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, &
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, &
    -1, -1, -1, -1]
  integer, parameter :: ML_DEFAULT(0:52) = [1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, &
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, &
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, &
    -1, -1, -1, -1, -1]
  integer, parameter :: OF_DEFAULT(0:28) = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, &
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1]
  ! kinds: 1 = literals length, 2 = offset, 3 = match length
  integer, parameter :: KIND_MAX_SYM(3) = [35, 31, 52]
  integer, parameter :: KIND_MAX_LOG(3) = [9, 8, 9]

  !> tANS decoding table: symbol, bits to read, baseline per cell.
  type :: fse_t
    integer :: alog = 0
    integer :: sym(0:511) = 0, nb(0:511) = 0, base(0:511) = 0
  end type fse_t

  type :: huf_t
    integer :: max_bits = 0
    integer :: sym(0:2047) = 0, nb(0:2047) = 0
  end type huf_t

  type :: frame_t
    integer(int64) :: rep(3) = [1_int64, 4_int64, 8_int64]
    logical :: has_huf = .false.
    type(huf_t) :: huf
    logical :: has_t(3) = .false.
    type(fse_t) :: t(3)
  end type frame_t

  type :: bbits_t
    integer(int64) :: start = 0, bits = 0
  end type bbits_t

  type(fse_t), save :: predef(3)
  logical, save :: predef_ready = .false.

  ! Per-block scratch, grown on demand.
  integer(int8), allocatable, save :: lit(:)
  integer(int64), allocatable, save :: seq_ll(:), seq_of(:), seq_ml(:)

  character(len=64), save :: zstd_err = ''

contains

  subroutine fail(e, msg)
    integer, intent(out) :: e
    character(len=*), intent(in) :: msg
    e = 1
    zstd_err = msg
  end subroutine fail

  pure integer(int64) function le(d, pos, n)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: pos
    integer, intent(in) :: n
    integer :: i
    le = 0
    do i = n - 1, 0, -1
      le = ior(shiftl(le, 8), int(ub(d(pos + i)), int64))
    end do
  end function le

  ! ------------------------------------------------------------ bitstreams
  subroutine br_init(d, dn, start, end_, br, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: dn, start, end_
    type(bbits_t), intent(out) :: br
    integer, intent(out) :: e
    integer :: last
    e = 0
    if (start < 0 .or. end_ > dn .or. end_ <= start) then
      call fail(e, 'empty or out-of-range bitstream')
      return
    end if
    last = ub(d(end_ - 1))
    if (last == 0) then
      call fail(e, 'bitstream end marker missing')
      return
    end if
    br%start = start
    br%bits = 8_int64 * (end_ - start - 1) + highbit(int(last, int64))
  end subroutine br_init

  pure integer(int64) function window(d, start, lo, hi)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: start, lo, hi
    integer(int64) :: first, last, k, w
    first = shiftr(lo, 3)
    last = shiftr(hi - 1, 3)
    w = 0
    do k = last, first, -1
      w = ior(shiftl(w, 8), int(ub(d(start + k)), int64))
    end do
    window = iand(shiftr(w, int(iand(lo, 7_int64))), shiftl(1_int64, int(hi - lo)) - 1)
  end function window

  pure integer(int64) function br_peek(d, br, n)
    integer(int8), intent(in) :: d(0:)
    type(bbits_t), intent(in) :: br
    integer, intent(in) :: n
    integer(int64) :: lo, hi
    hi = br%bits
    lo = hi - n
    if (n == 0 .or. hi <= 0) then
      br_peek = 0
    else if (lo < 0) then
      br_peek = shiftl(window(d, br%start, 0_int64, hi), int(-lo))
    else
      br_peek = window(d, br%start, lo, hi)
    end if
  end function br_peek

  integer(int64) function br_read(d, br, n)
    integer(int8), intent(in) :: d(0:)
    type(bbits_t), intent(inout) :: br
    integer, intent(in) :: n
    br_read = br_peek(d, br, n)
    br%bits = br%bits - n
  end function br_read

  ! ------------------------------------------------------------ FSE
  subroutine read_fse_desc(d, pos, limit, max_symbol, max_log, probs, nprobs, alog, endp, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: pos, limit
    integer, intent(in) :: max_symbol, max_log
    integer, intent(out) :: probs(0:), nprobs, alog
    integer(int64), intent(out) :: endp
    integer, intent(out) :: e
    integer(int64) :: bitpos
    integer :: remaining, threshold, nbits, biggest, low, value, prob, rep
    e = 0
    nprobs = 0
    endp = pos
    bitpos = pos * 8
    alog = take(4) + 5
    if (alog > max_log) then
      call fail(e, 'FSE accuracy log too large')
      return
    end if
    remaining = 2**alog + 1
    threshold = 2**alog
    nbits = alog + 1
    do while (remaining > 1)
      if (nprobs > max_symbol) then
        call fail(e, 'FSE description has too many symbols')
        return
      end if
      biggest = 2 * threshold - 1 - remaining
      low = peek(nbits - 1)
      if (low < biggest) then
        value = low
        bitpos = bitpos + (nbits - 1)
      else
        value = take(nbits)
        if (value >= threshold) value = value - biggest
      end if
      prob = value - 1
      probs(nprobs) = prob
      nprobs = nprobs + 1
      remaining = remaining - abs(prob)
      if (prob == 0) then
        do
          rep = take(2)
          if (nprobs + rep > max_symbol + 1) then
            call fail(e, 'corrupt FSE description')
            return
          end if
          if (rep > 0) probs(nprobs:nprobs + rep - 1) = 0
          nprobs = nprobs + rep
          if (rep /= 3) exit
        end do
      end if
      do while (remaining < threshold)
        nbits = nbits - 1
        threshold = threshold / 2
      end do
    end do
    if (remaining /= 1 .or. nprobs > max_symbol + 1) then
      call fail(e, 'corrupt FSE description')
      return
    end if
    endp = (bitpos + 7) / 8
    if (endp > limit) call fail(e, 'FSE description overruns its section')
  contains
    integer function peek(n)
      integer, intent(in) :: n
      integer :: i
      integer(int64) :: q
      peek = 0
      do i = 0, n - 1
        q = bitpos + i
        if (shiftr(q, 3) < limit) then
          if (btest(ub(d(shiftr(q, 3))), int(iand(q, 7_int64)))) peek = ibset(peek, i)
        end if
      end do
    end function peek
    integer function take(n)
      integer, intent(in) :: n
      take = peek(n)
      bitpos = bitpos + n
    end function take
  end subroutine read_fse_desc

  subroutine build_fse(probs, nprobs, alog, t, e)
    integer, intent(in) :: probs(0:), nprobs, alog
    type(fse_t), intent(out) :: t
    integer, intent(out) :: e
    integer :: size, high, s, p, step, mask, pos, k, cell, x, nb
    integer :: cell_sym(0:511), counter(0:255)
    e = 0
    size = 2**alog
    high = size - 1
    cell_sym = 0
    do s = 0, nprobs - 1
      p = probs(s)
      if (p == -1) then
        if (high < 0) then
          call fail(e, 'corrupt FSE distribution')
          return
        end if
        cell_sym(high) = s
        high = high - 1
        counter(s) = 1
      else
        counter(s) = p
      end if
    end do
    step = size / 2 + size / 8 + 3
    mask = size - 1
    pos = 0
    do s = 0, nprobs - 1
      p = probs(s)
      do k = 1, max(p, 0)
        cell_sym(pos) = s
        pos = iand(pos + step, mask)
        do while (pos > high)
          pos = iand(pos + step, mask)
        end do
      end do
    end do
    if (pos /= 0) then
      call fail(e, 'corrupt FSE distribution')
      return
    end if
    t%alog = alog
    do cell = 0, size - 1
      s = cell_sym(cell)
      x = counter(s)
      counter(s) = counter(s) + 1
      if (x <= 0) then
        call fail(e, 'corrupt FSE distribution')
        return
      end if
      nb = alog - highbit(int(x, int64))
      t%sym(cell) = s
      t%nb(cell) = nb
      t%base(cell) = shiftl(x, nb) - size
    end do
  end subroutine build_fse

  subroutine init_predef()
    integer :: e
    integer :: pr(0:255)
    pr = 0
    pr(0:35) = LL_DEFAULT
    call build_fse(pr, 36, 6, predef(1), e)
    pr = 0
    pr(0:28) = OF_DEFAULT
    call build_fse(pr, 29, 5, predef(2), e)
    pr = 0
    pr(0:52) = ML_DEFAULT
    call build_fse(pr, 53, 6, predef(3), e)
    predef_ready = .true.
  end subroutine init_predef

  ! ------------------------------------------------------------ Huffman
  subroutine build_huffman(w, nw, h, e)
    integer, intent(inout) :: w(0:)
    integer, intent(in) :: nw
    type(huf_t), intent(out) :: h
    integer, intent(out) :: e
    integer :: total, i, mb, rest, nall, ww, start, sym, k
    integer :: next_cell(0:12), cnt(0:12)
    e = 0
    if (nw > 255) then
      call fail(e, 'too many Huffman weights')
      return
    end if
    total = 0
    do i = 0, nw - 1
      if (w(i) > 11) then
        call fail(e, 'Huffman weight too large')
        return
      end if
      if (w(i) > 0) total = total + 2**(w(i) - 1)
    end do
    if (total == 0) then
      call fail(e, 'empty Huffman table')
      return
    end if
    mb = highbit(int(total, int64)) + 1
    if (mb > 11) then
      call fail(e, 'Huffman code too long')
      return
    end if
    rest = 2**mb - total
    if (iand(rest, rest - 1) /= 0) then
      call fail(e, 'corrupt Huffman weights')
      return
    end if
    w(nw) = highbit(int(rest, int64)) + 1
    nall = nw + 1
    cnt = 0
    do i = 0, nall - 1
      if (w(i) > 0) cnt(w(i)) = cnt(w(i)) + 1
    end do
    start = 0
    do ww = 1, mb
      next_cell(ww) = start
      start = start + cnt(ww) * 2**(ww - 1)
    end do
    h%max_bits = mb
    do sym = 0, nall - 1
      ww = w(sym)
      if (ww == 0) cycle
      do k = next_cell(ww), next_cell(ww) + 2**(ww - 1) - 1
        h%sym(k) = sym
        h%nb(k) = mb + 1 - ww
      end do
      next_cell(ww) = next_cell(ww) + 2**(ww - 1)
    end do
  end subroutine build_huffman

  subroutine read_huf_desc(d, dn, pos, limit, h, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: dn, limit
    integer(int64), intent(inout) :: pos
    type(huf_t), intent(out) :: h
    integer, intent(out) :: e
    integer :: hb, n, i, b, nw, nprobs, alog
    integer :: w(0:263), probs(0:263)
    integer(int64) :: end_, p, s1, s2
    type(fse_t) :: t
    type(bbits_t) :: br
    e = 0
    if (pos >= limit) then
      call fail(e, 'missing Huffman description')
      return
    end if
    hb = ub(d(pos))
    pos = pos + 1
    nw = 0
    w = 0
    if (hb < 128) then
      end_ = pos + hb
      if (end_ > limit) then
        call fail(e, 'Huffman description overruns literals')
        return
      end if
      call read_fse_desc(d, pos, end_, 255, 6, probs, nprobs, alog, p, e)
      if (e /= 0) return
      call build_fse(probs, nprobs, alog, t, e)
      if (e /= 0) return
      call br_init(d, dn, p, end_, br, e)
      if (e /= 0) return
      s1 = br_read(d, br, alog)
      s2 = br_read(d, br, alog)
      do
        if (nw > 255) then
          call fail(e, 'too many Huffman weights')
          return
        end if
        w(nw) = t%sym(s1)
        nw = nw + 1
        s1 = t%base(s1) + br_read(d, br, t%nb(s1))
        if (br%bits < 0) then
          w(nw) = t%sym(s2)
          nw = nw + 1
          exit
        end if
        w(nw) = t%sym(s2)
        nw = nw + 1
        s2 = t%base(s2) + br_read(d, br, t%nb(s2))
        if (br%bits < 0) then
          w(nw) = t%sym(s1)
          nw = nw + 1
          exit
        end if
      end do
      pos = end_
    else
      n = hb - 127
      end_ = pos + (n + 1) / 2
      if (end_ > limit) then
        call fail(e, 'Huffman description overruns literals')
        return
      end if
      do i = 0, n - 1
        b = ub(d(pos + i / 2))
        if (mod(i, 2) == 0) then
          w(nw) = shiftr(b, 4)
        else
          w(nw) = iand(b, 15)
        end if
        nw = nw + 1
      end do
      pos = end_
    end if
    call build_huffman(w, nw, h, e)
  end subroutine read_huf_desc

  subroutine huf_stream(d, dn, start, end_, h, count, nlit, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: dn, start, end_, count
    type(huf_t), intent(in) :: h
    integer(int64), intent(inout) :: nlit
    integer, intent(out) :: e
    type(bbits_t) :: br
    integer(int64) :: k, idx
    integer :: s
    call br_init(d, dn, start, end_, br, e)
    if (e /= 0) return
    do k = 1, count
      idx = br_peek(d, br, h%max_bits)
      s = h%sym(idx)
      if (s > 127) s = s - 256
      lit(nlit) = int(s, int8)
      nlit = nlit + 1
      br%bits = br%bits - h%nb(idx)
    end do
    if (br%bits /= 0) call fail(e, 'Huffman stream not fully consumed')
  end subroutine huf_stream

  subroutine ensure_lit(n)
    integer(int64), intent(in) :: n
    if (allocated(lit)) then
      if (size(lit, kind=int64) >= n) return
      deallocate(lit)
    end if
    allocate(lit(0:max(n, 131072_int64) - 1))
  end subroutine ensure_lit

  ! ------------------------------------------------------------ literals
  subroutine decode_literals(d, dn, pos, end_, fr, nlit, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: dn, end_
    integer(int64), intent(inout) :: pos
    type(frame_t), intent(inout) :: fr
    integer(int64), intent(out) :: nlit
    integer, intent(out) :: e
    integer :: b0, ltype, sf, streams, hlen, width, k
    integer(int64) :: size, h, regen, comp, lit_end, sizes(4), counts(4), quarter
    e = 0
    nlit = 0
    if (pos >= end_) then
      call fail(e, 'missing literals section')
      return
    end if
    b0 = ub(d(pos))
    ltype = iand(b0, 3)
    sf = iand(shiftr(b0, 2), 3)
    if (ltype == 0 .or. ltype == 1) then
      if (sf == 0 .or. sf == 2) then
        size = shiftr(b0, 3)
        pos = pos + 1
      else if (sf == 1) then
        if (pos + 1 >= dn) then
          call fail(e, 'truncated input')
          return
        end if
        size = shiftr(b0, 4) + shiftl(le(d, pos + 1, 1), 4)
        pos = pos + 2
      else
        if (pos + 2 >= dn) then
          call fail(e, 'truncated input')
          return
        end if
        size = shiftr(b0, 4) + shiftl(le(d, pos + 1, 1), 4) + shiftl(le(d, pos + 2, 1), 12)
        pos = pos + 3
      end if
      call ensure_lit(size)
      if (ltype == 0) then
        if (pos + size > end_) then
          call fail(e, 'raw literals overrun block')
          return
        end if
        if (size > 0) lit(0:size - 1) = d(pos:pos + size - 1)
        nlit = size
        pos = pos + size
        return
      end if
      if (pos >= end_) then
        call fail(e, 'RLE literals overrun block')
        return
      end if
      if (size > 0) lit(0:size - 1) = d(pos)
      nlit = size
      pos = pos + 1
      return
    end if
    select case (sf)
    case (0)
      streams = 1; hlen = 3; width = 10
    case (1)
      streams = 4; hlen = 3; width = 10
    case (2)
      streams = 4; hlen = 4; width = 14
    case default
      streams = 4; hlen = 5; width = 18
    end select
    if (pos + hlen > dn) then
      call fail(e, 'truncated input')
      return
    end if
    h = le(d, pos, hlen)
    regen = iand(shiftr(h, 4), shiftl(1_int64, width) - 1)
    comp = iand(shiftr(h, 4 + width), shiftl(1_int64, width) - 1)
    pos = pos + hlen
    lit_end = pos + comp
    if (lit_end > end_) then
      call fail(e, 'compressed literals overrun block')
      return
    end if
    if (ltype == 2) then
      call read_huf_desc(d, dn, pos, lit_end, fr%huf, e)
      if (e /= 0) return
      fr%has_huf = .true.
    else if (.not. fr%has_huf) then
      call fail(e, 'treeless literals without a previous Huffman table')
      return
    end if
    call ensure_lit(regen)
    if (streams == 1) then
      call huf_stream(d, dn, pos, lit_end, fr%huf, regen, nlit, e)
      if (e /= 0) return
    else
      if (pos + 6 > dn) then
        call fail(e, 'truncated input')
        return
      end if
      sizes(1) = le(d, pos, 2)
      sizes(2) = le(d, pos + 2, 2)
      sizes(3) = le(d, pos + 4, 2)
      pos = pos + 6
      sizes(4) = lit_end - pos - sizes(1) - sizes(2) - sizes(3)
      quarter = (regen + 3) / 4
      counts(1:3) = quarter
      counts(4) = regen - 3 * quarter
      if (sizes(4) < 1 .or. counts(4) < 0) then
        call fail(e, 'corrupt 4-stream literals')
        return
      end if
      do k = 1, 4
        call huf_stream(d, dn, pos, pos + sizes(k), fr%huf, counts(k), nlit, e)
        if (e /= 0) return
        pos = pos + sizes(k)
      end do
    end if
    pos = lit_end
  end subroutine decode_literals

  ! ------------------------------------------------------------ sequences
  subroutine read_seq_table(d, pos, end_, mode, kind, fr, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: end_
    integer, intent(in) :: mode, kind
    type(frame_t), intent(inout) :: fr
    integer, intent(out) :: e
    integer :: probs(0:263), nprobs, alog, s
    integer(int64) :: p
    e = 0
    select case (mode)
    case (0)
      fr%t(kind) = predef(kind)
    case (1)
      if (pos >= end_) then
        call fail(e, 'bad RLE sequence symbol')
        return
      end if
      s = ub(d(pos))
      if (s > KIND_MAX_SYM(kind)) then
        call fail(e, 'bad RLE sequence symbol')
        return
      end if
      fr%t(kind)%alog = 0
      fr%t(kind)%sym(0) = s
      fr%t(kind)%nb(0) = 0
      fr%t(kind)%base(0) = 0
      pos = pos + 1
    case (2)
      call read_fse_desc(d, pos, end_, KIND_MAX_SYM(kind), KIND_MAX_LOG(kind), probs, nprobs, alog, p, e)
      if (e /= 0) return
      call build_fse(probs, nprobs, alog, fr%t(kind), e)
      if (e /= 0) return
      pos = p
    case default
      if (.not. fr%has_t(kind)) then
        call fail(e, 'repeat mode without a previous table')
        return
      end if
    end select
    fr%has_t(kind) = .true.
  end subroutine read_seq_table

  subroutine ensure_seq(n)
    integer(int64), intent(in) :: n
    if (allocated(seq_ll)) then
      if (size(seq_ll, kind=int64) >= n) return
      deallocate(seq_ll, seq_of, seq_ml)
    end if
    allocate(seq_ll(max(n, 1024_int64)), seq_of(max(n, 1024_int64)), seq_ml(max(n, 1024_int64)))
  end subroutine ensure_seq

  subroutine decode_sequences(d, dn, pos, end_, fr, count, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: dn, end_
    integer(int64), intent(inout) :: pos
    type(frame_t), intent(inout) :: fr
    integer(int64), intent(out) :: count
    integer, intent(out) :: e
    integer :: b0, modes, of_code, ml_code, ll_code
    integer(int64) :: i, ll_s, of_s, ml_s
    type(bbits_t) :: br
    e = 0
    count = 0
    if (pos >= end_) then
      call fail(e, 'missing sequences section')
      return
    end if
    b0 = ub(d(pos))
    if (b0 == 0) then
      if (pos + 1 /= end_) call fail(e, 'data after empty sequences section')
      return
    end if
    if (b0 < 128) then
      count = b0
      pos = pos + 1
    else if (b0 < 255) then
      if (pos + 1 >= end_) then
        call fail(e, 'missing compression modes')
        return
      end if
      count = shiftl(int(b0 - 128, int64), 8) + le(d, pos + 1, 1)
      pos = pos + 2
    else
      if (pos + 2 >= end_) then
        call fail(e, 'missing compression modes')
        return
      end if
      count = le(d, pos + 1, 2) + 32512_int64
      pos = pos + 3
    end if
    if (pos >= end_) then
      call fail(e, 'missing compression modes')
      return
    end if
    modes = ub(d(pos))
    pos = pos + 1
    if (iand(modes, 3) /= 0) then
      call fail(e, 'reserved compression-mode bits set')
      return
    end if
    call read_seq_table(d, pos, end_, iand(shiftr(modes, 6), 3), 1, fr, e)
    if (e /= 0) return
    call read_seq_table(d, pos, end_, iand(shiftr(modes, 4), 3), 2, fr, e)
    if (e /= 0) return
    call read_seq_table(d, pos, end_, iand(shiftr(modes, 2), 3), 3, fr, e)
    if (e /= 0) return
    call br_init(d, dn, pos, end_, br, e)
    if (e /= 0) return
    call ensure_seq(count)
    associate (llt => fr%t(1), oft => fr%t(2), mlt => fr%t(3))
      ll_s = br_read(d, br, llt%alog)
      of_s = br_read(d, br, oft%alog)
      ml_s = br_read(d, br, mlt%alog)
      do i = 1, count
        of_code = oft%sym(of_s)
        ml_code = mlt%sym(ml_s)
        ll_code = llt%sym(ll_s)
        seq_of(i) = shiftl(1_int64, of_code) + br_read(d, br, of_code)
        seq_ml(i) = ML_BASE(ml_code) + br_read(d, br, ML_BITS(ml_code))
        seq_ll(i) = LL_BASE(ll_code) + br_read(d, br, LL_BITS(ll_code))
        if (i /= count) then
          ll_s = llt%base(ll_s) + br_read(d, br, llt%nb(ll_s))
          ml_s = mlt%base(ml_s) + br_read(d, br, mlt%nb(ml_s))
          of_s = oft%base(of_s) + br_read(d, br, oft%nb(of_s))
        end if
      end do
    end associate
    if (br%bits /= 0) call fail(e, 'sequence bitstream not fully consumed')
  end subroutine decode_sequences

  subroutine execute_sequences(count, nlit, out, frame_start, rep, e)
    integer(int64), intent(in) :: count, nlit, frame_start
    type(bytes_t), intent(inout) :: out
    integer(int64), intent(inout) :: rep(3)
    integer, intent(out) :: e
    integer(int64) :: i, litp, ll, ov, ml, offset, idx, src, k, r0
    e = 0
    litp = 0
    do i = 1, count
      ll = seq_ll(i)
      ov = seq_of(i)
      ml = seq_ml(i)
      if (litp + ll > nlit) then
        call fail(e, 'sequence consumes more literals than available')
        return
      end if
      if (out%n + ll > ZSTD_MAX_OUT) then
        call fail(e, 'decompressed size limit exceeded')
        return
      end if
      if (ll > 0) then
        call bytes_reserve(out, out%n + ll)
        out%d(out%n:out%n + ll - 1) = lit(litp:litp + ll - 1)
        out%n = out%n + ll
        litp = litp + ll
      end if
      if (ov > 3) then
        offset = ov - 3
        rep(3) = rep(2)
        rep(2) = rep(1)
        rep(1) = offset
      else
        idx = ov - 1
        if (ll == 0) idx = idx + 1
        select case (idx)
        case (0)
          offset = rep(1)
        case (1)
          offset = rep(2)
          rep(2) = rep(1)
          rep(1) = offset
        case (2)
          offset = rep(3)
          rep(3) = rep(2)
          rep(2) = rep(1)
          rep(1) = offset
        case default
          r0 = rep(1)
          offset = r0 - 1
          rep(3) = rep(2)
          rep(2) = r0
          rep(1) = offset
        end select
      end if
      if (offset <= 0 .or. offset > out%n - frame_start) then
        call fail(e, 'match offset out of range')
        return
      end if
      if (out%n + ml > ZSTD_MAX_OUT) then
        call fail(e, 'decompressed size limit exceeded')
        return
      end if
      call bytes_reserve(out, out%n + ml)
      src = out%n - offset
      if (offset >= ml) then
        out%d(out%n:out%n + ml - 1) = out%d(src:src + ml - 1)
      else
        do k = 0, ml - 1
          out%d(out%n + k) = out%d(src + k)
        end do
      end if
      out%n = out%n + ml
    end do
    if (litp < nlit) then
      if (out%n + (nlit - litp) > ZSTD_MAX_OUT) then
        call fail(e, 'decompressed size limit exceeded')
        return
      end if
      call bytes_reserve(out, out%n + (nlit - litp))
      out%d(out%n:out%n + nlit - litp - 1) = lit(litp:nlit - 1)
      out%n = out%n + (nlit - litp)
    end if
  end subroutine execute_sequences

  ! ------------------------------------------------------------ frames
  subroutine decode_frame(d, dn, pos, out, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: dn
    integer(int64), intent(inout) :: pos
    type(bytes_t), intent(inout) :: out
    integer, intent(out) :: e
    integer :: fhd, fcs_flag, single, has_ck, did_flag, did_size, fcs_size, last, btype
    integer(int64) :: content_size, frame_start, header, bsize, end_, nlit, nseq, expected, hint
    logical :: has_cs
    type(frame_t), allocatable :: fr
    e = 0
    if (pos + 1 > dn) then
      call fail(e, 'truncated input')
      return
    end if
    fhd = ub(d(pos))
    pos = pos + 1
    fcs_flag = shiftr(fhd, 6)
    single = iand(shiftr(fhd, 5), 1)
    has_ck = iand(shiftr(fhd, 2), 1)
    did_flag = iand(fhd, 3)
    if (iand(fhd, 8) /= 0) then
      call fail(e, 'reserved frame header bit set')
      return
    end if
    if (single == 0) then
      if (pos + 1 > dn) then
        call fail(e, 'truncated input')
        return
      end if
      pos = pos + 1
    end if
    select case (did_flag)
    case (0)
      did_size = 0
    case (1)
      did_size = 1
    case (2)
      did_size = 2
    case default
      did_size = 4
    end select
    if (did_size > 0) then
      if (pos + did_size > dn) then
        call fail(e, 'truncated input')
        return
      end if
      if (le(d, pos, did_size) /= 0) then
        call fail(e, 'zstd dictionaries are not supported')
        return
      end if
    end if
    pos = pos + did_size
    select case (fcs_flag)
    case (0)
      fcs_size = single
    case (1)
      fcs_size = 2
    case (2)
      fcs_size = 4
    case default
      fcs_size = 8
    end select
    has_cs = .false.
    content_size = 0
    if (fcs_size > 0) then
      if (pos + fcs_size > dn) then
        call fail(e, 'truncated input')
        return
      end if
      content_size = le(d, pos, fcs_size)
      if (fcs_size == 2) content_size = content_size + 256
      has_cs = .true.
      pos = pos + fcs_size
    end if
    frame_start = out%n
    if (has_cs .and. content_size > 0) then
      hint = min(content_size, ZSTD_MAX_OUT - out%n, 134217728_int64)
      if (hint > 0) call bytes_reserve(out, out%n + hint)
    end if
    allocate(fr)
    do
      if (pos + 3 > dn) then
        call fail(e, 'truncated input')
        return
      end if
      header = le(d, pos, 3)
      pos = pos + 3
      last = int(iand(header, 1_int64))
      btype = int(iand(shiftr(header, 1), 3_int64))
      bsize = shiftr(header, 3)
      if (bsize > BLOCK_SIZE_MAX) then
        call fail(e, 'block too large')
        return
      end if
      select case (btype)
      case (0)
        if (pos + bsize > dn) then
          call fail(e, 'truncated raw block')
          return
        end if
        if (out%n + bsize > ZSTD_MAX_OUT) then
          call fail(e, 'decompressed size limit exceeded')
          return
        end if
        call bytes_append(out, d, pos, bsize)
        pos = pos + bsize
      case (1)
        if (pos + 1 > dn) then
          call fail(e, 'truncated input')
          return
        end if
        if (out%n + bsize > ZSTD_MAX_OUT) then
          call fail(e, 'decompressed size limit exceeded')
          return
        end if
        call bytes_reserve(out, out%n + bsize)
        if (bsize > 0) out%d(out%n:out%n + bsize - 1) = d(pos)
        out%n = out%n + bsize
        pos = pos + 1
      case (2)
        end_ = pos + bsize
        if (end_ > dn) then
          call fail(e, 'truncated compressed block')
          return
        end if
        call decode_literals(d, dn, pos, end_, fr, nlit, e)
        if (e /= 0) return
        call decode_sequences(d, dn, pos, end_, fr, nseq, e)
        if (e /= 0) return
        call execute_sequences(nseq, nlit, out, frame_start, fr%rep, e)
        if (e /= 0) return
        pos = end_
      case default
        call fail(e, 'reserved block type')
        return
      end select
      if (out%n > ZSTD_MAX_OUT) then
        call fail(e, 'decompressed size limit exceeded')
        return
      end if
      if (last /= 0) exit
    end do
    if (has_cs) then
      if (out%n - frame_start /= content_size) then
        call fail(e, 'frame content size mismatch')
        return
      end if
    end if
    if (has_ck /= 0) then
      if (pos + 4 > dn) then
        call fail(e, 'truncated input')
        return
      end if
      expected = le(d, pos, 4)
      pos = pos + 4
      if (iand(xxh64(out%d, frame_start, out%n - frame_start), int(z'FFFFFFFF', int64)) /= expected) then
        call fail(e, 'content checksum mismatch')
        return
      end if
    end if
  end subroutine decode_frame

  !> Decompress every frame of d(0:dn-1) into out (out%n is reset to 0).
  subroutine zstd_decompress(d, dn, out, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: dn
    type(bytes_t), intent(inout) :: out
    integer, intent(out) :: e
    integer(int64) :: pos, magic, size
    e = 0
    out%n = 0
    if (.not. predef_ready) call init_predef()
    pos = 0
    do while (pos < dn)
      if (pos + 4 > dn) then
        call fail(e, 'truncated input')
        return
      end if
      magic = le(d, pos, 4)
      if (iand(magic, int(z'FFFFFFF0', int64)) == int(z'184D2A50', int64)) then
        if (pos + 8 > dn) then
          call fail(e, 'truncated input')
          return
        end if
        size = le(d, pos + 4, 4)
        if (pos + 8 + size > dn) then
          call fail(e, 'truncated skippable frame')
          return
        end if
        pos = pos + 8 + size
      else if (magic == int(z'FD2FB528', int64)) then
        pos = pos + 4
        call decode_frame(d, dn, pos, out, e)
        if (e /= 0) return
      else
        call fail(e, 'unknown frame magic')
        return
      end if
    end do
  end subroutine zstd_decompress

end module ob_zstd
