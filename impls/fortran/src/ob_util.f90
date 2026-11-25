! ob_util: growable byte buffers, a string builder, unsigned 64-bit helpers
! and the small text utilities every other OnlyBlocks module leans on.
module ob_util
  use iso_fortran_env, only: int8, int16, int32, int64, real64
  implicit none
  public

  !> Growable 0-based byte buffer. Only d(0:n-1) is meaningful.
  type :: bytes_t
    integer(int8), allocatable :: d(:)
    integer(int64) :: n = 0
  end type bytes_t

  !> Growable character buffer. Only s(1:n) is meaningful.
  type :: sb_t
    character(len=:), allocatable :: s
    integer(int64) :: n = 0
  end type sb_t

  !> A (position, length) view into some other buffer.
  type :: span_t
    integer(int64) :: p = 0, n = 0
  end type span_t

  character(len=*), parameter :: HEXD = '0123456789abcdef'

contains

  pure elemental integer function ub(b)
    integer(int8), intent(in) :: b
    ub = iand(int(b, int32), 255)
  end function ub

  !> Index of the most significant set bit (x > 0).
  pure elemental integer function highbit(x)
    integer(int64), intent(in) :: x
    highbit = 63 - leadz(x)
  end function highbit

  pure logical function streq(a, b)
    character(len=*), intent(in) :: a, b
    streq = .false.
    if (len(a) /= len(b)) return
    streq = (a == b)
  end function streq

  ! ---------------------------------------------------------------- bytes_t
  subroutine bytes_reserve(b, cap)
    type(bytes_t), intent(inout) :: b
    integer(int64), intent(in) :: cap
    integer(int8), allocatable :: t(:)
    integer(int64) :: newcap
    if (allocated(b%d)) then
      if (size(b%d, kind=int64) >= cap) return
      newcap = max(cap, 2_int64 * size(b%d, kind=int64))
      allocate(t(0:newcap - 1))
      if (b%n > 0) t(0:b%n - 1) = b%d(0:b%n - 1)
      call move_alloc(t, b%d)
    else
      allocate(b%d(0:max(cap, 64_int64) - 1))
    end if
  end subroutine bytes_reserve

  subroutine bytes_append(b, src, p, n)
    type(bytes_t), intent(inout) :: b
    integer(int8), intent(in) :: src(0:)
    integer(int64), intent(in) :: p, n
    if (n <= 0) return
    call bytes_reserve(b, b%n + n)
    b%d(b%n:b%n + n - 1) = src(p:p + n - 1)
    b%n = b%n + n
  end subroutine bytes_append

  subroutine bytes_push(b, v)
    type(bytes_t), intent(inout) :: b
    integer, intent(in) :: v
    call bytes_reserve(b, b%n + 1)
    b%d(b%n) = int(iand(v, 255), int8)
    if (iand(v, 255) > 127) b%d(b%n) = int(iand(v, 255) - 256, int8)
    b%n = b%n + 1
  end subroutine bytes_push

  pure integer(int8) function to_i8(v)
    integer, intent(in) :: v
    integer :: w
    w = iand(v, 255)
    if (w > 127) w = w - 256
    to_i8 = int(w, int8)
  end function to_i8

  ! ---------------------------------------------------------------- sb_t
  subroutine sb_reserve(sb, extra)
    type(sb_t), intent(inout) :: sb
    integer(int64), intent(in) :: extra
    character(len=:), allocatable :: t
    integer(int64) :: need, cap
    need = sb%n + extra
    if (.not. allocated(sb%s)) then
      allocate(character(len=max(need, 256_int64)) :: sb%s)
      return
    end if
    if (len(sb%s, kind=int64) >= need) return
    cap = max(need, 2_int64 * len(sb%s, kind=int64))
    allocate(character(len=cap) :: t)
    if (sb%n > 0) t(1:sb%n) = sb%s(1:sb%n)
    call move_alloc(t, sb%s)
  end subroutine sb_reserve

  subroutine sb_clear(sb)
    type(sb_t), intent(inout) :: sb
    sb%n = 0
  end subroutine sb_clear

  subroutine sb_add(sb, str)
    type(sb_t), intent(inout) :: sb
    character(len=*), intent(in) :: str
    integer(int64) :: l
    l = len(str, kind=int64)
    if (l == 0) return
    if (.not. allocated(sb%s)) then
      call sb_reserve(sb, l)
    else if (sb%n + l > len(sb%s, kind=int64)) then
      call sb_reserve(sb, l)
    end if
    sb%s(sb%n + 1:sb%n + l) = str
    sb%n = sb%n + l
  end subroutine sb_add

  subroutine sb_addc(sb, c)
    type(sb_t), intent(inout) :: sb
    character(len=1), intent(in) :: c
    if (.not. allocated(sb%s)) then
      call sb_reserve(sb, 1_int64)
    else if (sb%n + 1 > len(sb%s, kind=int64)) then
      call sb_reserve(sb, 1_int64)
    end if
    sb%n = sb%n + 1
    sb%s(sb%n:sb%n) = c
  end subroutine sb_addc

  !> Append another builder's content.
  subroutine sb_cat(sb, other)
    type(sb_t), intent(inout) :: sb
    type(sb_t), intent(in) :: other
    if (other%n <= 0) return
    call sb_reserve(sb, other%n)
    sb%s(sb%n + 1:sb%n + other%n) = other%s(1:other%n)
    sb%n = sb%n + other%n
  end subroutine sb_cat

  ! ---------------------------------------------------------------- u64 maths
  !> Unsigned division of n (any u64 bit pattern) by 0 < d < 2^62.
  pure subroutine udivmod(n, d, q, r)
    integer(int64), intent(in) :: n, d
    integer(int64), intent(out) :: q, r
    if (n >= 0) then
      q = n / d
      r = n - q * d
    else
      q = shiftl(shiftr(n, 1) / d, 1)
      r = n - q * d
      if (bge(r, d)) then
        q = q + 1
        r = r - d
      end if
    end if
  end subroutine udivmod

  !> Decimal text of an unsigned 64-bit value.
  pure function u64_str(v) result(s)
    integer(int64), intent(in) :: v
    character(len=:), allocatable :: s
    character(len=20) :: buf
    integer :: i
    integer(int64) :: x, q, r
    if (v == 0) then
      s = '0'
      return
    end if
    x = v
    i = 20
    do while (x /= 0)
      call udivmod(x, 10_int64, q, r)
      buf(i:i) = achar(48 + int(r))
      i = i - 1
      x = q
    end do
    s = buf(i + 1:20)
  end function u64_str

  pure function i64_str(v) result(s)
    integer(int64), intent(in) :: v
    character(len=:), allocatable :: s
    if (v < 0) then
      s = '-' // u64_str(-v)
    else
      s = u64_str(v)
    end if
  end function i64_str

  pure function itoa(v) result(s)
    integer, intent(in) :: v
    character(len=:), allocatable :: s
    s = i64_str(int(v, int64))
  end function itoa

  subroutine sb_u64(sb, v)
    type(sb_t), intent(inout) :: sb
    integer(int64), intent(in) :: v
    character(len=20) :: buf
    integer :: i
    integer(int64) :: x, q, r
    if (v == 0) then
      call sb_addc(sb, '0')
      return
    end if
    x = v
    i = 20
    do while (x /= 0)
      call udivmod(x, 10_int64, q, r)
      buf(i:i) = achar(48 + int(r))
      i = i - 1
      x = q
    end do
    call sb_add(sb, buf(i + 1:20))
  end subroutine sb_u64

  subroutine sb_i64(sb, v)
    type(sb_t), intent(inout) :: sb
    integer(int64), intent(in) :: v
    if (v < 0) then
      call sb_addc(sb, '-')
      call sb_u64(sb, -v)
    else
      call sb_u64(sb, v)
    end if
  end subroutine sb_i64

  subroutine sb_int(sb, v)
    type(sb_t), intent(inout) :: sb
    integer, intent(in) :: v
    call sb_i64(sb, int(v, int64))
  end subroutine sb_int

  !> Parse an unsigned decimal (digits only) into a u64 bit pattern.
  pure subroutine parse_u64_digits(s, v, ok)
    character(len=*), intent(in) :: s
    integer(int64), intent(out) :: v
    logical, intent(out) :: ok
    integer :: i, c
    integer(int64) :: q, r, lim_q, lim_r
    v = 0
    ok = .false.
    if (len(s) == 0) return
    ! 2^64-1 = 18446744073709551615 -> (2^64-1)/10 and (2^64-1) mod 10
    call udivmod(-1_int64, 10_int64, lim_q, lim_r)
    do i = 1, len(s)
      c = iachar(s(i:i)) - 48
      if (c < 0 .or. c > 9) return
      if (bgt(v, lim_q)) return
      if (v == lim_q .and. c > lim_r) return
      q = v * 10
      r = q + c
      v = r
    end do
    ok = .true.
  end subroutine parse_u64_digits

  ! ---------------------------------------------------------------- UTF-8
  !> Strict UTF-8 validation of d(p:p+n-1).
  pure logical function utf8_ok(d, p, n)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer(int64) :: i, e
    integer :: c, c1, k, need
    utf8_ok = .false.
    i = p
    e = p + n
    do while (i < e)
      c = ub(d(i))
      if (c < 128) then
        i = i + 1
        cycle
      end if
      if (c >= 194 .and. c <= 223) then
        need = 1
      else if (c >= 224 .and. c <= 239) then
        need = 2
      else if (c >= 240 .and. c <= 244) then
        need = 3
      else
        return
      end if
      if (i + need >= e) return
      c1 = ub(d(i + 1))
      if (c == 224) then
        if (c1 < 160 .or. c1 > 191) return
      else if (c == 237) then
        if (c1 < 128 .or. c1 > 159) return
      else if (c == 240) then
        if (c1 < 144 .or. c1 > 191) return
      else if (c == 244) then
        if (c1 < 128 .or. c1 > 143) return
      else
        if (c1 < 128 .or. c1 > 191) return
      end if
      do k = 2, need
        c1 = ub(d(i + k))
        if (c1 < 128 .or. c1 > 191) return
      end do
      i = i + need + 1
    end do
    utf8_ok = .true.
  end function utf8_ok

  ! ---------------------------------------------------------------- JSON text
  !> Append a JSON string literal for raw bytes d(p:p+n-1) (already valid UTF-8).
  subroutine sb_json_bytes(sb, d, p, n)
    type(sb_t), intent(inout) :: sb
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer(int64) :: i
    integer :: c
    call sb_reserve(sb, n + 2)
    call sb_addc(sb, '"')
    do i = p, p + n - 1
      c = ub(d(i))
      call json_esc_char(sb, c)
    end do
    call sb_addc(sb, '"')
  end subroutine sb_json_bytes

  !> Append a JSON string literal for Fortran text.
  subroutine sb_json_text(sb, s)
    type(sb_t), intent(inout) :: sb
    character(len=*), intent(in) :: s
    integer :: i
    call sb_addc(sb, '"')
    do i = 1, len(s)
      call json_esc_char(sb, iachar(s(i:i)))
    end do
    call sb_addc(sb, '"')
  end subroutine sb_json_text

  subroutine json_esc_char(sb, c)
    type(sb_t), intent(inout) :: sb
    integer, intent(in) :: c
    if (c == 34) then
      call sb_add(sb, '\"')
    else if (c == 92) then
      call sb_add(sb, '\\')
    else if (c < 32) then
      select case (c)
      case (10)
        call sb_add(sb, '\n')
      case (13)
        call sb_add(sb, '\r')
      case (9)
        call sb_add(sb, '\t')
      case default
        call sb_add(sb, '\u00')
        call sb_addc(sb, HEXD(c / 16 + 1:c / 16 + 1))
        call sb_addc(sb, HEXD(mod(c, 16) + 1:mod(c, 16) + 1))
      end select
    else
      call sb_addc(sb, achar(c))
    end if
  end subroutine json_esc_char

  !> ASCII lower-case copy.
  pure function lower(s) result(t)
    character(len=*), intent(in) :: s
    character(len=len(s)) :: t
    integer :: i, c
    do i = 1, len(s)
      c = iachar(s(i:i))
      if (c >= 65 .and. c <= 90) c = c + 32
      t(i:i) = achar(c)
    end do
  end function lower

end module ob_util
