! ob_codec: Base58 (Bitcoin alphabet), Base64 (RFC 4648 with padding),
! shortest round-trip doubles and real_number_string_trimmed.
module ob_codec
  use ob_util
  use, intrinsic :: ieee_arithmetic, only: ieee_is_finite
  implicit none
  private
  public :: sb_b58, sb_b64, b58_decode32, sb_f64, sb_real_number_trimmed, parse_u64_plus

  character(len=*), parameter :: B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  character(len=*), parameter :: B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  integer(int64), parameter :: B58P5 = 656356768_int64   ! 58**5

contains

  !> Append Base58 of d(p:p+n-1). Works in limbs of 58^5 to cut the quadratic cost.
  subroutine sb_b58(sb, d, p, n)
    type(sb_t), intent(inout) :: sb
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer(int64), allocatable :: limbs(:)
    integer(int64) :: zeros, i, carry, nl, j, v
    integer :: k, ndig
    character(len=5) :: dig
    zeros = 0
    do while (zeros < n)
      if (d(p + zeros) /= 0) exit
      zeros = zeros + 1
    end do
    call sb_reserve(sb, zeros + 2 * n + 2)
    do i = 1, zeros
      call sb_addc(sb, '1')
    end do
    if (zeros == n) return
    allocate(limbs((n - zeros) / 3 + 2))
    nl = 0
    do i = p + zeros, p + n - 1
      carry = int(ub(d(i)), int64)
      do j = 1, nl
        carry = carry + limbs(j) * 256_int64
        limbs(j) = mod(carry, B58P5)
        carry = carry / B58P5
      end do
      do while (carry > 0)
        nl = nl + 1
        limbs(nl) = mod(carry, B58P5)
        carry = carry / B58P5
      end do
    end do
    ! Most significant limb without leading zeros, then fixed 5-digit limbs.
    do j = nl, 1, -1
      v = limbs(j)
      do k = 5, 1, -1
        dig(k:k) = B58(int(mod(v, 58_int64)) + 1:int(mod(v, 58_int64)) + 1)
        v = v / 58
      end do
      if (j == nl) then
        ndig = 5
        do while (ndig > 1 .and. dig(6 - ndig:6 - ndig) == '1')
          ndig = ndig - 1
        end do
        call sb_add(sb, dig(6 - ndig:5))
      else
        call sb_add(sb, dig)
      end if
    end do
  end subroutine sb_b58

  !> Decode a Base58 string that must produce exactly 32 bytes.
  subroutine b58_decode32(s, out, ok)
    character(len=*), intent(in) :: s
    integer(int8), intent(out) :: out(32)
    logical, intent(out) :: ok
    integer :: buf(64), nb, zeros, i, j, c, carry, total
    ok = .false.
    out = 0
    zeros = 0
    do while (zeros < len(s))
      if (s(zeros + 1:zeros + 1) /= '1') exit
      zeros = zeros + 1
    end do
    nb = 0
    buf = 0
    do i = zeros + 1, len(s)
      c = index(B58, s(i:i)) - 1
      if (c < 0) return
      carry = c
      do j = 1, nb
        carry = carry + buf(j) * 58
        buf(j) = iand(carry, 255)
        carry = shiftr(carry, 8)
      end do
      do while (carry > 0)
        nb = nb + 1
        if (nb > 64) return
        buf(nb) = iand(carry, 255)
        carry = shiftr(carry, 8)
      end do
    end do
    total = zeros + nb
    if (total /= 32) return
    do i = 1, nb
      out(33 - i) = to_i8(buf(i))
    end do
    ok = .true.
  end subroutine b58_decode32

  subroutine sb_b64(sb, d, p, n)
    type(sb_t), intent(inout) :: sb
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer(int64) :: i, e
    integer :: b0, b1, b2, v
    call sb_reserve(sb, 4 * (n / 3 + 1))
    i = p
    e = p + n
    do while (i + 3 <= e)
      b0 = ub(d(i)); b1 = ub(d(i + 1)); b2 = ub(d(i + 2))
      v = ior(ior(shiftl(b0, 16), shiftl(b1, 8)), b2)
      call put(shiftr(v, 18))
      call put(iand(shiftr(v, 12), 63))
      call put(iand(shiftr(v, 6), 63))
      call put(iand(v, 63))
      i = i + 3
    end do
    if (e - i == 1) then
      b0 = ub(d(i))
      v = shiftl(b0, 16)
      call put(shiftr(v, 18))
      call put(iand(shiftr(v, 12), 63))
      call sb_add(sb, '==')
    else if (e - i == 2) then
      b0 = ub(d(i)); b1 = ub(d(i + 1))
      v = ior(shiftl(b0, 16), shiftl(b1, 8))
      call put(shiftr(v, 18))
      call put(iand(shiftr(v, 12), 63))
      call put(iand(shiftr(v, 6), 63))
      call sb_addc(sb, '=')
    end if
  contains
    subroutine put(x)
      integer, intent(in) :: x
      call sb_addc(sb, B64(x + 1:x + 1))
    end subroutine put
  end subroutine sb_b64

  !> Shortest decimal that reads back to exactly x (JSON number; null if non-finite).
  subroutine sb_f64(sb, x)
    type(sb_t), intent(inout) :: sb
    real(real64), intent(in) :: x
    character(len=40) :: buf
    character(len=24) :: digits
    character(len=16) :: fmt
    real(real64) :: y
    integer :: p, i, nd, ex, ios, epos, k
    if (.not. ieee_is_finite(x)) then
      call sb_add(sb, 'null')
      return
    end if
    if (x == 0.0_real64) then
      call sb_add(sb, '0.0')
      return
    end if
    do p = 1, 17
      write(fmt, '(a,i0,a)') '(ES40.', p - 1, 'E3)'
      write(buf, fmt) x
      read(buf, *, iostat=ios) y
      if (ios == 0 .and. y == x) exit
    end do
    buf = adjustl(buf)
    ! buf looks like [-]d.dddE+xxx (or [-]d.E+xxx when p == 1)
    epos = index(buf, 'E')
    read(buf(epos + 1:), *) ex
    nd = 0
    digits = ''
    do i = 1, epos - 1
      if (buf(i:i) >= '0' .and. buf(i:i) <= '9') then
        nd = nd + 1
        digits(nd:nd) = buf(i:i)
      end if
    end do
    do while (nd > 1 .and. digits(nd:nd) == '0')
      nd = nd - 1
    end do
    if (x < 0) call sb_addc(sb, '-')
    if (ex >= 0 .and. ex < 17) then
      ! integer part has ex+1 digits
      do k = 1, ex + 1
        if (k <= nd) then
          call sb_addc(sb, digits(k:k))
        else
          call sb_addc(sb, '0')
        end if
      end do
      call sb_addc(sb, '.')
      if (nd > ex + 1) then
        call sb_add(sb, digits(ex + 2:nd))
      else
        call sb_addc(sb, '0')
      end if
    else if (ex < 0 .and. ex >= -6) then
      call sb_add(sb, '0.')
      do k = 1, -ex - 1
        call sb_addc(sb, '0')
      end do
      call sb_add(sb, digits(1:nd))
    else
      call sb_addc(sb, digits(1:1))
      if (nd > 1) then
        call sb_addc(sb, '.')
        call sb_add(sb, digits(2:nd))
      end if
      call sb_addc(sb, 'e')
      call sb_int(sb, ex)
    end if
  end subroutine sb_f64

  !> real_number_string_trimmed(amount, decimals) from WIRE_FORMATS.md section 15.4.
  subroutine sb_real_number_trimmed(sb, amount, decimals)
    type(sb_t), intent(inout) :: sb
    integer(int64), intent(in) :: amount
    integer, intent(in) :: decimals
    character(len=:), allocatable :: s
    character(len=300) :: t
    integer :: ls, n, k
    s = u64_str(amount)
    if (decimals == 0) then
      call sb_add(sb, s)
      return
    end if
    ls = len(s)
    if (ls <= decimals) then
      t(1:2) = '0.'
      n = 2
      do k = 1, decimals - ls
        n = n + 1
        t(n:n) = '0'
      end do
      t(n + 1:n + ls) = s
      n = n + ls
    else
      t(1:ls - decimals) = s(1:ls - decimals)
      t(ls - decimals + 1:ls - decimals + 1) = '.'
      t(ls - decimals + 2:ls + 1) = s(ls - decimals + 1:ls)
      n = ls + 1
    end if
    do while (n > 0)
      if (t(n:n) /= '0') exit
      n = n - 1
    end do
    if (n > 0) then
      if (t(n:n) == '.') n = n - 1
    end if
    call sb_add(sb, t(1:n))
  end subroutine sb_real_number_trimmed

  !> Rust u64::from_str on d(p:p+n-1): optional '+', then 1+ ASCII digits, no overflow.
  pure subroutine parse_u64_plus(d, p, n, v, ok)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer(int64), intent(out) :: v
    logical, intent(out) :: ok
    character(len=:), allocatable :: s
    integer(int64) :: i, q
    v = 0
    ok = .false.
    q = p
    if (n <= 0) return
    if (ub(d(p)) == 43) q = p + 1
    if (q >= p + n) return
    allocate(character(len=p + n - q) :: s)
    do i = q, p + n - 1
      s(i - q + 1:i - q + 1) = achar(ub(d(i)))
    end do
    call parse_u64_digits(s, v, ok)
  end subroutine parse_u64_plus

end module ob_codec
