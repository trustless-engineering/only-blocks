! ob_hash: CRC-64/GO-ISO, FNV-1a 64 and XXH64, all as wrapping int64
! arithmetic (the build uses -fwrapv so multiplication is modulo 2^64).
module ob_hash
  use ob_util
  implicit none
  private
  public :: crc64_go_iso, fnv1a64, xxh64

  integer(int64), save :: crc_tab(0:255)
  logical, save :: crc_ready = .false.

  integer(int64), parameter :: P1 = int(z'9E3779B185EBCA87', int64)
  integer(int64), parameter :: P2 = int(z'C2B2AE3D27D4EB4F', int64)
  integer(int64), parameter :: P3 = int(z'165667B19E3779F9', int64)
  integer(int64), parameter :: P4 = int(z'85EBCA77C2B2AE63', int64)
  integer(int64), parameter :: P5 = int(z'27D4EB2F165667C5', int64)

contains

  subroutine crc_init()
    integer :: i, k
    integer(int64) :: c, poly
    poly = int(z'D800000000000000', int64)
    do i = 0, 255
      c = int(i, int64)
      do k = 1, 8
        if (iand(c, 1_int64) /= 0) then
          c = ieor(shiftr(c, 1), poly)
        else
          c = shiftr(c, 1)
        end if
      end do
      crc_tab(i) = c
    end do
    crc_ready = .true.
  end subroutine crc_init

  !> Reflected CRC-64 with poly 0x1B, init and xorout all-ones.
  function crc64_go_iso(d, p, n) result(crc)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer(int64) :: crc, i
    if (.not. crc_ready) call crc_init()
    crc = -1_int64
    do i = p, p + n - 1
      crc = ieor(crc_tab(int(iand(ieor(crc, int(d(i), int64)), 255_int64))), shiftr(crc, 8))
    end do
    crc = not(crc)
  end function crc64_go_iso

  !> FNV-1a 64: xor the byte in, then multiply by the FNV prime.
  pure function fnv1a64(d, p, n) result(h)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer(int64) :: h, i
    integer(int64), parameter :: OFFSET = int(z'CBF29CE484222325', int64)
    integer(int64), parameter :: PRIME = int(z'00000100000001B3', int64)
    h = OFFSET
    do i = p, p + n - 1
      h = ieor(h, iand(int(d(i), int64), 255_int64))
      h = h * PRIME
    end do
  end function fnv1a64

  pure integer(int64) function le64(d, i)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: i
    integer :: k
    le64 = 0
    do k = 7, 0, -1
      le64 = ior(shiftl(le64, 8), iand(int(d(i + k), int64), 255_int64))
    end do
  end function le64

  pure integer(int64) function le32(d, i)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: i
    integer :: k
    le32 = 0
    do k = 3, 0, -1
      le32 = ior(shiftl(le32, 8), iand(int(d(i + k), int64), 255_int64))
    end do
  end function le32

  pure integer(int64) function xround(acc, lane)
    integer(int64), intent(in) :: acc, lane
    xround = ishftc(acc + lane * P2, 31) * P1
  end function xround

  !> XXH64 with seed 0 over d(p:p+n-1).
  pure function xxh64(d, p, n) result(h)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer(int64) :: h, v(4), i, e
    integer :: j
    i = p
    e = p + n
    if (n >= 32) then
      v(1) = P1 + P2
      v(2) = P2
      v(3) = 0
      v(4) = -P1
      do while (i + 32 <= e)
        do j = 1, 4
          v(j) = xround(v(j), le64(d, i + 8 * (j - 1)))
        end do
        i = i + 32
      end do
      h = ishftc(v(1), 1) + ishftc(v(2), 7) + ishftc(v(3), 12) + ishftc(v(4), 18)
      do j = 1, 4
        h = ieor(h, xround(0_int64, v(j))) * P1 + P4
      end do
    else
      h = P5
    end if
    h = h + n
    do while (i + 8 <= e)
      h = ishftc(ieor(h, xround(0_int64, le64(d, i))), 27) * P1 + P4
      i = i + 8
    end do
    if (i + 4 <= e) then
      h = ishftc(ieor(h, le32(d, i) * P1), 23) * P2 + P3
      i = i + 4
    end if
    do while (i < e)
      h = ishftc(ieor(h, iand(int(d(i), int64), 255_int64) * P5), 11) * P1
      i = i + 1
    end do
    h = ieor(h, shiftr(h, 33))
    h = h * P2
    h = ieor(h, shiftr(h, 29))
    h = h * P3
    h = ieor(h, shiftr(h, 32))
  end function xxh64

end module ob_hash
