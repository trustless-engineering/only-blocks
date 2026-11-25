! Offline self-test: hash check values, Base58/Base64 vectors and the
! ZSTD_MINI_SPEC.md section 9 frames. Build with: bash build.sh --test
program selftest
  use ob_util
  use ob_hash
  use ob_zstd
  use ob_codec
  implicit none
  integer :: fails
  fails = 0
  call t_hashes()
  call t_codec()
  call t_zstd('28b52ffd2000010000', '')
  call t_zstd('28b52ffd200a5100006f6e6c79626c6f636b73', '6f6e6c79626c6f636b73')
  call t_zstd('28b52ffd2064230300aa', repeat('aa', 100))
  call t_zstd('502a4d180300000001020328b52ffd2000010000', '')
  call t_zstd('28b52ffd0068950000606f6e6c79626c6f636b7320210100fe8a17', &
       hexs('onlyblocks onlyblocks onlyblocks!'))
  call t_zstd('28b52ffd04584d00001861626301007e6e0848c3d30e', hexs(repeat('abc', 8)))
  if (fails == 0) then
    print '(a)', 'selftest: all checks passed'
  else
    print '(a,i0,a)', 'selftest: ', fails, ' FAILED'
    error stop 1
  end if
contains
  subroutine check(cond, what)
    logical, intent(in) :: cond
    character(len=*), intent(in) :: what
    if (.not. cond) then
      fails = fails + 1
      print '(2a)', 'FAIL: ', what
    else
      print '(2a)', 'ok:   ', what
    end if
  end subroutine
  function hexs(s) result(h)
    character(len=*), intent(in) :: s
    character(len=:), allocatable :: h
    integer :: i, c
    h = ''
    do i = 1, len(s)
      c = iachar(s(i:i))
      h = h // HEXD(c/16+1:c/16+1) // HEXD(mod(c,16)+1:mod(c,16)+1)
    end do
  end function
  subroutine unhex(h, b)
    character(len=*), intent(in) :: h
    type(bytes_t), intent(inout) :: b
    integer :: i
    b%n = 0
    call bytes_reserve(b, 1_int64)
    do i = 1, len(h), 2
      call bytes_push(b, (index(HEXD, h(i:i))-1)*16 + index(HEXD, h(i+1:i+1))-1)
    end do
  end subroutine
  subroutine t_hashes()
    type(bytes_t) :: b
    call unhex(hexs('123456789'), b)
    call check(crc64_go_iso(b%d, 0_int64, b%n) == int(z'B90956C775A41001', int64), 'crc64("123456789")')
    call check(crc64_go_iso(b%d, 0_int64, 0_int64) == 0, 'crc64("")')
    call check(fnv1a64(b%d, 0_int64, b%n) == int(z'06D5573923C6CDFC', int64), 'fnv1a("123456789")')
    call check(fnv1a64(b%d, 0_int64, 0_int64) == int(z'CBF29CE484222325', int64), 'fnv1a("")')
    call unhex(hexs('a'), b)
    call check(fnv1a64(b%d, 0_int64, b%n) == int(z'AF63DC4C8601EC8C', int64), 'fnv1a("a")')
    call check(xxh64(b%d, 0_int64, 0_int64) == int(z'EF46DB3751D8E999', int64), 'xxh64("")')
    call check(xxh64(b%d, 0_int64, 1_int64) == int(z'D24EC4F1A98C6E5B', int64), 'xxh64("a")')
  end subroutine
  subroutine t_codec()
    type(bytes_t) :: b
    type(sb_t) :: sb
    integer(int8) :: k(32)
    logical :: ok
    call unhex('00012aff', b)
    call sb_b58(sb, b%d, 0_int64, b%n)
    call check(sb%s(1:sb%n) == '1Pki', 'base58 00012aff -> 1Pki')
    sb%n = 0
    call unhex(repeat('00', 32), b)
    call sb_b58(sb, b%d, 0_int64, b%n)
    call check(sb%s(1:sb%n) == repeat('1', 32), 'base58 32 zero bytes')
    sb%n = 0
    call unhex('00ff012a', b)
    call sb_b64(sb, b%d, 0_int64, b%n)
    call check(sb%s(1:sb%n) == 'AP8BKg==', 'base64 00ff012a')
    call b58_decode32('BPFLoaderUpgradeab1e11111111111111111111111', k, ok)
    call unhex(repeat('00', 0), b)
    b%n = 0
    call bytes_reserve(b, 32_int64)
    b%d(0:31) = k
    b%n = 32
    sb%n = 0
    call sb_b58(sb, b%d, 0_int64, b%n)
    call check(ok .and. sb%s(1:sb%n) == 'BPFLoaderUpgradeab1e11111111111111111111111', 'base58 round trip')
    sb%n = 0
    call sb_real_number_trimmed(sb, 1250000_int64, 6); call check(sb%s(1:sb%n) == '1.25', 'rnst 1.25')
    sb%n = 0
    call sb_real_number_trimmed(sb, 5_int64, 6); call check(sb%s(1:sb%n) == '0.000005', 'rnst 0.000005')
    sb%n = 0
    call sb_real_number_trimmed(sb, 0_int64, 255); call check(sb%s(1:sb%n) == '0', 'rnst 0/255')
    sb%n = 0
    call sb_real_number_trimmed(sb, -1_int64, 20); call check(sb%s(1:sb%n) == '0.18446744073709551615', 'rnst max/20')
    sb%n = 0
    call sb_real_number_trimmed(sb, 1000000_int64, 6); call check(sb%s(1:sb%n) == '1', 'rnst 1')
    sb%n = 0
    call sb_f64(sb, 5d-6); call check(sb%s(1:sb%n) == '0.000005', 'f64 5e-6 '//sb%s(1:sb%n))
    sb%n = 0
    call sb_f64(sb, 1.25d0); call check(sb%s(1:sb%n) == '1.25', 'f64 1.25 '//sb%s(1:sb%n))
    sb%n = 0
    call sb_f64(sb, 0.1d0); call check(sb%s(1:sb%n) == '0.1', 'f64 0.1 '//sb%s(1:sb%n))
    sb%n = 0
    call sb_f64(sb, 1d300); call check(sb%s(1:sb%n) == '1e300', 'f64 1e300 '//sb%s(1:sb%n))
  end subroutine
  subroutine t_zstd(inhex, outhex)
    character(len=*), intent(in) :: inhex, outhex
    type(bytes_t) :: inb, outb, want
    integer :: e
    call unhex(inhex, inb)
    call unhex(outhex, want)
    call zstd_decompress(inb%d, inb%n, outb, e)
    if (e /= 0) then
      call check(.false., 'zstd '//inhex//' error: '//trim(zstd_err))
      return
    end if
    if (outb%n /= want%n) then
      call check(.false., 'zstd '//inhex//' length')
      return
    end if
    if (want%n > 0) then
      call check(all(outb%d(0:outb%n-1) == want%d(0:want%n-1)), 'zstd '//inhex)
    else
      call check(.true., 'zstd '//inhex)
    end if
  end subroutine
end program
