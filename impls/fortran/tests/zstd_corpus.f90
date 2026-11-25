! Test driver: for each argument pair "<frame.zst> <expected>", decompress the
! frame with ob_zstd and compare byte for byte. Usage: zstd_corpus a.zst a ...
program zstd_corpus
  use ob_util
  use ob_zstd
  implicit none
  integer :: i, n, e, bad
  type(bytes_t) :: inb, want, outb
  character(len=4096) :: a, b
  n = command_argument_count()
  bad = 0
  do i = 1, n - 1, 2
    call get_command_argument(i, a)
    call get_command_argument(i + 1, b)
    call slurp(trim(a), inb)
    call slurp(trim(b), want)
    call zstd_decompress(inb%d, inb%n, outb, e)
    if (e /= 0) then
      print '(4a)', 'FAIL ', trim(a), ': ', trim(zstd_err)
      bad = bad + 1
    else if (outb%n /= want%n) then
      print '(3a,i0,a,i0)', 'FAIL ', trim(a), ' length ', outb%n, ' want ', want%n
      bad = bad + 1
    else if (want%n > 0) then
      if (any(outb%d(0:outb%n-1) /= want%d(0:want%n-1))) then
        print '(2a)', 'FAIL ', trim(a), ' content'
        bad = bad + 1
      end if
    end if
  end do
  print '(a,i0,a,i0)', 'zstd corpus: ', n / 2 - bad, ' ok, failures: ', bad
  if (bad > 0) error stop 1
contains
  subroutine slurp(path, b)
    character(len=*), intent(in) :: path
    type(bytes_t), intent(inout) :: b
    integer :: u, sz
    open(newunit=u, file=path, access='stream', form='unformatted', status='old', action='read')
    inquire(unit=u, size=sz)
    b%n = 0
    call bytes_reserve(b, int(max(sz, 1), int64))
    if (sz > 0) read(u) b%d(0:sz-1)
    b%n = sz
    close(u)
  end subroutine
end program
