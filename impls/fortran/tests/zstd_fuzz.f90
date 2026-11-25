! Mutation fuzzer: corrupt each input frame N times (byte flips, truncation,
! splices) and decode. Built with -fcheck=all, any out-of-bounds access aborts.
program zstd_fuzz
  use ob_util
  use ob_zstd
  implicit none
  integer :: i, k, e, n, it, nerr, nok, flips
  type(bytes_t) :: orig, mut, outb
  character(len=4096) :: a, cnt
  real :: r
  call get_command_argument(1, cnt)
  read(cnt, *) n
  nerr = 0; nok = 0
  call random_init(.true., .false.)
  do i = 2, command_argument_count()
    call get_command_argument(i, a)
    call slurp(trim(a), orig)
    if (orig%n < 4) cycle
    do it = 1, n
      mut%n = 0
      call bytes_append(mut, orig%d, 0_int64, orig%n)
      call random_number(r)
      flips = 1 + int(r * 4)
      do k = 1, flips
        call random_number(r)
        if (r < 0.1 .and. mut%n > 5) then
          call random_number(r)
          mut%n = 4 + int(r * real(mut%n - 4))          ! truncate
        else
          call random_number(r)
          mut%d(int(r * real(mut%n), int64)) = to_i8(int(r * 997.0))
        end if
      end do
      call zstd_decompress(mut%d, mut%n, outb, e)
      if (e == 0) then
        nok = nok + 1
      else
        nerr = nerr + 1
      end if
    end do
  end do
  print '(a,i0,a,i0,a)', 'zstd fuzz: ', nok + nerr, ' mutated frames, ', nerr, ' rejected, no crash'
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
