! OnlyBlocks in Fortran 2018: a single-process, zero-dependency, zero-disk
! historical Solana getBlock JSON-RPC server backed by Old Faithful Range reads.
program onlyblocks
  use iso_c_binding
  use iso_fortran_env, only: output_unit, error_unit
  use ob_util
  use ob_posix
  use ob_http, only: upstream_config
  use ob_rpc, only: rpc_init
  use ob_server
  implicit none
  character(len=:), allocatable :: bind, base, arg, host
  integer :: i, nargs, colon, port, ip(4), k
  logical :: have_bind, have_base, ok
  integer(c_int) :: lfd

  have_bind = .false.
  have_base = .false.
  nargs = command_argument_count()
  i = 1
  do while (i <= nargs)
    arg = get_arg(i)
    if (streq(arg, '--bind') .or. streq(arg, '--base-url')) then
      if (i == nargs) call die('missing value for ' // arg)
      if (streq(arg, '--bind')) then
        bind = get_arg(i + 1)
        have_bind = .true.
      else
        base = get_arg(i + 1)
        have_base = .true.
      end if
      i = i + 2
    else if (len(arg) > 7 .and. arg(1:min(7, len(arg))) == '--bind=') then
      bind = arg(8:)
      have_bind = .true.
      i = i + 1
    else if (len(arg) >= 11 .and. arg(1:min(11, len(arg))) == '--base-url=') then
      base = arg(12:)
      have_base = .true.
      i = i + 1
    else if (streq(arg, '--help') .or. streq(arg, '-h')) then
      write(output_unit, '(a)') 'usage: onlyblocks [--bind HOST:PORT] [--base-url URL]'
      stop
    else
      call die('unknown argument: ' // arg)
    end if
  end do
  if (.not. have_bind) bind = get_env('ONLYBLOCKS_BIND', '127.0.0.1:8899')
  if (.not. have_base) base = get_env('OLD_FAITHFUL_BASE_URL', 'https://files.old-faithful.net')

  ! --base-url normalization: trim whitespace, strip every trailing '/'.
  base = strip_ws(base)
  k = len(base)
  do while (k > 0)
    if (base(k:k) /= '/') exit
    k = k - 1
  end do
  base = base(1:k)
  if (.not. upstream_config(base)) call die('invalid --base-url (need http:// or https://): ' // base)

  colon = index(bind, ':', back=.true.)
  if (colon <= 1 .or. colon == len(bind)) call die('invalid --bind (need HOST:PORT): ' // bind)
  host = bind(1:colon - 1)
  if (host(1:1) == '[') call die('IPv6 bind addresses are not supported: ' // bind)
  port = 0
  do k = colon + 1, len(bind)
    if (bind(k:k) < '0' .or. bind(k:k) > '9') call die('invalid port in --bind: ' // bind)
    port = port * 10 + iachar(bind(k:k)) - 48
    if (port > 65535) call die('invalid port in --bind: ' // bind)
  end do
  call resolve_ipv4(host, ip, ok)
  if (.not. ok) call die('cannot resolve bind host: ' // host)

  call install_signals()
  call random_init(.false., .false.)
  call rpc_init()
  lfd = open_listener(ip, port)
  if (lfd < 0) call die('cannot listen on ' // bind)
  write(output_unit, '(a)') 'onlyblocks-fortran listening on ' // bind // ' (archive ' // base // ')'
  flush(output_unit)
  call serve_forever(lfd)

contains

  function get_arg(n) result(s)
    integer, intent(in) :: n
    character(len=:), allocatable :: s
    integer :: l
    call get_command_argument(n, length=l)
    allocate(character(len=l) :: s)
    if (l > 0) call get_command_argument(n, s)
  end function get_arg

  function get_env(name, default) result(s)
    character(len=*), intent(in) :: name, default
    character(len=:), allocatable :: s
    integer :: l, st
    call get_environment_variable(name, length=l, status=st)
    if (st /= 0 .or. l == 0) then
      s = default
      return
    end if
    allocate(character(len=l) :: s)
    call get_environment_variable(name, s)
  end function get_env

  function strip_ws(s) result(t)
    character(len=*), intent(in) :: s
    character(len=:), allocatable :: t
    integer :: a, b
    a = 1
    b = len(s)
    do while (a <= b)
      if (.not. is_ws(s(a:a))) exit
      a = a + 1
    end do
    do while (b >= a)
      if (.not. is_ws(s(b:b))) exit
      b = b - 1
    end do
    t = s(a:b)
  end function strip_ws

  logical function is_ws(c)
    character(len=1), intent(in) :: c
    is_ws = (c == ' ' .or. iachar(c) == 9 .or. iachar(c) == 10 .or. iachar(c) == 13 .or. &
             iachar(c) == 11 .or. iachar(c) == 12)
  end function is_ws

  subroutine die(msg)
    character(len=*), intent(in) :: msg
    write(error_unit, '(a)') 'onlyblocks: ' // msg
    error stop 2
  end subroutine die

end program onlyblocks
