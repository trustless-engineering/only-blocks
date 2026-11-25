! ob_posix: iso_c_binding declarations of the (non-variadic) libc calls the
! server needs, plus thin Fortran wrappers. Constants are the Darwin values
! from <sys/socket.h>, <netinet/in.h> and <sys/signal.h>.
module ob_posix
  use iso_c_binding
  use ob_util
  implicit none
  public

  integer(c_int), parameter :: AF_INET = 2, SOCK_STREAM = 1
  integer(c_int), parameter :: SOL_SOCKET = int(z'FFFF', c_int)
  integer(c_int), parameter :: SO_REUSEADDR = 4, SO_SNDTIMEO = int(z'1005', c_int)
  integer(c_int), parameter :: SO_RCVTIMEO = int(z'1006', c_int), SO_NOSIGPIPE = int(z'1022', c_int)
  integer(c_int), parameter :: IPPROTO_TCP = 6, TCP_NODELAY = 1
  integer(c_int), parameter :: SIGINT = 2, SIGPIPE = 13, SIGTERM = 15
  integer(c_int), parameter :: EINTR = 4

  type, bind(c) :: timeval_t
    integer(c_int64_t) :: sec
    integer(c_int64_t) :: usec   ! Darwin: int32 tv_usec + padding (little-endian)
  end type timeval_t

  interface
    function c_socket(domain, stype, protocol) bind(c, name='socket') result(r)
      import :: c_int
      integer(c_int), value :: domain, stype, protocol
      integer(c_int) :: r
    end function c_socket

    function c_setsockopt(s, level, optname, optval, optlen) bind(c, name='setsockopt') result(r)
      import :: c_int, c_ptr, c_int32_t
      integer(c_int), value :: s, level, optname
      type(c_ptr), value :: optval
      integer(c_int32_t), value :: optlen
      integer(c_int) :: r
    end function c_setsockopt

    function c_bind(s, addr, addrlen) bind(c, name='bind') result(r)
      import :: c_int, c_ptr, c_int32_t
      integer(c_int), value :: s
      type(c_ptr), value :: addr
      integer(c_int32_t), value :: addrlen
      integer(c_int) :: r
    end function c_bind

    function c_connect(s, addr, addrlen) bind(c, name='connect') result(r)
      import :: c_int, c_ptr, c_int32_t
      integer(c_int), value :: s
      type(c_ptr), value :: addr
      integer(c_int32_t), value :: addrlen
      integer(c_int) :: r
    end function c_connect

    function c_listen(s, backlog) bind(c, name='listen') result(r)
      import :: c_int
      integer(c_int), value :: s, backlog
      integer(c_int) :: r
    end function c_listen

    function c_accept(s, addr, addrlen) bind(c, name='accept') result(r)
      import :: c_int, c_ptr
      integer(c_int), value :: s
      type(c_ptr), value :: addr, addrlen
      integer(c_int) :: r
    end function c_accept

    function c_recv(s, buf, length, flags) bind(c, name='recv') result(r)
      import :: c_int, c_ptr, c_size_t, c_long
      integer(c_int), value :: s, flags
      type(c_ptr), value :: buf
      integer(c_size_t), value :: length
      integer(c_long) :: r
    end function c_recv

    function c_send(s, buf, length, flags) bind(c, name='send') result(r)
      import :: c_int, c_ptr, c_size_t, c_long
      integer(c_int), value :: s, flags
      type(c_ptr), value :: buf
      integer(c_size_t), value :: length
      integer(c_long) :: r
    end function c_send

    function c_close(fd) bind(c, name='close') result(r)
      import :: c_int
      integer(c_int), value :: fd
      integer(c_int) :: r
    end function c_close

    function c_shutdown(fd, how) bind(c, name='shutdown') result(r)
      import :: c_int
      integer(c_int), value :: fd, how
      integer(c_int) :: r
    end function c_shutdown

    function c_signal(sig, handler) bind(c, name='signal') result(r)
      import :: c_int, c_funptr
      integer(c_int), value :: sig
      type(c_funptr), value :: handler
      type(c_funptr) :: r
    end function c_signal

    subroutine c_exit_now(status) bind(c, name='_exit')
      import :: c_int
      integer(c_int), value :: status
    end subroutine c_exit_now

    function c_usleep(usec) bind(c, name='usleep') result(r)
      import :: c_int, c_int32_t
      integer(c_int32_t), value :: usec
      integer(c_int) :: r
    end function c_usleep

    function c_time(tloc) bind(c, name='time') result(r)
      import :: c_ptr, c_int64_t
      type(c_ptr), value :: tloc
      integer(c_int64_t) :: r
    end function c_time

    function c_getaddrinfo(node, service, hints, res) bind(c, name='getaddrinfo') result(r)
      import :: c_int, c_char, c_ptr
      character(kind=c_char), intent(in) :: node(*)
      type(c_ptr), value :: service, hints
      type(c_ptr), intent(out) :: res
      integer(c_int) :: r
    end function c_getaddrinfo

    subroutine c_freeaddrinfo(res) bind(c, name='freeaddrinfo')
      import :: c_ptr
      type(c_ptr), value :: res
    end subroutine c_freeaddrinfo

    function c_popen(command, mode) bind(c, name='popen') result(r)
      import :: c_char, c_ptr
      character(kind=c_char), intent(in) :: command(*), mode(*)
      type(c_ptr) :: r
    end function c_popen

    function c_pclose(stream) bind(c, name='pclose') result(r)
      import :: c_ptr, c_int
      type(c_ptr), value :: stream
      integer(c_int) :: r
    end function c_pclose

    function c_fread(ptr, sz, nitems, stream) bind(c, name='fread') result(r)
      import :: c_ptr, c_size_t
      type(c_ptr), value :: ptr, stream
      integer(c_size_t), value :: sz, nitems
      integer(c_size_t) :: r
    end function c_fread

    function c_errno_loc() bind(c, name='__error') result(r)
      import :: c_ptr
      type(c_ptr) :: r
    end function c_errno_loc
  end interface

contains

  integer function errno()
    integer(c_int), pointer :: p
    call c_f_pointer(c_errno_loc(), p)
    errno = int(p)
  end function errno

  subroutine on_terminate(sig) bind(c)
    integer(c_int), value :: sig
    if (sig >= 0) call c_exit_now(0_c_int)
  end subroutine on_terminate

  !> SIGINT/SIGTERM exit immediately with status 0; SIGPIPE is ignored.
  subroutine install_signals()
    type(c_funptr) :: old
    old = c_signal(SIGTERM, c_funloc(on_terminate))
    old = c_signal(SIGINT, c_funloc(on_terminate))
    old = c_signal(SIGPIPE, transfer(1_c_intptr_t, c_null_funptr))   ! SIG_IGN
  end subroutine install_signals

  subroutine set_int_opt(fd, level, name, v)
    integer(c_int), intent(in) :: fd, level, name
    integer(c_int), intent(in) :: v
    integer(c_int), target :: val
    integer(c_int) :: r
    val = v
    r = c_setsockopt(fd, level, name, c_loc(val), 4_c_int32_t)
  end subroutine set_int_opt

  subroutine set_timeouts(fd, seconds)
    integer(c_int), intent(in) :: fd
    integer, intent(in) :: seconds
    type(timeval_t), target :: tv
    integer(c_int) :: r
    tv%sec = seconds
    tv%usec = 0
    r = c_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, c_loc(tv), 16_c_int32_t)
    r = c_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, c_loc(tv), 16_c_int32_t)
  end subroutine set_timeouts

  !> Build a Darwin sockaddr_in (16 bytes) for ip (host order bytes a.b.c.d) and port.
  subroutine make_sockaddr(ip, port, sa)
    integer, intent(in) :: ip(4), port
    integer(c_int8_t), intent(out) :: sa(16)
    sa = 0
    sa(1) = 16_c_int8_t
    sa(2) = int(AF_INET, c_int8_t)
    sa(3) = to_i8(shiftr(port, 8))
    sa(4) = to_i8(iand(port, 255))
    sa(5) = to_i8(ip(1)); sa(6) = to_i8(ip(2)); sa(7) = to_i8(ip(3)); sa(8) = to_i8(ip(4))
  end subroutine make_sockaddr

  !> Parse a dotted-quad IPv4 literal.
  subroutine parse_ipv4(s, ip, ok)
    character(len=*), intent(in) :: s
    integer, intent(out) :: ip(4)
    logical, intent(out) :: ok
    integer :: i, k, v, nd
    ok = .false.
    ip = 0
    k = 1
    v = 0
    nd = 0
    do i = 1, len(s)
      if (s(i:i) == '.') then
        if (nd == 0 .or. k >= 4) return
        ip(k) = v
        k = k + 1
        v = 0
        nd = 0
      else if (s(i:i) >= '0' .and. s(i:i) <= '9') then
        v = v * 10 + (iachar(s(i:i)) - 48)
        nd = nd + 1
        if (v > 255 .or. nd > 3) return
      else
        return
      end if
    end do
    if (k /= 4 .or. nd == 0) return
    ip(4) = v
    ok = .true.
  end subroutine parse_ipv4

  !> Resolve a host to an IPv4 address (literal, or getaddrinfo AF_INET).
  subroutine resolve_ipv4(host, ip, ok)
    character(len=*), intent(in) :: host
    integer, intent(out) :: ip(4)
    logical, intent(out) :: ok
    integer(c_int32_t), target :: hints(12)    ! struct addrinfo is 48 bytes on Darwin
    type(c_ptr) :: res, addrp
    integer(c_int) :: r
    integer(c_int8_t), pointer :: ai(:), sa(:)
    integer(c_intptr_t) :: addr_int
    integer :: k
    call parse_ipv4(host, ip, ok)
    if (ok) return
    if (streq(host, 'localhost')) then
      ip = [127, 0, 0, 1]
      ok = .true.
      return
    end if
    hints = 0
    hints(2) = AF_INET
    hints(3) = SOCK_STREAM
    r = c_getaddrinfo(trim(host) // c_null_char, c_null_ptr, c_loc(hints), res)
    if (r /= 0 .or. .not. c_associated(res)) return
    call c_f_pointer(res, ai, [48])
    ! ai_addr lives at byte offset 32 on Darwin (after ai_canonname at 24).
    addr_int = 0
    do k = 8, 1, -1
      addr_int = ior(shiftl(addr_int, 8), int(iand(int(ai(32 + k)), 255), c_intptr_t))
    end do
    addrp = transfer(addr_int, c_null_ptr)
    if (c_associated(addrp)) then
      call c_f_pointer(addrp, sa, [16])
      do k = 1, 4
        ip(k) = iand(int(sa(4 + k)), 255)
      end do
      ok = .true.
    end if
    call c_freeaddrinfo(res)
  end subroutine resolve_ipv4

  !> Send all n bytes of a character buffer.
  logical function send_all_chars(fd, s, n)
    integer(c_int), intent(in) :: fd
    character(len=*), intent(in), target :: s
    integer(int64), intent(in) :: n
    integer(int64) :: off
    integer(c_long) :: r
    send_all_chars = .false.
    off = 0
    do while (off < n)
      r = c_send(fd, c_loc(s(off + 1:off + 1)), int(min(n - off, 1048576_int64), c_size_t), 0_c_int)
      if (r < 0) then
        if (errno() == EINTR) cycle
        return
      end if
      if (r == 0) return
      off = off + r
    end do
    send_all_chars = .true.
  end function send_all_chars

  !> recv into b%d(b%n:) up to `want` bytes; returns bytes read, 0 on EOF, <0 on error.
  integer(int64) function recv_into(fd, b, want)
    integer(c_int), intent(in) :: fd
    type(bytes_t), intent(inout), target :: b
    integer(int64), intent(in) :: want
    integer(c_long) :: r
    call bytes_reserve(b, b%n + want)
    do
      r = c_recv(fd, c_loc(b%d(b%n)), int(want, c_size_t), 0_c_int)
      if (r < 0) then
        if (errno() == EINTR) cycle
      end if
      exit
    end do
    if (r > 0) b%n = b%n + r
    recv_into = r
  end function recv_into

  subroutine sleep_ms(ms)
    integer(int64), intent(in) :: ms
    integer(int64) :: left
    integer(c_int) :: r
    left = ms
    do while (left > 0)
      r = c_usleep(int(min(left, 900_int64) * 1000_int64, c_int32_t))
      left = left - min(left, 900_int64)
    end do
  end subroutine sleep_ms

end module ob_posix
