! ob_server: the inbound HTTP/1.1 side. One connection at a time: read the
! head, frame the body (Content-Length or chunked, 1 MiB cap), answer, close.
module ob_server
  use iso_c_binding
  use ob_util
  use ob_posix
  use ob_http
  use ob_rpc
  implicit none
  private
  public :: open_listener, serve_forever

  integer(int64), parameter :: MAX_BODY = 1048576_int64
  type(sb_t), save :: response
  type(bytes_t), save :: body

contains

  !> socket + SO_REUSEADDR + bind + listen. Returns the fd or -1.
  integer(c_int) function open_listener(ip, port)
    integer, intent(in) :: ip(4), port
    integer(c_int) :: fd, r
    integer(c_int8_t), target :: sa(16)
    open_listener = -1
    fd = c_socket(AF_INET, SOCK_STREAM, 0_c_int)
    if (fd < 0) return
    call set_int_opt(fd, SOL_SOCKET, SO_REUSEADDR, 1_c_int)
    call make_sockaddr(ip, port, sa)
    r = c_bind(fd, c_loc(sa), 16_c_int32_t)
    if (r /= 0) then
      r = c_close(fd)
      return
    end if
    r = c_listen(fd, 128_c_int)
    if (r /= 0) then
      r = c_close(fd)
      return
    end if
    open_listener = fd
  end function open_listener

  subroutine serve_forever(lfd)
    integer(c_int), intent(in) :: lfd
    integer(c_int) :: fd, r
    do
      fd = c_accept(lfd, c_null_ptr, c_null_ptr)
      if (fd < 0) cycle
      call set_int_opt(fd, SOL_SOCKET, SO_NOSIGPIPE, 1_c_int)
      call set_int_opt(fd, IPPROTO_TCP, TCP_NODELAY, 1_c_int)
      call set_timeouts(fd, 10)
      call handle_connection(fd)
      r = c_close(fd)
    end do
  end subroutine serve_forever

  subroutine send_simple(fd, status)
    integer(c_int), intent(in) :: fd
    character(len=*), intent(in) :: status
    character(len=:), allocatable :: msg
    logical :: ok
    msg = 'HTTP/1.1 ' // status // achar(13) // achar(10) // 'Content-Length: 0' // achar(13) // achar(10) // &
          'Connection: close' // achar(13) // achar(10) // achar(13) // achar(10)
    ok = send_all_chars(fd, msg, len(msg, kind=int64))
  end subroutine send_simple

  subroutine handle_connection(fd)
    integer(c_int), intent(in) :: fd
    type(reader_t) :: rd
    character(len=:), allocatable :: head, method, target, v, line, text, hdr
    integer :: st, sp1, sp2, eol
    integer(int64) :: clen, i
    logical :: found, ok, chunked
    call rd_init_socket(rd, fd)
    call rd_head(rd, head, st)
    if (st == RD_TOOBIG) then
      call send_simple(fd, '431 Request Header Fields Too Large')
      return
    end if
    if (st /= RD_OK) return
    eol = index(head, achar(13))
    if (eol == 0) eol = len(head) + 1
    line = head(1:eol - 1)
    sp1 = index(line, ' ')
    sp2 = index(line, ' ', back=.true.)
    if (sp1 == 0 .or. sp2 <= sp1) then
      call send_simple(fd, '400 Bad Request')
      return
    end if
    method = line(1:sp1 - 1)
    target = line(sp1 + 1:sp2 - 1)
    if (.not. streq(target, '/')) then
      call send_simple(fd, '404 Not Found')
      return
    end if
    if (.not. streq(method, 'POST')) then
      call send_simple(fd, '405 Method Not Allowed')
      return
    end if
    call header_value(head, 'transfer-encoding', v, found)
    chunked = .false.
    if (found) chunked = index(lower(v), 'chunked') > 0
    call header_value(head, 'expect', v, found)
    if (found) then
      if (streq(lower(v), '100-continue')) then
        hdr = 'HTTP/1.1 100 Continue' // achar(13) // achar(10) // achar(13) // achar(10)
        ok = send_all_chars(fd, hdr, len(hdr, kind=int64))
      end if
    end if
    body%n = 0
    if (chunked) then
      call rd_body_chunked(rd, MAX_BODY, body, st)
      if (st == RD_TOOBIG) then
        call send_simple(fd, '413 Payload Too Large')
        return
      end if
      if (st /= RD_OK) return
    else
      call header_value(head, 'content-length', v, found)
      if (found) then
        call parse_content_length(v, clen, ok)
        if (.not. ok) then
          call send_simple(fd, '400 Bad Request')
          return
        end if
        if (clen > MAX_BODY) then
          call send_simple(fd, '413 Payload Too Large')
          return
        end if
        call rd_body_len(rd, clen, body, st)
        if (st /= RD_OK) return
      end if
    end if
    allocate(character(len=body%n) :: text)
    do i = 0, body%n - 1
      text(i + 1:i + 1) = achar(ub(body%d(i)))
    end do
    call rpc_handle(text, response)
    hdr = 'HTTP/1.1 200 OK' // achar(13) // achar(10) // &
          'Content-Type: application/json' // achar(13) // achar(10) // &
          'Content-Length: ' // u64_str(response%n) // achar(13) // achar(10) // &
          'Connection: close' // achar(13) // achar(10) // achar(13) // achar(10)
    ok = send_all_chars(fd, hdr, len(hdr, kind=int64))
    if (ok) ok = send_all_chars(fd, response%s, response%n)
  end subroutine handle_connection

end module ob_server
