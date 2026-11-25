! ob_http: buffered readers over sockets and pipes, HTTP/1.1 framing
! (Content-Length, chunked, read-to-close) and the upstream Range client:
! raw POSIX TCP for http://, the OS curl binary over popen for https://.
module ob_http
  use iso_c_binding
  use ob_util
  use ob_posix
  implicit none
  private
  public :: reader_t, rd_init_socket, rd_head, rd_body_len, rd_body_chunked, rd_find_head
  public :: upstream_config, range_fetch, base_scheme, base_url
  public :: FETCH_OK, FETCH_NOTFOUND, FETCH_FATAL
  public :: RD_OK, RD_CLOSED, RD_TOOBIG, header_value, parse_content_length

  integer, parameter :: RD_OK = 0, RD_CLOSED = 1, RD_TOOBIG = 2
  integer, parameter :: FETCH_OK = 0, FETCH_NOTFOUND = 1, FETCH_RETRY = 2, FETCH_FATAL = 3
  integer, parameter :: MAX_HEAD = 65536
  integer, parameter :: MAX_RETRIES = 4
  integer(int64), parameter :: INITIAL_BACKOFF_MS = 200, MAX_BACKOFF_MS = 10000

  type :: reader_t
    integer :: kind = 1                 ! 1 socket, 2 pipe (FILE*)
    integer(c_int) :: fd = -1
    type(c_ptr) :: fp = c_null_ptr
    type(bytes_t) :: buf
    integer(int64) :: pos = 0           ! first unconsumed byte of buf
  end type reader_t

  ! Upstream origin, set once at start-up.
  integer, save :: base_scheme = 1      ! 1 http, 2 https
  character(len=:), allocatable, save :: base_url, base_host, base_authority, base_path
  integer, save :: base_port = 80
  character(len=:), allocatable, save :: curl_bin

contains

  ! ================================================================ readers
  subroutine rd_init_socket(rd, fd)
    type(reader_t), intent(inout) :: rd
    integer(c_int), intent(in) :: fd
    rd%kind = 1
    rd%fd = fd
    rd%buf%n = 0
    rd%pos = 0
    call bytes_reserve(rd%buf, 16384_int64)
  end subroutine rd_init_socket

  !> Read more bytes into rd%buf. Returns the count (0 on EOF or error).
  integer(int64) function rd_fill(rd, want)
    type(reader_t), intent(inout), target :: rd
    integer(int64), intent(in) :: want
    integer(c_size_t) :: got
    if (rd%kind == 1) then
      rd_fill = recv_into(rd%fd, rd%buf, want)
      if (rd_fill < 0) rd_fill = 0
    else
      call bytes_reserve(rd%buf, rd%buf%n + want)
      got = c_fread(c_loc(rd%buf%d(rd%buf%n)), 1_c_size_t, int(want, c_size_t), rd%fp)
      rd%buf%n = rd%buf%n + int(got, int64)
      rd_fill = int(got, int64)
    end if
  end function rd_fill

  !> Position just past the first CRLFCRLF at or after `from`, or -1.
  integer(int64) function rd_find_head(b, from)
    type(bytes_t), intent(in) :: b
    integer(int64), intent(in) :: from
    integer(int64) :: i
    rd_find_head = -1
    do i = max(from, 0_int64), b%n - 4
      if (b%d(i) == 13) then
        if (b%d(i + 1) == 10) then
          if (b%d(i + 2) == 13) then
            if (b%d(i + 3) == 10) then
              rd_find_head = i + 4
              return
            end if
          end if
        end if
      end if
    end do
  end function rd_find_head

  !> Read one header block starting at rd%pos; head text excludes the blank line.
  subroutine rd_head(rd, head, st)
    type(reader_t), intent(inout) :: rd
    character(len=:), allocatable, intent(out) :: head
    integer, intent(out) :: st
    integer(int64) :: endp, scan, i, got
    scan = rd%pos
    do
      endp = rd_find_head(rd%buf, scan)
      if (endp > 0) exit
      if (rd%buf%n - rd%pos > MAX_HEAD) then
        st = RD_TOOBIG
        return
      end if
      scan = max(rd%pos, rd%buf%n - 3)
      got = rd_fill(rd, 16384_int64)
      if (got <= 0) then
        st = RD_CLOSED
        return
      end if
    end do
    allocate(character(len=endp - 4 - rd%pos) :: head)
    do i = rd%pos, endp - 5
      head(i - rd%pos + 1:i - rd%pos + 1) = achar(ub(rd%buf%d(i)))
    end do
    rd%pos = endp
    st = RD_OK
  end subroutine rd_head

  !> Exactly n body bytes into out.
  subroutine rd_body_len(rd, n, out, st)
    type(reader_t), intent(inout), target :: rd
    integer(int64), intent(in) :: n
    type(bytes_t), intent(inout), target :: out
    integer, intent(out) :: st
    integer(int64) :: have, take, got
    integer(c_size_t) :: g
    out%n = 0
    call bytes_reserve(out, max(n, 1_int64))
    have = rd%buf%n - rd%pos
    take = min(have, n)
    if (take > 0) then
      out%d(0:take - 1) = rd%buf%d(rd%pos:rd%pos + take - 1)
      out%n = take
      rd%pos = rd%pos + take
    end if
    do while (out%n < n)
      if (rd%kind == 1) then
        got = recv_into(rd%fd, out, min(n - out%n, 1048576_int64))
      else
        g = c_fread(c_loc(out%d(out%n)), 1_c_size_t, int(n - out%n, c_size_t), rd%fp)
        got = int(g, int64)
        out%n = out%n + got
      end if
      if (got <= 0) then
        st = RD_CLOSED
        return
      end if
    end do
    st = RD_OK
  end subroutine rd_body_len

  !> Body until EOF, aborting once more than cap bytes arrive.
  subroutine rd_body_eof(rd, cap, hint, out, st)
    type(reader_t), intent(inout), target :: rd
    integer(int64), intent(in) :: cap, hint
    type(bytes_t), intent(inout), target :: out
    integer, intent(out) :: st
    integer(int64) :: have, got
    integer(c_size_t) :: g
    out%n = 0
    call bytes_reserve(out, max(min(hint, cap) + 1, 4096_int64))
    have = rd%buf%n - rd%pos
    if (have > cap) then
      st = RD_TOOBIG
      return
    end if
    if (have > 0) then
      out%d(0:have - 1) = rd%buf%d(rd%pos:rd%pos + have - 1)
      out%n = have
      rd%pos = rd%buf%n
    end if
    do
      if (rd%kind == 1) then
        got = recv_into(rd%fd, out, 65536_int64)
      else
        call bytes_reserve(out, out%n + 65536_int64)
        g = c_fread(c_loc(out%d(out%n)), 1_c_size_t, 65536_c_size_t, rd%fp)
        got = int(g, int64)
        out%n = out%n + got
      end if
      if (got <= 0) exit
      if (out%n > cap) then
        st = RD_TOOBIG
        return
      end if
    end do
    st = RD_OK
  end subroutine rd_body_eof

  !> Decode a chunked body (extensions and trailers ignored), capped at cap bytes.
  subroutine rd_body_chunked(rd, cap, out, st)
    type(reader_t), intent(inout) :: rd
    integer(int64), intent(in) :: cap
    type(bytes_t), intent(inout) :: out
    integer, intent(out) :: st
    character(len=:), allocatable :: line
    integer(int64) :: size, take
    integer :: i, h
    type(bytes_t) :: piece
    out%n = 0
    call bytes_reserve(out, 4096_int64)
    do
      call read_line(rd, line, st)
      if (st /= RD_OK) return
      size = 0
      do i = 1, len(line)
        h = index('0123456789abcdef', lower(line(i:i))) - 1
        if (h < 0) exit
        if (size > 268435456_int64) then
          st = RD_TOOBIG
          return
        end if
        size = size * 16 + h
      end do
      if (i == 1) then
        st = RD_CLOSED
        return
      end if
      if (size == 0) exit
      if (out%n + size > cap) then
        st = RD_TOOBIG
        return
      end if
      call rd_body_len(rd, size, piece, st)
      if (st /= RD_OK) return
      take = piece%n
      call bytes_append(out, piece%d, 0_int64, take)
      call read_line(rd, line, st)
      if (st /= RD_OK) return
    end do
    do
      call read_line(rd, line, st)
      if (st /= RD_OK) return
      if (len(line) == 0) exit
    end do
    st = RD_OK
  end subroutine rd_body_chunked

  subroutine read_line(rd, line, st)
    type(reader_t), intent(inout) :: rd
    character(len=:), allocatable, intent(out) :: line
    integer, intent(out) :: st
    integer(int64) :: i, e, got, scan
    scan = rd%pos
    do
      e = -1
      do i = scan, rd%buf%n - 2
        if (rd%buf%d(i) == 13) then
          if (rd%buf%d(i + 1) == 10) then
            e = i
            exit
          end if
        end if
      end do
      if (e >= 0) exit
      if (rd%buf%n - rd%pos > MAX_HEAD) then
        st = RD_TOOBIG
        return
      end if
      scan = max(rd%pos, rd%buf%n - 1)
      got = rd_fill(rd, 16384_int64)
      if (got <= 0) then
        st = RD_CLOSED
        return
      end if
    end do
    allocate(character(len=e - rd%pos) :: line)
    do i = rd%pos, e - 1
      line(i - rd%pos + 1:i - rd%pos + 1) = achar(ub(rd%buf%d(i)))
    end do
    rd%pos = e + 2
    st = RD_OK
  end subroutine read_line

  ! ================================================================ headers
  !> Value of the last header `name` (case-insensitive) in a head block; found=.false. if absent.
  subroutine header_value(head, name, val, found)
    character(len=*), intent(in) :: head, name
    character(len=:), allocatable, intent(out) :: val
    logical, intent(out) :: found
    integer :: ls, le_, colon
    found = .false.
    val = ''
    ls = index(head, achar(10)) + 1        ! skip the start line
    if (ls <= 1) return
    do while (ls <= len(head))
      le_ = index(head(ls:), achar(10))
      if (le_ == 0) then
        le_ = len(head) + 1
      else
        le_ = ls + le_ - 1
      end if
      colon = index(head(ls:le_ - 1), ':')
      if (colon > 1) then
        if (streq(lower(trim(adjustl(head(ls:ls + colon - 2)))), name)) then
          val = trim(adjustl(strip_cr(head(ls + colon:le_ - 1))))
          found = .true.
        end if
      end if
      ls = le_ + 1
    end do
  contains
    function strip_cr(s) result(t)
      character(len=*), intent(in) :: s
      character(len=:), allocatable :: t
      t = s
      if (len(t) > 0) then
        if (t(len(t):len(t)) == achar(13)) t = t(1:len(t) - 1)
      end if
      do while (len(t) > 0)
        if (t(len(t):len(t)) /= ' ' .and. t(len(t):len(t)) /= achar(9)) exit
        t = t(1:len(t) - 1)
      end do
    end function strip_cr
  end subroutine header_value

  !> Strict decimal Content-Length.
  subroutine parse_content_length(s, v, ok)
    character(len=*), intent(in) :: s
    integer(int64), intent(out) :: v
    logical, intent(out) :: ok
    call parse_u64_digits(s, v, ok)
    if (ok) then
      if (v < 0) ok = .false.
    end if
  end subroutine parse_content_length

  !> Status code from a response head, or -1.
  integer function status_code(head)
    character(len=*), intent(in) :: head
    integer :: sp, i
    status_code = -1
    if (len(head) < 12) return
    if (head(1:5) /= 'HTTP/') return
    sp = index(head, ' ')
    if (sp == 0 .or. sp + 3 > len(head)) return
    status_code = 0
    do i = sp + 1, sp + 3
      if (head(i:i) < '0' .or. head(i:i) > '9') then
        status_code = -1
        return
      end if
      status_code = status_code * 10 + iachar(head(i:i)) - 48
    end do
  end function status_code

  ! ================================================================ Retry-After
  integer(int64) function days_from_civil(y0, m, d)
    integer(int64), intent(in) :: y0, m, d
    integer(int64) :: y, era, yoe, doy, doe, mp
    y = y0
    if (m <= 2) y = y - 1
    if (y >= 0) then
      era = y / 400
    else
      era = (y - 399) / 400
    end if
    yoe = y - era * 400
    if (m > 2) then
      mp = m - 3
    else
      mp = m + 9
    end if
    doy = (153 * mp + 2) / 5 + d - 1
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    days_from_civil = era * 146097 + doe - 719468
  end function days_from_civil

  !> Retry-After as milliseconds (delta-seconds or IMF-fixdate); -1 if unparseable.
  integer(int64) function retry_after_ms(v)
    character(len=*), intent(in) :: v
    integer(int64) :: secs, y, mo, d, hh, mm, ss, t, now
    logical :: ok
    integer :: comma, ios
    character(len=3) :: mon
    retry_after_ms = -1
    if (len(v) == 0) return
    call parse_u64_digits(v, secs, ok)
    if (ok) then
      if (secs < 0 .or. secs > 100000000_int64) secs = 100000000_int64
      retry_after_ms = secs * 1000
      return
    end if
    ! IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
    comma = index(v, ',')
    if (comma == 0 .or. len(v) < comma + 25) return
    read(v(comma + 2:comma + 3), '(i2)', iostat=ios) d
    if (ios /= 0) return
    mon = v(comma + 5:comma + 7)
    mo = (index('JanFebMarAprMayJunJulAugSepOctNovDec', mon) + 2) / 3
    if (mo < 1 .or. mod(index('JanFebMarAprMayJunJulAugSepOctNovDec', mon) - 1, 3) /= 0) return
    read(v(comma + 9:comma + 12), '(i4)', iostat=ios) y
    if (ios /= 0) return
    read(v(comma + 14:comma + 15), '(i2)', iostat=ios) hh
    if (ios /= 0) return
    read(v(comma + 17:comma + 18), '(i2)', iostat=ios) mm
    if (ios /= 0) return
    read(v(comma + 20:comma + 21), '(i2)', iostat=ios) ss
    if (ios /= 0) return
    t = days_from_civil(y, mo, d) * 86400 + hh * 3600 + mm * 60 + ss
    now = c_time(c_null_ptr)
    if (t <= now) then
      retry_after_ms = 0
    else
      retry_after_ms = (t - now) * 1000
    end if
  end function retry_after_ms

  ! ================================================================ upstream
  !> Parse and remember the base URL. Returns .false. if it is unusable.
  logical function upstream_config(url)
    character(len=*), intent(in) :: url
    character(len=:), allocatable :: rest, auth
    integer :: slash, colon, i, port
    logical :: ok, ex
    upstream_config = .false.
    base_url = url
    if (len(url) >= 7 .and. streq(lower(url(1:min(7, len(url)))), 'http://')) then
      base_scheme = 1
      rest = url(8:)
      base_port = 80
    else if (len(url) >= 8 .and. streq(lower(url(1:min(8, len(url)))), 'https://')) then
      base_scheme = 2
      rest = url(9:)
      base_port = 443
    else
      return
    end if
    slash = index(rest, '/')
    if (slash > 0) then
      auth = rest(1:slash - 1)
      base_path = rest(slash:)
    else
      auth = rest
      base_path = ''
    end if
    if (len(auth) == 0) return
    if (index(auth, '@') > 0) return
    do i = 1, len(url)
      if (iachar(url(i:i)) <= 32 .or. url(i:i) == "'" .or. iachar(url(i:i)) >= 127) return
    end do
    base_authority = auth
    colon = index(auth, ':', back=.true.)
    if (auth(1:1) == '[') then
      if (base_scheme == 1) return          ! IPv6 http:// origins are not supported
      colon = index(auth, ']:', back=.true.)
      if (colon > 0) colon = colon + 1
    end if
    if (colon > 0) then
      base_host = auth(1:colon - 1)
      port = 0
      if (colon == len(auth)) return
      do i = colon + 1, len(auth)
        if (auth(i:i) < '0' .or. auth(i:i) > '9') return
        port = port * 10 + iachar(auth(i:i)) - 48
        if (port > 65535) return
      end do
      base_port = port
    else
      base_host = auth
    end if
    if (len(base_host) == 0) return
    inquire(file='/usr/bin/curl', exist=ex)
    if (ex) then
      curl_bin = '/usr/bin/curl'
    else
      curl_bin = 'curl'
    end if
    ok = .true.
    upstream_config = ok
  end function upstream_config

  !> GET {base}{path} with Range: bytes=start-end. code = FETCH_OK/NOTFOUND/FATAL.
  subroutine range_fetch(path, start, end_, cap, expected, out, code, msg)
    character(len=*), intent(in) :: path
    integer(int64), intent(in) :: start, end_, cap, expected
    type(bytes_t), intent(inout) :: out
    integer, intent(out) :: code
    character(len=:), allocatable, intent(out) :: msg
    integer :: attempt, r
    integer(int64) :: ra, base, delay
    real(real64) :: u
    msg = ''
    do attempt = 0, MAX_RETRIES
      if (base_scheme == 1) then
        call attempt_http(path, start, end_, cap, expected, out, r, ra, msg)
      else
        call attempt_curl(path, start, end_, cap, expected, out, r, ra, msg)
      end if
      if (r /= FETCH_RETRY) then
        code = r
        return
      end if
      if (attempt == MAX_RETRIES) exit
      if (ra >= 0) then
        delay = min(ra, MAX_BACKOFF_MS)
      else
        base = min(INITIAL_BACKOFF_MS * 2_int64**min(attempt, 30), MAX_BACKOFF_MS)
        call random_number(u)
        delay = int(real(base, real64) * (0.5_real64 + 0.5_real64 * u), int64)
      end if
      if (delay > 0) call sleep_ms(delay)
    end do
    code = FETCH_FATAL
    msg = 'upstream retries exhausted: ' // msg
  end subroutine range_fetch

  subroutine classify(head, r, ra, msg)
    character(len=*), intent(in) :: head
    integer, intent(out) :: r
    integer(int64), intent(out) :: ra
    character(len=:), allocatable, intent(inout) :: msg
    integer :: sc
    character(len=:), allocatable :: v
    logical :: found
    ra = -1
    sc = status_code(head)
    if (sc == 206) then
      r = FETCH_OK
    else if (sc == 404) then
      r = FETCH_NOTFOUND
      msg = 'HTTP 404'
    else if (sc == 429 .or. (sc >= 500 .and. sc <= 599)) then
      r = FETCH_RETRY
      call header_value(head, 'retry-after', v, found)
      if (found) ra = retry_after_ms(v)
      msg = 'HTTP ' // itoa(sc)
    else if (sc < 0) then
      r = FETCH_RETRY
      msg = 'malformed upstream status line'
    else
      r = FETCH_FATAL
      msg = 'unexpected upstream HTTP status ' // itoa(sc) // ' (expected 206)'
    end if
  end subroutine classify

  subroutine attempt_http(path, start, end_, cap, expected, out, r, ra, msg)
    character(len=*), intent(in) :: path
    integer(int64), intent(in) :: start, end_, cap, expected
    type(bytes_t), intent(inout) :: out
    integer, intent(out) :: r
    integer(int64), intent(out) :: ra
    character(len=:), allocatable, intent(inout) :: msg
    integer(c_int) :: fd, rc
    integer :: ip(4), st
    integer(c_int8_t), target :: sa(16)
    logical :: ok, found, chunked
    character(len=:), allocatable :: req, head, v
    integer(int64) :: clen
    type(reader_t) :: rd
    ra = -1
    r = FETCH_RETRY
    call resolve_ipv4(base_host, ip, ok)
    if (.not. ok) then
      msg = 'cannot resolve ' // base_host
      return
    end if
    fd = c_socket(AF_INET, SOCK_STREAM, 0_c_int)
    if (fd < 0) then
      msg = 'socket() failed'
      return
    end if
    call set_int_opt(fd, SOL_SOCKET, SO_NOSIGPIPE, 1_c_int)
    call set_int_opt(fd, IPPROTO_TCP, TCP_NODELAY, 1_c_int)
    call set_timeouts(fd, 60)
    call make_sockaddr(ip, base_port, sa)
    rc = c_connect(fd, c_loc(sa), 16_c_int32_t)
    if (rc /= 0) then
      msg = 'connect failed'
      rc = c_close(fd)
      return
    end if
    req = 'GET ' // base_path // path // ' HTTP/1.1' // achar(13) // achar(10) // &
          'Host: ' // base_authority // achar(13) // achar(10) // &
          'Range: bytes=' // u64_str(start) // '-' // u64_str(end_) // achar(13) // achar(10) // &
          'User-Agent: onlyblocks/fortran' // achar(13) // achar(10) // &
          'Accept: */*' // achar(13) // achar(10) // &
          'Accept-Encoding: identity' // achar(13) // achar(10) // &
          'Connection: close' // achar(13) // achar(10) // achar(13) // achar(10)
    if (.not. send_all_chars(fd, req, len(req, kind=int64))) then
      msg = 'send failed'
      rc = c_close(fd)
      return
    end if
    call rd_init_socket(rd, fd)
    call rd_head(rd, head, st)
    if (st /= RD_OK) then
      msg = 'connection closed before the response head'
      rc = c_close(fd)
      return
    end if
    call classify(head, r, ra, msg)
    if (r /= FETCH_OK) then
      rc = c_close(fd)
      return
    end if
    call header_value(head, 'transfer-encoding', v, found)
    chunked = .false.
    if (found) chunked = index(lower(v), 'chunked') > 0
    if (chunked) then
      call rd_body_chunked(rd, cap, out, st)
    else
      call header_value(head, 'content-length', v, found)
      if (found) then
        call parse_content_length(v, clen, ok)
        if (.not. ok) then
          r = FETCH_FATAL
          msg = 'invalid upstream Content-Length'
          rc = c_close(fd)
          return
        end if
        if (clen > cap) then
          r = FETCH_FATAL
          msg = 'Content-Length ' // u64_str(clen) // ' exceeds the cap'
          rc = c_close(fd)
          return
        end if
        call rd_body_len(rd, clen, out, st)
      else
        call rd_body_eof(rd, cap, expected, out, st)
      end if
    end if
    rc = c_close(fd)
    if (st == RD_TOOBIG) then
      r = FETCH_FATAL
      msg = 'upstream body exceeds the cap'
      return
    else if (st /= RD_OK) then
      r = FETCH_RETRY
      msg = 'connection closed before the body was complete'
      return
    end if
    if (out%n /= expected) then
      r = FETCH_FATAL
      msg = 'byte length mismatch: expected ' // u64_str(expected) // ', got ' // u64_str(out%n)
      return
    end if
    r = FETCH_OK
  end subroutine attempt_http

  subroutine attempt_curl(path, start, end_, cap, expected, out, r, ra, msg)
    character(len=*), intent(in) :: path
    integer(int64), intent(in) :: start, end_, cap, expected
    type(bytes_t), intent(inout) :: out
    integer, intent(out) :: r
    integer(int64), intent(out) :: ra
    character(len=:), allocatable, intent(inout) :: msg
    character(len=:), allocatable :: cmd, head, v, reason
    type(reader_t) :: rd
    integer :: st, sc, ps, fdn
    integer(c_int) :: rc
    integer(int64) :: clen
    logical :: found, ok
    ra = -1
    r = FETCH_RETRY
    ! `exec` replaces the shell, so curl is the only child; low fds of ours are closed for it.
    cmd = 'exec ' // curl_bin // ' -q -sS -i --http1.1 --connect-timeout 10 --max-time 60' // &
          " -H 'Range: bytes=" // u64_str(start) // '-' // u64_str(end_) // "'" // &
          " -A 'onlyblocks/fortran' '" // base_url // path // "'"
    do fdn = 3, 9
      cmd = cmd // ' ' // achar(48 + fdn) // '<&-'
    end do
    rd%kind = 2
    rd%fp = c_popen(cmd // c_null_char, 'r' // c_null_char)
    if (.not. c_associated(rd%fp)) then
      msg = 'popen(curl) failed'
      return
    end if
    call bytes_reserve(rd%buf, 16384_int64)
    do
      call rd_head(rd, head, st)
      if (st /= RD_OK) then
        msg = 'curl produced no response head'
        rc = c_pclose(rd%fp)
        return
      end if
      sc = status_code(head)
      ps = index(head, achar(13))
      if (ps == 0) ps = len(head) + 1
      reason = lower(head(1:ps - 1))
      if (sc >= 100 .and. sc < 200) cycle
      if (sc == 200 .and. index(reason, 'connection established') > 0) cycle
      exit
    end do
    call classify(head, r, ra, msg)
    if (r /= FETCH_OK) then
      rc = c_pclose(rd%fp)
      return
    end if
    clen = expected
    call header_value(head, 'content-length', v, found)
    if (found) then
      call parse_content_length(v, clen, ok)
      if (ok .and. clen > cap) then
        r = FETCH_FATAL
        msg = 'Content-Length exceeds the cap'
        rc = c_pclose(rd%fp)
        return
      end if
      if (.not. ok) clen = expected
    end if
    call rd_body_eof(rd, cap, clen, out, st)
    rc = c_pclose(rd%fp)
    if (st == RD_TOOBIG) then
      r = FETCH_FATAL
      msg = 'upstream body exceeds the cap'
      return
    end if
    if (rc /= 0) then
      r = FETCH_RETRY
      msg = 'curl exited with status ' // itoa(int(rc))
      return
    end if
    if (out%n /= expected) then
      r = FETCH_FATAL
      msg = 'byte length mismatch: expected ' // u64_str(expected) // ', got ' // u64_str(out%n)
      return
    end if
    r = FETCH_OK
  end subroutine attempt_curl

end module ob_http
