! ob_json: a strict RFC 8259 parser for JSON-RPC request bodies. It builds a
! flat node table (first-child / next-sibling links into the source text),
! validates UTF-8 and surrogate pairs, and caps nesting at 128 levels.
module ob_json
  use ob_util
  implicit none
  private
  public :: jdoc_t, json_parse, jget, jstr, jraw, jkey_eq, jstr_eq, jlen
  public :: J_NULL, J_FALSE, J_TRUE, J_NUM, J_STR, J_ARR, J_OBJ

  integer, parameter :: J_NULL = 0, J_FALSE = 1, J_TRUE = 2, J_NUM = 3, J_STR = 4, J_ARR = 5, J_OBJ = 6
  integer, parameter :: MAX_DEPTH = 128

  type :: jdoc_t
    integer :: n = 0
    !> kind, value text span [p, q], first child, next sibling, member key span [kp, kq]
    integer, allocatable :: kind(:), p(:), q(:), child(:), next(:), kp(:), kq(:)
    logical, allocatable :: esc(:), kesc(:), isint(:)
  end type jdoc_t

contains

  subroutine grow(doc)
    type(jdoc_t), intent(inout) :: doc
    integer :: cap
    integer, allocatable :: ti(:)
    logical, allocatable :: tl(:)
    if (.not. allocated(doc%kind)) then
      cap = 64
      allocate(doc%kind(cap), doc%p(cap), doc%q(cap), doc%child(cap), doc%next(cap), doc%kp(cap), doc%kq(cap))
      allocate(doc%esc(cap), doc%kesc(cap), doc%isint(cap))
      return
    end if
    if (doc%n < size(doc%kind)) return
    cap = 2 * size(doc%kind)
    call gi(doc%kind); call gi(doc%p); call gi(doc%q); call gi(doc%child)
    call gi(doc%next); call gi(doc%kp); call gi(doc%kq)
    call gl(doc%esc); call gl(doc%kesc); call gl(doc%isint)
  contains
    subroutine gi(a)
      integer, allocatable, intent(inout) :: a(:)
      allocate(ti(cap))
      ti(1:size(a)) = a
      call move_alloc(ti, a)
    end subroutine gi
    subroutine gl(a)
      logical, allocatable, intent(inout) :: a(:)
      allocate(tl(cap))
      tl(1:size(a)) = a
      call move_alloc(tl, a)
    end subroutine gl
  end subroutine grow

  integer function new_node(doc, kind, p)
    type(jdoc_t), intent(inout) :: doc
    integer, intent(in) :: kind, p
    call grow(doc)
    doc%n = doc%n + 1
    new_node = doc%n
    doc%kind(new_node) = kind
    doc%p(new_node) = p
    doc%q(new_node) = p
    doc%child(new_node) = 0
    doc%next(new_node) = 0
    doc%kp(new_node) = 0
    doc%kq(new_node) = -1
    doc%esc(new_node) = .false.
    doc%kesc(new_node) = .false.
    doc%isint(new_node) = .false.
  end function new_node

  !> Parse txt. On success root > 0; on any syntax error root = 0.
  subroutine json_parse(txt, doc, root)
    character(len=*), intent(in) :: txt
    type(jdoc_t), intent(inout) :: doc
    integer, intent(out) :: root
    integer :: pos, n
    logical :: ok
    doc%n = 0
    n = len(txt)
    pos = 1
    root = 0
    call skip_ws(txt, pos)
    call parse_value(txt, pos, doc, 1, root, ok)
    if (.not. ok) then
      root = 0
      return
    end if
    call skip_ws(txt, pos)
    if (pos <= n) root = 0
  end subroutine json_parse

  subroutine skip_ws(txt, pos)
    character(len=*), intent(in) :: txt
    integer, intent(inout) :: pos
    integer :: c
    do while (pos <= len(txt))
      c = iachar(txt(pos:pos))
      if (c /= 32 .and. c /= 9 .and. c /= 10 .and. c /= 13) exit
      pos = pos + 1
    end do
  end subroutine skip_ws

  recursive subroutine parse_value(txt, pos, doc, depth, node, ok)
    character(len=*), intent(in) :: txt
    integer, intent(inout) :: pos
    type(jdoc_t), intent(inout) :: doc
    integer, intent(in) :: depth
    integer, intent(out) :: node
    logical, intent(out) :: ok
    integer :: n, c, last, child, kp, kq
    logical :: kesc
    ok = .false.
    node = 0
    n = len(txt)
    if (pos > n) return
    c = iachar(txt(pos:pos))
    select case (c)
    case (123) ! {
      if (depth > MAX_DEPTH) return
      node = new_node(doc, J_OBJ, pos)
      pos = pos + 1
      call skip_ws(txt, pos)
      if (pos > n) return
      if (txt(pos:pos) == '}') then
        pos = pos + 1
        doc%q(node) = pos - 1
        ok = .true.
        return
      end if
      last = 0
      do
        call skip_ws(txt, pos)
        if (pos > n) return
        if (txt(pos:pos) /= '"') return
        call scan_string(txt, pos, kp, kq, kesc, ok)
        if (.not. ok) return
        ok = .false.
        call skip_ws(txt, pos)
        if (pos > n) return
        if (txt(pos:pos) /= ':') return
        pos = pos + 1
        call skip_ws(txt, pos)
        call parse_value(txt, pos, doc, depth + 1, child, ok)
        if (.not. ok) return
        ok = .false.
        doc%kp(child) = kp
        doc%kq(child) = kq
        doc%kesc(child) = kesc
        if (last == 0) then
          doc%child(node) = child
        else
          doc%next(last) = child
        end if
        last = child
        call skip_ws(txt, pos)
        if (pos > n) return
        if (txt(pos:pos) == ',') then
          pos = pos + 1
          cycle
        else if (txt(pos:pos) == '}') then
          pos = pos + 1
          exit
        else
          return
        end if
      end do
      doc%q(node) = pos - 1
      ok = .true.
    case (91) ! [
      if (depth > MAX_DEPTH) return
      node = new_node(doc, J_ARR, pos)
      pos = pos + 1
      call skip_ws(txt, pos)
      if (pos > n) return
      if (txt(pos:pos) == ']') then
        pos = pos + 1
        doc%q(node) = pos - 1
        ok = .true.
        return
      end if
      last = 0
      do
        call skip_ws(txt, pos)
        call parse_value(txt, pos, doc, depth + 1, child, ok)
        if (.not. ok) return
        ok = .false.
        if (last == 0) then
          doc%child(node) = child
        else
          doc%next(last) = child
        end if
        last = child
        call skip_ws(txt, pos)
        if (pos > n) return
        if (txt(pos:pos) == ',') then
          pos = pos + 1
          cycle
        else if (txt(pos:pos) == ']') then
          pos = pos + 1
          exit
        else
          return
        end if
      end do
      doc%q(node) = pos - 1
      ok = .true.
    case (34) ! "
      node = new_node(doc, J_STR, pos)
      call scan_string(txt, pos, kp, kq, kesc, ok)
      if (.not. ok) return
      doc%p(node) = kp
      doc%q(node) = kq
      doc%esc(node) = kesc
    case (116) ! true
      if (pos + 3 > n) return
      if (txt(pos:pos + 3) /= 'true') return
      node = new_node(doc, J_TRUE, pos)
      pos = pos + 4
      doc%q(node) = pos - 1
      ok = .true.
    case (102) ! false
      if (pos + 4 > n) return
      if (txt(pos:pos + 4) /= 'false') return
      node = new_node(doc, J_FALSE, pos)
      pos = pos + 5
      doc%q(node) = pos - 1
      ok = .true.
    case (110) ! null
      if (pos + 3 > n) return
      if (txt(pos:pos + 3) /= 'null') return
      node = new_node(doc, J_NULL, pos)
      pos = pos + 4
      doc%q(node) = pos - 1
      ok = .true.
    case default
      if (c == 45 .or. (c >= 48 .and. c <= 57)) then
        node = new_node(doc, J_NUM, pos)
        call scan_number(txt, pos, doc%isint(node), ok)
        doc%q(node) = pos - 1
      end if
    end select
  end subroutine parse_value

  logical function isdig(txt, pos)
    character(len=*), intent(in) :: txt
    integer, intent(in) :: pos
    isdig = .false.
    if (pos > len(txt)) return
    isdig = (txt(pos:pos) >= '0' .and. txt(pos:pos) <= '9')
  end function isdig

  subroutine scan_number(txt, pos, isint, ok)
    character(len=*), intent(in) :: txt
    integer, intent(inout) :: pos
    logical, intent(out) :: isint
    logical, intent(out) :: ok
    integer :: n
    ok = .false.
    isint = .true.
    n = len(txt)
    if (txt(pos:pos) == '-') pos = pos + 1
    if (.not. isdig(txt, pos)) return
    if (txt(pos:pos) == '0') then
      pos = pos + 1
    else
      do while (isdig(txt, pos))
        pos = pos + 1
      end do
    end if
    if (pos <= n) then
      if (txt(pos:pos) == '.') then
        isint = .false.
        pos = pos + 1
        if (.not. isdig(txt, pos)) return
        do while (isdig(txt, pos))
          pos = pos + 1
        end do
      end if
    end if
    if (pos <= n) then
      if (txt(pos:pos) == 'e' .or. txt(pos:pos) == 'E') then
        isint = .false.
        pos = pos + 1
        if (pos <= n) then
          if (txt(pos:pos) == '+' .or. txt(pos:pos) == '-') pos = pos + 1
        end if
        if (.not. isdig(txt, pos)) return
        do while (isdig(txt, pos))
          pos = pos + 1
        end do
      end if
    end if
    ok = .true.
  end subroutine scan_number

  integer function hexval(ch)
    character(len=1), intent(in) :: ch
    hexval = index('0123456789abcdef', lower(ch)) - 1
  end function hexval

  !> Scan a string starting at the opening quote. [p, q] is the raw content.
  subroutine scan_string(txt, pos, p, q, esc, ok)
    character(len=*), intent(in) :: txt
    integer, intent(inout) :: pos
    integer, intent(out) :: p, q
    logical, intent(out) :: esc, ok
    integer :: n, c, need, k, c1, u, u2
    ok = .false.
    esc = .false.
    n = len(txt)
    pos = pos + 1
    p = pos
    q = pos - 1
    do
      if (pos > n) return
      c = iachar(txt(pos:pos))
      if (c == 34) then
        q = pos - 1
        pos = pos + 1
        ok = .true.
        return
      else if (c == 92) then
        esc = .true.
        if (pos + 1 > n) return
        select case (txt(pos + 1:pos + 1))
        case ('"', '\', '/', 'b', 'f', 'n', 'r', 't')
          pos = pos + 2
        case ('u')
          call read_u4(pos + 2, u)
          if (u < 0) return
          pos = pos + 6
          if (u >= 56320 .and. u <= 57343) return          ! lone trailing surrogate
          if (u >= 55296 .and. u <= 56319) then             ! leading surrogate needs a partner
            if (pos + 1 > n) return
            if (txt(pos:pos + 1) /= '\u') return
            call read_u4(pos + 2, u2)
            if (u2 < 56320 .or. u2 > 57343) return
            pos = pos + 6
          end if
        case default
          return
        end select
      else if (c < 32) then
        return
      else if (c < 128) then
        pos = pos + 1
      else
        if (c >= 194 .and. c <= 223) then
          need = 1
        else if (c >= 224 .and. c <= 239) then
          need = 2
        else if (c >= 240 .and. c <= 244) then
          need = 3
        else
          return
        end if
        if (pos + need > n) return
        c1 = iachar(txt(pos + 1:pos + 1))
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
          c1 = iachar(txt(pos + k:pos + k))
          if (c1 < 128 .or. c1 > 191) return
        end do
        pos = pos + need + 1
      end if
    end do
  contains
    subroutine read_u4(at, v)
      integer, intent(in) :: at
      integer, intent(out) :: v
      integer :: i, h
      v = -1
      if (at + 3 > n) return
      v = 0
      do i = at, at + 3
        h = hexval(txt(i:i))
        if (h < 0) then
          v = -1
          return
        end if
        v = v * 16 + h
      end do
    end subroutine read_u4
  end subroutine scan_string

  !> Decode the escapes of txt(p:q) into UTF-8 text.
  function unescape(txt, p, q) result(s)
    character(len=*), intent(in) :: txt
    integer, intent(in) :: p, q
    character(len=:), allocatable :: s
    character(len=:), allocatable :: buf
    integer :: i, n, u, u2
    allocate(character(len=max(q - p + 1, 0) + 4) :: buf)
    n = 0
    i = p
    do while (i <= q)
      if (txt(i:i) /= '\') then
        n = n + 1
        buf(n:n) = txt(i:i)
        i = i + 1
        cycle
      end if
      select case (txt(i + 1:i + 1))
      case ('"')
        call put(34)
      case ('\')
        call put(92)
      case ('/')
        call put(47)
      case ('b')
        call put(8)
      case ('f')
        call put(12)
      case ('n')
        call put(10)
      case ('r')
        call put(13)
      case ('t')
        call put(9)
      case ('u')
        u = h4(i + 2)
        if (u >= 55296 .and. u <= 56319) then
          u2 = h4(i + 8)
          u = 65536 + (u - 55296) * 1024 + (u2 - 56320)
          i = i + 6
        end if
        call put_cp(u)
        i = i + 4
      end select
      i = i + 2
    end do
    s = buf(1:n)
  contains
    integer function h4(at)
      integer, intent(in) :: at
      integer :: k
      h4 = 0
      do k = at, at + 3
        h4 = h4 * 16 + hexval(txt(k:k))
      end do
    end function h4
    subroutine put(c)
      integer, intent(in) :: c
      n = n + 1
      buf(n:n) = achar(c)
    end subroutine put
    subroutine put_cp(cp)
      integer, intent(in) :: cp
      if (cp < 128) then
        call put(cp)
      else if (cp < 2048) then
        call put(192 + shiftr(cp, 6))
        call put(128 + iand(cp, 63))
      else if (cp < 65536) then
        call put(224 + shiftr(cp, 12))
        call put(128 + iand(shiftr(cp, 6), 63))
        call put(128 + iand(cp, 63))
      else
        call put(240 + shiftr(cp, 18))
        call put(128 + iand(shiftr(cp, 12), 63))
        call put(128 + iand(shiftr(cp, 6), 63))
        call put(128 + iand(cp, 63))
      end if
    end subroutine put_cp
  end function unescape

  !> Decoded value of a string node.
  function jstr(doc, txt, node) result(s)
    type(jdoc_t), intent(in) :: doc
    character(len=*), intent(in) :: txt
    integer, intent(in) :: node
    character(len=:), allocatable :: s
    if (doc%esc(node)) then
      s = unescape(txt, doc%p(node), doc%q(node))
    else
      s = txt(doc%p(node):doc%q(node))
    end if
  end function jstr

  !> Raw source text of any node (strings include their quotes).
  function jraw(doc, txt, node) result(s)
    type(jdoc_t), intent(in) :: doc
    character(len=*), intent(in) :: txt
    integer, intent(in) :: node
    character(len=:), allocatable :: s
    if (doc%kind(node) == J_STR) then
      s = txt(doc%p(node) - 1:doc%q(node) + 1)
    else
      s = txt(doc%p(node):doc%q(node))
    end if
  end function jraw

  logical function jstr_eq(doc, txt, node, want)
    type(jdoc_t), intent(in) :: doc
    character(len=*), intent(in) :: txt, want
    integer, intent(in) :: node
    jstr_eq = .false.
    if (doc%kind(node) /= J_STR) return
    if (doc%esc(node)) then
      jstr_eq = streq(unescape(txt, doc%p(node), doc%q(node)), want)
    else
      jstr_eq = streq(txt(doc%p(node):doc%q(node)), want)
    end if
  end function jstr_eq

  logical function jkey_eq(doc, txt, member, want)
    type(jdoc_t), intent(in) :: doc
    character(len=*), intent(in) :: txt, want
    integer, intent(in) :: member
    if (doc%kesc(member)) then
      jkey_eq = streq(unescape(txt, doc%kp(member), doc%kq(member)), want)
    else
      jkey_eq = streq(txt(doc%kp(member):doc%kq(member)), want)
    end if
  end function jkey_eq

  !> Last member of object `obj` named `key` (duplicate keys: last wins), or 0.
  integer function jget(doc, txt, obj, key)
    type(jdoc_t), intent(in) :: doc
    character(len=*), intent(in) :: txt, key
    integer, intent(in) :: obj
    integer :: c
    jget = 0
    c = doc%child(obj)
    do while (c /= 0)
      if (jkey_eq(doc, txt, c, key)) jget = c
      c = doc%next(c)
    end do
  end function jget

  integer function jlen(doc, node)
    type(jdoc_t), intent(in) :: doc
    integer, intent(in) :: node
    integer :: c
    jlen = 0
    c = doc%child(node)
    do while (c /= 0)
      jlen = jlen + 1
      c = doc%next(c)
    end do
  end function jlen

end module ob_json
