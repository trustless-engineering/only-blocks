! ob_cache: bounded RAM-only LRU maps keyed by u64 slot. Chained hash
! buckets plus an intrusive doubly linked recency list, all in flat arrays.
module ob_cache
  use ob_util
  implicit none
  private
  public :: lru_t, lru_init, lru_get, lru_put

  type :: lru_t
    integer :: cap = 0, count = 0, nbuckets = 0
    integer :: head = 0, tail = 0, free = 0     ! head = most recent
    integer(int64), allocatable :: key(:), v1(:), v2(:)
    integer(int8), allocatable :: h(:, :)       ! optional 32-byte payload
    integer, allocatable :: prev(:), next(:), chain(:), bucket(:)
    logical :: with_hash = .false.
  end type lru_t

contains

  subroutine lru_init(c, cap, with_hash)
    type(lru_t), intent(inout) :: c
    integer, intent(in) :: cap
    logical, intent(in) :: with_hash
    integer :: nb
    c%cap = cap
    nb = 1
    do while (nb < cap)
      nb = nb * 2
    end do
    c%nbuckets = nb
    allocate(c%key(cap), c%v1(cap), c%v2(cap), c%prev(cap), c%next(cap), c%chain(cap))
    allocate(c%bucket(0:nb - 1))
    c%bucket = 0
    c%with_hash = with_hash
    if (with_hash) allocate(c%h(32, cap))
    c%count = 0
    c%head = 0
    c%tail = 0
  end subroutine lru_init

  pure integer function slot_hash(k, nb)
    integer(int64), intent(in) :: k
    integer, intent(in) :: nb
    integer(int64) :: x
    x = k * int(z'9E3779B97F4A7C15', int64)
    slot_hash = int(iand(shiftr(x, 32), int(nb - 1, int64)))
  end function slot_hash

  subroutine unlink(c, i)
    type(lru_t), intent(inout) :: c
    integer, intent(in) :: i
    if (c%prev(i) /= 0) then
      c%next(c%prev(i)) = c%next(i)
    else
      c%head = c%next(i)
    end if
    if (c%next(i) /= 0) then
      c%prev(c%next(i)) = c%prev(i)
    else
      c%tail = c%prev(i)
    end if
  end subroutine unlink

  subroutine push_front(c, i)
    type(lru_t), intent(inout) :: c
    integer, intent(in) :: i
    c%prev(i) = 0
    c%next(i) = c%head
    if (c%head /= 0) c%prev(c%head) = i
    c%head = i
    if (c%tail == 0) c%tail = i
  end subroutine push_front

  integer function find(c, k)
    type(lru_t), intent(in) :: c
    integer(int64), intent(in) :: k
    integer :: i
    find = 0
    i = c%bucket(slot_hash(k, c%nbuckets))
    do while (i /= 0)
      if (c%key(i) == k) then
        find = i
        return
      end if
      i = c%chain(i)
    end do
  end function find

  !> Look up k; on a hit, mark it most recently used.
  logical function lru_get(c, k, v1, v2, h)
    type(lru_t), intent(inout) :: c
    integer(int64), intent(in) :: k
    integer(int64), intent(out) :: v1, v2
    integer(int8), intent(out), optional :: h(32)
    integer :: i
    v1 = 0
    v2 = 0
    i = find(c, k)
    lru_get = (i /= 0)
    if (i == 0) return
    v1 = c%v1(i)
    v2 = c%v2(i)
    if (present(h) .and. c%with_hash) h = c%h(:, i)
    if (c%head /= i) then
      call unlink(c, i)
      call push_front(c, i)
    end if
  end function lru_get

  subroutine lru_put(c, k, v1, v2, h)
    type(lru_t), intent(inout) :: c
    integer(int64), intent(in) :: k, v1, v2
    integer(int8), intent(in), optional :: h(32)
    integer :: i, b, j
    i = find(c, k)
    if (i == 0) then
      if (c%count < c%cap) then
        c%count = c%count + 1
        i = c%count
      else
        ! evict the least recently used entry and reuse its cell
        i = c%tail
        call unlink(c, i)
        b = slot_hash(c%key(i), c%nbuckets)
        if (c%bucket(b) == i) then
          c%bucket(b) = c%chain(i)
        else
          j = c%bucket(b)
          do while (j /= 0)
            if (c%chain(j) == i) then
              c%chain(j) = c%chain(i)
              exit
            end if
            j = c%chain(j)
          end do
        end if
      end if
      c%key(i) = k
      b = slot_hash(k, c%nbuckets)
      c%chain(i) = c%bucket(b)
      c%bucket(b) = i
      call push_front(c, i)
    else if (c%head /= i) then
      call unlink(c, i)
      call push_front(c, i)
    end if
    c%v1(i) = v1
    c%v2(i) = v2
    if (present(h) .and. c%with_hash) c%h(:, i) = h
  end subroutine lru_put

end module ob_cache
