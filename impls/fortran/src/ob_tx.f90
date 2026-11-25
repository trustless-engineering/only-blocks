! ob_tx: Solana VersionedTransaction wire format (legacy and v0 messages, and
! SIMD-0385 v1 transactions) decoded as offsets into the reassembled transaction bytes.
module ob_tx
  use ob_util
  implicit none
  private
  public :: tx_t, parse_tx, compact_u16

  type :: tx_t
    integer(int64) :: consumed = 0
    integer :: nsig = 0
    integer(int64) :: sig_pos = 0
    logical :: v0 = .false.
    logical :: v1 = .false.
    integer :: ver = -1                      ! -1 legacy, 0 or 1
    ! v1 transactionConfig values; has_* false renders null.
    logical :: has_pf = .false., has_cu = .false., has_la = .false., has_hs = .false.
    integer(int64) :: pf = 0, cu = 0, la = 0, hs = 0
    integer :: nrs = 0, nros = 0, nrou = 0
    integer :: nkeys = 0
    integer(int64) :: keys_pos = 0, bh_pos = 0
    integer :: nix = 0
    integer, allocatable :: ix_prog(:), ix_nacc(:), ix_ndata(:)
    integer(int64), allocatable :: ix_acc(:), ix_data(:)
    integer :: nlut = 0
    integer(int64), allocatable :: lut_key(:), lut_w(:), lut_r(:)
    integer, allocatable :: lut_nw(:), lut_nr(:)
  end type tx_t

contains

  !> Strict compact-u16 (short_vec length).
  subroutine compact_u16(d, pos, lim, v, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer, intent(out) :: v, e
    integer :: k, b
    e = 1
    v = 0
    do k = 0, 2
      if (pos >= lim) return
      b = ub(d(pos))
      pos = pos + 1
      if (k > 0 .and. b == 0) return
      if (k == 2 .and. b >= 128) return
      v = ior(v, shiftl(iand(b, 127), 7 * k))
      if (b < 128) exit
    end do
    if (v > 65535) return
    e = 0
  end subroutine compact_u16

  subroutine parse_tx(d, n, tx, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: n
    type(tx_t), intent(inout) :: tx
    integer, intent(out) :: e
    integer(int64) :: pos
    integer :: p, k, m, t
    pos = 0
    e = 1
    tx%v0 = .false.
    tx%v1 = .false.
    tx%ver = -1
    tx%nlut = 0
    if (n < 1) return
    p = ub(d(0))
    if (p == 129) then
      call parse_v1(d, n, tx, e)
      return
    end if
    if (p >= 128) return
    call compact_u16(d, pos, n, tx%nsig, e)
    if (e /= 0) return
    e = 1
    tx%sig_pos = pos
    if (n - pos < 64_int64 * tx%nsig) return
    pos = pos + 64_int64 * tx%nsig
    if (pos >= n) return
    p = ub(d(pos))
    if (iand(p, 128) == 0) then
      tx%v0 = .false.
    else
      if (iand(p, 127) /= 0) return          ! 127 = off-chain message, others unsupported
      tx%v0 = .true.
      tx%ver = 0
      pos = pos + 1
    end if
    if (n - pos < 3) return
    tx%nrs = ub(d(pos))
    tx%nros = ub(d(pos + 1))
    tx%nrou = ub(d(pos + 2))
    pos = pos + 3
    call compact_u16(d, pos, n, tx%nkeys, e)
    if (e /= 0) return
    e = 1
    tx%keys_pos = pos
    if (n - pos < 32_int64 * tx%nkeys) return
    pos = pos + 32_int64 * tx%nkeys
    if (n - pos < 32) return
    tx%bh_pos = pos
    pos = pos + 32
    call compact_u16(d, pos, n, m, e)
    if (e /= 0) return
    tx%nix = m
    call ensure_ix(tx, m)
    do k = 1, m
      e = 1
      if (pos >= n) return
      tx%ix_prog(k) = ub(d(pos))
      pos = pos + 1
      call compact_u16(d, pos, n, tx%ix_nacc(k), e)
      if (e /= 0) return
      e = 1
      tx%ix_acc(k) = pos
      if (n - pos < tx%ix_nacc(k)) return
      pos = pos + tx%ix_nacc(k)
      call compact_u16(d, pos, n, tx%ix_ndata(k), e)
      if (e /= 0) return
      e = 1
      tx%ix_data(k) = pos
      if (n - pos < tx%ix_ndata(k)) return
      pos = pos + tx%ix_ndata(k)
    end do
    tx%nlut = 0
    if (tx%v0) then
      call compact_u16(d, pos, n, t, e)
      if (e /= 0) return
      tx%nlut = t
      call ensure_lut(tx, t)
      do k = 1, t
        e = 1
        if (n - pos < 32) return
        tx%lut_key(k) = pos
        pos = pos + 32
        call compact_u16(d, pos, n, tx%lut_nw(k), e)
        if (e /= 0) return
        e = 1
        tx%lut_w(k) = pos
        if (n - pos < tx%lut_nw(k)) return
        pos = pos + tx%lut_nw(k)
        call compact_u16(d, pos, n, tx%lut_nr(k), e)
        if (e /= 0) return
        e = 1
        tx%lut_r(k) = pos
        if (n - pos < tx%lut_nr(k)) return
        pos = pos + tx%lut_nr(k)
      end do
    end if
    tx%consumed = pos
    e = 0
  end subroutine parse_tx

  !> Unsigned little-endian integer of w bytes at d(pos).
  integer(int64) function le_uint(d, pos, w)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: pos
    integer, intent(in) :: w
    integer :: k
    le_uint = 0
    do k = w - 1, 0, -1
      le_uint = ior(shiftl(le_uint, 8), int(ub(d(pos + k)), int64))
    end do
  end function le_uint

  !> SIMD-0385 v1 (0x81): fixed-width header, u32 config mask, blockhash,
  !> u8 counts, static keys, config values, instruction headers, payloads,
  !> then numRequiredSignatures tail signatures.
  subroutine parse_v1(d, n, tx, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: n
    type(tx_t), intent(inout) :: tx
    integer, intent(out) :: e
    integer(int64) :: pos, mask
    integer :: k, m
    e = 1
    pos = 1
    if (n - pos < 7) return
    tx%nrs = ub(d(pos))
    tx%nros = ub(d(pos + 1))
    tx%nrou = ub(d(pos + 2))
    mask = le_uint(d, pos + 3, 4)
    pos = pos + 7
    if (iand(mask, not(31_int64)) /= 0) return
    if (iand(mask, 3_int64) == 1 .or. iand(mask, 3_int64) == 2) return
    if (n - pos < 34) return
    tx%bh_pos = pos
    pos = pos + 32
    m = ub(d(pos))
    tx%nkeys = ub(d(pos + 1))
    pos = pos + 2
    tx%keys_pos = pos
    if (n - pos < 32_int64 * tx%nkeys) return
    pos = pos + 32_int64 * tx%nkeys
    tx%has_pf = iand(mask, 3_int64) == 3
    tx%has_cu = iand(mask, 4_int64) /= 0
    tx%has_la = iand(mask, 8_int64) /= 0
    tx%has_hs = iand(mask, 16_int64) /= 0
    if (tx%has_pf) then
      if (n - pos < 8) return
      tx%pf = le_uint(d, pos, 8)
      pos = pos + 8
    end if
    if (tx%has_cu) then
      if (n - pos < 4) return
      tx%cu = le_uint(d, pos, 4)
      pos = pos + 4
    end if
    if (tx%has_la) then
      if (n - pos < 4) return
      tx%la = le_uint(d, pos, 4)
      pos = pos + 4
    end if
    if (tx%has_hs) then
      if (n - pos < 4) return
      tx%hs = le_uint(d, pos, 4)
      pos = pos + 4
    end if
    tx%nix = m
    call ensure_ix(tx, m)
    if (n - pos < 4_int64 * m) return
    do k = 1, m
      tx%ix_prog(k) = ub(d(pos))
      tx%ix_nacc(k) = ub(d(pos + 1))
      tx%ix_ndata(k) = int(le_uint(d, pos + 2, 2))
      pos = pos + 4
    end do
    do k = 1, m
      if (n - pos < int(tx%ix_nacc(k), int64) + tx%ix_ndata(k)) return
      tx%ix_acc(k) = pos
      pos = pos + tx%ix_nacc(k)
      tx%ix_data(k) = pos
      pos = pos + tx%ix_ndata(k)
    end do
    tx%nsig = tx%nrs
    tx%sig_pos = pos
    if (n - pos < 64_int64 * tx%nsig) return
    pos = pos + 64_int64 * tx%nsig
    tx%v1 = .true.
    tx%ver = 1
    tx%consumed = pos
    e = 0
  end subroutine parse_v1

  subroutine ensure_ix(tx, m)
    type(tx_t), intent(inout) :: tx
    integer, intent(in) :: m
    if (allocated(tx%ix_prog)) then
      if (size(tx%ix_prog) >= m) return
      deallocate(tx%ix_prog, tx%ix_nacc, tx%ix_ndata, tx%ix_acc, tx%ix_data)
    end if
    allocate(tx%ix_prog(max(m, 16)), tx%ix_nacc(max(m, 16)), tx%ix_ndata(max(m, 16)))
    allocate(tx%ix_acc(max(m, 16)), tx%ix_data(max(m, 16)))
  end subroutine ensure_ix

  subroutine ensure_lut(tx, m)
    type(tx_t), intent(inout) :: tx
    integer, intent(in) :: m
    if (allocated(tx%lut_key)) then
      if (size(tx%lut_key) >= m) return
      deallocate(tx%lut_key, tx%lut_w, tx%lut_r, tx%lut_nw, tx%lut_nr)
    end if
    allocate(tx%lut_key(max(m, 4)), tx%lut_w(max(m, 4)), tx%lut_r(max(m, 4)))
    allocate(tx%lut_nw(max(m, 4)), tx%lut_nr(max(m, 4)))
  end subroutine ensure_lut

end module ob_tx
