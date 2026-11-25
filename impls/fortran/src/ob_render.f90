! ob_render: JSON serialization of transactions, metadata and rewards for
! every encoding / transactionDetails combination (WIRE_FORMATS.md section 13).
module ob_render
  use ob_util
  use ob_codec
  use ob_tx, only: tx_t
  use ob_meta
  implicit none
  private
  public :: opts_t, render_init, render_tx_entry, render_reward_list
  public :: ENC_JSON, ENC_PARSED, ENC_B64, ENC_B58, DET_FULL, DET_ACCOUNTS, DET_SIGS, DET_NONE

  integer, parameter :: ENC_JSON = 1, ENC_PARSED = 2, ENC_B64 = 3, ENC_B58 = 4
  integer, parameter :: DET_FULL = 1, DET_ACCOUNTS = 2, DET_SIGS = 3, DET_NONE = 4

  type :: opts_t
    integer :: encoding = ENC_JSON
    integer :: details = DET_FULL
    logical :: rewards = .true.
    integer :: maxv = -1
  end type opts_t

  integer, parameter :: NRESERVED = 31
  character(len=44), parameter :: RESERVED_B58(NRESERVED) = [character(len=44) :: &
    'AddressLookupTab1e1111111111111111111111111', 'BPFLoader2111111111111111111111111111111111', &
    'BPFLoader1111111111111111111111111111111111', 'BPFLoaderUpgradeab1e11111111111111111111111', &
    'ComputeBudget111111111111111111111111111111', 'Config1111111111111111111111111111111111111', &
    'Ed25519SigVerify111111111111111111111111111', 'Feature111111111111111111111111111111111111', &
    'LoaderV411111111111111111111111111111111111', 'KeccakSecp256k11111111111111111111111111111', &
    'Secp256r1SigVerify1111111111111111111111111', 'StakeConfig11111111111111111111111111111111', &
    'Stake11111111111111111111111111111111111111', '11111111111111111111111111111111', &
    'Vote111111111111111111111111111111111111111', 'ZkE1Gama1Proof11111111111111111111111111111', &
    'ZkTokenProof1111111111111111111111111111111', 'SysvarC1ock11111111111111111111111111111111', &
    'SysvarEpochRewards1111111111111111111111111', 'SysvarEpochSchedu1e111111111111111111111111', &
    'SysvarFees111111111111111111111111111111111', 'Sysvar1nstructions1111111111111111111111111', &
    'SysvarLastRestartS1ot1111111111111111111111', 'SysvarRecentB1ockHashes11111111111111111111', &
    'SysvarRent111111111111111111111111111111111', 'SysvarRewards111111111111111111111111111111', &
    'SysvarS1otHashes111111111111111111111111111', 'SysvarS1otHistory11111111111111111111111111', &
    'SysvarStakeHistory1111111111111111111111111', 'NativeLoader1111111111111111111111111111111', &
    'Sysvar1111111111111111111111111111111111111']
  integer(int8), save :: reserved(32, NRESERVED)
  integer(int8), save :: upgradeable(32)

  ! Combined key list (static keys, then loaded writable, then loaded readonly).
  integer(int8), allocatable, save :: kb(:)
  integer, save :: nk = 0, nstatic = 0, nwritable_loaded = 0

contains

  subroutine render_init()
    integer :: i
    logical :: ok
    do i = 1, NRESERVED
      call b58_decode32(trim(RESERVED_B58(i)), reserved(:, i), ok)
      if (.not. ok) error stop 'bad reserved key table'
    end do
    upgradeable = reserved(:, 4)
    allocate(kb(0:32 * 1024 - 1))
  end subroutine render_init

  subroutine sb_bool(sb, v)
    type(sb_t), intent(inout) :: sb
    logical, intent(in) :: v
    if (v) then
      call sb_add(sb, 'true')
    else
      call sb_add(sb, 'false')
    end if
  end subroutine sb_bool

  subroutine sb_opt_u64(sb, has, v)
    type(sb_t), intent(inout) :: sb
    logical, intent(in) :: has
    integer(int64), intent(in) :: v
    if (has) then
      call sb_u64(sb, v)
    else
      call sb_add(sb, 'null')
    end if
  end subroutine sb_opt_u64

  subroutine sb_b58_str(sb, d, p, n)
    type(sb_t), intent(inout) :: sb
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    call sb_addc(sb, '"')
    call sb_b58(sb, d, p, n)
    call sb_addc(sb, '"')
  end subroutine sb_b58_str

  !> Build the combined key list for flags and partially decoded instructions.
  subroutine build_keys(t, tx, complete, m, pl)
    type(bytes_t), intent(in) :: t
    type(tx_t), intent(in) :: tx
    logical, intent(in) :: complete
    type(meta_t), intent(in) :: m
    type(bytes_t), intent(in) :: pl
    integer :: total, k
    integer(int8), allocatable :: tmp(:)
    nstatic = tx%nkeys
    nwritable_loaded = 0
    total = tx%nkeys
    if (tx%v0 .and. complete) then
      total = total + m%nlw + m%nlr
      nwritable_loaded = m%nlw
    end if
    if (size(kb) < 32 * total) then
      allocate(tmp(0:32 * total - 1))
      call move_alloc(tmp, kb)
    end if
    nk = total
    if (tx%nkeys > 0) kb(0:32 * tx%nkeys - 1) = t%d(tx%keys_pos:tx%keys_pos + 32 * tx%nkeys - 1)
    if (tx%v0 .and. complete) then
      do k = 1, m%nlw
        kb(32 * (tx%nkeys + k - 1):32 * (tx%nkeys + k) - 1) = pl%d(m%lw(k)%p:m%lw(k)%p + 31)
      end do
      do k = 1, m%nlr
        kb(32 * (tx%nkeys + m%nlw + k - 1):32 * (tx%nkeys + m%nlw + k) - 1) = pl%d(m%lr(k)%p:m%lr(k)%p + 31)
      end do
    end if
  end subroutine build_keys

  logical function key_is(i, ref)
    integer, intent(in) :: i
    integer(int8), intent(in) :: ref(32)
    key_is = all(kb(32 * i:32 * i + 31) == ref)
  end function key_is

  logical function is_reserved(i)
    integer, intent(in) :: i
    integer :: r
    is_reserved = .false.
    do r = 1, NRESERVED
      if (key_is(i, reserved(:, r))) then
        is_reserved = .true.
        return
      end if
    end do
  end function is_reserved

  !> Account list with signer/writable/source flags (section 14).
  subroutine render_account_keys(sb, tx)
    type(sb_t), intent(inout) :: sb
    type(tx_t), intent(in) :: tx
    integer :: i, k
    logical :: signer, wi, demoted, has_upgradeable
    has_upgradeable = .false.
    do i = 0, nk - 1
      if (key_is(i, upgradeable)) then
        has_upgradeable = .true.
        exit
      end if
    end do
    call sb_addc(sb, '[')
    do i = 0, nk - 1
      if (i > 0) call sb_addc(sb, ',')
      signer = i < tx%nrs
      if (i >= nstatic) then
        wi = (i - nstatic) < nwritable_loaded
      else if (i >= tx%nrs) then
        wi = (i - tx%nrs) < max(0, nstatic - tx%nrs - tx%nrou)
      else
        wi = i < max(0, tx%nrs - tx%nros)
      end if
      demoted = .false.
      if (i <= 255 .and. .not. has_upgradeable) then
        do k = 1, tx%nix
          if (tx%ix_prog(k) == i) then
            demoted = .true.
            exit
          end if
        end do
      end if
      if (wi) then
        if (is_reserved(i) .or. demoted) wi = .false.
      end if
      call sb_add(sb, '{"pubkey":')
      call sb_b58_str(sb, kb, 32_int64 * i, 32_int64)
      call sb_add(sb, ',"writable":')
      call sb_bool(sb, wi)
      call sb_add(sb, ',"signer":')
      call sb_bool(sb, signer)
      if (i < nstatic) then
        call sb_add(sb, ',"source":"transaction"}')
      else
        call sb_add(sb, ',"source":"lookupTable"}')
      end if
    end do
    call sb_addc(sb, ']')
  end subroutine render_account_keys

  subroutine render_signatures(sb, t, tx)
    type(sb_t), intent(inout) :: sb
    type(bytes_t), intent(in) :: t
    type(tx_t), intent(in) :: tx
    integer :: k
    call sb_add(sb, '"signatures":[')
    do k = 1, tx%nsig
      if (k > 1) call sb_addc(sb, ',')
      call sb_b58_str(sb, t%d, tx%sig_pos + 64_int64 * (k - 1), 64_int64)
    end do
    call sb_addc(sb, ']')
  end subroutine render_signatures

  subroutine render_u8_list(sb, d, p, n)
    type(sb_t), intent(inout) :: sb
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer(int64) :: k
    call sb_addc(sb, '[')
    do k = 0, n - 1
      if (k > 0) call sb_addc(sb, ',')
      call sb_int(sb, ub(d(p + k)))
    end do
    call sb_addc(sb, ']')
  end subroutine render_u8_list

  !> ["<b58 key>", ...] for account indexes d(p:p+n-1); error if out of range.
  subroutine render_key_list(sb, d, p, n, e)
    type(sb_t), intent(inout) :: sb
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p, n
    integer, intent(out) :: e
    integer(int64) :: k
    integer :: idx
    e = 0
    call sb_addc(sb, '[')
    do k = 0, n - 1
      if (k > 0) call sb_addc(sb, ',')
      idx = ub(d(p + k))
      if (idx >= nk) then
        e = 1
        return
      end if
      call sb_b58_str(sb, kb, 32_int64 * idx, 32_int64)
    end do
    call sb_addc(sb, ']')
  end subroutine render_key_list

  subroutine render_lookups(sb, t, tx)
    type(sb_t), intent(inout) :: sb
    type(bytes_t), intent(in) :: t
    type(tx_t), intent(in) :: tx
    integer :: k
    call sb_add(sb, ',"addressTableLookups":[')
    do k = 1, tx%nlut
      if (k > 1) call sb_addc(sb, ',')
      call sb_add(sb, '{"accountKey":')
      call sb_b58_str(sb, t%d, tx%lut_key(k), 32_int64)
      call sb_add(sb, ',"writableIndexes":')
      call render_u8_list(sb, t%d, tx%lut_w(k), int(tx%lut_nw(k), int64))
      call sb_add(sb, ',"readonlyIndexes":')
      call render_u8_list(sb, t%d, tx%lut_r(k), int(tx%lut_nr(k), int64))
      call sb_addc(sb, '}')
    end do
    call sb_addc(sb, ']')
  end subroutine render_lookups

  !> One element of the block's "transactions" array.
  subroutine render_tx_entry(sb, t, tx, complete, m, pl, o, e)
    type(sb_t), intent(inout) :: sb
    type(bytes_t), intent(in) :: t, pl
    type(tx_t), intent(in) :: tx
    logical, intent(in) :: complete
    type(meta_t), intent(in) :: m
    type(opts_t), intent(in) :: o
    integer, intent(out) :: e
    integer :: k, idx
    e = 0
    call build_keys(t, tx, complete, m, pl)
    call sb_add(sb, '{"transaction":')
    if (o%details == DET_ACCOUNTS) then
      call sb_addc(sb, '{')
      call render_signatures(sb, t, tx)
      call sb_add(sb, ',"accountKeys":')
      call render_account_keys(sb, tx)
      call sb_addc(sb, '}')
    else if (o%encoding == ENC_B64 .or. o%encoding == ENC_B58) then
      call sb_add(sb, '["')
      if (o%encoding == ENC_B64) then
        call sb_b64(sb, t%d, 0_int64, tx%consumed)
        call sb_add(sb, '","base64"]')
      else
        call sb_b58(sb, t%d, 0_int64, tx%consumed)
        call sb_add(sb, '","base58"]')
      end if
    else
      call sb_addc(sb, '{')
      call render_signatures(sb, t, tx)
      call sb_add(sb, ',"message":{')
      if (o%encoding == ENC_JSON) then
        call sb_add(sb, '"header":{"numRequiredSignatures":')
        call sb_int(sb, tx%nrs)
        call sb_add(sb, ',"numReadonlySignedAccounts":')
        call sb_int(sb, tx%nros)
        call sb_add(sb, ',"numReadonlyUnsignedAccounts":')
        call sb_int(sb, tx%nrou)
        call sb_add(sb, '},"accountKeys":[')
        do k = 1, tx%nkeys
          if (k > 1) call sb_addc(sb, ',')
          call sb_b58_str(sb, t%d, tx%keys_pos + 32_int64 * (k - 1), 32_int64)
        end do
        call sb_addc(sb, ']')
      else
        call sb_add(sb, '"accountKeys":')
        call render_account_keys(sb, tx)
      end if
      call sb_add(sb, ',"recentBlockhash":')
      call sb_b58_str(sb, t%d, tx%bh_pos, 32_int64)
      call sb_add(sb, ',"instructions":[')
      do k = 1, tx%nix
        if (k > 1) call sb_addc(sb, ',')
        if (o%encoding == ENC_JSON) then
          call sb_add(sb, '{"programIdIndex":')
          call sb_int(sb, tx%ix_prog(k))
          call sb_add(sb, ',"accounts":')
          call render_u8_list(sb, t%d, tx%ix_acc(k), int(tx%ix_nacc(k), int64))
        else
          idx = tx%ix_prog(k)
          if (idx >= nk) then
            e = 1
            return
          end if
          call sb_add(sb, '{"programId":')
          call sb_b58_str(sb, kb, 32_int64 * idx, 32_int64)
          call sb_add(sb, ',"accounts":')
          call render_key_list(sb, t%d, tx%ix_acc(k), int(tx%ix_nacc(k), int64), e)
          if (e /= 0) return
        end if
        call sb_add(sb, ',"data":')
        call sb_b58_str(sb, t%d, tx%ix_data(k), int(tx%ix_ndata(k), int64))
        call sb_add(sb, ',"stackHeight":1}')
      end do
      call sb_addc(sb, ']')
      if (tx%v0) call render_lookups(sb, t, tx)
      if (tx%v1) then
        call sb_add(sb, ',"transactionConfig":{"priorityFee":')
        call sb_opt_u64(sb, tx%has_pf, tx%pf)
        call sb_add(sb, ',"computeUnitLimit":')
        call sb_opt_u64(sb, tx%has_cu, tx%cu)
        call sb_add(sb, ',"loadedAccountsDataSizeLimit":')
        call sb_opt_u64(sb, tx%has_la, tx%la)
        call sb_add(sb, ',"heapSize":')
        call sb_opt_u64(sb, tx%has_hs, tx%hs)
        call sb_addc(sb, '}')
      end if
      call sb_add(sb, '}}')
    end if
    call sb_add(sb, ',"meta":')
    if (complete) then
      call render_meta(sb, m, pl, o, e)
      if (e /= 0) return
    else
      call sb_add(sb, 'null')
    end if
    if (complete .and. o%maxv >= 0) then
      if (tx%ver >= 0) then
        call sb_add(sb, ',"version":')
        call sb_int(sb, tx%ver)
      else
        call sb_add(sb, ',"version":"legacy"')
      end if
    end if
    call sb_addc(sb, '}')
  end subroutine render_tx_entry

  subroutine render_token_balances(sb, has, tbs, n, pl)
    type(sb_t), intent(inout) :: sb
    logical, intent(in) :: has
    type(tokbal_t), intent(in) :: tbs(:)
    integer, intent(in) :: n
    type(bytes_t), intent(in) :: pl
    integer :: k
    integer(int64) :: amt
    logical :: ok
    if (.not. has) then
      call sb_add(sb, 'null')
      return
    end if
    call sb_addc(sb, '[')
    do k = 1, n
      associate (tb => tbs(k))
        if (k > 1) call sb_addc(sb, ',')
        call sb_add(sb, '{"accountIndex":')
        call sb_int(sb, tb%account_index)
        call sb_add(sb, ',"mint":')
        call sb_json_bytes(sb, pl%d, tb%mint%p, tb%mint%n)
        call sb_add(sb, ',"uiTokenAmount":{"uiAmount":')
        if (tb%has_ui) then
          call sb_f64(sb, tb%ui)
        else
          call sb_add(sb, 'null')
        end if
        call sb_add(sb, ',"decimals":')
        call sb_int(sb, tb%decimals)
        call sb_add(sb, ',"amount":')
        call sb_json_bytes(sb, pl%d, tb%amount%p, tb%amount%n)
        call sb_add(sb, ',"uiAmountString":')
        if (tb%uias%n > 0) then
          call sb_json_bytes(sb, pl%d, tb%uias%p, tb%uias%n)
        else
          call parse_u64_plus(pl%d, tb%amount%p, tb%amount%n, amt, ok)
          if (.not. ok) amt = 0
          call sb_addc(sb, '"')
          call sb_real_number_trimmed(sb, amt, tb%decimals)
          call sb_addc(sb, '"')
        end if
        call sb_addc(sb, '}')
        if (tb%owner%n > 0) then
          call sb_add(sb, ',"owner":')
          call sb_json_bytes(sb, pl%d, tb%owner%p, tb%owner%n)
        end if
        if (tb%program_id%n > 0) then
          call sb_add(sb, ',"programId":')
          call sb_json_bytes(sb, pl%d, tb%program_id%p, tb%program_id%n)
        end if
        call sb_addc(sb, '}')
      end associate
    end do
    call sb_addc(sb, ']')
  end subroutine render_token_balances

  !> [Reward, ...]
  subroutine render_reward_list(sb, rw, n, pl)
    type(sb_t), intent(inout) :: sb
    type(reward_t), intent(in) :: rw(:)
    integer, intent(in) :: n
    type(bytes_t), intent(in) :: pl
    integer :: k
    call sb_reserve(sb, int(n, int64) * 120)
    call sb_addc(sb, '[')
    do k = 1, n
      if (k > 1) call sb_addc(sb, ',')
      call sb_add(sb, '{"pubkey":')
      call sb_json_bytes(sb, pl%d, rw(k)%pubkey%p, rw(k)%pubkey%n)
      call sb_add(sb, ',"lamports":')
      call sb_i64(sb, rw(k)%lamports)
      call sb_add(sb, ',"postBalance":')
      call sb_u64(sb, rw(k)%post_balance)
      call sb_add(sb, ',"rewardType":')
      select case (rw(k)%rtype)
      case (1)
        call sb_add(sb, '"Fee"')
      case (2)
        call sb_add(sb, '"Rent"')
      case (3)
        call sb_add(sb, '"Staking"')
      case (4)
        call sb_add(sb, '"Voting"')
      case default
        call sb_add(sb, 'null')
      end select
      call sb_add(sb, ',"commission":')
      if (rw(k)%commission >= 0) then
        call sb_int(sb, rw(k)%commission)
      else
        call sb_add(sb, 'null')
      end if
      call sb_addc(sb, '}')
    end do
    call sb_addc(sb, ']')
  end subroutine render_reward_list

  subroutine render_meta(sb, m, pl, o, e)
    type(sb_t), intent(inout) :: sb
    type(meta_t), intent(in) :: m
    type(bytes_t), intent(in) :: pl
    type(opts_t), intent(in) :: o
    integer, intent(out) :: e
    integer :: k, j, q
    logical :: acc, parsed
    e = 0
    acc = (o%details == DET_ACCOUNTS)
    parsed = (o%encoding == ENC_PARSED)
    call sb_add(sb, '{"err":')
    if (m%is_err) then
      call sb_add(sb, m%err_json)
      call sb_add(sb, ',"status":{"Err":')
      call sb_add(sb, m%err_json)
      call sb_addc(sb, '}')
    else
      call sb_add(sb, 'null,"status":{"Ok":null}')
    end if
    call sb_add(sb, ',"fee":')
    call sb_u64(sb, m%fee)
    call sb_add(sb, ',"preBalances":[')
    do k = 1, m%npre
      if (k > 1) call sb_addc(sb, ',')
      call sb_u64(sb, m%pre(k))
    end do
    call sb_add(sb, '],"postBalances":[')
    do k = 1, m%npost
      if (k > 1) call sb_addc(sb, ',')
      call sb_u64(sb, m%post(k))
    end do
    call sb_addc(sb, ']')
    if (.not. acc) then
      call sb_add(sb, ',"innerInstructions":')
      if (.not. m%has_inner) then
        call sb_add(sb, 'null')
      else
        call sb_addc(sb, '[')
        do k = 1, m%ninner
          if (k > 1) call sb_addc(sb, ',')
          call sb_add(sb, '{"index":')
          call sb_int(sb, m%inner(k)%index)
          call sb_add(sb, ',"instructions":[')
          do j = 1, m%inner(k)%count
            q = m%inner(k)%first + j - 1
            if (j > 1) call sb_addc(sb, ',')
            associate (ix => m%iix(q))
              if (parsed) then
                if (ix%prog >= nk) then
                  e = 1
                  return
                end if
                call sb_add(sb, '{"programId":')
                call sb_b58_str(sb, kb, 32_int64 * ix%prog, 32_int64)
                call sb_add(sb, ',"accounts":')
                call render_key_list(sb, pl%d, ix%acc%p, ix%acc%n, e)
                if (e /= 0) return
              else
                call sb_add(sb, '{"programIdIndex":')
                call sb_int(sb, ix%prog)
                call sb_add(sb, ',"accounts":')
                call render_u8_list(sb, pl%d, ix%acc%p, ix%acc%n)
              end if
              call sb_add(sb, ',"data":')
              call sb_b58_str(sb, pl%d, ix%data%p, ix%data%n)
              call sb_add(sb, ',"stackHeight":')
              if (ix%has_sh) then
                call sb_u64(sb, ix%sh)
              else
                call sb_add(sb, 'null')
              end if
              call sb_addc(sb, '}')
            end associate
          end do
          call sb_add(sb, ']}')
        end do
        call sb_addc(sb, ']')
      end if
      call sb_add(sb, ',"logMessages":')
      if (.not. m%has_logs) then
        call sb_add(sb, 'null')
      else
        call sb_addc(sb, '[')
        do k = 1, m%nlogs
          if (k > 1) call sb_addc(sb, ',')
          call sb_json_bytes(sb, pl%d, m%logs(k)%p, m%logs(k)%n)
        end do
        call sb_addc(sb, ']')
      end if
    end if
    call sb_add(sb, ',"preTokenBalances":')
    call render_token_balances(sb, m%has_pretb, m%pretb, m%npretb, pl)
    call sb_add(sb, ',"postTokenBalances":')
    call render_token_balances(sb, m%has_posttb, m%posttb, m%nposttb, pl)
    if (o%rewards) then
      call sb_add(sb, ',"rewards":')
      if (m%has_rewards) then
        call render_reward_list(sb, m%rw, m%nrw, pl)
      else
        call sb_add(sb, 'null')
      end if
    else if (.not. acc) then
      call sb_add(sb, ',"rewards":null')
    end if
    if (.not. acc .and. .not. parsed) then
      call sb_add(sb, ',"loadedAddresses":{"writable":[')
      do k = 1, m%nlw
        if (k > 1) call sb_addc(sb, ',')
        call sb_b58_str(sb, pl%d, m%lw(k)%p, 32_int64)
      end do
      call sb_add(sb, '],"readonly":[')
      do k = 1, m%nlr
        if (k > 1) call sb_addc(sb, ',')
        call sb_b58_str(sb, pl%d, m%lr(k)%p, 32_int64)
      end do
      call sb_add(sb, ']}')
    end if
    if (.not. acc) then
      if (m%has_ret) then
        call sb_add(sb, ',"returnData":{"programId":')
        call sb_b58_str(sb, pl%d, m%ret_prog%p, 32_int64)
        call sb_add(sb, ',"data":["')
        call sb_b64(sb, pl%d, m%ret_data%p, m%ret_data%n)
        call sb_add(sb, '","base64"]}')
      end if
      if (m%has_cu) then
        call sb_add(sb, ',"computeUnitsConsumed":')
        call sb_u64(sb, m%cu)
      end if
      if (m%has_cost) then
        call sb_add(sb, ',"costUnits":')
        call sb_u64(sb, m%cost)
      end if
    end if
    call sb_addc(sb, '}')
  end subroutine render_meta

end module ob_render
