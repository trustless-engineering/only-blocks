! ob_meta: transaction status metadata and block rewards. Protobuf (prost
! semantics) and pre-epoch-157 bincode layouts both decode into one model whose
! strings and byte fields are spans into the decoded payload buffer.
module ob_meta
  use ob_util
  use ob_codec, only: parse_u64_plus
  use ob_zstd, only: zstd_decompress
  implicit none
  private
  public :: meta_t, tokbal_t, reward_t, iix_t, inner_t, rewards_t
  public :: decode_meta_frame, decode_rewards_frame, meta_default, meta_err

  integer(int64), parameter :: BINCODE_SLOT_CUTOFF = 67824000_int64
  real(real64), parameter :: F64_EPS = 2.220446049250313e-16_real64

  type :: tokbal_t
    integer :: account_index = 0, decimals = 0
    type(span_t) :: mint, owner, program_id, amount, uias
    logical :: has_ui = .false.
    real(real64) :: ui = 0.0_real64
  end type tokbal_t

  type :: reward_t
    type(span_t) :: pubkey
    integer(int64) :: lamports = 0, post_balance = 0
    integer :: rtype = 0          ! 0 none, 1 Fee, 2 Rent, 3 Staking, 4 Voting
    integer :: commission = -1    ! -1 none
    type(span_t) :: comm, bps     ! protobuf strings, resolved after parsing
    logical :: has_comm = .false., has_bps = .false.
  end type reward_t

  type :: iix_t
    integer :: prog = 0
    type(span_t) :: acc, data
    logical :: has_sh = .false.
    integer(int64) :: sh = 0
  end type iix_t

  type :: inner_t
    integer :: index = 0, first = 1, count = 0
  end type inner_t

  type :: meta_t
    logical :: is_err = .false.
    character(len=:), allocatable :: err_json
    integer(int64) :: fee = 0
    integer :: npre = 0, npost = 0
    integer(int64), allocatable :: pre(:), post(:)
    logical :: has_inner = .false.
    integer :: ninner = 0, niix = 0
    type(inner_t), allocatable :: inner(:)
    type(iix_t), allocatable :: iix(:)
    logical :: has_logs = .false.
    integer :: nlogs = 0
    type(span_t), allocatable :: logs(:)
    logical :: has_pretb = .false., has_posttb = .false.
    integer :: npretb = 0, nposttb = 0
    type(tokbal_t), allocatable :: pretb(:), posttb(:)
    logical :: has_rewards = .false.
    integer :: nrw = 0
    type(reward_t), allocatable :: rw(:)
    integer :: nlw = 0, nlr = 0
    type(span_t), allocatable :: lw(:), lr(:)
    logical :: has_ret = .false.
    type(span_t) :: ret_prog, ret_data
    logical :: has_cu = .false., has_cost = .false.
    integer(int64) :: cu = 0, cost = 0
  end type meta_t

  type :: rewards_t
    integer :: n = 0
    type(reward_t), allocatable :: rw(:)
    logical :: has_parts = .false.
    integer(int64) :: parts = 0
  end type rewards_t

  !> Protobuf-only raw fields resolved by the conversion step.
  type :: pbraw_t
    logical :: has_err = .false., inner_none = .false., logs_none = .false., ret_none = .false.
    logical :: has_ret = .false.
    type(span_t) :: err, ret_prog, ret_data
  end type pbraw_t

  character(len=40), parameter :: TX_ERR_NAMES(0:38) = [character(len=40) :: &
    'AccountInUse', 'AccountLoadedTwice', 'AccountNotFound', 'ProgramAccountNotFound', &
    'InsufficientFundsForFee', 'InvalidAccountForFee', 'AlreadyProcessed', 'BlockhashNotFound', &
    'InstructionError', 'CallChainTooDeep', 'MissingSignatureForFee', 'InvalidAccountIndex', &
    'SignatureFailure', 'InvalidProgramForExecution', 'SanitizeFailure', 'ClusterMaintenance', &
    'AccountBorrowOutstanding', 'WouldExceedMaxBlockCostLimit', 'UnsupportedVersion', &
    'InvalidWritableAccount', 'WouldExceedMaxAccountCostLimit', 'WouldExceedAccountDataBlockLimit', &
    'TooManyAccountLocks', 'AddressLookupTableNotFound', 'InvalidAddressLookupTableOwner', &
    'InvalidAddressLookupTableData', 'InvalidAddressLookupTableIndex', 'InvalidRentPayingAccount', &
    'WouldExceedMaxVoteCostLimit', 'WouldExceedAccountDataTotalLimit', 'DuplicateInstruction', &
    'InsufficientFundsForRent', 'MaxLoadedAccountsDataSizeExceeded', 'InvalidLoadedAccountsDataSizeLimit', &
    'ResanitizationNeeded', 'ProgramExecutionTemporarilyRestricted', 'UnbalancedTransaction', &
    'ProgramCacheHitMaxLimit', 'CommitCancelled']

  character(len=40), parameter :: IX_ERR_NAMES(0:53) = [character(len=40) :: &
    'GenericError', 'InvalidArgument', 'InvalidInstructionData', 'InvalidAccountData', &
    'AccountDataTooSmall', 'InsufficientFunds', 'IncorrectProgramId', 'MissingRequiredSignature', &
    'AccountAlreadyInitialized', 'UninitializedAccount', 'UnbalancedInstruction', 'ModifiedProgramId', &
    'ExternalAccountLamportSpend', 'ExternalAccountDataModified', 'ReadonlyLamportChange', &
    'ReadonlyDataModified', 'DuplicateAccountIndex', 'ExecutableModified', 'RentEpochModified', &
    'NotEnoughAccountKeys', 'AccountDataSizeChanged', 'AccountNotExecutable', 'AccountBorrowFailed', &
    'AccountBorrowOutstanding', 'DuplicateAccountOutOfSync', 'Custom', 'InvalidError', &
    'ExecutableDataModified', 'ExecutableLamportChange', 'ExecutableAccountNotRentExempt', &
    'UnsupportedProgramId', 'CallDepth', 'MissingAccount', 'ReentrancyNotAllowed', &
    'MaxSeedLengthExceeded', 'InvalidSeeds', 'InvalidRealloc', 'ComputationalBudgetExceeded', &
    'PrivilegeEscalation', 'ProgramEnvironmentSetupFailure', 'ProgramFailedToComplete', &
    'ProgramFailedToCompile', 'Immutable', 'IncorrectAuthority', 'BorshIoError', 'AccountNotRentExempt', &
    'InvalidAccountOwner', 'ArithmeticOverflow', 'UnsupportedSysvar', 'IllegalOwner', &
    'MaxAccountsDataAllocationsExceeded', 'MaxAccountsExceeded', 'MaxInstructionTraceLengthExceeded', &
    'BuiltinProgramsMustConsumeComputeUnits']

  character(len=96), save :: meta_err = ''

contains

  ! ============================================================ model helpers
  subroutine meta_default(m)
    type(meta_t), intent(inout) :: m
    m%is_err = .false.
    m%fee = 0
    m%npre = 0
    m%npost = 0
    m%has_inner = .false.
    m%ninner = 0
    m%niix = 0
    m%has_logs = .false.
    m%nlogs = 0
    m%has_pretb = .false.
    m%has_posttb = .false.
    m%npretb = 0
    m%nposttb = 0
    m%has_rewards = .false.
    m%nrw = 0
    m%nlw = 0
    m%nlr = 0
    m%has_ret = .false.
    m%has_cu = .false.
    m%has_cost = .false.
    m%cu = 0
    m%cost = 0
    if (.not. allocated(m%pre)) then
      allocate(m%pre(16), m%post(16), m%inner(4), m%iix(8), m%logs(8), m%pretb(4), m%posttb(4))
      allocate(m%rw(4), m%lw(4), m%lr(4))
    end if
  end subroutine meta_default

  subroutine push_i64(a, n, v)
    integer(int64), allocatable, intent(inout) :: a(:)
    integer, intent(inout) :: n
    integer(int64), intent(in) :: v
    integer(int64), allocatable :: t(:)
    if (n >= size(a)) then
      allocate(t(2 * size(a)))
      t(1:n) = a(1:n)
      call move_alloc(t, a)
    end if
    n = n + 1
    a(n) = v
  end subroutine push_i64

  subroutine push_span(a, n, v)
    type(span_t), allocatable, intent(inout) :: a(:)
    integer, intent(inout) :: n
    type(span_t), intent(in) :: v
    type(span_t), allocatable :: t(:)
    if (n >= size(a)) then
      allocate(t(2 * size(a)))
      t(1:n) = a(1:n)
      call move_alloc(t, a)
    end if
    n = n + 1
    a(n) = v
  end subroutine push_span

  subroutine push_tb(a, n)
    type(tokbal_t), allocatable, intent(inout) :: a(:)
    integer, intent(inout) :: n
    type(tokbal_t), allocatable :: t(:)
    type(tokbal_t) :: blank
    if (n >= size(a)) then
      allocate(t(2 * size(a)))
      t(1:n) = a(1:n)
      call move_alloc(t, a)
    end if
    n = n + 1
    a(n) = blank
  end subroutine push_tb

  subroutine push_rw(a, n)
    type(reward_t), allocatable, intent(inout) :: a(:)
    integer, intent(inout) :: n
    type(reward_t), allocatable :: t(:)
    type(reward_t) :: blank
    if (n >= size(a)) then
      allocate(t(2 * size(a)))
      t(1:n) = a(1:n)
      call move_alloc(t, a)
    end if
    n = n + 1
    a(n) = blank
  end subroutine push_rw

  subroutine push_iix(a, n)
    type(iix_t), allocatable, intent(inout) :: a(:)
    integer, intent(inout) :: n
    type(iix_t), allocatable :: t(:)
    type(iix_t) :: blank
    if (n >= size(a)) then
      allocate(t(2 * size(a)))
      t(1:n) = a(1:n)
      call move_alloc(t, a)
    end if
    n = n + 1
    a(n) = blank
  end subroutine push_iix

  subroutine push_inner(a, n)
    type(inner_t), allocatable, intent(inout) :: a(:)
    integer, intent(inout) :: n
    type(inner_t), allocatable :: t(:)
    type(inner_t) :: blank
    if (n >= size(a)) then
      allocate(t(2 * size(a)))
      t(1:n) = a(1:n)
      call move_alloc(t, a)
    end if
    n = n + 1
    a(n) = blank
  end subroutine push_inner

  ! ============================================================ protobuf wire
  subroutine pb_varint(d, pos, lim, v, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer(int64), intent(out) :: v
    integer, intent(out) :: e
    integer :: i, b
    e = 1
    v = 0
    do i = 0, 9
      if (pos >= lim) return
      b = ub(d(pos))
      pos = pos + 1
      if (i == 9 .and. b > 1) return
      v = ior(v, shiftl(int(iand(b, 127), int64), 7 * i))
      if (b < 128) then
        e = 0
        return
      end if
    end do
  end subroutine pb_varint

  subroutine pb_key(d, pos, lim, fn, wt, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer, intent(out) :: fn, wt, e
    integer(int64) :: k
    fn = 0
    wt = 0
    call pb_varint(d, pos, lim, k, e)
    if (e /= 0) return
    e = 1
    if (bgt(k, 4294967295_int64)) return
    wt = int(iand(k, 7_int64))
    fn = int(shiftr(k, 3))
    if (wt > 5 .or. fn < 1) return
    e = 0
  end subroutine pb_key

  subroutine pb_lenspan(d, pos, lim, sp, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    type(span_t), intent(out) :: sp
    integer, intent(out) :: e
    integer(int64) :: l
    call pb_varint(d, pos, lim, l, e)
    if (e /= 0) return
    e = 1
    if (bgt(l, lim - pos)) return
    sp%p = pos
    sp%n = l
    pos = pos + l
    e = 0
  end subroutine pb_lenspan

  recursive subroutine pb_skip(d, pos, lim, fn, wt, depth, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer, intent(in) :: fn, wt, depth
    integer, intent(out) :: e
    integer(int64) :: v
    type(span_t) :: sp
    integer :: f2, w2
    e = 1
    select case (wt)
    case (0)
      call pb_varint(d, pos, lim, v, e)
    case (1)
      if (lim - pos < 8) return
      pos = pos + 8
      e = 0
    case (2)
      call pb_lenspan(d, pos, lim, sp, e)
    case (5)
      if (lim - pos < 4) return
      pos = pos + 4
      e = 0
    case (3)
      if (depth > 100) return
      do
        call pb_key(d, pos, lim, f2, w2, e)
        if (e /= 0) return
        if (w2 == 4) then
          e = 1
          if (f2 /= fn) return
          e = 0
          return
        end if
        call pb_skip(d, pos, lim, f2, w2, depth + 1, e)
        if (e /= 0) return
      end do
    case default
      return
    end select
  end subroutine pb_skip

  !> UTF-8 string field.
  subroutine pb_string(d, pos, lim, sp, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    type(span_t), intent(out) :: sp
    integer, intent(out) :: e
    call pb_lenspan(d, pos, lim, sp, e)
    if (e /= 0) return
    if (.not. utf8_ok(d, sp%p, sp%n)) e = 1
  end subroutine pb_string

  ! ============================================================ protobuf messages
  subroutine pb_reward(d, p0, lim, r, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    type(reward_t), intent(inout) :: r
    integer, intent(out) :: e
    integer(int64) :: pos, v
    integer :: fn, wt, t32
    type(span_t) :: sp
    pos = p0
    e = 0
    do while (pos < lim)
      call pb_key(d, pos, lim, fn, wt, e)
      if (e /= 0) return
      select case (fn)
      case (1, 5, 6)
        if (wt /= 2) then
          e = 1
          return
        end if
        call pb_string(d, pos, lim, sp, e)
        if (e /= 0) return
        if (fn == 1) then
          r%pubkey = sp
        else if (fn == 5) then
          r%comm = sp
          r%has_comm = .true.
        else
          r%bps = sp
          r%has_bps = .true.
        end if
      case (2, 3, 4)
        if (wt /= 0) then
          e = 1
          return
        end if
        call pb_varint(d, pos, lim, v, e)
        if (e /= 0) return
        if (fn == 2) then
          r%lamports = v
        else if (fn == 3) then
          r%post_balance = v
        else
          t32 = int(iand(v, 4294967295_int64) - merge(4294967296_int64, 0_int64, btest(v, 31)))
          if (t32 >= 1 .and. t32 <= 4) then
            r%rtype = t32
          else
            r%rtype = 0
          end if
        end if
      case default
        call pb_skip(d, pos, lim, fn, wt, 0, e)
        if (e /= 0) return
      end select
    end do
  end subroutine pb_reward

  !> Resolve commission: u8 from `commission`, else u16 bps / 100 when <= 255.
  subroutine resolve_commission(d, r)
    integer(int8), intent(in) :: d(0:)
    type(reward_t), intent(inout) :: r
    integer(int64) :: v
    logical :: ok
    r%commission = -1
    if (r%has_comm) then
      call parse_u64_plus(d, r%comm%p, r%comm%n, v, ok)
      if (ok .and. v >= 0 .and. v <= 255) then
        r%commission = int(v)
        return
      end if
    end if
    if (r%has_bps) then
      call parse_u64_plus(d, r%bps%p, r%bps%n, v, ok)
      if (ok .and. v >= 0 .and. v <= 65535) then
        if (v / 100 <= 255) r%commission = int(v / 100)
      end if
    end if
  end subroutine resolve_commission

  subroutine pb_ui_amount(d, p0, lim, tb, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    type(tokbal_t), intent(inout) :: tb
    integer, intent(out) :: e
    integer(int64) :: pos, v, bits
    integer :: fn, wt, k
    type(span_t) :: sp
    pos = p0
    e = 0
    do while (pos < lim)
      call pb_key(d, pos, lim, fn, wt, e)
      if (e /= 0) return
      select case (fn)
      case (1)
        if (wt /= 1 .or. lim - pos < 8) then
          e = 1
          return
        end if
        bits = 0
        do k = 7, 0, -1
          bits = ior(shiftl(bits, 8), int(ub(d(pos + k)), int64))
        end do
        tb%ui = transfer(bits, tb%ui)
        pos = pos + 8
      case (2)
        if (wt /= 0) then
          e = 1
          return
        end if
        call pb_varint(d, pos, lim, v, e)
        if (e /= 0) return
        tb%decimals = int(iand(v, 255_int64))
      case (3, 4)
        if (wt /= 2) then
          e = 1
          return
        end if
        call pb_string(d, pos, lim, sp, e)
        if (e /= 0) return
        if (fn == 3) then
          tb%amount = sp
        else
          tb%uias = sp
        end if
      case default
        call pb_skip(d, pos, lim, fn, wt, 0, e)
        if (e /= 0) return
      end select
    end do
  end subroutine pb_ui_amount

  subroutine pb_token_balance(d, p0, lim, tb, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    type(tokbal_t), intent(inout) :: tb
    integer, intent(out) :: e
    integer(int64) :: pos, v
    integer :: fn, wt
    type(span_t) :: sp
    pos = p0
    e = 0
    do while (pos < lim)
      call pb_key(d, pos, lim, fn, wt, e)
      if (e /= 0) return
      select case (fn)
      case (1)
        if (wt /= 0) then
          e = 1
          return
        end if
        call pb_varint(d, pos, lim, v, e)
        if (e /= 0) return
        tb%account_index = int(iand(v, 255_int64))
      case (2, 4, 5)
        if (wt /= 2) then
          e = 1
          return
        end if
        call pb_string(d, pos, lim, sp, e)
        if (e /= 0) return
        if (fn == 2) then
          tb%mint = sp
        else if (fn == 4) then
          tb%owner = sp
        else
          tb%program_id = sp
        end if
      case (3)
        if (wt /= 2) then
          e = 1
          return
        end if
        call pb_lenspan(d, pos, lim, sp, e)
        if (e /= 0) return
        call pb_ui_amount(d, sp%p, sp%p + sp%n, tb, e)
        if (e /= 0) return
      case default
        call pb_skip(d, pos, lim, fn, wt, 0, e)
        if (e /= 0) return
      end select
    end do
  end subroutine pb_token_balance

  subroutine pb_inner_ix(d, p0, lim, ix, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    type(iix_t), intent(inout) :: ix
    integer, intent(out) :: e
    integer(int64) :: pos, v
    integer :: fn, wt
    type(span_t) :: sp
    pos = p0
    e = 0
    do while (pos < lim)
      call pb_key(d, pos, lim, fn, wt, e)
      if (e /= 0) return
      select case (fn)
      case (1, 4)
        if (wt /= 0) then
          e = 1
          return
        end if
        call pb_varint(d, pos, lim, v, e)
        if (e /= 0) return
        if (fn == 1) then
          ix%prog = int(iand(v, 255_int64))
        else
          ix%has_sh = .true.
          ix%sh = iand(v, 4294967295_int64)
        end if
      case (2, 3)
        if (wt /= 2) then
          e = 1
          return
        end if
        call pb_lenspan(d, pos, lim, sp, e)
        if (e /= 0) return
        if (fn == 2) then
          ix%acc = sp
        else
          ix%data = sp
        end if
      case default
        call pb_skip(d, pos, lim, fn, wt, 0, e)
        if (e /= 0) return
      end select
    end do
  end subroutine pb_inner_ix

  subroutine pb_inner_set(d, p0, lim, m, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    type(meta_t), intent(inout) :: m
    integer, intent(out) :: e
    integer(int64) :: pos, v
    integer :: fn, wt, slot
    type(span_t) :: sp
    call push_inner(m%inner, m%ninner)
    slot = m%ninner
    m%inner(slot)%first = m%niix + 1
    m%inner(slot)%count = 0
    m%inner(slot)%index = 0
    pos = p0
    e = 0
    do while (pos < lim)
      call pb_key(d, pos, lim, fn, wt, e)
      if (e /= 0) return
      select case (fn)
      case (1)
        if (wt /= 0) then
          e = 1
          return
        end if
        call pb_varint(d, pos, lim, v, e)
        if (e /= 0) return
        m%inner(slot)%index = int(iand(v, 255_int64))
      case (2)
        if (wt /= 2) then
          e = 1
          return
        end if
        call pb_lenspan(d, pos, lim, sp, e)
        if (e /= 0) return
        call push_iix(m%iix, m%niix)
        call pb_inner_ix(d, sp%p, sp%p + sp%n, m%iix(m%niix), e)
        if (e /= 0) return
        m%inner(slot)%count = m%inner(slot)%count + 1
      case default
        call pb_skip(d, pos, lim, fn, wt, 0, e)
        if (e /= 0) return
      end select
    end do
  end subroutine pb_inner_set

  !> Parse a protobuf TransactionStatusMeta (parse failures only; conversion is separate).
  subroutine pb_meta(d, p0, lim, m, raw, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    type(meta_t), intent(inout) :: m
    type(pbraw_t), intent(inout) :: raw
    integer, intent(out) :: e
    integer(int64) :: pos, v, q
    integer :: fn, wt, f2, w2
    type(span_t) :: sp, s2
    call meta_default(m)
    m%has_pretb = .true.
    m%has_posttb = .true.
    m%has_rewards = .true.
    pos = p0
    e = 0
    do while (pos < lim)
      call pb_key(d, pos, lim, fn, wt, e)
      if (e /= 0) return
      select case (fn)
      case (1, 14)
        if (wt /= 2) then
          e = 1
          return
        end if
        call pb_lenspan(d, pos, lim, sp, e)
        if (e /= 0) return
        if (fn == 1) then
          raw%has_err = .true.
        else
          raw%has_ret = .true.
        end if
        q = sp%p
        do while (q < sp%p + sp%n)
          call pb_key(d, q, sp%p + sp%n, f2, w2, e)
          if (e /= 0) return
          if (fn == 1 .and. f2 == 1) then
            if (w2 /= 2) then
              e = 1
              return
            end if
            call pb_lenspan(d, q, sp%p + sp%n, s2, e)
            if (e /= 0) return
            raw%err = s2
          else if (fn == 14 .and. (f2 == 1 .or. f2 == 2)) then
            if (w2 /= 2) then
              e = 1
              return
            end if
            call pb_lenspan(d, q, sp%p + sp%n, s2, e)
            if (e /= 0) return
            if (f2 == 1) then
              raw%ret_prog = s2
            else
              raw%ret_data = s2
            end if
          else
            call pb_skip(d, q, sp%p + sp%n, f2, w2, 0, e)
            if (e /= 0) return
          end if
        end do
      case (2, 10, 11, 15, 16, 17)
        if (wt /= 0) then
          e = 1
          return
        end if
        call pb_varint(d, pos, lim, v, e)
        if (e /= 0) return
        select case (fn)
        case (2)
          m%fee = v
        case (10)
          raw%inner_none = (v /= 0)
        case (11)
          raw%logs_none = (v /= 0)
        case (15)
          raw%ret_none = (v /= 0)
        case (16)
          m%has_cu = .true.
          m%cu = v
        case default
          m%has_cost = .true.
          m%cost = v
        end select
      case (3, 4)
        if (wt == 0) then
          call pb_varint(d, pos, lim, v, e)
          if (e /= 0) return
          if (fn == 3) then
            call push_i64(m%pre, m%npre, v)
          else
            call push_i64(m%post, m%npost, v)
          end if
        else if (wt == 2) then
          call pb_lenspan(d, pos, lim, sp, e)
          if (e /= 0) return
          q = sp%p
          do while (q < sp%p + sp%n)
            call pb_varint(d, q, sp%p + sp%n, v, e)
            if (e /= 0) return
            if (fn == 3) then
              call push_i64(m%pre, m%npre, v)
            else
              call push_i64(m%post, m%npost, v)
            end if
          end do
        else
          e = 1
          return
        end if
      case (5, 6, 7, 8, 9, 12, 13)
        if (wt /= 2) then
          e = 1
          return
        end if
        if (fn == 6) then
          call pb_string(d, pos, lim, sp, e)
        else
          call pb_lenspan(d, pos, lim, sp, e)
        end if
        if (e /= 0) return
        select case (fn)
        case (5)
          call pb_inner_set(d, sp%p, sp%p + sp%n, m, e)
        case (6)
          call push_span(m%logs, m%nlogs, sp)
        case (7)
          call push_tb(m%pretb, m%npretb)
          call pb_token_balance(d, sp%p, sp%p + sp%n, m%pretb(m%npretb), e)
        case (8)
          call push_tb(m%posttb, m%nposttb)
          call pb_token_balance(d, sp%p, sp%p + sp%n, m%posttb(m%nposttb), e)
        case (9)
          call push_rw(m%rw, m%nrw)
          call pb_reward(d, sp%p, sp%p + sp%n, m%rw(m%nrw), e)
        case (12)
          call push_span(m%lw, m%nlw, sp)
        case default
          call push_span(m%lr, m%nlr, sp)
        end select
        if (e /= 0) return
      case default
        call pb_skip(d, pos, lim, fn, wt, 0, e)
        if (e /= 0) return
      end select
    end do
  end subroutine pb_meta

  !> Section 10.3 conversion. Failures here are final (no codec fallback).
  subroutine pb_convert(d, m, raw, e)
    integer(int8), intent(in) :: d(0:)
    type(meta_t), intent(inout) :: m
    type(pbraw_t), intent(in) :: raw
    integer, intent(out) :: e
    integer :: k
    integer(int64) :: q
    e = 0
    if (raw%has_err) then
      q = raw%err%p
      call bc_txerr(d, q, raw%err%p + raw%err%n, m%err_json, e)
      if (e /= 0) then
        meta_err = 'undecodable TransactionError'
        return
      end if
      m%is_err = .true.
    end if
    m%has_inner = .not. raw%inner_none
    m%has_logs = .not. raw%logs_none
    do k = 1, m%npretb
      call fix_tb(m%pretb(k))
    end do
    do k = 1, m%nposttb
      call fix_tb(m%posttb(k))
    end do
    do k = 1, m%nrw
      call resolve_commission(d, m%rw(k))
    end do
    do k = 1, m%nlw
      if (m%lw(k)%n /= 32) e = 1
    end do
    do k = 1, m%nlr
      if (m%lr(k)%n /= 32) e = 1
    end do
    if (e /= 0) then
      meta_err = 'loaded address is not 32 bytes'
      return
    end if
    m%has_ret = .false.
    if (.not. raw%ret_none .and. raw%has_ret) then
      if (raw%ret_prog%n /= 32) then
        e = 1
        meta_err = 'return data program id is not 32 bytes'
        return
      end if
      m%has_ret = .true.
      m%ret_prog = raw%ret_prog
      m%ret_data = raw%ret_data
    end if
  contains
    subroutine fix_tb(tb)
      type(tokbal_t), intent(inout) :: tb
      tb%has_ui = abs(tb%ui) > F64_EPS
    end subroutine fix_tb
  end subroutine pb_convert

  subroutine pb_rewards(d, p0, lim, rs, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    type(rewards_t), intent(inout) :: rs
    integer, intent(out) :: e
    integer(int64) :: pos, q, v
    integer :: fn, wt, f2, w2, k
    type(span_t) :: sp
    rs%n = 0
    rs%has_parts = .false.
    rs%parts = 0
    if (.not. allocated(rs%rw)) allocate(rs%rw(16))
    pos = p0
    e = 0
    do while (pos < lim)
      call pb_key(d, pos, lim, fn, wt, e)
      if (e /= 0) return
      select case (fn)
      case (1, 2)
        if (wt /= 2) then
          e = 1
          return
        end if
        call pb_lenspan(d, pos, lim, sp, e)
        if (e /= 0) return
        if (fn == 1) then
          call push_rw(rs%rw, rs%n)
          call pb_reward(d, sp%p, sp%p + sp%n, rs%rw(rs%n), e)
          if (e /= 0) return
        else
          rs%has_parts = .true.
          q = sp%p
          do while (q < sp%p + sp%n)
            call pb_key(d, q, sp%p + sp%n, f2, w2, e)
            if (e /= 0) return
            if (f2 == 1) then
              if (w2 /= 0) then
                e = 1
                return
              end if
              call pb_varint(d, q, sp%p + sp%n, v, e)
              if (e /= 0) return
              rs%parts = v
            else
              call pb_skip(d, q, sp%p + sp%n, f2, w2, 0, e)
              if (e /= 0) return
            end if
          end do
        end if
      case default
        call pb_skip(d, pos, lim, fn, wt, 0, e)
        if (e /= 0) return
      end select
    end do
    do k = 1, rs%n
      call resolve_commission(d, rs%rw(k))
    end do
  end subroutine pb_rewards

  ! ============================================================ bincode
  subroutine bc_fixed(d, pos, lim, nb, v, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer, intent(in) :: nb
    integer(int64), intent(out) :: v
    integer, intent(out) :: e
    integer :: k
    v = 0
    e = 1
    if (lim - pos < nb) return
    do k = nb - 1, 0, -1
      v = ior(shiftl(v, 8), int(ub(d(pos + k)), int64))
    end do
    pos = pos + nb
    e = 0
  end subroutine bc_fixed

  subroutine bc_option(d, pos, lim, some, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    logical, intent(out) :: some
    integer, intent(out) :: e
    integer(int64) :: t
    some = .false.
    call bc_fixed(d, pos, lim, 1, t, e)
    if (e /= 0) return
    if (t > 1) then
      e = 1
      return
    end if
    some = (t == 1)
  end subroutine bc_option

  subroutine bc_string(d, pos, lim, sp, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    type(span_t), intent(out) :: sp
    integer, intent(out) :: e
    integer(int64) :: l
    call bc_fixed(d, pos, lim, 8, l, e)
    if (e /= 0) return
    e = 1
    if (bgt(l, lim - pos)) return
    if (.not. utf8_ok(d, pos, l)) return
    sp%p = pos
    sp%n = l
    pos = pos + l
    e = 0
  end subroutine bc_string

  subroutine bc_compact_bytes(d, pos, lim, sp, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    type(span_t), intent(out) :: sp
    integer, intent(out) :: e
    integer :: k, b, v
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
    if (lim - pos < v) return
    sp%p = pos
    sp%n = v
    pos = pos + v
    e = 0
  end subroutine bc_compact_bytes

  !> Bincode TransactionError -> JSON text.
  subroutine bc_txerr(d, pos, lim, js, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    character(len=:), allocatable, intent(out) :: js
    integer, intent(out) :: e
    integer(int64) :: v, idx, iv, c
    js = 'null'
    call bc_fixed(d, pos, lim, 4, v, e)
    if (e /= 0) return
    if (v >= 39) then
      e = 1
      return
    end if
    select case (int(v))
    case (8)
      call bc_fixed(d, pos, lim, 1, idx, e)
      if (e /= 0) return
      call bc_fixed(d, pos, lim, 4, iv, e)
      if (e /= 0) return
      if (iv >= 54) then
        e = 1
        return
      end if
      if (iv == 25) then
        call bc_fixed(d, pos, lim, 4, c, e)
        if (e /= 0) return
        js = '{"InstructionError":[' // u64_str(idx) // ',{"Custom":' // u64_str(c) // '}]}'
      else
        js = '{"InstructionError":[' // u64_str(idx) // ',"' // trim(IX_ERR_NAMES(iv)) // '"]}'
      end if
    case (30)
      call bc_fixed(d, pos, lim, 1, idx, e)
      if (e /= 0) return
      js = '{"DuplicateInstruction":' // u64_str(idx) // '}'
    case (31, 35)
      call bc_fixed(d, pos, lim, 1, idx, e)
      if (e /= 0) return
      js = '{"' // trim(TX_ERR_NAMES(v)) // '":{"account_index":' // u64_str(idx) // '}}'
    case default
      js = '"' // trim(TX_ERR_NAMES(v)) // '"'
    end select
  end subroutine bc_txerr

  logical function at_eof(pos, lim)
    integer(int64), intent(in) :: pos, lim
    at_eof = (pos >= lim)
  end function at_eof

  !> StoredExtendedReward (layout 1) or the 4-field legacy reward (layout 2).
  subroutine bc_reward(d, pos, lim, layout, r, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer, intent(in) :: layout
    type(reward_t), intent(inout) :: r
    integer, intent(out) :: e
    integer(int64) :: v
    logical :: some
    call bc_string(d, pos, lim, r%pubkey, e)
    if (e /= 0) return
    call bc_fixed(d, pos, lim, 8, r%lamports, e)
    if (e /= 0) return
    r%post_balance = 0
    r%rtype = 0
    r%commission = -1
    if (layout == 2 .or. .not. at_eof(pos, lim)) then
      call bc_fixed(d, pos, lim, 8, r%post_balance, e)
      if (e /= 0) return
    else
      return
    end if
    if (layout == 2 .or. .not. at_eof(pos, lim)) then
      call bc_option(d, pos, lim, some, e)
      if (e /= 0) return
      if (some) then
        call bc_fixed(d, pos, lim, 4, v, e)
        if (e /= 0) return
        if (v > 3) then
          e = 1
          return
        end if
        r%rtype = int(v) + 1
      end if
    else
      return
    end if
    if (layout == 2) return
    if (.not. at_eof(pos, lim)) then
      call bc_option(d, pos, lim, some, e)
      if (e /= 0) return
      if (some) then
        call bc_fixed(d, pos, lim, 1, v, e)
        if (e /= 0) return
        r%commission = int(v)
      end if
    end if
  end subroutine bc_reward

  !> Token balance: tbv 0 = StoredTokenBalance, 1 = V1, 2 = V2.
  subroutine bc_token_balance(d, pos, lim, tbv, tb, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer, intent(in) :: tbv
    type(tokbal_t), intent(inout) :: tb
    integer, intent(out) :: e
    integer(int64) :: v
    call bc_fixed(d, pos, lim, 1, v, e)
    if (e /= 0) return
    tb%account_index = int(v)
    call bc_string(d, pos, lim, tb%mint, e)
    if (e /= 0) return
    call bc_fixed(d, pos, lim, 8, v, e)
    if (e /= 0) return
    tb%ui = transfer(v, tb%ui)
    tb%has_ui = .true.
    call bc_fixed(d, pos, lim, 1, v, e)
    if (e /= 0) return
    tb%decimals = int(v)
    call bc_string(d, pos, lim, tb%amount, e)
    if (e /= 0) return
    tb%uias%n = 0
    tb%owner%n = 0
    tb%program_id%n = 0
    if (tbv == 1) return
    if (tbv == 2) then
      call bc_string(d, pos, lim, tb%owner, e)
      return
    end if
    if (at_eof(pos, lim)) return
    call bc_string(d, pos, lim, tb%owner, e)
    if (e /= 0) return
    if (at_eof(pos, lim)) return
    call bc_string(d, pos, lim, tb%program_id, e)
  end subroutine bc_token_balance

  subroutine bc_vec_len(d, pos, lim, n, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(inout) :: pos
    integer(int64), intent(in) :: lim
    integer(int64), intent(out) :: n
    integer, intent(out) :: e
    call bc_fixed(d, pos, lim, 8, n, e)
    if (e /= 0) return
    if (bgt(n, lim - pos)) e = 1    ! every element takes at least one byte
  end subroutine bc_vec_len

  !> One bincode TransactionStatusMeta layout attempt.
  subroutine bc_meta(d, p0, lim, legacy, tbv, strict, m, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    logical, intent(in) :: legacy, strict
    integer, intent(in) :: tbv
    type(meta_t), intent(inout) :: m
    integer, intent(out) :: e
    integer(int64) :: pos, v, n, k, j, ni
    logical :: some
    type(span_t) :: sp
    call meta_default(m)
    pos = p0
    call bc_fixed(d, pos, lim, 4, v, e)
    if (e /= 0) return
    if (v == 1) then
      call bc_txerr(d, pos, lim, m%err_json, e)
      if (e /= 0) return
      m%is_err = .true.
    else if (v /= 0) then
      e = 1
      return
    end if
    call bc_fixed(d, pos, lim, 8, m%fee, e)
    if (e /= 0) return
    call bc_fixed(d, pos, lim, 8, n, e)
    if (e /= 0) return
    if (bgt(n, (lim - pos) / 8)) then
      e = 1
      return
    end if
    do k = 1, n
      call bc_fixed(d, pos, lim, 8, v, e)
      call push_i64(m%pre, m%npre, v)
    end do
    call bc_fixed(d, pos, lim, 8, n, e)
    if (e /= 0) return
    if (bgt(n, (lim - pos) / 8)) then
      e = 1
      return
    end if
    do k = 1, n
      call bc_fixed(d, pos, lim, 8, v, e)
      call push_i64(m%post, m%npost, v)
    end do
    ! inner_instructions (eof)
    if (at_eof(pos, lim)) goto 900
    call bc_option(d, pos, lim, some, e)
    if (e /= 0) return
    if (some) then
      m%has_inner = .true.
      call bc_vec_len(d, pos, lim, n, e)
      if (e /= 0) return
      do k = 1, n
        call push_inner(m%inner, m%ninner)
        call bc_fixed(d, pos, lim, 1, v, e)
        if (e /= 0) return
        m%inner(m%ninner)%index = int(v)
        m%inner(m%ninner)%first = m%niix + 1
        call bc_vec_len(d, pos, lim, ni, e)
        if (e /= 0) return
        do j = 1, ni
          call push_iix(m%iix, m%niix)
          m%inner(m%ninner)%count = m%inner(m%ninner)%count + 1
          call bc_fixed(d, pos, lim, 1, v, e)
          if (e /= 0) return
          m%iix(m%niix)%prog = int(v)
          call bc_compact_bytes(d, pos, lim, m%iix(m%niix)%acc, e)
          if (e /= 0) return
          call bc_compact_bytes(d, pos, lim, m%iix(m%niix)%data, e)
          if (e /= 0) return
          if (.not. legacy) then
            call bc_option(d, pos, lim, some, e)
            if (e /= 0) return
            if (some) then
              call bc_fixed(d, pos, lim, 4, v, e)
              if (e /= 0) return
              m%iix(m%niix)%has_sh = .true.
              m%iix(m%niix)%sh = v
            end if
          end if
        end do
      end do
    end if
    ! log_messages (eof)
    if (at_eof(pos, lim)) goto 900
    call bc_option(d, pos, lim, some, e)
    if (e /= 0) return
    if (some) then
      m%has_logs = .true.
      call bc_vec_len(d, pos, lim, n, e)
      if (e /= 0) return
      do k = 1, n
        call bc_string(d, pos, lim, sp, e)
        if (e /= 0) return
        call push_span(m%logs, m%nlogs, sp)
      end do
    end if
    ! pre/post token balances (eof)
    if (at_eof(pos, lim)) goto 900
    call bc_option(d, pos, lim, some, e)
    if (e /= 0) return
    if (some) then
      m%has_pretb = .true.
      call bc_vec_len(d, pos, lim, n, e)
      if (e /= 0) return
      do k = 1, n
        call push_tb(m%pretb, m%npretb)
        call bc_token_balance(d, pos, lim, tbv, m%pretb(m%npretb), e)
        if (e /= 0) return
      end do
    end if
    if (at_eof(pos, lim)) goto 900
    call bc_option(d, pos, lim, some, e)
    if (e /= 0) return
    if (some) then
      m%has_posttb = .true.
      call bc_vec_len(d, pos, lim, n, e)
      if (e /= 0) return
      do k = 1, n
        call push_tb(m%posttb, m%nposttb)
        call bc_token_balance(d, pos, lim, tbv, m%posttb(m%nposttb), e)
        if (e /= 0) return
      end do
    end if
    ! rewards (eof)
    if (at_eof(pos, lim)) goto 900
    call bc_option(d, pos, lim, some, e)
    if (e /= 0) return
    if (some) then
      m%has_rewards = .true.
      call bc_vec_len(d, pos, lim, n, e)
      if (e /= 0) return
      do k = 1, n
        call push_rw(m%rw, m%nrw)
        call bc_reward(d, pos, lim, 1, m%rw(m%nrw), e)
        if (e /= 0) return
      end do
    end if
    ! return_data (eof)
    if (at_eof(pos, lim)) goto 900
    call bc_option(d, pos, lim, some, e)
    if (e /= 0) return
    if (some) then
      if (lim - pos < 32) then
        e = 1
        return
      end if
      m%ret_prog%p = pos
      m%ret_prog%n = 32
      pos = pos + 32
      call bc_fixed(d, pos, lim, 8, n, e)
      if (e /= 0) return
      if (bgt(n, lim - pos)) then
        e = 1
        return
      end if
      m%ret_data%p = pos
      m%ret_data%n = n
      pos = pos + n
      m%has_ret = .true.
    end if
    ! compute_units_consumed, cost_units (eof)
    if (at_eof(pos, lim)) goto 900
    call bc_option(d, pos, lim, some, e)
    if (e /= 0) return
    if (some) then
      call bc_fixed(d, pos, lim, 8, m%cu, e)
      if (e /= 0) return
      m%has_cu = .true.
    end if
    if (at_eof(pos, lim)) goto 900
    call bc_option(d, pos, lim, some, e)
    if (e /= 0) return
    if (some) then
      call bc_fixed(d, pos, lim, 8, m%cost, e)
      if (e /= 0) return
      m%has_cost = .true.
    end if
900 continue
    e = 0
    if (strict .and. pos /= lim) e = 1
  end subroutine bc_meta

  subroutine bincode_metadata(d, p0, lim, m, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    type(meta_t), intent(inout) :: m
    integer, intent(out) :: e
    call bc_meta(d, p0, lim, .false., 0, .true., m, e)
    if (e == 0) return
    call bc_meta(d, p0, lim, .true., 1, .true., m, e)
    if (e == 0) return
    call bc_meta(d, p0, lim, .true., 2, .true., m, e)
    if (e == 0) return
    call bc_meta(d, p0, lim, .true., 0, .true., m, e)
    if (e == 0) return
    call bc_meta(d, p0, lim, .false., 0, .false., m, e)
  end subroutine bincode_metadata

  subroutine bc_rewards_layout(d, p0, lim, layout, strict, rs, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    integer, intent(in) :: layout
    logical, intent(in) :: strict
    type(rewards_t), intent(inout) :: rs
    integer, intent(out) :: e
    integer(int64) :: pos, n, k
    rs%n = 0
    rs%has_parts = .false.
    if (.not. allocated(rs%rw)) allocate(rs%rw(16))
    pos = p0
    call bc_vec_len(d, pos, lim, n, e)
    if (e /= 0) return
    do k = 1, n
      call push_rw(rs%rw, rs%n)
      call bc_reward(d, pos, lim, layout, rs%rw(rs%n), e)
      if (e /= 0) return
    end do
    if (strict .and. pos /= lim) e = 1
  end subroutine bc_rewards_layout

  subroutine bincode_rewards(d, p0, lim, rs, e)
    integer(int8), intent(in) :: d(0:)
    integer(int64), intent(in) :: p0, lim
    type(rewards_t), intent(inout) :: rs
    integer, intent(out) :: e
    call bc_rewards_layout(d, p0, lim, 1, .true., rs, e)
    if (e == 0) return
    call bc_rewards_layout(d, p0, lim, 2, .true., rs, e)
    if (e == 0) return
    call bc_rewards_layout(d, p0, lim, 1, .false., rs, e)
  end subroutine bincode_rewards

  ! ============================================================ epoch-157 split
  subroutine meta_bytes(slot, d, n, m, e)
    integer(int64), intent(in) :: slot, n
    integer(int8), intent(in) :: d(0:)
    type(meta_t), intent(inout) :: m
    integer, intent(out) :: e
    type(pbraw_t) :: raw
    if (slot >= 0 .and. slot < BINCODE_SLOT_CUTOFF) then
      call bincode_metadata(d, 0_int64, n, m, e)
      if (e == 0) return
      raw = pbraw_t()
      call pb_meta(d, 0_int64, n, m, raw, e)
      if (e /= 0) then
        meta_err = 'undecodable pre-157 metadata'
        return
      end if
      call pb_convert(d, m, raw, e)
    else
      raw = pbraw_t()
      call pb_meta(d, 0_int64, n, m, raw, e)
      if (e == 0) then
        call pb_convert(d, m, raw, e)
        return
      end if
      call bincode_metadata(d, 0_int64, n, m, e)
      if (e /= 0) meta_err = 'undecodable metadata'
    end if
  end subroutine meta_bytes

  subroutine rewards_bytes(slot, d, n, rs, e)
    integer(int64), intent(in) :: slot, n
    integer(int8), intent(in) :: d(0:)
    type(rewards_t), intent(inout) :: rs
    integer, intent(out) :: e
    if (slot >= 0 .and. slot < BINCODE_SLOT_CUTOFF) then
      call bincode_rewards(d, 0_int64, n, rs, e)
      if (e == 0) return
      call pb_rewards(d, 0_int64, n, rs, e)
    else
      call pb_rewards(d, 0_int64, n, rs, e)
      if (e == 0) return
      call bincode_rewards(d, 0_int64, n, rs, e)
    end if
    if (e /= 0) meta_err = 'undecodable rewards'
  end subroutine rewards_bytes

  logical function is_zstd(f)
    type(bytes_t), intent(in) :: f
    is_zstd = .false.
    if (f%n < 4) return
    is_zstd = (f%d(0) == 40_int8 .and. f%d(1) == -75_int8 .and. f%d(2) == 47_int8 .and. f%d(3) == -3_int8)
  end function is_zstd

  !> Section 9.1 for metadata. has_meta = .false. for an empty frame. Spans refer to pl.
  subroutine decode_meta_frame(slot, frame, pl, m, has_meta, e)
    integer(int64), intent(in) :: slot
    type(bytes_t), intent(in) :: frame
    type(bytes_t), intent(inout) :: pl
    type(meta_t), intent(inout) :: m
    logical, intent(out) :: has_meta
    integer, intent(out) :: e
    integer :: ze
    has_meta = .false.
    e = 0
    if (frame%n == 0) return
    has_meta = .true.
    if (is_zstd(frame)) then
      call zstd_decompress(frame%d, frame%n, pl, ze)
      if (ze == 0) then
        call meta_bytes(slot, pl%d, pl%n, m, e)
        return
      end if
      call copy_into(frame, pl)
      call meta_bytes(slot, pl%d, pl%n, m, e)
    else
      call copy_into(frame, pl)
      call meta_bytes(slot, pl%d, pl%n, m, e)
      if (e == 0) return
      call zstd_decompress(frame%d, frame%n, pl, ze)
      if (ze /= 0) then
        e = 1
        return
      end if
      call meta_bytes(slot, pl%d, pl%n, m, e)
    end if
  end subroutine decode_meta_frame

  subroutine decode_rewards_frame(slot, frame, pl, rs, e)
    integer(int64), intent(in) :: slot
    type(bytes_t), intent(in) :: frame
    type(bytes_t), intent(inout) :: pl
    type(rewards_t), intent(inout) :: rs
    integer, intent(out) :: e
    integer :: ze
    e = 0
    rs%n = 0
    rs%has_parts = .false.
    if (.not. allocated(rs%rw)) allocate(rs%rw(16))
    if (frame%n == 0) return
    if (is_zstd(frame)) then
      call zstd_decompress(frame%d, frame%n, pl, ze)
      if (ze == 0) then
        call rewards_bytes(slot, pl%d, pl%n, rs, e)
        return
      end if
      call copy_into(frame, pl)
      call rewards_bytes(slot, pl%d, pl%n, rs, e)
    else
      call copy_into(frame, pl)
      call rewards_bytes(slot, pl%d, pl%n, rs, e)
      if (e == 0) return
      call zstd_decompress(frame%d, frame%n, pl, ze)
      if (ze /= 0) then
        e = 1
        return
      end if
      call rewards_bytes(slot, pl%d, pl%n, rs, e)
    end if
  end subroutine decode_rewards_frame

  subroutine copy_into(src, dst)
    type(bytes_t), intent(in) :: src
    type(bytes_t), intent(inout) :: dst
    dst%n = 0
    call bytes_reserve(dst, max(src%n, 1_int64))
    if (src%n > 0) dst%d(0:src%n - 1) = src%d(0:src%n - 1)
    dst%n = src%n
  end subroutine copy_into

end module ob_meta
