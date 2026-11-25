<?php
declare(strict_types=1);

final class Instruction
{
    public function __construct(
        public readonly int $program,
        public readonly string $accounts,
        public readonly string $data,
        public ?int $height = null,
    ) {}

    public static function read(Reader $r, ?int $height = null): self
    {
        return new self($r->u8(), $r->take($r->compact()), $r->take($r->compact()), $height);
    }

    public static function indices(string $bytes): array
    {
        return array_values(unpack('C*', $bytes));
    }

    public function json(?array $keys): array
    {
        $accounts = self::indices($this->accounts);
        $data = base58($this->data);
        $stackHeight = $this->height;
        if ($keys === null) return ['programIdIndex' => $this->program] + compact('accounts', 'data', 'stackHeight');
        $key = static fn(int $i) => $keys[$i] ?? throw new FormatError('Invalid account index');
        return ['programId' => $key($this->program), 'accounts' => array_map($key, $accounts)] + compact('data', 'stackHeight');
    }
}

final class Meta
{
    public mixed $error = null;
    public int|RawNumber $fee = 0;
    public array $pre = [], $post = [];
    public ?array $inner = null, $logs = null, $preTokens = null, $postTokens = null, $rewards = null;
    public array $writable = [], $readonly = [];
    public ?array $return = null;
    public int|RawNumber|null $compute = null, $cost = null;

    public function json(bool $accounts, ?array $keys, bool $includeRewards): array
    {
        $result = [
            'err' => $this->error, 'status' => $this->error === null ? ['Ok' => null] : ['Err' => $this->error],
            'fee' => $this->fee, 'preBalances' => $this->pre, 'postBalances' => $this->post,
            'preTokenBalances' => $this->preTokens, 'postTokenBalances' => $this->postTokens,
        ];
        if ($includeRewards || !$accounts) $result['rewards'] = $includeRewards ? $this->rewards : null;
        if ($accounts) return $result;

        $result['innerInstructions'] = $this->inner === null ? null : array_map(
            fn(array $group) => ['index' => $group[0], 'instructions' => array_map(fn(Instruction $ins) => $ins->json($keys), $group[1])],
            $this->inner,
        );
        $result['logMessages'] = $this->logs;
        if ($keys === null) $result['loadedAddresses'] = ['writable' => $this->writable, 'readonly' => $this->readonly];
        if ($this->return !== null) $result['returnData'] = $this->return;
        if ($this->compute !== null) $result['computeUnitsConsumed'] = $this->compute;
        if ($this->cost !== null) $result['costUnits'] = $this->cost;
        return $result;
    }
}

final class Proto
{
    // Wire type codes: v=varint, p=packed varints, b=bytes, s=UTF-8, d=double.
    // Uppercase letters select nested message schemas, and * marks repetition.
    private const SCHEMAS = [
        'M' => 'E v p p I* s* T* T* R* v v b* b* D v v v',
        'E' => 'b', 'I' => 'v J*', 'J' => 'v b b v',
        'T' => 'v s A s s', 'A' => 'd v s s', 'D' => 'b b',
        'S' => 'R* N', 'N' => 'v', 'R' => 's v v v s s',
    ];

    private static function key(Reader $r): array
    {
        $key = $r->varint();
        require_valid($key >= 8 && $key <= 0xffffffff, 'Invalid protobuf key');
        return [$key >> 3, $key & 7];
    }

    private static function skip(Reader $r, int $field, int $wire, int $depth = 0): void
    {
        require_valid($depth < 100, 'Protobuf group nesting too deep');
        switch ($wire) {
            case 0: $r->varint(); return;
            case 1: $r->skip(8); return;
            case 2: $r->skip($r->varint()); return;
            case 5: $r->skip(4); return;
            case 3:
                while (true) {
                    [$number, $type] = self::key($r);
                    if ($type === 4) {
                        require_valid($number === $field, 'Mismatched protobuf group');
                        return;
                    }
                    self::skip($r, $number, $type, $depth + 1);
                }
            default: throw new FormatError('Invalid protobuf wire type');
        }
    }

    public static function read(Reader $r, string $schema, array $message = []): array
    {
        static $schemas = [];
        $fields = $schemas[$schema] ??= explode(' ', self::SCHEMAS[$schema]);
        while ($r->left() > 0) {
            [$field, $wire] = self::key($r);
            if (!isset($fields[$field - 1])) {
                self::skip($r, $field, $wire);
                continue;
            }
            $spec = $fields[$field - 1];
            $type = $spec[0];
            if ($type === 'p') {
                require_valid($wire === 0 || $wire === 2, 'Invalid packed protobuf field');
                if ($wire === 0) $message[$field][] = $r->varint();
                else {
                    $packed = $r->section($r->varint());
                    while ($packed->left() > 0) $message[$field][] = $packed->varint();
                }
                continue;
            }

            require_valid($wire === ($type === 'v' ? 0 : ($type === 'd' ? 1 : 2)), 'Wrong protobuf wire type');
            $repeated = strlen($spec) > 1;
            $value = match ($type) {
                'v' => $r->varint(),
                'd' => $r->f64(),
                's' => utf8($r->take($r->varint())),
                'b' => $r->take($r->varint()),
                default => self::read($r->section($r->varint()), $type, $repeated ? [] : ($message[$field] ?? [])),
            };
            if ($repeated) $message[$field][] = $value;
            else $message[$field] = $value;
        }
        return $message;
    }
}

final class Metadata
{
    private const REWARD_TYPES = ['Fee', 'Rent', 'Staking', 'Voting'];
    private const TX_ERRORS = [
        'AccountInUse', 'AccountLoadedTwice', 'AccountNotFound', 'ProgramAccountNotFound', 'InsufficientFundsForFee',
        'InvalidAccountForFee', 'AlreadyProcessed', 'BlockhashNotFound', 'InstructionError', 'CallChainTooDeep',
        'MissingSignatureForFee', 'InvalidAccountIndex', 'SignatureFailure', 'InvalidProgramForExecution', 'SanitizeFailure',
        'ClusterMaintenance', 'AccountBorrowOutstanding', 'WouldExceedMaxBlockCostLimit', 'UnsupportedVersion', 'InvalidWritableAccount',
        'WouldExceedMaxAccountCostLimit', 'WouldExceedAccountDataBlockLimit', 'TooManyAccountLocks', 'AddressLookupTableNotFound',
        'InvalidAddressLookupTableOwner', 'InvalidAddressLookupTableData', 'InvalidAddressLookupTableIndex', 'InvalidRentPayingAccount',
        'WouldExceedMaxVoteCostLimit', 'WouldExceedAccountDataTotalLimit', 'DuplicateInstruction', 'InsufficientFundsForRent',
        'MaxLoadedAccountsDataSizeExceeded', 'InvalidLoadedAccountsDataSizeLimit', 'ResanitizationNeeded',
        'ProgramExecutionTemporarilyRestricted', 'UnbalancedTransaction', 'ProgramCacheHitMaxLimit', 'CommitCancelled',
    ];
    private const INSTRUCTION_ERRORS = [
        'GenericError', 'InvalidArgument', 'InvalidInstructionData', 'InvalidAccountData', 'AccountDataTooSmall', 'InsufficientFunds',
        'IncorrectProgramId', 'MissingRequiredSignature', 'AccountAlreadyInitialized', 'UninitializedAccount', 'UnbalancedInstruction',
        'ModifiedProgramId', 'ExternalAccountLamportSpend', 'ExternalAccountDataModified', 'ReadonlyLamportChange', 'ReadonlyDataModified',
        'DuplicateAccountIndex', 'ExecutableModified', 'RentEpochModified', 'NotEnoughAccountKeys', 'AccountDataSizeChanged',
        'AccountNotExecutable', 'AccountBorrowFailed', 'AccountBorrowOutstanding', 'DuplicateAccountOutOfSync', 'Custom', 'InvalidError',
        'ExecutableDataModified', 'ExecutableLamportChange', 'ExecutableAccountNotRentExempt', 'UnsupportedProgramId', 'CallDepth',
        'MissingAccount', 'ReentrancyNotAllowed', 'MaxSeedLengthExceeded', 'InvalidSeeds', 'InvalidRealloc', 'ComputationalBudgetExceeded',
        'PrivilegeEscalation', 'ProgramEnvironmentSetupFailure', 'ProgramFailedToComplete', 'ProgramFailedToCompile', 'Immutable',
        'IncorrectAuthority', 'BorshIoError', 'AccountNotRentExempt', 'InvalidAccountOwner', 'ArithmeticOverflow', 'UnsupportedSysvar',
        'IllegalOwner', 'MaxAccountsDataAllocationsExceeded', 'MaxAccountsExceeded', 'MaxInstructionTraceLengthExceeded',
        'BuiltinProgramsMustConsumeComputeUnits',
    ];

    private static function instructionError(Reader $r): string|array
    {
        $type = $r->u32();
        if ($type === 25) return ['Custom' => $r->u32()];
        return self::INSTRUCTION_ERRORS[$type] ?? throw new FormatError('Unknown instruction error');
    }

    private static function error(Reader $r): string|array
    {
        $type = $r->u32();
        return match ($type) {
            8 => ['InstructionError' => [$r->u8(), self::instructionError($r)]],
            30 => ['DuplicateInstruction' => $r->u8()],
            31, 35 => [self::TX_ERRORS[$type] => ['account_index' => $r->u8()]],
            default => self::TX_ERRORS[$type] ?? throw new FormatError('Unknown transaction error'),
        };
    }

    private static function pubkey(string $data): string
    {
        require_valid(strlen($data) === 32, 'Invalid pubkey length');
        return base58($data);
    }

    private static function tokenText(string $amount, int $decimals): string
    {
        $text = sprintf('%u', unsigned_decimal($amount) ?? 0);
        if ($decimals === 0) return $text;
        $text = str_pad($text, $decimals + 1, '0', STR_PAD_LEFT);
        return rtrim(rtrim(substr($text, 0, -$decimals) . '.' . substr($text, -$decimals), '0'), '.');
    }

    private static function token(int $accountIndex, string $mint, string $owner, string $programId,
        ?float $uiAmount, int $decimals, string $amount, string $uiAmountString = ''): array
    {
        if ($uiAmount !== null && !is_finite($uiAmount)) $uiAmount = null;
        if ($uiAmountString === '') $uiAmountString = self::tokenText($amount, $decimals);
        $uiTokenAmount = compact('uiAmount', 'decimals', 'amount', 'uiAmountString');
        $result = compact('accountIndex', 'mint', 'uiTokenAmount');
        if ($owner !== '') $result['owner'] = $owner;
        if ($programId !== '') $result['programId'] = $programId;
        return $result;
    }

    private static function protoReward(array $p): array
    {
        $pubkey = $p[1] ?? '';
        $lamports = $p[2] ?? 0;
        $postBalance = unsigned_json($p[3] ?? 0);
        $type = ($p[4] ?? 0) & 0xffffffff;
        $rewardType = self::REWARD_TYPES[$type - 1] ?? null;
        $commission = unsigned_decimal($p[5] ?? '');
        if ($commission === null || $commission < 0 || $commission > 255) {
            $bps = unsigned_decimal($p[6] ?? '');
            $commission = $bps === null || $bps < 0 || $bps > 65535 || $bps >= 25600 ? null : intdiv($bps, 100);
        }
        return compact('pubkey', 'lamports', 'postBalance', 'rewardType', 'commission');
    }

    private static function protoToken(array $p): array
    {
        $amount = $p[3] ?? [];
        $ui = $amount[1] ?? 0.0;
        return self::token(($p[1] ?? 0) & 255, $p[2] ?? '', $p[4] ?? '', $p[5] ?? '',
            abs($ui) > 2.220446049250313e-16 ? $ui : null, ($amount[2] ?? 0) & 255, $amount[3] ?? '', $amount[4] ?? '');
    }

    private static function returnData(string $key, string $data): array
    {
        return ['programId' => self::pubkey($key), 'data' => [base64_encode($data), 'base64']];
    }

    private static function convertMeta(array $p): Meta
    {
        $meta = new Meta();
        $meta->error = isset($p[1]) ? self::error(new Reader($p[1][1] ?? '')) : null;
        $meta->fee = unsigned_json($p[2] ?? 0);
        $meta->pre = array_map('unsigned_json', $p[3] ?? []);
        $meta->post = array_map('unsigned_json', $p[4] ?? []);
        $meta->inner = !empty($p[10]) ? null : array_map(
            fn(array $i) => [($i[1] ?? 0) & 255, array_map(
                fn(array $x) => new Instruction(($x[1] ?? 0) & 255, $x[2] ?? '', $x[3] ?? '', isset($x[4]) ? $x[4] & 0xffffffff : null),
                $i[2] ?? [],
            )],
            $p[5] ?? [],
        );
        $meta->logs = !empty($p[11]) ? null : ($p[6] ?? []);
        $meta->preTokens = array_map(self::protoToken(...), $p[7] ?? []);
        $meta->postTokens = array_map(self::protoToken(...), $p[8] ?? []);
        $meta->rewards = array_map(self::protoReward(...), $p[9] ?? []);
        $meta->writable = array_map(self::pubkey(...), $p[12] ?? []);
        $meta->readonly = array_map(self::pubkey(...), $p[13] ?? []);
        if (empty($p[15]) && isset($p[14])) $meta->return = self::returnData($p[14][1] ?? '', $p[14][2] ?? '');
        if (isset($p[16])) $meta->compute = unsigned_json($p[16]);
        if (isset($p[17])) $meta->cost = unsigned_json($p[17]);
        return $meta;
    }

    private static function text(Reader $r): string { return utf8($r->take($r->u64())); }

    private static function option(Reader $r, callable $decode, bool $eof = false): mixed
    {
        if ($eof && $r->left() === 0) return null;
        return match ($r->u8()) {
            0 => null, 1 => $decode(), default => throw new FormatError('Invalid bincode option'),
        };
    }

    private static function storedReward(Reader $r, bool $legacy = false): array
    {
        $pubkey = self::text($r);
        $lamports = $r->u64();
        $postBalance = unsigned_json(!$legacy && $r->left() === 0 ? 0 : $r->u64());
        $rewardType = self::option($r, fn() => self::REWARD_TYPES[$r->u32()] ?? throw new FormatError('Unknown reward type'), !$legacy);
        $commission = $legacy ? null : self::option($r, $r->u8(...), true);
        return compact('pubkey', 'lamports', 'postBalance', 'rewardType', 'commission');
    }

    private static function storedToken(Reader $r, int $layout): array
    {
        $index = $r->u8();
        $mint = self::text($r);
        $ui = $r->f64();
        $decimals = $r->u8();
        $amount = self::text($r);
        $owner = $layout === 1 || ($layout !== 2 && $r->left() === 0) ? '' : self::text($r);
        $program = $layout === 1 || $layout === 2 || $r->left() === 0 ? '' : self::text($r);
        return self::token($index, $mint, $owner, $program, $ui, $decimals, $amount);
    }

    private static function storedMeta(string $data, int $layout, bool $strict): Meta
    {
        $r = new Reader($data);
        $m = new Meta();
        $m->error = match ($r->u32()) {
            0 => null, 1 => self::error($r), default => throw new FormatError('Invalid bincode status'),
        };
        $m->fee = unsigned_json($r->u64());
        $balance = fn() => unsigned_json($r->u64());
        $m->pre = $r->items($r->u64(), 8, $balance);
        $m->post = $r->items($r->u64(), 8, $balance);
        $instruction = static function () use ($r, $layout): Instruction {
            $i = Instruction::read($r);
            if ($layout === 0) $i->height = self::option($r, $r->u32(...));
            return $i;
        };
        $m->inner = self::option($r, fn() => $r->items($r->u64(), 9,
            fn() => [$r->u8(), $r->items($r->u64(), 3, $instruction)]), true);
        $m->logs = self::option($r, fn() => $r->items($r->u64(), 8, fn() => self::text($r)), true);
        $tokens = fn() => $r->items($r->u64(), 26, fn() => self::storedToken($r, $layout));
        $m->preTokens = self::option($r, $tokens, true);
        $m->postTokens = self::option($r, $tokens, true);
        $m->rewards = self::option($r, fn() => $r->items($r->u64(), 16, fn() => self::storedReward($r)), true);
        $m->return = self::option($r, fn() => self::returnData($r->take(32), $r->take($r->u64())), true);
        $m->compute = self::option($r, $balance, true);
        $m->cost = self::option($r, $balance, true);
        require_valid(!$strict || $r->left() === 0, 'Trailing bincode metadata');
        return $m;
    }

    private static function binMeta(string $data): Meta
    {
        for ($layout = 0; $layout < 4; $layout++) {
            try { return self::storedMeta($data, $layout, true); }
            catch (FormatError) {}
        }
        return self::storedMeta($data, 0, false);
    }

    private static function binRewards(string $data): array
    {
        for ($layout = 0; ; $layout++) {
            $r = new Reader($data);
            try {
                $rewards = $r->items($r->u64(), 16, fn() => self::storedReward($r, $layout === 1));
                require_valid($layout === 2 || $r->left() === 0, 'Trailing bincode rewards');
                return [$rewards, null];
            } catch (FormatError $error) {
                if ($layout === 2) throw $error;
            }
        }
    }

    private static function protoRewards(string $data): array
    {
        $p = Proto::read(new Reader($data), 'S');
        return [array_map(self::protoReward(...), $p[1] ?? []), isset($p[2]) ? unsigned_json($p[2][1] ?? 0) : null];
    }

    private static function frame(string $data, callable $decode): mixed
    {
        if (str_starts_with($data, "\x28\xb5\x2f\xfd")) {
            try { $plain = Zstd::decode($data); }
            catch (FormatError) { $plain = $data; }
            return $decode($plain);
        }
        try { return $decode($data); }
        catch (FormatError $first) {
            try { $plain = Zstd::decode($data); }
            catch (FormatError) { throw $first; }
            return $decode($plain);
        }
    }

    public static function meta(int $slot, string $data): ?Meta
    {
        if ($data === '') return null;
        return self::frame($data, static function (string $b) use ($slot): Meta {
            if ($slot >= 0 && $slot < 67_824_000) {
                try { return self::binMeta($b); }
                catch (FormatError) { return self::convertMeta(Proto::read(new Reader($b), 'M')); }
            }
            try { $p = Proto::read(new Reader($b), 'M'); }
            catch (FormatError) { return self::binMeta($b); }
            return self::convertMeta($p);
        });
    }

    public static function rewards(int $slot, string $data): array
    {
        if ($data === '') return [[], null];
        return self::frame($data, static function (string $b) use ($slot): array {
            if ($slot >= 0 && $slot < 67_824_000) {
                try { return self::binRewards($b); }
                catch (FormatError) { return self::protoRewards($b); }
            }
            try { return self::protoRewards($b); }
            catch (FormatError) { return self::binRewards($b); }
        });
    }
}
