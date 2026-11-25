package Metadata;
use strict;
use warnings;
use POSIX qw(isfinite);
use Wire;
use Zstd;
use Exporter 'import';
our @EXPORT = qw(metadata rewards empty_meta);

my @instruction_errors = qw(
    GenericError InvalidArgument InvalidInstructionData InvalidAccountData AccountDataTooSmall
    InsufficientFunds IncorrectProgramId MissingRequiredSignature AccountAlreadyInitialized
    UninitializedAccount UnbalancedInstruction ModifiedProgramId ExternalAccountLamportSpend
    ExternalAccountDataModified ReadonlyLamportChange ReadonlyDataModified DuplicateAccountIndex
    ExecutableModified RentEpochModified NotEnoughAccountKeys AccountDataSizeChanged
    AccountNotExecutable AccountBorrowFailed AccountBorrowOutstanding DuplicateAccountOutOfSync
    Custom InvalidError ExecutableDataModified ExecutableLamportChange ExecutableAccountNotRentExempt
    UnsupportedProgramId CallDepth MissingAccount ReentrancyNotAllowed MaxSeedLengthExceeded
    InvalidSeeds InvalidRealloc ComputationalBudgetExceeded PrivilegeEscalation
    ProgramEnvironmentSetupFailure ProgramFailedToComplete ProgramFailedToCompile Immutable
    IncorrectAuthority BorshIoError AccountNotRentExempt InvalidAccountOwner ArithmeticOverflow
    UnsupportedSysvar IllegalOwner MaxAccountsDataAllocationsExceeded MaxAccountsExceeded
    MaxInstructionTraceLengthExceeded BuiltinProgramsMustConsumeComputeUnits
);
my @tx_errors = qw(
    AccountInUse AccountLoadedTwice AccountNotFound ProgramAccountNotFound InsufficientFundsForFee
    InvalidAccountForFee AlreadyProcessed BlockhashNotFound InstructionError CallChainTooDeep
    MissingSignatureForFee InvalidAccountIndex SignatureFailure InvalidProgramForExecution
    SanitizeFailure ClusterMaintenance AccountBorrowOutstanding WouldExceedMaxBlockCostLimit
    UnsupportedVersion InvalidWritableAccount WouldExceedMaxAccountCostLimit
    WouldExceedAccountDataBlockLimit TooManyAccountLocks AddressLookupTableNotFound
    InvalidAddressLookupTableOwner InvalidAddressLookupTableData InvalidAddressLookupTableIndex
    InvalidRentPayingAccount WouldExceedMaxVoteCostLimit WouldExceedAccountDataTotalLimit
    DuplicateInstruction InsufficientFundsForRent MaxLoadedAccountsDataSizeExceeded
    InvalidLoadedAccountsDataSizeLimit ResanitizationNeeded ProgramExecutionTemporarilyRestricted
    UnbalancedTransaction ProgramCacheHitMaxLimit CommitCancelled
);
my @types = qw(Fee Rent Staking Voting);

sub tx_error {
    my ($r) = @_;
    my $tag = u32($r);
    die "Unknown TransactionError\n" if $tag > $#tx_errors;
    my $name = $tx_errors[$tag];
    if ($tag == 8) {
        my ($index, $kind) = (u8($r), u32($r));
        die "Unknown InstructionError\n" if $kind > $#instruction_errors;
        return {$name => [$index, $kind == 25 ? {Custom => u32($r)} : $instruction_errors[$kind]]};
    }
    return {$name => u8($r)} if $tag == 30;
    return {$name => {account_index => u8($r)}} if $tag == 31 || $tag == 35;
    return $name;
}
sub uint_text {
    my ($text, $maximum) = @_;
    return undef unless defined $text && $text =~ /\A\+?0*([0-9]{1,20})\z/;
    my $digits = $1;
    return undef if length($digits) == length("$maximum") && $digits gt "$maximum"
                 || length($digits) > length("$maximum");
    return 0 + $digits;
}
sub token {
    my ($index, $mint, $ui, $decimals, $amount, $owner, $program, $display) = @_;
    if (!defined($display) || $display eq '') {
        $display = '' . (uint_text($amount, U64) // 0);
        if ($decimals) {
            $display = ('0' x ($decimals + 1 - length($display))) . $display;
            substr($display, -$decimals, 0, '.');
            $display =~ s/0+\z//;
            $display =~ s/\.\z//;
        }
    }
    my $value = {accountIndex => $index, mint => $mint, uiTokenAmount => {
        uiAmount => defined($ui) && isfinite($ui) ? $ui : undef,
        decimals => $decimals, amount => "$amount", uiAmountString => "$display",
    }};
    $value->{owner} = $owner if defined($owner) && $owner ne '';
    $value->{programId} = $program if defined($program) && $program ne '';
    return $value;
}
sub empty_meta {
    return {err => undef, fee => 0, preBalances => [], postBalances => [], innerInstructions => undef,
            logMessages => undef, preTokenBalances => undef, postTokenBalances => undef, rewards => undef,
            loadedAddresses => {writable => [], readonly => []}};
}

my $instr = {1=>['programIdIndex','v'],2=>['accounts','b'],3=>['data','b'],4=>['stackHeight','v']};
my $inner = {1=>['index','v'],2=>['instructions',$instr,1]};
my $amount = {1=>['uiAmount','d'],2=>['decimals','v'],3=>['amount','s'],4=>['uiAmountString','s']};
my $token = {1=>['accountIndex','v'],2=>['mint','s'],3=>['uiTokenAmount',$amount],4=>['owner','s'],5=>['programId','s']};
my $reward = {1=>['pubkey','s'],2=>['lamports','v'],3=>['postBalance','v'],4=>['rewardType','v'],
              5=>['commission','s'],6=>['commissionBps','s']};
my $rewards = {1=>['rewards',$reward,1],2=>['partitions',{1=>['count','v']}]};
my $meta = {
    1=>['error',{1=>['bytes','b']}],2=>['fee','v'],3=>['preBalances','v',1],4=>['postBalances','v',1],
    5=>['innerInstructions',$inner,1],6=>['logMessages','s',1],7=>['preTokenBalances',$token,1],
    8=>['postTokenBalances',$token,1],9=>['rewards',$reward,1],10=>['innerInstructionsNone','v'],
    11=>['logMessagesNone','v'],12=>['loadedWritable','b',1],13=>['loadedReadonly','b',1],
    14=>['returnData',{1=>['programId','b'],2=>['data','b']}],15=>['returnDataNone','v'],
    16=>['computeUnitsConsumed','v'],17=>['costUnits','v'],
};
sub proto_key {
    my $key = varint($_[0]);
    die "Invalid protobuf key\n" if $key < 8 || $key > 0xffffffff;
    return ($key >> 3, $key & 7);
}
sub skip_proto {
    my ($r, $field, $wire, $depth) = @_;
    if ($wire == 0) { varint($r) }
    elsif ($wire == 1) { take($r, 8) }
    elsif ($wire == 2) { take($r, varint($r)) }
    elsif ($wire == 3) {
        die "Protobuf group nesting limit\n" if $depth >= 100;
        while (1) {
            my ($tag, $mode) = proto_key($r);
            if ($mode == 4) {
                die "Mismatched protobuf group\n" unless $tag == $field;
                last;
            }
            skip_proto($r, $tag, $mode, $depth + 1);
        }
    }
    elsif ($wire == 5) { take($r, 4) }
    else { die "Invalid protobuf wire type\n" }
}
sub proto {
    my ($data, $schema, $target) = @_;
    $target //= {};
    my $r = reader($data);
    while (left($r)) {
        my ($field, $wire) = proto_key($r);
        my $desc = $schema->{$field};
        if (!$desc) {
            skip_proto($r, $field, $wire, 0);
            next;
        }
        my ($name, $mode, $repeated) = @$desc;
        if ($repeated && $mode eq 'v' && $wire == 2) {
            my $packed = reader(take($r, varint($r)));
            push @{$target->{$name}}, varint($packed) while left($packed);
            next;
        }
        die "Wrong protobuf wire type\n" unless $wire == ($mode eq 'v' ? 0 : $mode eq 'd' ? 1 : 2);
        my $value = $wire == 0 ? varint($r) : $wire == 1 ? f64($r) : take($r, varint($r));
        if (ref($mode)) {
            $value = proto($value, $mode, $repeated ? undef : $target->{$name});
        } elsif ($mode eq 's') {
            $value = utf8str($value);
        }
        if ($repeated) { push @{$target->{$name}}, $value }
        else { $target->{$name} = $value }
    }
    return $target;
}
sub proto_reward {
    my ($v) = @_;
    my $commission = uint_text($v->{commission}, 255);
    my $bps = uint_text($v->{commissionBps}, 65535);
    $commission = int($bps / 100) if !defined($commission) && defined($bps) && $bps < 25600;
    my $kind = ($v->{rewardType} // 0) & 0xffffffff;
    return {pubkey => $v->{pubkey} // '', lamports => unpack('q', pack('Q', $v->{lamports} // 0)),
            postBalance => $v->{postBalance} // 0,
            rewardType => $kind >= 1 && $kind <= 4 ? $types[$kind - 1] : undef, commission => $commission};
}
sub proto_token {
    my ($v) = @_;
    my $a = $v->{uiTokenAmount} // {};
    my $ui = $a->{uiAmount};
    $ui = undef if defined($ui) && (!isfinite($ui) || abs($ui) <= 2.220446049250313e-16);
    return token(($v->{accountIndex} // 0) & 255, $v->{mint} // '', $ui, ($a->{decimals} // 0) & 255,
                 $a->{amount} // '', $v->{owner}, $v->{programId}, $a->{uiAmountString});
}
sub proto_instruction {
    my ($v) = @_;
    return {programIdIndex => ($v->{programIdIndex} // 0) & 255, accounts => $v->{accounts} // '',
            data => $v->{data} // '', stackHeight => defined $v->{stackHeight} ? $v->{stackHeight} & 0xffffffff : undef};
}
sub proto_meta {
    my ($v) = @_;
    my $out = empty_meta();
    $out->{err} = tx_error(reader($v->{error}{bytes} // '')) if exists $v->{error};
    for my $key (qw(fee preBalances postBalances computeUnitsConsumed costUnits)) {
        $out->{$key} = $v->{$key} if exists $v->{$key};
    }
    if (!$v->{innerInstructionsNone}) {
        $out->{innerInstructions} = [map {
            {index => ($_->{index} // 0) & 255, instructions => [map { proto_instruction($_) } @{$_->{instructions} // []}]}
        } @{$v->{innerInstructions} // []}];
    }
    $out->{logMessages} = $v->{logMessages} // [] unless $v->{logMessagesNone};
    for my $key (qw(preTokenBalances postTokenBalances)) {
        $out->{$key} = [map { proto_token($_) } @{$v->{$key} // []}];
    }
    $out->{rewards} = [map { proto_reward($_) } @{$v->{rewards} // []}];
    $out->{loadedAddresses} = {writable => [map { pubkey($_) } @{$v->{loadedWritable} // []}],
                               readonly => [map { pubkey($_) } @{$v->{loadedReadonly} // []}]};
    if ($v->{returnData} && !$v->{returnDataNone}) {
        $out->{returnData} = {programId => pubkey($v->{returnData}{programId}),
                             data => [b64($v->{returnData}{data} // ''), 'base64']};
    }
    return $out;
}
sub proto_rewards {
    my ($v) = @_;
    my $out = {rewards => [map { proto_reward($_) } @{$v->{rewards} // []}]};
    $out->{numRewardPartitions} = $v->{partitions}{count} // 0 if $v->{partitions};
    return $out;
}
sub stored_reward {
    my ($r, $extended) = @_;
    $extended //= 1;
    my ($key, $lamports) = (str($r), i64($r));
    my $post = left($r) || !$extended ? u64($r) : 0;
    my $kind = left($r) || !$extended ? option($r, sub {
        my $tag = u32($r);
        die "Invalid RewardType\n" if $tag > $#types;
        return $types[$tag];
    }) : undef;
    my $commission = $extended && left($r) ? option($r, \&u8) : undef;
    return {pubkey => $key, lamports => $lamports, postBalance => $post, rewardType => $kind, commission => $commission};
}
sub stored_token {
    my ($r, $layout) = @_;
    my ($index, $mint, $ui, $decimals, $amount) = (u8($r), str($r), f64($r), u8($r), str($r));
    my $owner = $layout >= 2 && left($r) ? str($r) : '';
    my $program = $layout >= 3 && left($r) ? str($r) : '';
    return token($index, $mint, $ui, $decimals, $amount, $owner, $program);
}
sub stored_meta {
    my ($r, $legacy, $layout) = @_;
    my $status = u32($r);
    die "Invalid bincode result tag\n" if $status > 1;
    my $out = empty_meta();
    $out->{err} = $status ? tx_error($r) : undef;
    $out->{fee} = u64($r);
    $out->{$_} = vector($r, 8, \&u64) for qw(preBalances postBalances);
    my @fields = (
        [innerInstructions => sub { vector($r, 9, sub {
            my $index = u8($r);
            return {index => $index, instructions => vector($r, $legacy ? 3 : 4, sub {
                my $ix = instruction($r);
                $ix->{stackHeight} = option($r, \&u32) unless $legacy;
                return $ix;
            })};
        }) }],
        [logMessages => sub { vector($r, 8, \&str) }],
        [preTokenBalances => sub { vector($r, 26, sub { stored_token($r, $layout) }) }],
        [postTokenBalances => sub { vector($r, 26, sub { stored_token($r, $layout) }) }],
        [rewards => sub { vector($r, 16, sub { stored_reward($r) }) }],
        [returnData => sub { return {programId => pubkey(take($r, 32)), data => [b64(take($r, u64($r))), 'base64']} }],
        [computeUnitsConsumed => \&u64], [costUnits => \&u64],
    );
    for my $field (@fields) {
        last unless left($r);
        my $value = option($r, $field->[1]);
        $out->{$field->[0]} = $value if defined $value;
    }
    return $out;
}
sub bincode {
    my ($data, @layouts) = @_;
    for my $decode (@layouts) {
        my $r = reader($data);
        my $out = eval { $decode->($r) };
        return $out if !$@ && !left($r);
    }
    return $layouts[0]->(reader($data)); # Historical deserializer permits trailing bytes.
}
sub bincode_meta {
    return bincode($_[0], sub { stored_meta($_[0], 0, 3) },
                   map { my $layout = $_; sub { stored_meta($_[0], 1, $layout) } } (1..3));
}
sub bincode_rewards {
    return {rewards => bincode($_[0], sub { vector($_[0], 16, \&stored_reward) },
                                     sub { vector($_[0], 25, sub { stored_reward($_[0], 0) }) })};
}
sub decode {
    my ($slot, $data, $schema, $convert, $stored) = @_;
    if ($slot < 67824000) {
        my $out = eval { $stored->($data) };
        return $out unless $@;
    }
    my $parsed = eval { proto($data, $schema) };
    return $slot >= 67824000 ? $stored->($data) : die($@) if $@;
    return $convert->($parsed);
}
sub unwrap {
    my ($slot, $data, @codecs) = @_;
    if ($data =~ /\A(?:\x28\xb5\x2f\xfd|[\x50-\x5f]\x2a\x4d\x18)/) {
        my $plain = eval { Zstd::decompress($data) };
        return decode($slot, defined($plain) ? $plain : $data, @codecs);
    }
    return decode($slot, $data, @codecs);
}
sub metadata { length($_[1]) ? unwrap(@_, $meta, \&proto_meta, \&bincode_meta) : undef }
sub rewards { length($_[1]) ? unwrap(@_, $rewards, \&proto_rewards, \&bincode_rewards) : {rewards => []} }
1;
