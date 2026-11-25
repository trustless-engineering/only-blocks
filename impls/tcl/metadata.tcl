set ::instruction_errors {
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
}
set ::tx_errors {
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
}
set ::reward_types {Fee Rent Staking Voting}
proc tx_error {name} {
    upvar 1 $name r
    set variant [u32 r]
    set name [lindex $::tx_errors $variant]
    if {$name eq ""} {error "Unknown TransactionError"}
    switch -- $variant {
        8 {
            set i [u8 r]
            set tag [u32 r]
            set kind [lindex $::instruction_errors $tag]
            if {$kind eq ""} {error "Unknown InstructionError"}
            if {$tag == 25} {
                set payload [jo [dict create Custom [jn [u32 r]]]]
            } else {
                set payload [js $kind]
            }
            return [jo [dict create $name [ja [list [jn $i] $payload]]]]
        }
        30 {return [jo [dict create $name [jn [u8 r]]]]}
        31 - 35 {return [jo [dict create $name [jo [dict create account_index [jn [u8 r]]]]]]}
        default {return [js $name]}
    }
}
proc uint_text {s max} {
    if {![regexp {\A[+]?0*([0-9]{1,20})\Z} $s -> digits]} {return {}}
    scan $digits %lld n
    if {$n <= $max} {return $n}
    return {}
}
proc token_balance {index mint ui decimals amount owner program {display {}}} {
    if {$display eq ""} {
        set display [uint_text $amount $::u64max]
        if {$display eq ""} {set display 0}
        if {$decimals} {
            set pad [expr {max(0, $decimals + 1 - [string length $display])}]
            set display [string repeat 0 $pad]$display
            set dot [expr {[string length $display] - $decimals}]
            set display [string range $display 0 [expr {$dot - 1}]].[string range $display $dot end]
            set display [string trimright [string trimright $display 0] .]
        }
    }
    if {$ui ne "" && ([catch {expr {abs($ui) < Inf}} finite] || !$finite)} {set ui {}}
    set ans [dict create accountIndex [jn $index] mint [js $mint] \
        uiTokenAmount [jo [dict create uiAmount [jn $ui] decimals [jn $decimals] \
            amount [js $amount] uiAmountString [js $display]]]]
    if {$owner ne ""} {dict set ans owner [js $owner]}
    if {$program ne ""} {dict set ans programId [js $program]}
    jo $ans
}
proc empty_meta {} {
    dict create err {} fee [jn 0] preBalances [ja {}] postBalances [ja {}] \
        innerInstructions {} logMessages {} preTokenBalances {} postTokenBalances {} rewards {} \
        loadedAddresses [dict create writable {} readonly {}]
}

# Field descriptors give name, wire scalar type (or schema name), and repetition.
array set ::proto_schema {
    ix {1 {programIdIndex v} 2 {accounts b} 3 {data b} 4 {stackHeight v}}
    inner {1 {index v} 2 {instructions ix 1}}
    amount {1 {uiAmount d} 2 {decimals v} 3 {amount s} 4 {uiAmountString s}}
    token {1 {accountIndex v} 2 {mint s} 3 {uiTokenAmount amount} 4 {owner s} 5 {programId s}}
    reward {1 {pubkey s} 2 {lamports v} 3 {postBalance v} 4 {rewardType v} 5 {commission s} 6 {commissionBps s}}
    rewards {1 {rewards reward 1} 2 {partitions partitions}}
    partitions {1 {count v}}
    err {1 {bytes b}}
    return {1 {programId b} 2 {data b}}
    meta {
        1 {error err} 2 {fee v} 3 {preBalances v 1} 4 {postBalances v 1}
        5 {innerInstructions inner 1} 6 {logMessages s 1} 7 {preTokenBalances token 1}
        8 {postTokenBalances token 1} 9 {rewards reward 1} 10 {innerInstructionsNone v}
        11 {logMessagesNone v} 12 {loadedWritable b 1} 13 {loadedReadonly b 1}
        14 {returnData return} 15 {returnDataNone v} 16 {computeUnitsConsumed v} 17 {costUnits v}
    }
}
proc proto_key {name} {
    upvar 1 $name r
    set k [varint r]
    if {$k < 8 || $k > 0xffffffff} {error "Invalid protobuf key"}
    list [expr {$k >> 3}] [expr {$k & 7}]
}
proc skip_proto {name field mode depth} {
    upvar 1 $name r
    switch -- $mode {
        0 {varint r}
        1 {take r 8}
        2 {take r [varint r]}
        3 {
            if {$depth >= 100} {error "Protobuf group nesting limit"}
            incr depth
            while 1 {
                lassign [proto_key r] tag wire
                if {$wire == 4} {
                    if {$tag != $field} {error "Mismatched protobuf group"}
                    break
                }
                skip_proto r $tag $wire $depth
            }
        }
        5 {take r 4}
        default {error "Invalid protobuf wire type"}
    }
}
proc proto {data schema_name {target {}}} {
    set schema $::proto_schema($schema_name)
    set r [reader $data]
    while {[left r]} {
        lassign [proto_key r] field wire
        if {![dict exists $schema $field]} {
            skip_proto r $field $wire 0
            continue
        }
        lassign [dict get $schema $field] name mode repeated
        if {$repeated eq "1" && $mode eq "v" && $wire == 2} {
            set packed [reader [take r [varint r]]]
            while {[left packed]} {dict lappend target $name [varint packed]}
            continue
        }
        if {$wire != ($mode eq "v" ? 0 : $mode eq "d" ? 1 : 2)} {error "Wrong protobuf wire type"}
        switch -- $mode {
            v {set v [varint r]}
            d {set v [f64 r]}
            b {set v [take r [varint r]]}
            s {set v [utext [take r [varint r]]]}
            default {
                set old {}
                if {$repeated ne "1"} {set old [fetch $target $name]}
                set v [proto [take r [varint r]] $mode $old]
            }
        }
        if {$repeated eq "1"} {dict lappend target $name $v} else {dict set target $name $v}
    }
    return $target
}
proc reward_json {pubkey lamports post kind commission} {
    if {$kind ne ""} {set kind [js $kind]}
    jo [dict create pubkey [js $pubkey] lamports [jn $lamports] postBalance [jn $post] \
        rewardType $kind commission [jn $commission]]
}
proc proto_reward {v} {
    set commission [uint_text [fetch $v commission] 255]
    set bps [uint_text [fetch $v commissionBps] 65535]
    if {$commission eq "" && $bps ne "" && $bps < 25600} {set commission [expr {$bps / 100}]}
    set kind [expr {([fetch $v rewardType 0] & 0xffffffff) - 1}]
    set type {}
    if {$kind >= 0 && $kind < [llength $::reward_types]} {set type [lindex $::reward_types $kind]}
    set lamports [fetch $v lamports 0]
    if {$lamports >= (1 << 63)} {set lamports [expr {$lamports - (1 << 64)}]}
    reward_json [fetch $v pubkey] $lamports [fetch $v postBalance 0] $type $commission
}
proc proto_token {v} {
    set a [fetch $v uiTokenAmount]
    set ui [fetch $a uiAmount 0]
    if {[catch {expr {abs($ui) > 2.220446049250313e-16}} nonzero] || !$nonzero} {set ui {}}
    token_balance [expr {[fetch $v accountIndex 0] & 255}] [fetch $v mint] $ui \
        [expr {[fetch $a decimals 0] & 255}] [fetch $a amount] [fetch $v owner] \
        [fetch $v programId] [fetch $a uiAmountString]
}
proc proto_instruction {v} {
    set height [fetch $v stackHeight]
    if {$height ne ""} {set height [expr {$height & 0xffffffff}]}
    dict create programIdIndex [expr {[fetch $v programIdIndex 0] & 255}] \
        accounts [fetch $v accounts] data [fetch $v data] stackHeight $height
}
proc return_json {key data} {
    jo [dict create programId [js [pubkey $key]] data [ja [list [js [b64 $data]] [js base64]]]]
}
proc proto_meta {v} {
    set out [empty_meta]
    if {[dict exists $v error]} {
        set r [reader [fetch [dict get $v error] bytes]]
        dict set out err [tx_error r]
    }
    foreach key {fee computeUnitsConsumed costUnits} {
        if {[dict exists $v $key]} {dict set out $key [jn [dict get $v $key]]}
    }
    foreach key {preBalances postBalances} {dict set out $key [jarray jn [fetch $v $key]]}
    if {![fetch $v innerInstructionsNone 0]} {
        set groups {}
        foreach group [fetch $v innerInstructions] {
            set instructions {}
            foreach ix [fetch $group instructions] {lappend instructions [proto_instruction $ix]}
            lappend groups [dict create index [expr {[fetch $group index 0] & 255}] instructions $instructions]
        }
        dict set out innerInstructions [list $groups]
    }
    if {![fetch $v logMessagesNone 0]} {dict set out logMessages [jarray js [fetch $v logMessages]]}
    foreach key {preTokenBalances postTokenBalances} {
        dict set out $key [jarray proto_token [fetch $v $key]]
    }
    dict set out rewards [jarray proto_reward [fetch $v rewards]]
    foreach {key tag} {loadedWritable writable loadedReadonly readonly} {
        set keys {}
        foreach bytes [fetch $v $key] {lappend keys [pubkey $bytes]}
        dict set out loadedAddresses $tag $keys
    }
    if {[dict exists $v returnData] && ![fetch $v returnDataNone 0]} {
        set d [dict get $v returnData]
        dict set out returnData [return_json [fetch $d programId] [fetch $d data]]
    }
    return $out
}
proc proto_rewards {v} {
    set out [dict create rewards [jarray proto_reward [fetch $v rewards]]]
    if {[dict exists $v partitions]} {
        dict set out numRewardPartitions [jn [fetch [dict get $v partitions] count 0]]
    }
    return $out
}
proc stored_reward_type {name} {
    upvar 1 $name r
    set kind [lindex $::reward_types [u32 r]]
    if {$kind eq ""} {error "Invalid RewardType"}
    return $kind
}
proc stored_reward {extended name} {
    upvar 1 $name r
    set key [bstr r]
    set lamports [i64 r]
    set post 0
    set kind {}
    set commission {}
    if {[left r] || !$extended} {set post [u64 r]}
    if {[left r] || !$extended} {set kind [option r stored_reward_type]}
    if {$extended && [left r]} {set commission [option r u8]}
    reward_json $key $lamports $post $kind $commission
}
proc stored_token {layout name} {
    upvar 1 $name r
    set index [u8 r]
    set mint [bstr r]
    set ui [f64 r]
    set decimals [u8 r]
    set amount [bstr r]
    set owner {}
    set program {}
    if {$layout >= 2 && [left r]} {set owner [bstr r]}
    if {$layout >= 3 && [left r]} {set program [bstr r]}
    token_balance $index $mint $ui $decimals $amount $owner $program
}
proc stored_inner_ix {legacy name} {
    upvar 1 $name r
    set ix [instruction r]
    if {!$legacy} {dict set ix stackHeight [option r u32]}
    return $ix
}
proc stored_group {legacy name} {
    upvar 1 $name r
    dict create index [u8 r] instructions [vector r [expr {$legacy ? 3 : 4}] [list stored_inner_ix $legacy]]
}
proc stored_inner {legacy name} {
    upvar 1 $name r
    list [vector r 9 [list stored_group $legacy]]
}
proc stored_array {min command name} {
    upvar 1 $name r
    ja [vector r $min $command]
}
proc read_json_string {name} {upvar 1 $name r; js [bstr r]}
proc read_json_num {name} {upvar 1 $name r; jn [u64 r]}
proc stored_return {name} {upvar 1 $name r; return_json [take r 32] [take r [u64 r]]}
proc stored_meta {legacy layout name} {
    upvar 1 $name r
    set status [u32 r]
    if {$status > 1} {error "Invalid bincode result tag"}
    set out [empty_meta]
    if {$status} {dict set out err [tx_error r]}
    dict set out fee [jn [u64 r]]
    foreach field {preBalances postBalances} {dict set out $field [stored_array 8 read_json_num r]}
    set fields [dict create innerInstructions [list stored_inner $legacy] \
        logMessages {stored_array 8 read_json_string} \
        preTokenBalances [list stored_array 26 [list stored_token $layout]] \
        postTokenBalances [list stored_array 26 [list stored_token $layout]] \
        rewards {stored_array 16 {stored_reward 1}} returnData stored_return \
        computeUnitsConsumed read_json_num costUnits read_json_num]
    dict for {name command} $fields {
        if {![left r]} {break}
        set v [option r $command]
        if {$v ne ""} {dict set out $name $v}
    }
    return $out
}
proc bincode {data layouts} {
    foreach cmd $layouts {
        set r [reader $data]
        if {![catch {{*}$cmd r} out] && ![left r]} {return $out}
    }
    set r [reader $data]
    {*}[lindex $layouts 0] r
}
proc bincode_meta {data} {
    bincode $data {{stored_meta 0 3} {stored_meta 1 1} {stored_meta 1 2} {stored_meta 1 3}}
}
proc bincode_rewards {data} {
    dict create rewards [bincode $data {{stored_array 16 {stored_reward 1}} {stored_array 25 {stored_reward 0}}}]
}
proc decode_payload {slot data schema convert stored} {
    if {$slot < 67824000 && ![catch {$stored $data} decoded]} {return $decoded}
    if {[catch {proto $data $schema} parsed opts]} {
        if {$slot >= 67824000} {return [$stored $data]}
        return -options $opts $parsed
    }
    $convert $parsed
}
proc unwrap_payload {slot data schema convert stored} {
    if {[regexp {\A(?:\x28\xb5\x2f\xfd|[\x50-\x5f]\x2a\x4d\x18)} $data] &&
        ![catch {zstd::decompress $data} plain]} {set data $plain}
    decode_payload $slot $data $schema $convert $stored
}
proc metadata {slot data} {
    if {$data eq ""} {return {}}
    unwrap_payload $slot $data meta proto_meta bincode_meta
}
proc rewards {slot data} {
    if {$data eq ""} {return [dict create rewards [ja {}]]}
    unwrap_payload $slot $data rewards proto_rewards bincode_rewards
}
