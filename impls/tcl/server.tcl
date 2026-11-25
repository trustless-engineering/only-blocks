set dir [file dirname [info script]]
foreach module {wire json zstd metadata http} {source [file join $dir $module.tcl]}
unset dir module

set ::zero_hash [string repeat 1 32]
set ::upgradeable BPFLoaderUpgradeab1e11111111111111111111111
set ::reserved {}
foreach key {
    AddressLookupTab1e1111111111111111111111111 BPFLoader2111111111111111111111111111111111
    BPFLoader1111111111111111111111111111111111 BPFLoaderUpgradeab1e11111111111111111111111
    ComputeBudget111111111111111111111111111111 Config1111111111111111111111111111111111111
    Ed25519SigVerify111111111111111111111111111 Feature111111111111111111111111111111111111
    LoaderV411111111111111111111111111111111111 KeccakSecp256k11111111111111111111111111111
    Secp256r1SigVerify1111111111111111111111111 StakeConfig11111111111111111111111111111111
    Stake11111111111111111111111111111111111111 11111111111111111111111111111111
    Vote111111111111111111111111111111111111111 ZkE1Gama1Proof11111111111111111111111111111
    ZkTokenProof1111111111111111111111111111111 SysvarC1ock11111111111111111111111111111111
    SysvarEpochRewards1111111111111111111111111 SysvarEpochSchedu1e111111111111111111111111
    SysvarFees111111111111111111111111111111111 Sysvar1nstructions1111111111111111111111111
    SysvarLastRestartS1ot1111111111111111111111 SysvarRecentB1ockHashes11111111111111111111
    SysvarRent111111111111111111111111111111111 SysvarRewards111111111111111111111111111111
    SysvarS1otHashes111111111111111111111111111 SysvarS1otHistory11111111111111111111111111
    SysvarStakeHistory1111111111111111111111111 NativeLoader1111111111111111111111111111111
    Sysvar1111111111111111111111111111111111111
} {dict set ::reserved $key 1}
unset key

proc account_objects {message keys writable_count} {
    set static [llength [dict get $message accountKeys]]
    set header [dict get $message header]
    set signers [dict get $header numRequiredSignatures]
    set programs {}
    foreach ix [dict get $message instructions] {dict set programs [dict get $ix programIdIndex] 1}
    set upgrade [expr {$::upgradeable in $keys}]
    set i 0
    set out {}
    foreach key $keys {
        set lookup [expr {$i >= $static}]
        if {$lookup} {
            set writable [expr {$i - $static < $writable_count}]
        } elseif {$i < $signers} {
            set writable [expr {$i < $signers - [dict get $header numReadonlySignedAccounts]}]
        } else {
            set writable [expr {$i < $static - [dict get $header numReadonlyUnsignedAccounts]}]
        }
        set writable [expr {$writable && ![dict exists $::reserved $key] && ($upgrade || ![dict exists $programs $i])}]
        lappend out [jo [dict create pubkey [js $key] signer [jb [expr {$i < $signers}]] writable [jb $writable] \
            source [js [expr {$lookup ? "lookupTable" : "transaction"}]]]]
        incr i
    }
    ja $out
}
proc address_at {keys i} {
    if {$i >= [llength $keys]} {error "Instruction account index out of range"}
    js [lindex $keys $i]
}
proc ix_json {parsed keys ix} {
    set accounts [bytes_list [dict get $ix accounts]]
    set program [dict get $ix programIdIndex]
    set out [dict create data [js [base58 [dict get $ix data]]] stackHeight [jn [dict get $ix stackHeight]]]
    if {$parsed} {
        dict set out accounts [jarray [list address_at $keys] $accounts]
        dict set out programId [address_at $keys $program]
    } else {
        dict set out accounts [jarray jn $accounts]
        dict set out programIdIndex [jn $program]
    }
    jo $out
}
proc lookup_json {lookup} {
    jo [dict create accountKey [js [dict get $lookup accountKey]] \
        writableIndexes [jarray jn [dict get $lookup writableIndexes]] \
        readonlyIndexes [jarray jn [dict get $lookup readonlyIndexes]]]
}
proc b58_json {bytes} {js [base58 $bytes]}
proc tx_json {tx meta encoding details include_rewards max} {
    lassign $tx version signatures message raw
    set v0 [expr {$version eq "0"}]
    set v1 [expr {$version eq "1"}]
    if {$version ne "legacy"} {
        if {$max eq "" || $version > $max} {
            rpc_fail -32015 "Transaction version ($version) is not supported by the requesting client. Please try the request again with the following configuration parameter: \"maxSupportedTransactionVersion\": $version"
        }
        if {$meta eq ""} {set meta [empty_meta]}
    }
    set parsed [expr {$encoding eq "jsonParsed"}]
    set accounts [expr {$details eq "accounts"}]
    set keys [dict get $message accountKeys]
    if {$encoding in {base64 base58}} {
        if {$encoding eq "base64"} {set encoded [b64 $raw]} else {set encoded [base58 $raw]}
        set out [ja [list [js $encoded] [js $encoding]]]
    } else {
        if {$parsed || $accounts} {
            set writable {}
            if {$v0} {
                set writable [dict get $meta loadedAddresses writable]
                lappend keys {*}$writable {*}[dict get $meta loadedAddresses readonly]
            }
            set display [account_objects $message $keys [llength $writable]]
        } else {
            set display [jarray js $keys]
        }
        set out [dict create signatures [jarray b58_json $signatures]]
        if {$accounts} {
            dict set out accountKeys $display
        } else {
            dict set message accountKeys $display
            dict set message instructions [jarray [list ix_json $parsed $keys] [dict get $message instructions]]
            dict set message recentBlockhash [js [dict get $message recentBlockhash]]
            if {$v0} {
                dict set message addressTableLookups [jarray lookup_json [dict get $message addressTableLookups]]
            }
            if {$v1} {
                set c {}
                dict for {k v} [dict get $message transactionConfig] {dict set c $k [jn $v]}
                dict set message transactionConfig [jo $c]
            }
            if {$parsed} {
                dict unset message header
            } else {
                set h {}
                dict for {k v} [dict get $message header] {dict set h $k [jn $v]}
                dict set message header [jo $h]
            }
            dict set out message [jo $message]
        }
        set out [jo $out]
    }
    set result [dict create transaction $out meta {}]
    if {$meta eq ""} {return [jo $result]}
    set err [dict get $meta err]
    if {$err eq ""} {
        dict set meta status [jo [dict create Ok {}]]
    } else {
        dict set meta status [jo [dict create Err $err]]
    }
    if {!$include_rewards} {dict set meta rewards {}}
    if {$accounts} {
        foreach field {innerInstructions logMessages loadedAddresses returnData computeUnitsConsumed costUnits} {
            dict unset meta $field
        }
        if {!$include_rewards} {dict unset meta rewards}
    } else {
        if {$parsed} {
            dict unset meta loadedAddresses
        } else {
            set loaded {}
            dict for {kind addresses} [dict get $meta loadedAddresses] {
                dict set loaded $kind [jarray js $addresses]
            }
            dict set meta loadedAddresses [jo $loaded]
        }
        set group_data [dict get $meta innerInstructions]
        if {$group_data ne ""} {
            set groups {}
            foreach group [lindex $group_data 0] {
                lappend groups [jo [dict create index [jn [dict get $group index]] \
                    instructions [jarray [list ix_json $parsed $keys] [dict get $group instructions]]]]
            }
            dict set meta innerInstructions [ja $groups]
        }
    }
    dict set result meta [jo $meta]
    if {$max ne ""} {
        if {$version ne "legacy"} {
            dict set result version [jn $version]
        } else {
            dict set result version [js $version]
        }
    }
    jo $result
}

# Tcl arrays hold the doubly linked LRU without copying a large dictionary.
array set ::ranges {head {} tail {} size 0}
array set ::hashes {head {} tail {} size 0}
proc cache_detach {name key} {
    upvar 1 $name cache
    lassign $cache(node,$key) data prev next
    if {$prev eq ""} {set cache(head) $next} else {lset cache(node,$prev) 2 $next}
    if {$next eq ""} {set cache(tail) $prev} else {lset cache(node,$next) 1 $prev}
}
proc cache_put {name key data} {
    upvar #0 $name cache
    if {[info exists cache(node,$key)]} {
        cache_detach cache $key
    } else {
        incr cache(size)
    }
    set prev $cache(tail)
    set cache(node,$key) [list $data $prev {}]
    if {$prev eq ""} {set cache(head) $key} else {lset cache(node,$prev) 2 $key}
    set cache(tail) $key
    if {$cache(size) > 100000} {
        set oldest $cache(head)
        cache_detach cache $oldest
        unset cache(node,$oldest)
        incr cache(size) -1
    }
    return $data
}
proc cache_get {name key} {
    upvar #0 $name cache
    if {![info exists cache(node,$key)]} {return {}}
    cache_put $name $key [lindex $cache(node,$key) 0]
}
proc load_block {slot} {
    set record [cache_get ::ranges $slot]
    if {$record eq ""} {
        set r [reader [read_range $slot -slot-ranges.raw [expr {($slot % 432000) * 12}] 12 12]]
        set record [cache_put ::ranges $slot [list [u64 r] [u32 r]]]
    }
    lassign $record offset size
    if {!$size} {rpc_fail -32007 "Slot $slot was skipped"}
    if {$size > $::slice_limit} {error "CAR slice exceeds 128 MiB"}
    index_car [read_range $slot .car $offset $size $::slice_limit]
}
proc block_hash {slot index entries} {
    set hash $::zero_hash
    if {[llength $entries]} {
        set last [indexed $index [lindex $entries end] 1]
        set hash [pubkey [cbytes [lindex $last 2]]]
    }
    cache_put ::hashes $slot $hash
}
proc previous_hash {slot parent} {
    if {!$slot} {return $::zero_hash}
    set cached [cache_get ::hashes $parent]
    if {$cached ne ""} {return $cached}
    lassign [load_block $parent] index block
    if {[cuint [lindex $block 1]] eq ""} {error "Missing parent Block slot"}
    block_hash $parent $index [links [lindex $block 3]]
}
proc get_block {slot encoding details include_rewards max} {
    lassign [load_block $slot] index block
    if {[cuint [lindex $block 1] -1] != $slot} {error "Block slot mismatch"}
    set entries [links [lindex $block 3]]
    set info [carray [lindex $block 4]]
    set parent [cuint [lindex $info 0] 0]
    set hash [block_hash $slot $index $entries]
    set time [csint [lindex $info 1]]
    if {$time eq "0"} {set time {}}
    set out [dict create blockhash [js $hash] previousBlockhash [js [previous_hash $slot $parent]] \
        parentSlot [jn $parent] blockTime [jn $time] blockHeight [jn [cuint [lindex $info 2]]]]
    if {$details ne "none"} {
        set txs {}
        foreach key $entries {
            set entry [indexed $index $key 1]
            if {[string length [cbytes [lindex $entry 2]]] != 32} {error "Invalid Entry hash"}
            foreach tx_key [links [lindex $entry 3]] {
                set tx_node [indexed $index $tx_key 0]
                set tx [transaction [frame_payload $index [lindex $tx_node 1]]]
                if {$details eq "signatures"} {
                    set signatures [lindex $tx 1]
                    if {![llength $signatures]} {error "Transaction has no signature"}
                    lappend txs [b58_json [lindex $signatures 0]]
                } else {
                    set m {}
                    set frame [lindex $tx_node 2]
                    if {[is_type $frame a]} {set m [metadata $slot [frame_payload $index $frame]]}
                    lappend txs [tx_json $tx $m $encoding $details $include_rewards $max]
                }
            }
        }
        dict set out [expr {$details eq "signatures" ? "signatures" : "transactions"}] [ja $txs]
    }
    if {$include_rewards} {
        set data {}
        set link [lindex $block 5]
        if {[is_type $link b]} {
            lassign [cid_link $link] key absent
            if {!$absent && [dict exists $index $key]} {
                set node [indexed $index $key 5]
                if {[llength $node] > 2} {set data [frame_payload $index [lindex $node 2]]}
            }
        }
        set out [dict merge $out [rewards $slot $data]]
    }
    jo $out
}
proc bad_params {} {rpc_fail -32602 "Invalid params"}
proc uint_param {v max} {
    if {![is_type $v n]} {bad_params}
    set digits [value $v]
    if {![regexp {\A(?:0|[1-9][0-9]{0,19})\Z} $digits] || $digits > $max} {bad_params}
    return $digits
}
proc cfg_option {cfg key fallback} {
    set opt [fetch $cfg $key]
    if {$opt eq ""} {return $fallback}
    return $opt
}
proc params {node} {
    set p [value $node]
    if {![is_type $node a] || [llength $p] < 1 || [llength $p] > 2} {bad_params}
    set slot [uint_param [lindex $p 0] $::u64max]
    set cfg [lindex $p 1]
    if {[is_type $cfg s]} {
        set cfg [dict create encoding $cfg]
    } elseif {[is_type $cfg o]} {
        set cfg [value $cfg]
    } elseif {$cfg ne ""} {
        bad_params
    }
    set encoding [cfg_option $cfg encoding [js json]]
    set details [cfg_option $cfg transactionDetails [js full]]
    set rewards [cfg_option $cfg rewards [jb 1]]
    set commitment [cfg_option $cfg commitment [js finalized]]
    if {![is_type $encoding s] || [value $encoding] ni {json jsonParsed base64 base58} ||
        ![is_type $details s] || [value $details] ni {full accounts signatures none} ||
        ([value $details] eq "accounts" && [value $encoding] ne "json") ||
        ![is_type $rewards t] || ![is_type $commitment s] || [value $commitment] ni {finalized confirmed}} {
        bad_params
    }
    set max [fetch $cfg maxSupportedTransactionVersion]
    if {$max ne ""} {set max [uint_param $max 255]}
    if {[value $encoding] eq "base58" && $max ne "" && $max >= 1} {bad_params}
    list $slot [value $encoding] [value $details] [value $rewards] $max
}
proc response {id field val} {jo [dict create jsonrpc [js 2.0] $field $val id $id]}
proc error_response {id code message} {
    response $id error [jo [dict create code [jn $code] message [js $message]]]
}
proc dispatch {request} {
    if {![is_type $request o]} {return [error_response {} -32600 "Invalid Request"]}
    set r [value $request]
    set ver [fetch $r jsonrpc]
    set method [fetch $r method]
    set id [fetch $r id]
    if {($ver ne "" && ![is_type $ver s]) || ($method ne "" && ![is_type $method s]) ||
        ($id ne "" && [lindex $id 0] ni {s n})} {
        return [error_response {} -32600 "Invalid Request"]
    }
    if {$method eq "" || [value $ver] ne "2.0"} {return [error_response $id -32600 "Invalid Request"]}
    set p [fetch $r params]
    try {
        switch -- [value $method] {
            getHealth {
                if {$p ne "" && !([is_type $p a] && [value $p] eq "")} {bad_params}
                set result [js ok]
            }
            getBlock {set result [get_block {*}[params $p]]}
            default {rpc_fail -32601 "Method not found: [value $method]"}
        }
        return [response $id result $result]
    } on error {message opts} {
        lassign [dict get $opts -errorcode] type code
        if {$type eq "RPC" && $code < 0} {return [error_response $id $code $message]}
        if {[info exists ::env(ONLYBLOCKS_DEBUG)]} {puts stderr [dict get $opts -errorinfo]}
        return [error_response $id -32603 "Internal error"]
    }
}
proc rpc {raw} {
    if {[catch {json_parse $raw} req opts]} {
        if {[info exists ::env(ONLYBLOCKS_DEBUG)]} {puts stderr [dict get $opts -errorinfo]}
        return [error_response {} -32700 "Parse error"]
    }
    if {[is_type $req a]} {
        set items [value $req]
        if {[llength $items] < 1 || [llength $items] > 100} {
            return [error_response {} -32600 "Invalid batch size"]
        }
        return [jarray dispatch $items]
    }
    dispatch $req
}

proc configure_server {args} {
    set bind 127.0.0.1:8899
    set base https://files.old-faithful.net
    if {[info exists ::env(ONLYBLOCKS_BIND)]} {set bind $::env(ONLYBLOCKS_BIND)}
    if {[info exists ::env(OLD_FAITHFUL_BASE_URL)]} {set base $::env(OLD_FAITHFUL_BASE_URL)}
    for {set i 0} {$i < [llength $args]} {incr i} {
        set arg [lindex $args $i]
        if {![regexp {\A--(bind|base-url)(?:=(.*))?\Z} $arg -> name val]} {error "Unknown option $arg"}
        if {[string first "=" $arg] < 0} {
            incr i
            if {$i >= [llength $args]} {error "Missing value for --$name"}
            set val [lindex $args $i]
        }
        if {$name eq "bind"} {set bind $val} else {set base $val}
    }
    set base [string trimright [string trim $base] /]
    if {![regexp {\A(https?)://(([A-Za-z0-9._-]+)(?::([0-9]+))?)(/[^\x00-\x20\x7f?#]*)?\Z} \
            $base -> scheme authority host port prefix]} {
        error "Invalid archive base URL"
    }
    if {$port eq ""} {
        set port [expr {$scheme eq "https" ? 443 : 80}]
    } else {
        set port [bounded_number $port 65535 10]
        if {!$port || $port > 65535} {error "Invalid archive port"}
    }
    set ::origin [list $scheme $authority $host $port]
    set ::origin_prefix $prefix
    if {![regexp {\A([^:]+):([0-9]+)\Z} $bind -> host port]} {error "Invalid bind address"}
    set port [bounded_number $port 65535 10]
    if {$port > 65535} {error "Invalid bind port"}
    socket -server accept_client -myaddr $host $port
}
set listener [configure_server {*}$argv]
vwait forever
