# Readers hold the byte string and cursor. upvar keeps cursor updates local to
# the current decoder and avoids copying the backing bytes.
proc reader {data} {list $data 0}
proc left {name} {
    upvar 1 $name r
    expr {[string length [lindex $r 0]] - [lindex $r 1]}
}
proc take {name n} {
    upvar 1 $name r
    if {$n < 0 || $n > [left r]} {error "Truncated binary value"}
    lassign $r data p
    lset r 1 [expr {$p + $n}]
    string range $data $p [expr {$p + $n - 1}]
}
proc fixed {name width format} {
    upvar 1 $name r
    binary scan [take r $width] $format value
    return $value
}
proc u8 {name} {upvar 1 $name r; fixed r 1 cu}
proc u32 {name} {upvar 1 $name r; fixed r 4 iu}
proc u64 {name} {upvar 1 $name r; fixed r 8 wu}
proc i64 {name} {upvar 1 $name r; fixed r 8 w}
proc f64 {name} {upvar 1 $name r; fixed r 8 q}
proc varint {name} {
    upvar 1 $name r
    set value 0
    for {set shift 0} {$shift <= 63} {incr shift 7} {
        set b [u8 r]
        if {$shift == 63 && $b > 1} {error "Varint overflow"}
        set value [expr {$value | (($b & 127) << $shift)}]
        if {$b < 128} {return $value}
    }
}
proc compact {name} {
    upvar 1 $name r
    set value 0
    foreach shift {0 7 14} {
        set b [u8 r]
        if {($shift && !$b) || ($shift == 14 && $b > 3)} {error "Invalid compact-u16"}
        set value [expr {$value | (($b & 127) << $shift)}]
        if {$b < 128} {return $value}
    }
}
proc items {name count minimum command} {
    upvar 1 $name r
    if {$count > [left r] / $minimum} {error "Count exceeds enclosing field"}
    set result {}
    for {set i 0} {$i < $count} {incr i} {lappend result [{*}$command r]}
    return $result
}
proc vector {name minimum command} {
    upvar 1 $name r
    items r [u64 r] $minimum $command
}
proc option {name command} {
    upvar 1 $name r
    set tag [u8 r]
    if {$tag > 1} {error "Invalid bincode option"}
    if {$tag} {return [{*}$command r]}
    return {}
}
proc utext {bytes} {
    # Tcl's UTF-8 conversion can replace malformed data. Validate by
    # round-trip and reject surrogate encodings explicitly.
    if {[regexp {\xed[\xa0-\xbf][\x80-\xbf]} $bytes]} {error "Invalid Unicode scalar"}
    set text [encoding convertfrom utf-8 $bytes]
    if {[encoding convertto utf-8 $text] ne $bytes} {error "Invalid UTF-8"}
    return $text
}
proc bstr {name} {upvar 1 $name r; utext [take r [u64 r]]}
proc bytes_list {data} {binary scan $data cu* octets; return $octets}
proc base58 {data} {
    set alphabet 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    set hex [binary encode hex $data]
    if {$hex eq ""} {return {}}
    regexp {^(00)*} $hex leading
    set result {}
    for {set n [expr "0x$hex"]} {$n > 0} {set n [expr {$n / 58}]} {
        append result [string index $alphabet [expr {$n % 58}]]
    }
    return [string repeat 1 [expr {[string length $leading] / 2}]][string reverse $result]
}
proc b64 {data} {binary encode base64 $data}
proc pubkey {data} {
    if {[string length $data] != 32} {error "Expected a 32-byte key"}
    base58 $data
}

# A tagged CBOR value preserves distinctions between lists, bytes and ints.
proc is_type {value type} {expr {[lindex $value 0] eq $type}}
proc value {v} {lindex $v 1}
proc fetch {d key {default {}}} {
    if {[dict exists $d $key]} {return [dict get $d $key]}
    return $default
}
proc cuint {v {default {}}} {
    if {[is_type $v u]} {return [value $v]}
    return $default
}
proc csint {v} {
    if {[is_type $v i] || ([is_type $v u] && [value $v] < (1 << 63))} {return [value $v]}
    return {}
}
proc carray {v} {
    if {[is_type $v a]} {return [value $v]}
    return {}
}
proc cbytes {v} {
    if {[is_type $v b]} {return [value $v]}
    return {}
}
proc carg {name info} {
    upvar 1 $name r
    if {$info < 24} {return $info}
    if {$info == 31} {return -1}
    if {$info > 27} {error "Reserved CBOR argument"}
    fixed r [expr {1 << ($info - 24)}] [lindex {cu Su Iu Wu} [expr {$info - 24}]]
}
proc cmore {name} {
    upvar 1 $name r
    if {![left r]} {error "Missing CBOR break"}
    expr {[string index [lindex $r 0] [lindex $r 1]] ne "\xff"}
}
proc citem {name depth} {
    upvar 1 $name r
    if {$depth > 128} {error "CBOR nesting limit"}
    set head [u8 r]
    set major [expr {$head >> 5}]
    set info [expr {$head & 31}]
    if {$major == 7} {
        if {$info >= 20 && $info <= 23} {return {}}
        if {$info < 25 || $info > 27} {error "Unsupported CBOR simple value"}
        take r [expr {2 << ($info - 25)}]
        return {}
    }
    set n [carg r $info]
    if {$n < 0 && ($major < 2 || $major > 5)} {error "Invalid indefinite CBOR item"}
    switch -- $major {
        0 {return [list u $n]}
        1 {
            if {$n < (1 << 63)} {return [list i [expr {-1 - $n}]]}
            return {}
        }
        6 {return [citem r [expr {$depth + 1}]]}
        2 - 3 {
            set out {}
            if {$n >= 0} {
                set out [take r $n]
                if {$major == 3} {set out [utext $out]}
            } else {
                while {[cmore r]} {
                    set chunk [u8 r]
                    if {$chunk >> 5 != $major || ($chunk & 31) == 31} {error "Invalid CBOR chunk"}
                    set s [take r [carg r [expr {$chunk & 31}]]]
                    if {$major == 3} {set s [utext $s]}
                    append out $s
                }
                take r 1
            }
            return [list [expr {$major == 2 ? "b" : "s"}] $out]
        }
    }
    if {$n >= 0 && $n > [left r] / ($major - 3)} {error "CBOR count exceeds enclosing field"}
    set out {}
    set indefinite [expr {$n < 0}]
    incr depth
    while {$indefinite ? [cmore r] : $n > 0} {
        set item [citem r $depth]
        if {$major == 4} {
            lappend out $item
        } else {
            set v [citem r $depth]
            if {[is_type $item s]} {dict set out [value $item] $v}
        }
        if {!$indefinite} {incr n -1}
    }
    if {$indefinite} {take r 1}
    return [list [expr {$major == 4 ? "a" : "o"}] $out]
}
proc cbor {data} {
    set r [reader $data]
    set out [citem r 0]
    if {[left r]} {error "Trailing CBOR bytes"}
    return $out
}
proc cid {name} {
    upvar 1 $name r
    set start [lindex $r 1]
    set a [varint r]
    set b [varint r]
    set absent 0
    if {$a == 0x12 && $b == 0x20} {
        take r 32
    } else {
        if {$a != 1} {error "Unsupported CID version"}
        set code [varint r]
        set n [varint r]
        if {$n > 64} {error "CID digest too long"}
        take r $n
        set absent [expr {!$code && !$n}]
    }
    list [string range [lindex $r 0] $start [expr {[lindex $r 1] - 1}]] $absent
}
proc cid_link {v} {
    set bytes [cbytes $v]
    if {[string index $bytes 0] ne "\0"} {error "Invalid CID link"}
    set r [reader [string range $bytes 1 end]]
    cid r
}
proc links {v} {
    set out {}
    foreach item [carray $v] {lappend out [lindex [cid_link $item] 0]}
    return $out
}
proc kind {v expected} {
    if {[cuint [lindex [carray $v] 0] -1] != $expected} {error "Unexpected IPLD node kind"}
    carray $v
}
proc indexed {index key tag} {
    if {![dict exists $index $key]} {error "CID missing from CAR slice"}
    kind [cbor [dict get $index $key]] $tag
}
proc index_car {data} {
    set r [reader $data]
    set index {}
    set first 1
    set block {}
    while {[left r]} {
        set n [varint r]
        if {!$n} {continue}
        if {$n > (32 << 20)} {error "Oversize CAR section"}
        set section [reader [take r $n]]
        binary scan [lindex $section 0] cu first_byte
        if {$first && $first_byte >> 5 == 5 && ![catch {cbor [lindex $section 0]} header] &&
            [is_type $header o] && [dict exists [value $header] version]} {
            set first 0
            continue
        }
        set first 0
        lassign [cid section] key
        set node [take section [left section]]
        dict set index $key $node
        if {![string length $node]} {continue}
        binary scan $node cu head
        set info [expr {$head & 31}]
        if {$head >> 5 != 4 || ($info >= 28 && $info != 31)} {continue}
        set start [expr {$info < 24 || $info == 31 ? 1 : 1 + (1 << ($info - 24))}]
        if {[string index $node $start] eq "\x02"} {set block $node}
    }
    if {$block eq ""} {error "No Block node in CAR slice"}
    list $index [kind [cbor $block] 2]
}
set ::u64max 0xffffffffffffffff
set ::crc_table {}
for {set i 0} {$i < 256} {incr i} {
    set v $i
    for {set k 0} {$k < 8} {incr k} {
        set v [expr {($v >> 1) ^ (($v & 1) ? 0xd800000000000000 : 0)}]
    }
    lappend ::crc_table $v
}
unset i k v
proc crc64 {data} {
    set crc $::u64max
    set lookup $::crc_table
    # Scan bounded pieces to avoid materializing a Tcl object for every byte.
    for {set p 0} {$p < [string length $data]} {incr p 16384} {
        set n [expr {min(16384, [string length $data] - $p)}]
        binary scan $data "@${p}cu$n" octets
        foreach byte $octets {set crc [expr {($crc >> 8) ^ [lindex $lookup [expr {($crc & 255) ^ $byte}]]}]}
    }
    expr {$crc ^ $::u64max}
}
proc fnv1a {data} {
    set h 0xcbf29ce484222325
    for {set p 0} {$p < [string length $data]} {incr p 16384} {
        set n [expr {min(16384, [string length $data] - $p)}]
        binary scan $data "@${p}cu$n" octets
        foreach byte $octets {set h [expr {(($h ^ $byte) * 0x100000001b3) & $::u64max}]}
    }
    return $h
}
proc frame_payload {index root} {
    set root [kind $root 6]
    set out [cbytes [lindex $root 4]]
    set stack [lreverse [links [lindex $root 5]]]
    set seen {}
    while {[llength $stack]} {
        set key [lindex $stack end]
        set stack [lreplace $stack end end]
        if {[dict exists $seen $key]} {error "Repeated DataFrame CID"}
        dict set seen $key 1
        set frame [indexed $index $key 6]
        set chunk [cbytes [lindex $frame 4]]
        if {[string length $out] + [string length $chunk] > (128 << 20)} {error "Oversize DataFrame"}
        append out $chunk
        lappend stack {*}[lreverse [links [lindex $frame 5]]]
    }
    set expected [cuint [lindex $root 1]]
    if {$expected ne "" && [crc64 $out] != $expected && [fnv1a $out] != $expected} {
        error "DataFrame hash mismatch"
    }
    return $out
}
proc instruction {name {height {}}} {
    upvar 1 $name r
    dict create programIdIndex [u8 r] accounts [take r [compact r]] data [take r [compact r]] stackHeight $height
}
proc raw_signature {name} {upvar 1 $name r; take r 64}
proc read_pubkey {name} {upvar 1 $name r; pubkey [take r 32]}
proc tx_lookup {name} {
    upvar 1 $name r
    dict create accountKey [read_pubkey r] writableIndexes [bytes_list [take r [compact r]]] \
        readonlyIndexes [bytes_list [take r [compact r]]]
}
proc tx_instruction {name} {upvar 1 $name r; instruction r 1}
proc transaction {data} {
    set r [reader $data]
    set signatures [items r [compact r] 64 raw_signature]
    set prefix [u8 r]
    if {$prefix > 128} {error "Unsupported wire transaction version"}
    set v0 [expr {$prefix == 128}]
    set header [dict create numRequiredSignatures [expr {$v0 ? [u8 r] : $prefix}] \
        numReadonlySignedAccounts [u8 r] numReadonlyUnsignedAccounts [u8 r]]
    set message [dict create header $header accountKeys [items r [compact r] 32 read_pubkey] \
        recentBlockhash [read_pubkey r] instructions [items r [compact r] 3 tx_instruction]]
    if {$v0} {dict set message addressTableLookups [items r [compact r] 34 tx_lookup]}
    list [expr {$v0 ? 0 : "legacy"}] $signatures $message [string range $data 0 [expr {[lindex $r 1] - 1}]]
}
