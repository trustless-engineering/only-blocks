# RFC 8878, using the entropy tables and frame rules in ZSTD_MINI_SPEC.md.
namespace eval zstd {
    variable cap [expr {512 << 20}]
    variable ll_base {0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 18 20 22 24 28 32 40 48 64 128 256 512 1024 2048 4096 8192 16384 32768 65536}
    variable ll_bits [concat [lrepeat 16 0] {1 1 1 1 2 2 3 3 4 6 7 8 9 10 11 12 13 14 15 16}]
    variable ml_base {3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 37 39 41 43 47 51 59 67 83 99 131 259 515 1027 2051 4099 8195 16387 32771 65539}
    variable ml_bits [concat [lrepeat 32 0] {1 1 1 1 2 2 3 3 4 4 5 7 8 9 10 11 12 13 14 15 16}]
    variable max_symbols {35 31 52}
    variable max_logs {9 8 9}
    variable p1 0x9e3779b185ebca87
    variable p2 0xc2b2ae3d27d4eb4f
    variable p3 0x165667b19e3779f9
    variable p4 0x85ebca77c2b2ae63
    variable p5 0x27d4eb2f165667c5
    variable mask 0xffffffffffffffff
}
proc zstd::bw {v} {
    set n 0
    while {$v} {incr n; set v [expr {$v >> 1}]}
    return $n
}
proc zstd::le {data p n {end -1}} {
    if {$end == -1} {set end [string length $data]}
    if {$p < 0 || $n > $end - $p} {error "Truncated Zstd input"}
    switch -- $n {
        0 {return 0}
        1 {binary scan $data "@${p}cu" v}
        2 {binary scan $data "@${p}su" v}
        4 {binary scan $data "@${p}iu" v}
        8 {binary scan $data "@${p}wu" v}
        default {
            binary scan $data "@${p}cu$n" bytes
            set v 0
            foreach b [lreverse $bytes] {set v [expr {($v << 8) | $b}]}
        }
    }
    return $v
}
proc zstd::back {data start end} {
    if {$end <= $start} {error "Empty Zstd bitstream"}
    set final [le $data [expr {$end - 1}] 1]
    if {!$final} {error "Missing bitstream end marker"}
    expr {8 * ($end - $start - 1) + [bw $final] - 1}
}
proc zstd::peek_back {data start bits n} {
    if {!$n || $bits <= 0} {return 0}
    set low [expr {max(0, $bits - $n)}]
    set byte [expr {$low >> 3}]
    set word [le $data [expr {$start + $byte}] [expr {(($bits - 1) >> 3) - $byte + 1}]]
    expr {(($word >> ($low & 7)) & ((1 << ($bits - $low)) - 1)) << max(0, $n - $bits)}
}
proc zstd::rb {data start name n} {
    upvar 1 $name bits
    set v [peek_back $data $start $bits $n]
    incr bits -$n
    return $v
}
proc zstd::peek_fwd {data pos end n} {
    set v 0
    for {set i 0} {$i < $n && $pos + $i < $end} {incr i} {
        set bit [expr {$pos + $i}]
        set byte [le $data [expr {$bit >> 3}] 1]
        set v [expr {$v | ((($byte >> ($bit & 7)) & 1) << $i)}]
    }
    return $v
}
proc zstd::rf {data name end n} {
    upvar 1 $name pos
    if {$n > $end - $pos} {error "Truncated FSE description"}
    set v [peek_fwd $data $pos $end $n]
    incr pos $n
    return $v
}
proc zstd::fse_desc {data start finish max_symbol max_log} {
    set pos [expr {$start * 8}]
    set end [expr {$finish * 8}]
    set log [expr {[rf $data pos $end 4] + 5}]
    if {$log > $max_log} {error "FSE accuracy log too large"}
    set threshold [expr {1 << $log}]
    set remaining [expr {$threshold + 1}]
    set width [expr {$log + 1}]
    set weights {}
    while {$remaining > 1} {
        if {[llength $weights] > $max_symbol} {error "Too many FSE symbols"}
        set maximum [expr {2 * $threshold - 1 - $remaining}]
        set short [expr {$width - 1}]
        if {[peek_fwd $data $pos $end $short] < $maximum} {
            set v [rf $data pos $end $short]
        } else {
            set v [rf $data pos $end $width]
            if {$v >= $threshold} {incr v -$maximum}
        }
        set w [expr {$v - 1}]
        lappend weights $w
        incr remaining [expr {-abs($w)}]
        if {$remaining < 1} {error "Invalid FSE probability"}
        if {!$w} {
            while 1 {
                set repeat [rf $data pos $end 2]
                lappend weights {*}[lrepeat $repeat 0]
                if {[llength $weights] > $max_symbol + 1} {error "Too many FSE symbols"}
                if {$repeat != 3} {break}
            }
        }
        while {$remaining < $threshold} {
            incr width -1
            set threshold [expr {$threshold >> 1}]
        }
    }
    list $weights $log [expr {($pos + 7) >> 3}]
}
proc zstd::fse_table {weights log} {
    set size [expr {1 << $log}]
    set high [expr {$size - 1}]
    set mask $high
    set step [expr {($size >> 1) + ($size >> 3) + 3}]
    set cells [lrepeat $size {}]
    set counts {}
    set sum 0
    set i 0
    foreach weight $weights {
        lappend counts [expr {abs($weight)}]
        incr sum [expr {abs($weight)}]
        if {$weight == -1} {
            lset cells $high $i
            incr high -1
        }
        incr i
    }
    if {$sum != $size} {error "Invalid FSE distribution"}
    set pos 0
    set i 0
    foreach weight $weights {
        for {set j 0} {$j < $weight} {incr j} {
            lset cells $pos $i
            while 1 {
                set pos [expr {($pos + $step) & $mask}]
                if {$pos <= $high} {break}
            }
        }
        incr i
    }
    if {$pos} {error "Invalid FSE spread"}
    set out {}
    foreach symbol $cells {
        set n [lindex $counts $symbol]
        lset counts $symbol [expr {$n + 1}]
        set width [expr {$log + 1 - [bw $n]}]
        lappend out [list $symbol $width [expr {($n << $width) - $size}]]
    }
    return $out
}
namespace eval zstd {
    variable predefined {}
    foreach weights [list \
        [concat {4 3} [lrepeat 11 2] [lrepeat 3 1] [lrepeat 9 2] {3 2} [lrepeat 5 1] [lrepeat 4 -1]] \
        [concat [lrepeat 6 1] [lrepeat 3 2] [lrepeat 15 1] [lrepeat 5 -1]] \
        [concat {1 4 3} [lrepeat 6 2] [lrepeat 37 1] [lrepeat 7 -1]]] log {6 5 6} {
        lappend predefined [list [fse_table $weights $log] $log]
    }
    unset weights log
}
proc zstd::huffman_desc {data pos limit} {
    set head [le $data $pos 1 $limit]
    incr pos
    set weights {}
    if {$head < 128} {
        set end [expr {$pos + $head}]
        if {$end > $limit} {error "Huffman description overruns block"}
        lassign [fse_desc $data $pos $end 255 6] probs log start
        set table [fse_table $probs $log]
        set bits [back $data $start $end]
        set states [list [rb $data $start bits $log] [rb $data $start bits $log]]
        if {$bits < 0} {error "Truncated Huffman initial states"}
        set turn 0
        while 1 {
            if {[llength $weights] >= 255} {error "Too many Huffman weights"}
            lassign [lindex $table [lindex $states $turn]] symbol width base
            lappend weights $symbol
            lset states $turn [expr {$base + [rb $data $start bits $width]}]
            set turn [expr {$turn ^ 1}]
            if {$bits < 0} {
                lappend weights [lindex $table [lindex $states $turn] 0]
                break
            }
        }
    } else {
        set count [expr {$head - 127}]
        set end [expr {$pos + (($count + 1) >> 1)}]
        if {$end > $limit} {error "Huffman description overruns block"}
        for {set i 0} {$i < $count} {incr i} {
            set b [le $data [expr {$pos + ($i >> 1)}] 1 $end]
            lappend weights [expr {$i & 1 ? $b & 15 : $b >> 4}]
        }
    }
    set sum 0
    foreach w $weights {
        if {$w > 11} {error "Invalid Huffman weight"}
        if {$w} {incr sum [expr {1 << ($w - 1)}]}
    }
    set width [bw $sum]
    if {!$width || $width > 11 || [llength $weights] > 255} {error "Invalid Huffman width"}
    set rest [expr {(1 << $width) - $sum}]
    if {$rest & ($rest - 1)} {error "Invalid implied Huffman weight"}
    lappend weights [bw $rest]
    set table {}
    for {set w 1} {$w <= $width} {incr w} {
        set symbol 0
        foreach weight $weights {
            if {$weight == $w} {
                lappend table {*}[lrepeat [expr {1 << ($w - 1)}] [list $symbol [expr {$width + 1 - $w}]]]
            }
            incr symbol
        }
    }
    list [list $table $width] $end
}
proc zstd::huffman_stream {data start finish tree count} {
    lassign $tree table width
    set bits [back $data $start $finish]
    set out {}
    for {set i 0} {$i < $count} {incr i} {
        lassign [lindex $table [peek_back $data $start $bits $width]] symbol drop
        lappend out $symbol
        incr bits -$drop
    }
    if {$bits} {error "Huffman bitstream not fully consumed"}
    binary format cu* $out
}
proc zstd::literals {data pos end frame_name cap} {
    upvar 1 $frame_name frame
    set first [le $data $pos 1 $end]
    set type [expr {$first & 3}]
    set format [expr {($first >> 2) & 3}]
    if {$type < 2} {
        set width [lindex {1 2 1 3} $format]
        set n [expr {[le $data $pos $width $end] >> ($width == 1 ? 3 : 4)}]
        incr pos $width
        if {$n > $cap} {error "Literal output exceeds block limit"}
        if {$type} {
            return [list [string repeat [binary format cu [le $data $pos 1 $end]] $n] [expr {$pos + 1}]]
        }
        if {$n > $end - $pos} {error "Raw literals overrun block"}
        return [list [string range $data $pos [expr {$pos + $n - 1}]] [expr {$pos + $n}]]
    }
    lassign [lindex {{3 10} {3 10} {4 14} {5 18}} $format] length width
    set header [le $data $pos $length $end]
    set mask [expr {(1 << $width) - 1}]
    set n [expr {($header >> 4) & $mask}]
    incr pos $length
    set finish [expr {$pos + (($header >> (4 + $width)) & $mask)}]
    if {$finish > $end || $n > $cap} {error "Invalid compressed literals size"}
    if {$type == 2} {
        lassign [huffman_desc $data $pos $finish] tree pos
        dict set frame tree $tree
    } elseif {[dict exists $frame tree]} {
        set tree [dict get $frame tree]
    } else {
        error "Missing previous Huffman table"
    }
    if {!$format} {return [list [huffman_stream $data $pos $finish $tree $n] $finish]}
    set sizes {}
    set sum 0
    for {set i 0} {$i < 3} {incr i} {
        set size [le $data $pos 2 $finish]
        lappend sizes $size
        incr sum $size
        incr pos 2
    }
    lappend sizes [expr {$finish - $pos - $sum}]
    set quarter [expr {($n + 3) >> 2}]
    set last [expr {$n - 3 * $quarter}]
    if {$last < 0} {error "Invalid Huffman stream lengths"}
    set out {}
    foreach size $sizes count [list $quarter $quarter $quarter $last] {
        if {$size <= 0} {error "Invalid Huffman stream size"}
        append out [huffman_stream $data $pos [expr {$pos + $size}] $tree $count]
        incr pos $size
    }
    list $out $finish
}
proc zstd::seq_table {data pos end mode i frame_name} {
    upvar 1 $frame_name frame
    variable predefined
    variable max_symbols
    variable max_logs
    set max [lindex $max_symbols $i]
    switch -- $mode {
        0 {set table [lindex $predefined $i]}
        1 {
            set symbol [le $data $pos 1 $end]
            incr pos
            if {$symbol > $max} {error "Invalid RLE sequence symbol"}
            set table [list [list [list $symbol 0 0]] 0]
        }
        2 {
            lassign [fse_desc $data $pos $end $max [lindex $max_logs $i]] probs log pos
            set table [list [fse_table $probs $log] $log]
        }
        3 {
            if {![dict exists $frame seq $i]} {error "Missing previous FSE table"}
            set table [dict get $frame seq $i]
        }
    }
    dict set frame seq $i $table
    list $table $pos
}
proc zstd::offset {v ll frame_name} {
    upvar 1 $frame_name frame
    set offsets [dict get $frame offsets]
    set i [expr {$v - 1 + !$ll}]
    if {$v > 3 || $i == 3} {
        set d [expr {$v > 3 ? $v - 3 : [lindex $offsets 0] - 1}]
        set offsets [lrange $offsets 0 1]
    } else {
        set d [lindex $offsets $i]
        set offsets [lreplace $offsets $i $i]
    }
    dict set frame offsets [linsert $offsets 0 $d]
    return $d
}
proc zstd::compressed {data pos end frame_name out_name start window cap} {
    upvar 1 $frame_name frame $out_name out
    variable ll_base
    variable ll_bits
    variable ml_base
    variable ml_bits
    lassign [literals $data $pos $end frame $cap] literal pos
    set count [le $data $pos 1 $end]
    incr pos
    if {!$count} {
        if {$pos != $end} {error "Trailing bytes after empty sequence section"}
        append out $literal
        return
    }
    if {$count == 255} {
        set count [expr {[le $data $pos 2 $end] + 0x7f00}]
        incr pos 2
    } elseif {$count >= 128} {
        set count [expr {(($count - 128) << 8) + [le $data $pos 1 $end]}]
        incr pos
    }
    if {!$count || $count * 3 > $cap} {error "Invalid sequence count"}
    set modes [le $data $pos 1 $end]
    incr pos
    if {$modes & 3} {error "Reserved sequence mode bits"}
    set tables {}
    for {set i 0} {$i < 3} {incr i} {
        lassign [seq_table $data $pos $end [expr {($modes >> (6 - 2 * $i)) & 3}] $i frame] table pos
        lappend tables $table
    }
    set bits [back $data $pos $end]
    set states {}
    foreach table $tables {lappend states [rb $data $pos bits [lindex $table 1]]}
    set lit 0
    set max_end [expr {[string length $out] + $cap}]
    for {set i 1} {$i <= $count} {incr i} {
        lassign [lindex $tables 0 0 [lindex $states 0]] ll ll_width ll_start
        lassign [lindex $tables 1 0 [lindex $states 1]] of of_width of_start
        lassign [lindex $tables 2 0 [lindex $states 2]] ml ml_width ml_start
        set v [expr {(1 << $of) + [rb $data $pos bits $of]}]
        set match [expr {[lindex $ml_base $ml] + [rb $data $pos bits [lindex $ml_bits $ml]]}]
        set n [expr {[lindex $ll_base $ll] + [rb $data $pos bits [lindex $ll_bits $ll]]}]
        if {$bits < 0 || $lit + $n > [string length $literal] || [string length $out] + $n + $match > $max_end} {
            error "Invalid sequence length"
        }
        append out [string range $literal $lit [expr {$lit + $n - 1}]]
        incr lit $n
        set d [offset $v $n frame]
        set len [string length $out]
        if {$d <= 0 || $d > $window || $d > $len - $start} {error "Invalid match offset"}
        set from [expr {$len - $d}]
        if {$match <= $d} {
            append out [string range $out $from [expr {$from + $match - 1}]]
        } else {
            set pattern [string range $out $from end]
            append out [string repeat $pattern [expr {$match / $d}]] \
                [string range $pattern 0 [expr {$match % $d - 1}]]
        }
        if {$i < $count} {
            lset states 0 [expr {$ll_start + [rb $data $pos bits $ll_width]}]
            lset states 2 [expr {$ml_start + [rb $data $pos bits $ml_width]}]
            lset states 1 [expr {$of_start + [rb $data $pos bits $of_width]}]
        }
    }
    if {$bits || [string length $out] + [string length $literal] - $lit > $max_end} {
        error "Invalid trailing literals"
    }
    append out [string range $literal $lit end]
}
proc zstd::rotl {v n} {
    variable mask
    expr {(($v << $n) | ($v >> (64 - $n))) & $mask}
}
proc zstd::round {acc lane} {
    variable mask
    variable p1
    variable p2
    expr {([rotl [expr {($acc + $lane * $p2) & $mask}] 31] * $p1) & $mask}
}
proc zstd::xxh64 {data start} {
    variable mask
    variable p1
    variable p2
    variable p3
    variable p4
    variable p5
    set end [string length $data]
    set pos $start
    set h $p5
    if {$end - $start >= 32} {
        set acc [list [expr {($p1 + $p2) & $mask}] $p2 0 [expr {-$p1 & $mask}]]
        while {$pos + 32 <= $end} {
            for {set i 0} {$i < 4} {incr i} {
                lset acc $i [round [lindex $acc $i] [le $data [expr {$pos + 8 * $i}] 8]]
            }
            incr pos 32
        }
        set h 0
        foreach v $acc n {1 7 12 18} {set h [expr {($h + [rotl $v $n]) & $mask}]}
        foreach v $acc {set h [expr {(($h ^ [round 0 $v]) * $p1 + $p4) & $mask}]}
    }
    set h [expr {($h + $end - $start) & $mask}]
    while {$pos + 8 <= $end} {
        set h [expr {([rotl [expr {$h ^ [round 0 [le $data $pos 8]]}] 27] * $p1 + $p4) & $mask}]
        incr pos 8
    }
    if {$pos + 4 <= $end} {
        set lane [expr {([le $data $pos 4] * $p1) & $mask}]
        set h [expr {([rotl [expr {$h ^ $lane}] 23] * $p2 + $p3) & $mask}]
        incr pos 4
    }
    while {$pos < $end} {
        set lane [expr {([le $data $pos 1] * $p5) & $mask}]
        set h [expr {([rotl [expr {$h ^ $lane}] 11] * $p1) & $mask}]
        incr pos
    }
    set h [expr {(($h ^ ($h >> 33)) * $p2) & $mask}]
    set h [expr {(($h ^ ($h >> 29)) * $p3) & $mask}]
    expr {$h ^ ($h >> 32)}
}
proc zstd::decompress {data} {
    variable cap
    set pos 0
    set out {}
    set end [string length $data]
    while {$pos < $end} {
        set magic [le $data $pos 4 $end]
        incr pos 4
        if {($magic & 0xfffffff0) == 0x184d2a50} {
            incr pos [expr {4 + [le $data $pos 4 $end]}]
            if {$pos > $end} {error "Truncated skippable frame"}
            continue
        }
        if {$magic != 0xfd2fb528} {error "Unknown Zstd frame magic"}
        set desc [le $data $pos 1 $end]
        incr pos
        if {$desc & 8} {error "Reserved frame header bit"}
        set single [expr {$desc & 32}]
        if {!$single} {
            set wd [le $data $pos 1 $end]
            incr pos
            set base [expr {1 << (10 + ($wd >> 3))}]
            set window [expr {$base + ($base >> 3) * ($wd & 7)}]
        }
        set dict [lindex {0 1 2 4} [expr {$desc & 3}]]
        if {[le $data $pos $dict $end]} {error "Zstd dictionaries unsupported"}
        incr pos $dict
        set n [lindex [list [expr {$single ? 1 : 0}] 2 4 8] [expr {$desc >> 6}]]
        set size -1
        if {$n} {
            set size [expr {[le $data $pos $n $end] + ($n == 2 ? 256 : 0)}]
            incr pos $n
            if {$size > $cap - [string length $out]} {error "Decompressed size limit exceeded"}
        }
        if {$single} {set window $size}
        set max [expr {min($window, 128 << 10)}]
        set start [string length $out]
        set frame [dict create offsets {1 4 8}]
        while 1 {
            set head [le $data $pos 3 $end]
            incr pos 3
            set type [expr {($head >> 1) & 3}]
            set count [expr {$head >> 3}]
            set finish [expr {$pos + ($type == 1 ? 1 : $count)}]
            if {$type == 3 || $count > $max || $finish > $end} {error "Invalid Zstd block"}
            set limit [expr {min($max, $cap - [string length $out])}]
            if {$size >= 0} {set limit [expr {min($limit, $size - ([string length $out] - $start))}]}
            if {$type == 2} {
                compressed $data $pos $finish frame out $start $window $limit
            } else {
                if {$count > $limit} {error "Zstd block output exceeds limit"}
                if {$type == 1} {
                    append out [string repeat [string index $data $pos] $count]
                } else {
                    append out [string range $data $pos [expr {$finish - 1}]]
                }
            }
            set pos $finish
            if {$head & 1} {break}
        }
        if {$size >= 0 && [string length $out] - $start != $size} {error "Frame content size mismatch"}
        if {$desc & 4} {
            if {([xxh64 $out $start] & 0xffffffff) != [le $data $pos 4 $end]} {error "Content checksum mismatch"}
            incr pos 4
        }
    }
    return $out
}
