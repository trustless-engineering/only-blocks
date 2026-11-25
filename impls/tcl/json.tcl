# Tagged JSON values separate strings, number lexemes, booleans and arrays.
proc js {v} {list s $v}
proc jn {v} {
    if {$v eq ""} {return {}}
    list n $v
}
proc ja {v} {list a $v}
proc jo {v} {list o $v}
proc jb {v} {list t $v}
proc jarray {converter values} {
    set out {}
    foreach v $values {lappend out [{*}$converter $v]}
    ja $out
}
proc json_quote {s} {
    set escaped [string map [list \\ \\\\ \" \\\" \b \\b \f \\f \n \\n \r \\r \t \\t] $s]
    if {[regexp {[\x00-\x1f]} $escaped]} {
        set result {}
        foreach c [split $escaped {}] {
            scan $c %c n
            if {$n < 32} {append result [format {\u%04x} $n]} else {append result $c}
        }
        set escaped $result
    }
    return \"$escaped\"
}
proc json_encode {node} {
    lassign $node tag v
    switch -- $tag {
        s {return [json_quote $v]}
        n {return $v}
        t {return [expr {$v ? "true" : "false"}]}
        a {
            set parts {}
            foreach item $v {lappend parts [json_encode $item]}
            return \[[join $parts ,]\]
        }
        o {
            set parts {}
            dict for {key item} $v {lappend parts "[json_quote $key]:[json_encode $item]"}
            return \{[join $parts ,]\}
        }
        {} {return null}
        default {error "Invalid JSON node type"}
    }
}
proc jspace {s name} {
    upvar 1 $name p
    if {[regexp -indices -start $p -- {\A[ \t\r\n]+} $s run]} {set p [expr {[lindex $run 1] + 1}]}
}
proc jstring {s name} {
    upvar 1 $name p
    if {[string index $s $p] ne "\""} {error "Expected JSON string"}
    incr p
    set out {}
    while {$p < [string length $s]} {
        if {[regexp -indices -start $p -- {\A[^"\\\x00-\x1f]+} $s run]} {
            append out [string range $s {*}$run]
            set p [expr {[lindex $run 1] + 1}]
        }
        set c [string index $s $p]
        incr p
        if {$c eq "\""} {return $out}
        if {$c ne "\\"} {error "Invalid JSON string"}
        set esc [string index $s $p]
        incr p
        switch -- $esc {
            "\"" - "\\" - "/" {append out $esc}
            b {append out \b}
            f {append out \f}
            n {append out \n}
            r {append out \r}
            t {append out \t}
            u {
                set hex [string range $s $p [expr {$p + 3}]]
                if {![regexp {\A[0-9a-fA-F]{4}\Z} $hex]} {error "Invalid JSON Unicode escape"}
                scan $hex %x cp
                incr p 4
                if {$cp >= 0xd800 && $cp <= 0xdbff} {
                    if {![regexp -indices -start $p -- {\A\\u[dD][c-fC-F][0-9a-fA-F]{2}} $s tail]} {
                        error "Missing low surrogate"
                    }
                    scan [string range $s [expr {$p + 2}] [lindex $tail 1]] %x low
                    set cp [expr {0x10000 + (($cp - 0xd800) << 10) + ($low - 0xdc00)}]
                    incr p 6
                } elseif {$cp >= 0xdc00 && $cp <= 0xdfff} {
                    error "Unexpected low surrogate"
                }
                append out [format %c $cp]
            }
            default {error "Invalid JSON escape"}
        }
    }
    error "Unterminated JSON string"
}
proc jread {s name depth} {
    upvar 1 $name p
    if {$depth > 128} {error "JSON nesting limit"}
    jspace $s p
    set c [string index $s $p]
    if {$c eq "\""} {return [js [jstring $s p]]}
    if {$c eq "\{" || $c eq "\["} {
        set object [expr {$c eq "\{"}]
        set close [expr {$object ? "\}" : "\]"}]
        set out {}
        incr p
        incr depth
        jspace $s p
        if {[string index $s $p] eq $close} {
            incr p
            return [list [expr {$object ? "o" : "a"}] $out]
        }
        while 1 {
            jspace $s p
            if {$object} {
                set key [jstring $s p]
                jspace $s p
                if {[string index $s $p] ne ":"} {error "Missing JSON colon"}
                incr p
                dict set out $key [jread $s p $depth]
            } else {
                lappend out [jread $s p $depth]
            }
            jspace $s p
            set delimiter [string index $s $p]
            incr p
            if {$delimiter eq $close} {return [list [expr {$object ? "o" : "a"}] $out]}
            if {$delimiter ne ","} {error "Missing JSON comma"}
        }
    }
    foreach {token val} {null {} true {t 1} false {t 0}} {
        if {[string range $s $p [expr {$p + [string length $token] - 1}]] eq $token} {
            incr p [string length $token]
            return $val
        }
    }
    if {[regexp -indices -start $p -- {\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?} $s run]} {
        set p [expr {[lindex $run 1] + 1}]
        return [jn [string range $s {*}$run]]
    }
    error "Invalid JSON value"
}
proc json_parse {bytes} {
    set text [utext $bytes]
    set p 0
    set val [jread $text p 0]
    jspace $text p
    if {$p != [string length $text]} {error "Trailing JSON text"}
    return $val
}
