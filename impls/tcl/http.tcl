# Nonblocking channels and coroutines let health checks run during Range I/O.
set ::body_limit [expr {1 << 20}]
set ::slice_limit [expr {128 << 20}]
set ::clients 0
set ::sequence 0
set ::upstream 0
proc rpc_fail {code message} {return -code error -errorcode [list RPC $code] $message}
proc transport_fail {message} {return -code error -errorcode {TRANSPORT} $message}
proc await_io {channel event deadline} {
    set remaining [expr {$deadline - [clock milliseconds]}]
    if {$remaining <= 0} {transport_fail "HTTP deadline exceeded"}
    set self [info coroutine]
    fileevent $channel $event [list $self ready]
    set timer [after $remaining [list $self timeout]]
    try {
        set result [yield]
    } finally {
        after cancel $timer
        fileevent $channel $event {}
    }
    if {$result eq "timeout"} {transport_fail "HTTP deadline exceeded"}
}
proc pause {ms} {
    if {$ms <= 0} {return}
    after $ms [list [info coroutine] ready]
    yield
}
proc http_fill {name size} {
    upvar 1 $name r
    lassign $r channel buffer deadline
    while 1 {
        if {[clock milliseconds] >= $deadline} {transport_fail "HTTP deadline exceeded"}
        if {[catch {read $channel $size} data]} {transport_fail "HTTP read failed"}
        if {$data ne ""} {
            lset r 1 $buffer$data
            return 1
        }
        if {[eof $channel]} {return 0}
        await_io $channel readable $deadline
    }
}
proc http_line {name} {
    upvar 1 $name r
    while 1 {
        set buf [lindex $r 1]
        set end [string first "\r\n" $buf]
        if {$end > 8192 || ($end < 0 && [string length $buf] > 8193)} {error "HTTP line too long"}
        if {$end >= 0} {
            lset r 1 [string range $buf [expr {$end + 2}] end]
            return [string range $buf 0 [expr {$end - 1}]]
        }
        if {![http_fill r 4096]} {transport_fail "Incomplete HTTP line"}
    }
}
proc http_headers {name} {
    upvar 1 $name r
    set headers {}
    set size 0
    while {[set line [http_line r]] ne ""} {
        incr size [expr {2 + [string length $line]}]
        if {$size > 65536} {error "HTTP headers too large"}
        if {![regexp {\A([!#$%&'*+.^_\x60|~A-Za-z0-9-]+):[ \t]*(.*?)[ \t]*\Z} $line -> key val]} {
            error "Invalid HTTP header"
        }
        dict lappend headers [string tolower $key] $val
    }
    return $headers
}
proc http_take {name n} {
    upvar 1 $name r
    # Accumulate in a local variable so append retains an unshared Tcl object.
    set data {}
    while {$n} {
        set buf [lindex $r 1]
        set have [string length $buf]
        if {!$have} {
            if {![http_fill r [expr {min(65536, $n)}]]} {transport_fail "Incomplete HTTP body"}
            continue
        }
        if {$have <= $n} {
            append data $buf
            lset r 1 {}
            incr n -$have
        } else {
            append data [string range $buf 0 [expr {$n - 1}]]
            lset r 1 [string range $buf $n end]
            break
        }
    }
    return $data
}
proc bounded_number {text cap radix} {
    if {$radix == 10} {
        if {![regexp {\A[0-9]+\Z} $text]} {error "Invalid HTTP Content-Length"}
        set mode %d
    } else {
        if {![regexp {\A[0-9a-fA-F]+\Z} $text]} {error "Invalid HTTP chunk size"}
        set mode %x
    }
    set text [string trimleft $text 0]
    if {$text eq ""} {return 0}
    if {[string length $text] > 9} {return [expr {$cap + 1}]}
    scan $text $mode
}
proc http_body {name headers cap allow_eof dechunked} {
    upvar 1 $name r
    set te [fetch $headers transfer-encoding]
    set cl [fetch $headers content-length]
    set data {}
    if {$te ne "" && !$dechunked} {
        if {[llength $te] != 1 || [string tolower [lindex $te 0]] ne "chunked" || $cl ne ""} {
            error "Invalid HTTP transfer encoding"
        }
        while 1 {
            set line [http_line r]
            set count [lindex [split $line ";"] 0]
            set n [bounded_number $count $cap 16]
            if {!$n} {
                http_headers r
                break
            }
            if {$n > $cap - [string length $data]} {rpc_fail 413 "HTTP body exceeds limit"}
            append data [http_take r $n]
            if {[http_take r 2] ne "\r\n"} {error "Invalid HTTP chunk ending"}
        }
    } elseif {$cl ne ""} {
        if {[llength $cl] != 1} {error "Invalid HTTP Content-Length"}
        set n [bounded_number [lindex $cl 0] $cap 10]
        if {$n > $cap} {rpc_fail 413 "HTTP body exceeds limit"}
        set data [http_take r $n]
    } elseif {$allow_eof} {
        while 1 {
            append data [lindex $r 1]
            lset r 1 {}
            if {[string length $data] > $cap} {rpc_fail 413 "HTTP body exceeds limit"}
            if {![http_fill r [expr {min(65536, $cap + 1 - [string length $data])}]]} {break}
        }
    }
    return $data
}
proc archive_attempt {path range cap} {
    lassign $::origin scheme authority host port
    set deadline [expr {[clock milliseconds] + 60000}]
    set curl [expr {$scheme eq "https"}]
    if {$curl} {
        set command [list | /usr/bin/curl -q -s -i --globoff --suppress-connect-headers --connect-timeout 10 --max-time 60 \
            -A onlyblocks/tcl -H "Range: bytes=$range" -H "Accept-Encoding: identity" -- "https://$authority$path"]
        if {[catch {open $command r} channel]} {transport_fail "Unable to start TLS transport"}
    } else {
        if {[catch {socket -async $host $port} channel]} {transport_fail "Unable to connect to archive"}
    }
    try {
        fconfigure $channel -blocking 0 -translation binary -buffering none
        if {!$curl} {
            await_io $channel writable [expr {min($deadline, [clock milliseconds] + 10000)}]
            if {[fconfigure $channel -error] ne ""} {transport_fail "Unable to connect to archive"}
            set request "GET $path HTTP/1.1\r\nHost: $authority\r\nRange: bytes=$range\r\n"
            append request "Connection: close\r\nUser-Agent: onlyblocks/tcl\r\nAccept-Encoding: identity\r\n\r\n"
            if {[catch {puts -nonewline $channel $request}]} {transport_fail "Unable to write archive request"}
        }
        set r [list $channel {} $deadline]
        while 1 {
            if {![regexp {\AHTTP/[0-9](?:\.[0-9])? ([1-5][0-9][0-9])(?: |\Z)} [http_line r] -> status]} {
                error "Invalid upstream HTTP status"
            }
            set headers [http_headers r]
            if {$status == 101 || $status >= 200} {break}
        }
        if {$status != 206} {return [list $status [lindex [fetch $headers retry-after] 0]]}
        set data [http_body r $headers $cap 1 $curl]
        return [list $status $data]
    } finally {
        catch {close $channel}
    }
}
proc retry_ms {header attempt} {
    if {[regexp {\A[0-9]+\Z} $header]} {
        return [expr {1000 * min(10, [bounded_number $header 10 10])}]
    }
    if {$header ne "" && ![catch {clock scan $header -format {%a, %d %b %Y %H:%M:%S GMT} -gmt 1} date]} {
        return [expr {1000 * max(0, min(10, $date - [clock seconds]))}]
    }
    expr {int(200 * (1 << $attempt) * (0.5 + rand() * 0.5))}
}
proc read_range {slot suffix start size cap} {
    set end [expr {$start + $size - 1}]
    if {$end > $::u64max} {error "Range overflows u64"}
    set epoch [expr {$slot / 432000}]
    set path "$::origin_prefix/$epoch/epoch-$epoch$suffix"
    for {set retry 0} {$retry < 5} {incr retry} {
        while {$::upstream >= 32} {pause 10}
        incr ::upstream
        try {
            set failed [catch {archive_attempt $path "$start-$end" $cap} result opts]
        } finally {
            incr ::upstream -1
        }
        set retry_after {}
        if {$failed} {
            if {[dict get $opts -errorcode] ne "TRANSPORT"} {return -options $opts $result}
        } else {
            lassign $result status retry_after
            if {$status == 404} {rpc_fail -32004 "Block not available for slot $slot"}
            if {$status == 206} {
                if {[string length $retry_after] != $size} {error "Archive range body has wrong length"}
                return $retry_after
            }
            if {$status != 429 && $status < 500} {error "Unexpected archive HTTP status $status"}
        }
        if {$retry < 4} {pause [retry_ms $retry_after $retry]}
    }
    error "Archive retries exhausted"
}
proc serve_client {channel} {
    try {
        fconfigure $channel -blocking 0 -translation binary -buffering none
        set code "400 Bad Request"
        set data {}
        set r [list $channel {} [expr {[clock milliseconds] + 10000}]]
        try {
            if {![regexp {\A([A-Z]+) ([^ \t]+) HTTP/1\.[01]\Z} [http_line r] -> method path]} {
                error "Invalid request line"
            }
            if {$method ne "POST" || $path ne "/"} {
                set code "404 Not Found"
            } else {
                set raw [http_body r [http_headers r] $::body_limit 0 0]
                set code "200 OK"
                set data [encoding convertto utf-8 [json_encode [rpc $raw]]]
            }
        } trap {TRANSPORT} {} {
            return
        } trap {RPC 413} {} {
            set code "413 Payload Too Large"
        } on error {message opts} {
            if {[info exists ::env(ONLYBLOCKS_DEBUG)]} {puts stderr [dict get $opts -errorinfo]}
            set code "400 Bad Request"
        }
        set head "HTTP/1.1 $code\r\nConnection: close\r\nContent-Length: [string length $data]\r\n"
        if {$code eq "200 OK"} {append head "Content-Type: application/json\r\n"}
        puts -nonewline $channel $head\r\n$data
        set deadline [expr {[clock milliseconds] + 10000}]
        while {[chan pending output $channel] > 0} {await_io $channel writable $deadline}
    } on error {} {
        # A disconnect is local to this client.
    } finally {
        catch {close $channel}
        incr ::clients -1
    }
}
proc accept_client {channel address port} {
    if {$::clients >= 128} {
        close $channel
        return
    }
    incr ::clients
    coroutine ::http[incr ::sequence] serve_client $channel
}
