use strict;
use warnings;
no warnings 'recursion';
use IO::Socket::INET;
use JSON::PP ();
use POSIX qw(mktime);
use Time::HiRes qw(sleep alarm);
use Wire;
use Metadata;

use constant MAX_BODY => 1 << 20;
use constant MAX_SLICE => 128 << 20;
my $json = JSON::PP->new->utf8->allow_nonref;
my $bind = $ENV{ONLYBLOCKS_BIND} // '127.0.0.1:8899';
my $base = $ENV{OLD_FAITHFUL_BASE_URL} // 'https://files.old-faithful.net';
while (@ARGV) {
    my $arg = shift @ARGV;
    my ($name, $value) = $arg =~ /\A--(bind|base-url)(?:=(.*))?\z/s;
    die "Unknown option $arg\n" unless defined $name;
    $value //= shift @ARGV;
    die "Missing value for --$name\n" unless defined $value;
    if ($name eq 'bind') { $bind = $value } else { $base = $value }
}
$base =~ s/\A\s+|\s+\z//g;
$base =~ s{/+\z}{};
my ($scheme, $authority, $origin_host, $origin_port, $prefix) =
    $base =~ m{\A(https?)://(([A-Za-z0-9._-]+)(?::([0-9]+))?)(/[^\x00-\x20\x7f?#]*)?\z};
die "Invalid archive base URL\n" unless defined $scheme;
$origin_port //= $scheme eq 'https' ? 443 : 80;
die "Invalid archive port\n" unless $origin_port && $origin_port <= 65535;
$prefix //= '';
my ($host, $port) = $bind =~ /\A([^:]+):([0-9]+)\z/;
die "Invalid bind address\n" unless defined($host) && $port <= 65535;

my @reserved = qw(
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
);
my %reserved = map { $_ => 1 } @reserved;
sub bool { $_[0] ? JSON::PP::true : JSON::PP::false }
sub tx_json {
    my ($tx, $m, $encoding, $details, $rewards, $max) = @_;
    my ($version, $signatures, $message, $raw) = @$tx;
    my $v0 = $version eq '0';
    if ($v0) {
        rpc_fail(-32015, 'Transaction version (0) requires maxSupportedTransactionVersion') unless defined $max;
        $m //= empty_meta();
    }
    my $accounts = $details eq 'accounts';
    my $parsed = $encoding eq 'jsonParsed';
    my $keys;
    my $out;
    if ($encoding eq 'base64' || $encoding eq 'base58') {
        $out = [$encoding eq 'base64' ? b64($raw) : base58($raw), $encoding];
    } else {
        my @static = @{$message->{accountKeys}};
        my $display = \@static;
        if ($accounts || $parsed) {
            my $loaded = $v0 ? $m->{loadedAddresses} : {writable => [], readonly => []};
            $keys = [@static, @{$loaded->{writable}}, @{$loaded->{readonly}}];
            my $header = $message->{header};
            my $signers = $header->{numRequiredSignatures};
            my %program = map { $_->{programIdIndex} => 1 } @{$message->{instructions}};
            my $upgrade = grep { $_ eq 'BPFLoaderUpgradeab1e11111111111111111111111' } @$keys;
            $display = [map {
                my $i = $_;
                my $key = $keys->[$i];
                my $lookup = $i >= @static;
                my $writable = $lookup ? $i - @static < @{$loaded->{writable}}
                    : $i < $signers ? $i < $signers - $header->{numReadonlySignedAccounts}
                    : $i < @static - $header->{numReadonlyUnsignedAccounts};
                {pubkey => $key, signer => bool($i < $signers),
                 writable => bool($writable && !$reserved{$key} && ($upgrade || !$program{$i})),
                 source => $lookup ? 'lookupTable' : 'transaction'};
            } 0 .. $#$keys];
        }
        $out = {signatures => [map { base58($_) } @$signatures]};
        if ($accounts) {
            $out->{accountKeys} = $display;
        } else {
            $message->{accountKeys} = $display;
            $message->{instructions} = [map { ix_json($_, $keys) } @{$message->{instructions}}];
            delete $message->{header} if $parsed;
            $out->{message} = $message;
        }
    }
    if ($m) {
        $m->{status} = defined $m->{err} ? {Err => $m->{err}} : {Ok => undef};
        $m->{rewards} = undef unless $rewards;
        if ($accounts) {
            delete @$m{qw(innerInstructions logMessages loadedAddresses returnData computeUnitsConsumed costUnits)};
            delete $m->{rewards} unless $rewards;
        } else {
            delete $m->{loadedAddresses} if $parsed;
            for my $group (@{$m->{innerInstructions} // []}) {
                $group->{instructions} = [map { ix_json($_, $keys) } @{$group->{instructions}}];
            }
        }
    }
    my $result = {transaction => $out, meta => $m};
    $result->{version} = $version if $m && defined $max;
    return $result;
}
sub ix_json {
    my ($ix, $keys) = @_;
    my @accounts = unpack 'C*', $ix->{accounts};
    my $result = {data => base58($ix->{data}), stackHeight => $ix->{stackHeight}};
    if ($keys) {
        die "Instruction account index out of range\n" if grep { $_ > $#$keys } $ix->{programIdIndex}, @accounts;
        $result->{programId} = $keys->[$ix->{programIdIndex}];
        $result->{accounts} = [@$keys[@accounts]];
    } else {
        $result->{programIdIndex} = $ix->{programIdIndex};
        $result->{accounts} = \@accounts;
    }
    return $result;
}

# The endpoints are keys, and each node stores its two neighboring keys.
my ($ranges, $hashes) = ({entries=>{}}, {entries=>{}});
sub detach {
    my ($lru, $node) = @_;
    my ($prev, $next) = @$node[1, 2];
    if (defined $prev) { $lru->{entries}{$prev}[2] = $next } else { $lru->{oldest} = $next }
    if (defined $next) { $lru->{entries}{$next}[1] = $prev } else { $lru->{newest} = $prev }
}
sub cache_put {
    my ($lru, $key, $value) = @_;
    my $entries = $lru->{entries};
    detach($lru, $entries->{$key}) if exists $entries->{$key};
    my $tail = $lru->{newest};
    $entries->{$key} = [$value, $tail, undef];
    if (defined $tail) { $entries->{$tail}[2] = $key } else { $lru->{oldest} = $key }
    $lru->{newest} = $key;
    if (keys(%$entries) > 100000) {
        my $oldest = $lru->{oldest};
        detach($lru, delete $entries->{$oldest});
    }
    return $value;
}
sub cache_get {
    my ($lru, $key) = @_;
    return undef unless exists $lru->{entries}{$key};
    return cache_put($lru, $key, $lru->{entries}{$key}[0]);
}
sub rpc_fail { die bless([@_], 'OnlyBlocks::Error') }
sub transport_fail { die bless([@_], 'OnlyBlocks::Transport') }

# A shared bounded HTTP reader consumes socket or curl pipe input.
sub fill {
    my ($r, $max) = @_;
    my $n = sysread($r->[0], my $part, $max);
    transport_fail('HTTP read failed') unless defined $n;
    $r->[1] .= $part if $n;
    return $n;
}
sub http_line {
    my ($r) = @_;
    while (1) {
        my $end = index($r->[1], "\r\n");
        die "HTTP line too long\n" if $end > 8192 || ($end < 0 && length($r->[1]) > 8193);
        return substr(substr($r->[1], 0, $end + 2, ''), 0, $end) if $end >= 0;
        transport_fail('Incomplete HTTP line') unless fill($r, 4096);
    }
}
sub headers {
    my ($r) = @_;
    my %h;
    my $size = 0;
    while (length(my $line = http_line($r))) {
        $size += length($line) + 2;
        die "HTTP headers too large\n" if $size > 65536;
        my ($name, $value) = $line =~ /\A([!#\$%&'*+.^_\x60|~A-Za-z0-9-]+):[ \t]*(.*?)[ \t]*\z/;
        die "Invalid HTTP header\n" unless defined $name;
        push @{$h{lc $name}}, $value;
    }
    return \%h;
}
sub exactly {
    my ($r, $size) = @_;
    while (length($r->[1]) < $size) {
        my $remaining = $size - length($r->[1]);
        transport_fail('Incomplete HTTP body') unless fill($r, $remaining < 65536 ? $remaining : 65536);
    }
    return substr($r->[1], 0, $size, '');
}
sub bounded_number {
    my ($s, $cap, $hex) = @_;
    die "Invalid HTTP length\n" unless $s =~ ($hex ? qr/\A[0-9a-fA-F]+\z/ : qr/\A[0-9]+\z/);
    $s =~ s/\A0+//;
    return $cap + 1 if length($s) > 9;
    return $hex ? hex($s || '0') : 0 + ($s || '0');
}
sub body {
    my ($r, $h, $cap, $eof, $curl) = @_;
    my $data = '';
    my $te = $h->{'transfer-encoding'};
    my $cl = $h->{'content-length'};
    if ($te && !$curl) {
        die "Invalid HTTP transfer encoding\n" if @$te != 1 || lc($te->[0]) ne 'chunked' || $cl;
        while (1) {
            my ($count) = split /;/, http_line($r), 2;
            my $n = bounded_number($count // '', $cap, 1);
            if (!$n) {
                headers($r);
                last;
            }
            rpc_fail(413, 'HTTP body exceeds limit') if $n > $cap - length($data);
            $data .= exactly($r, $n);
            die "Invalid HTTP chunk ending\n" unless exactly($r, 2) eq "\r\n";
        }
    } elsif ($cl) {
        die "Invalid HTTP Content-Length\n" if @$cl != 1;
        my $n = bounded_number($cl->[0], $cap, 0);
        rpc_fail(413, 'HTTP body exceeds limit') if $n > $cap;
        $data = exactly($r, $n);
    } elsif ($eof) {
        while (length($r->[1]) <= $cap) {
            my $n = $cap + 1 - length($r->[1]);
            last unless fill($r, $n < 65536 ? $n : 65536);
        }
        rpc_fail(413, 'HTTP body exceeds limit') if length($r->[1]) > $cap;
        $data = $r->[1];
    }
    return $data;
}
sub attempt {
    my ($path, $range, $cap) = @_;
    my $fh;
    my $curl = $scheme eq 'https';
    if ($curl) {
        open($fh, '-|', '/usr/bin/curl', '-q', '-sS', '-i', '--globoff', '--suppress-connect-headers',
             '--connect-timeout', '10', '--max-time', '60', '-A', 'onlyblocks/perl',
             '-H', "Range: bytes=$range", '-H', 'Accept-Encoding: identity', '--', "https://$authority$path")
            or transport_fail('Unable to start TLS transport');
    } else {
        $fh = IO::Socket::INET->new(PeerHost=>$origin_host, PeerPort=>$origin_port, Timeout=>10)
            or transport_fail('Unable to connect to archive');
        print {$fh} "GET $path HTTP/1.1\r\nHost: $authority\r\nRange: bytes=$range\r\n"
            . "Connection: close\r\nUser-Agent: onlyblocks/perl\r\nAccept-Encoding: identity\r\n\r\n"
            or transport_fail('Unable to write upstream request');
    }
    my $r = [$fh, ''];
    my ($status, $h);
    do {
        my $line = http_line($r);
        ($status) = $line =~ m{\AHTTP/\d(?:\.\d)? ([1-5][0-9][0-9])(?: |\z)};
        die "Invalid upstream HTTP status\n" unless defined $status;
        $h = headers($r);
    } while ($status >= 100 && $status < 200 && $status != 101);
    return ($status, $h->{'retry-after'} // []) if $status != 206;
    my $data = body($r, $h, $cap, 1, $curl);
    close($fh) or transport_fail('HTTPS transport failed') if $curl;
    return ($status, $data);
}
sub retry_delay {
    my ($h, $attempt) = @_;
    if (defined $h) {
        if ($h =~ /\A[0-9]+\z/) {
            my $n = bounded_number($h, 10, 0);
            return $n > 10 ? 10 : $n;
        }
        my ($day, $month, $year, $hour, $minute, $sec) =
            $h =~ /\A[A-Za-z]{3}, ([0-9]{2}) ([A-Za-z]{3}) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT\z/;
        my %month;
        @month{qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)} = 0..11;
        if (defined $month && exists $month{$month} && $day >= 1 && $day <= 31
            && $hour < 24 && $minute < 60 && $sec <= 60) {
            my $date;
            {
                local $ENV{TZ} = 'UTC';
                POSIX::tzset();
                $date = mktime($sec, $minute, $hour, $day, $month{$month}, $year - 1900);
            }
            POSIX::tzset();
            my $seconds = $date - time;
            return $seconds < 0 ? 0 : $seconds > 10 ? 10 : $seconds;
        }
    }
    return 0.2 * (1 << $attempt) * (0.5 + rand(0.5));
}
sub epoch {
    # Halve the unsigned numerator before using exact signed division.
    my $half = $_[0] >> 1;
    use integer;
    return $half / 216000;
}
sub read_range {
    my ($slot, $suffix, $start, $size, $cap) = @_;
    die "Range overflows u64\n" if $start > U64 - ($size - 1);
    my $end = $start + ($size - 1);
    my $epoch = epoch($slot);
    my $path = "$prefix/$epoch/epoch-$epoch$suffix";
    for my $retry (0..4) {
        my ($status, $value);
        {
            local $SIG{ALRM} = sub { transport_fail('Archive request timed out') };
            my $ok = eval { alarm(60); ($status, $value) = attempt($path, "$start-$end", $cap); 1 };
            my $failure = $@;
            alarm(0);
            die $failure if !$ok && ref($failure) ne 'OnlyBlocks::Transport';
        }
        if (defined $status) {
            rpc_fail(-32004, "Block not available for slot $slot") if $status == 404;
            if ($status == 206) {
                die "Archive range body has wrong length\n" if length($value) != $size;
                return $value;
            }
            die "Unexpected archive HTTP status $status\n" if $status != 429 && $status < 500;
        }
        sleep(retry_delay(defined($status) ? $value->[0] : undef, $retry)) if $retry < 4;
    }
    die "Archive retries exhausted\n";
}
sub load_block {
    my ($slot) = @_;
    my $record = cache_get($ranges, $slot);
    if (!$record) {
        my $raw = read_range($slot, '-slot-ranges.raw', ($slot % 432000) * 12, 12, 12);
        $record = cache_put($ranges, $slot, [unpack 'Q<V', $raw]);
    }
    my ($offset, $length) = @$record;
    rpc_fail(-32007, "Slot $slot was skipped") unless $length;
    die "CAR slice exceeds 128 MiB\n" if $length > MAX_SLICE;
    return index_car(read_range($slot, '.car', $offset, $length, MAX_SLICE));
}
sub block_hash {
    my ($slot, $index, $entries) = @_;
    return cache_put($hashes, $slot, @$entries ? pubkey(bytes(indexed($index, $entries->[-1], 1)->[2])) : ZERO_HASH);
}
sub previous_hash {
    my ($slot, $parent) = @_;
    return ZERO_HASH unless $slot;
    my $cached = cache_get($hashes, $parent);
    return $cached if defined $cached;
    my ($index, $block) = load_block($parent);
    die "Missing parent Block slot\n" unless defined unsigned($block->[1]);
    return block_hash($parent, $index, links($block->[3]));
}
sub get_block {
    my ($slot, $encoding, $details, $include_rewards, $max) = @_;
    my ($index, $block) = load_block($slot);
    die "Block slot mismatch\n" unless (unsigned($block->[1]) // -1) == $slot;
    my $entries = links($block->[3]);
    my $info = ref($block->[4]) eq 'ARRAY' ? $block->[4] : [];
    my $parent = unsigned($info->[0]) // 0;
    my $hash = block_hash($slot, $index, $entries);
    my $out = {blockhash => $hash, previousBlockhash => previous_hash($slot, $parent),
               parentSlot => $parent, blockTime => signed($info->[1]) || undef, blockHeight => unsigned($info->[2])};
    if ($details ne 'none') {
        my @out;
        for my $key (@$entries) {
            my $entry = indexed($index, $key, 1);
            die "Invalid Entry hash\n" unless length(bytes($entry->[2]) // '') == 32;
            for my $tx_key (@{links($entry->[3])}) {
                my $node = indexed($index, $tx_key, 0);
                my @tx = transaction(frame_payload($index, $node->[1]));
                if ($details eq 'signatures') {
                    die "Transaction has no signature\n" unless @{$tx[1]};
                    push @out, base58($tx[1][0]);
                } else {
                    my $m = ref($node->[2]) eq 'ARRAY' ? metadata($slot, frame_payload($index, $node->[2])) : undef;
                    push @out, tx_json(\@tx, $m, $encoding, $details, $include_rewards, $max);
                }
            }
        }
        $out->{$details eq 'signatures' ? 'signatures' : 'transactions'} = \@out;
    }
    if ($include_rewards) {
        my $data = '';
        if (defined bytes($block->[5])) {
            my ($key, $absent) = cid_link($block->[5]);
            if (!$absent && exists $index->{$key}) {
                my $node = indexed($index, $key, 5);
                $data = frame_payload($index, $node->[2]) if @$node > 2;
            }
        }
        my $r = rewards($slot, $data);
        @$out{keys %$r} = values %$r;
    }
    return $out;
}

# JSON::PP handles UTF-8 escaping and serialization. A small tokenizer
# preserves numeric lexemes through parameter validation and ID echoing.
my $json_string = qr/"(?:[^"\\\x00-\x1f]++|\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4}))*"/;
my $json_number = qr/-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/;
sub string_token {
    my ($src) = @_;
    die "Invalid JSON string\n" unless $$src =~ /\G($json_string)/gc;
    my $s = $json->decode($1);
    die "Invalid Unicode scalar\n" if $s =~ /[\x{D800}-\x{DFFF}\x{110000}-\x{7FFFFFFF}]/;
    return $s;
}
sub json_value {
    my ($src, $depth) = @_;
    die "JSON nesting limit\n" if $depth > 128;
    $$src =~ /\G[ \t\r\n]*/gc;
    return string_token($src) if substr($$src, pos($$src) // 0, 1) eq '"';
    return bless([$1], 'OnlyBlocks::Number') if $$src =~ /\G($json_number)/gc;
    return undef if $$src =~ /\Gnull/gc;
    return bool(1) if $$src =~ /\Gtrue/gc;
    return bool(0) if $$src =~ /\Gfalse/gc;
    my $is_obj = $$src =~ /\G\{/gc;
    die "Invalid JSON value\n" unless $is_obj || $$src =~ /\G\[/gc;
    my $end = $is_obj ? qr/\}/ : qr/\]/;
    my $out = $is_obj ? {} : [];
    return $out if $$src =~ /\G[ \t\r\n]*$end/gc;
    while (1) {
        if ($is_obj) {
            $$src =~ /\G[ \t\r\n]*/gc;
            my $key = string_token($src);
            die "Missing JSON colon\n" unless $$src =~ /\G[ \t\r\n]*:/gc;
            $out->{$key} = json_value($src, $depth + 1);
        } else {
            push @$out, json_value($src, $depth + 1);
        }
        return $out if $$src =~ /\G[ \t\r\n]*$end/gc;
        die "Missing JSON comma\n" unless $$src =~ /\G[ \t\r\n]*,/gc;
    }
}
sub invalid { rpc_fail(-32602, 'Invalid params') }
sub uint_param {
    my ($v, $max) = @_;
    invalid() unless ref($v) eq 'OnlyBlocks::Number' && $v->[0] =~ /\A(?:0|[1-9][0-9]{0,19})\z/;
    my $digits = $v->[0];
    invalid() if length($digits) > length("$max") || length($digits) == length("$max") && $digits gt "$max";
    return 0 + $digits;
}
sub params {
    my ($p) = @_;
    invalid() unless ref($p) eq 'ARRAY' && @$p >= 1 && @$p <= 2;
    my $slot = uint_param($p->[0], U64);
    my $cfg = $p->[1];
    $cfg = !defined($cfg) ? {} : ref($cfg) ? $cfg : {encoding=>$cfg};
    invalid() unless ref($cfg) eq 'HASH';
    my $encoding = $cfg->{encoding} // 'json';
    my $details = $cfg->{transactionDetails} // 'full';
    my $rewards = $cfg->{rewards} // bool(1);
    my $commitment = $cfg->{commitment} // 'finalized';
    invalid() if ref($encoding) || $encoding !~ /\A(?:json|jsonParsed|base64|base58)\z/
                 || ref($details) || $details !~ /\A(?:full|accounts|signatures|none)\z/
                 || $details eq 'accounts' && $encoding ne 'json' || !JSON::PP::is_bool($rewards)
                 || ref($commitment) || $commitment !~ /\A(?:finalized|confirmed)\z/;
    my $max = $cfg->{maxSupportedTransactionVersion};
    return ($slot, $encoding, $details, $rewards, defined($max) ? uint_param($max, 255) : undef);
}
sub response {
    my ($id, $field, $value) = @_;
    my $encoded = $json->encode({jsonrpc=>'2.0', $field=>$value});
    my $id_text = ref($id) eq 'OnlyBlocks::Number' ? $id->[0] : $json->encode($id);
    return substr($encoded, 0, -1) . ',"id":' . $id_text . '}';
}
sub error { response($_[0], error => {code=>$_[1], message=>$_[2]}) }
sub dispatch {
    my ($r) = @_;
    return error(undef, -32600, 'Invalid Request') unless ref($r) eq 'HASH';
    my ($v, $method, $id, $p) = @$r{qw(jsonrpc method id params)};
    return error(undef, -32600, 'Invalid Request')
        if ref($v) || ref($method) || ref($id) && ref($id) ne 'OnlyBlocks::Number';
    return error($id, -32600, 'Invalid Request') unless defined($method) && ($v // '') eq '2.0';
    my $answer = eval {
        my $result;
        if ($method eq 'getHealth') {
            invalid() if defined($p) && !(ref($p) eq 'ARRAY' && !@$p);
            $result = 'ok';
        } elsif ($method eq 'getBlock') {
            $result = get_block(params($p));
        } else {
            rpc_fail(-32601, "Method not found: $method");
        }
        response($id, result => $result);
    };
    my $failure = $@;
    return $answer unless $failure;
    if (ref($failure) eq 'OnlyBlocks::Error' && $failure->[0] < 0) {
        return error($id, @$failure);
    }
    warn "$failure\n" if $ENV{ONLYBLOCKS_DEBUG} && !ref($failure);
    return error($id, -32603, 'Internal error');
}
sub rpc {
    my ($src) = @_;
    my $request = eval {
        my $r = json_value(\$src, 0);
        die "Trailing JSON text\n" unless $src =~ /\G[ \t\r\n]*\z/gc;
        $r;
    };
    if ($@) {
        warn $@ if $ENV{ONLYBLOCKS_DEBUG};
        return error(undef, -32700, 'Parse error');
    }
    if (ref($request) eq 'ARRAY') {
        return error(undef, -32600, 'Invalid batch size') if !@$request || @$request > 100;
        return '[' . join(',', map { dispatch($_) } @$request) . ']';
    }
    return dispatch($request);
}

sub handle {
    my ($fh) = @_;
    my ($status, $data) = ('400 Bad Request', '');
    my ($raw, $path);
    {
        local $SIG{ALRM} = sub { transport_fail('Client timed out') };
        my $ok = eval {
            alarm(10);
            my $r = [$fh, ''];
            my $line = http_line($r);
            my ($method, $target) = $line =~ m{\A([A-Z]+) (\S+) HTTP/1\.[01]\z};
            die "Invalid HTTP request line\n" unless defined $method;
            $path = $method eq 'POST' && $target eq '/';
            $raw = body($r, headers($r), MAX_BODY, 0, 0) if $path;
            1;
        };
        my $e = $@;
        alarm(0);
        return if ref($e) eq 'OnlyBlocks::Transport';
        if ($ok) {
            if ($path) { $status = '200 OK'; $data = rpc($raw) }
            else { $status = '404 Not Found' }
        } elsif (ref($e) eq 'OnlyBlocks::Error' && $e->[0] == 413) {
            $status = '413 Payload Too Large';
        }
    }
    local $SIG{ALRM} = sub { die "Client write timed out\n" };
    eval {
        alarm(10);
        my $type = $status eq '200 OK' ? "Content-Type: application/json\r\n" : '';
        print {$fh} "HTTP/1.1 $status\r\nConnection: close\r\n$type" . 'Content-Length: ' . length($data)
            . "\r\n\r\n" . $data;
    };
    alarm(0);
}
$SIG{PIPE} = 'IGNORE';
$SIG{INT} = $SIG{TERM} = sub { exit 0 };
my $listener = IO::Socket::INET->new(LocalAddr=>$host, LocalPort=>$port, Listen=>128, ReuseAddr=>1)
    or die "Listen on $bind: $!\n";
while (my $client = $listener->accept) {
    handle($client);
    close($client);
}
