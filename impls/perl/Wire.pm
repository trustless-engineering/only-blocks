package Wire;
use strict;
use warnings;
no warnings qw(portable recursion);
use MIME::Base64 qw(encode_base64);
use Exporter 'import';
our @EXPORT = qw(reader left take u8 u32 u64 i64 f64 varint compact items vector option str utf8str
                 base58 b64 pubkey bytes unsigned signed index_car indexed cid_link links frame_payload transaction instruction
                 ZERO_HASH U64 mul64 add64);
use constant U64 => 0xffffffffffffffff;
use constant ZERO_HASH => '1' x 32;

sub reader { [$_[0], 0] }
sub left { length($_[0][0]) - $_[0][1] }
sub take {
    my ($r, $n) = @_;
    die "Truncated binary value\n" if $n < 0 || $n > left($r);
    my $start = $r->[1];
    $r->[1] += $n;
    return substr($r->[0], $start, $n);
}
sub u8 { ord take($_[0], 1) }
sub u32 { unpack 'V', take($_[0], 4) }
sub u64 { unpack 'Q<', take($_[0], 8) }
sub i64 { unpack 'q<', take($_[0], 8) }
sub f64 { unpack 'd<', take($_[0], 8) }
sub varint {
    my ($r) = @_;
    my $value = 0;
    for (my $shift = 0; $shift <= 63; $shift += 7) {
        my $b = u8($r);
        die "Varint overflow\n" if $shift == 63 && $b > 1;
        $value |= ($b & 127) << $shift;
        return $value if $b < 128;
    }
}
sub compact {
    my ($r) = @_;
    my $value = 0;
    for my $shift (0, 7, 14) {
        my $b = u8($r);
        die "Invalid compact-u16\n" if ($shift && !$b) || ($shift == 14 && $b > 3);
        $value |= ($b & 127) << $shift;
        return $value if $b < 128;
    }
}
sub items {
    my ($r, $count, $minimum, $read) = @_;
    die "Count exceeds enclosing field\n" if $count > int(left($r) / $minimum);
    my @items;
    push @items, scalar $read->($r) for 1 .. $count;
    return \@items;
}
sub vector { my ($r, $min, $read) = @_; items($r, u64($r), $min, $read) }
sub option {
    my ($r, $read) = @_;
    my $tag = u8($r);
    die "Invalid bincode option\n" if $tag > 1;
    return $tag ? $read->($r) : undef;
}
sub utf8str {
    my ($s) = @_;
    utf8::decode($s) or die "Invalid UTF-8\n";
    die "Invalid Unicode scalar\n" if $s =~ /[\x{D800}-\x{DFFF}\x{110000}-\x{7FFFFFFF}]/;
    return $s;
}
sub str { utf8str(take($_[0], u64($_[0]))) }
sub base58 {
    use integer;
    my ($data) = @_;
    my $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    my $radix = 58 ** 5;
    my @groups;
    my $zeros = ($data =~ /\A(\x00*)/) ? length($1) : 0;
    my $tail = substr($data, $zeros);
    $tail = "\0" . $tail if length($tail) & 1;
    # Convert two input bytes at a time across groups of five output digits.
    for my $word (unpack 'n*', $tail) {
        my $carry = $word;
        for my $i (0 .. $#groups) {
            $carry += $groups[$i] << 16;
            $groups[$i] = $carry % $radix;
            $carry /= $radix;
        }
        push @groups, $carry if $carry;
    }
    my $digits = '';
    for my $group (@groups) {
        for (1 .. 5) {
            $digits .= substr($alphabet, $group % 58, 1);
            $group /= 58;
        }
    }
    $digits =~ s/1+\z//;
    return ('1' x $zeros) . reverse($digits);
}
sub b64 { encode_base64($_[0], '') }
sub pubkey {
    die "Expected a 32-byte key\n" unless defined $_[0] && length($_[0]) == 32;
    return base58($_[0]);
}
# CBOR bytes, text and numeric values have distinct representations.
sub bytes { ref($_[0]) eq 'Wire::Bytes' ? $_[0][0] : undef }
sub unsigned { ref($_[0]) eq 'Wire::Uint' ? $_[0][0] : undef }
sub signed {
    my ($v) = @_;
    return $v->[0] if ref($v) eq 'Wire::Int';
    return $v->[0] if ref($v) eq 'Wire::Uint' && $v->[0] <= 0x7fffffffffffffff;
    return undef;
}
sub argument {
    my ($r, $info) = @_;
    return $info if $info < 24;
    return undef if $info == 31;
    die "Reserved CBOR argument\n" if $info > 27;
    return unpack(('C', 'n', 'N', 'Q>')[$info - 24], take($r, 1 << ($info - 24)));
}
sub more {
    my ($r) = @_;
    die "Missing CBOR break\n" unless left($r);
    return ord(substr($r->[0], $r->[1], 1)) != 255;
}
sub cbor_item {
    my ($r, $depth) = @_;
    die "CBOR nesting limit\n" if $depth > 128;
    my $head = u8($r);
    my ($major, $info) = ($head >> 5, $head & 31);
    if ($major == 7) {
        return undef if $info >= 20 && $info <= 23;
        die "Unsupported CBOR simple value\n" if $info < 25 || $info > 27;
        take($r, 2 << ($info - 25));
        return undef; # No schema field consumes a CBOR float.
    }
    my $n = argument($r, $info);
    die "Invalid indefinite CBOR item\n" if !defined($n) && ($major < 2 || $major > 5);
    return bless([$n], 'Wire::Uint') if $major == 0;
    return $n <= 0x7fffffffffffffff ? bless([-1 - $n], 'Wire::Int') : undef if $major == 1;
    return cbor_item($r, $depth + 1) if $major == 6;
    if ($major == 2 || $major == 3) {
        my $data = '';
        if (defined $n) {
            $data = take($r, $n);
            $data = utf8str($data) if $major == 3;
        } else {
            while (more($r)) {
                my $chunk = u8($r);
                die "Invalid CBOR chunk\n" if $chunk >> 5 != $major || ($chunk & 31) == 31;
                my $s = take($r, argument($r, $chunk & 31));
                $data .= $major == 3 ? utf8str($s) : $s;
            }
            take($r, 1);
        }
        return $major == 2 ? bless([$data], 'Wire::Bytes') : $data;
    }
    die "CBOR count exceeds enclosing field\n" if defined($n) && $n > int(left($r) / ($major - 3));
    my $container = $major == 4 ? [] : {};
    while (defined($n) ? $n > 0 : more($r)) {
        my $item = cbor_item($r, $depth + 1);
        if ($major == 4) {
            push @$container, $item;
        } else {
            my $value = cbor_item($r, $depth + 1);
            $container->{$item} = $value if defined $item && !ref $item;
        }
        $n-- if defined $n;
    }
    take($r, 1) unless defined $n;
    return $container;
}
sub cbor {
    my $r = reader($_[0]);
    my $value = cbor_item($r, 0);
    die "Trailing CBOR bytes\n" if left($r);
    return $value;
}
sub cid {
    my ($r) = @_;
    my $start = $r->[1];
    my ($version, $codec) = (varint($r), varint($r));
    my $absent = 0;
    if ($version == 0x12 && $codec == 0x20) {
        take($r, 32);
    } else {
        die "Unsupported CID version\n" unless $version == 1;
        my ($code, $n) = (varint($r), varint($r));
        die "CID digest too long\n" if $n > 64;
        take($r, $n);
        $absent = !$code && !$n;
    }
    return (substr($r->[0], $start, $r->[1] - $start), $absent);
}
sub cid_link {
    my $value = bytes($_[0]);
    die "Invalid CID cid_link\n" unless defined($value) && substr($value, 0, 1) eq "\0";
    return cid(reader(substr($value, 1)));
}
sub links {
    return [] unless ref($_[0]) eq 'ARRAY';
    return [map { (cid_link($_))[0] } @{$_[0]}];
}
sub kind {
    my ($node, $tag) = @_;
    die "Unexpected IPLD node kind\n"
        unless ref($node) eq 'ARRAY' && (unsigned($node->[0]) // -1) == $tag;
    return $node;
}
sub indexed {
    my ($index, $key, $tag) = @_;
    die "CID missing from CAR slice\n" unless exists $index->{$key};
    return kind(cbor($index->{$key}), $tag);
}
sub index_car {
    my $r = reader($_[0]);
    my (%index, $block);
    my $first = 1;
    while (left($r)) {
        my $n = varint($r);
        next unless $n;
        die "Oversize CAR section\n" if $n > 32 << 20;
        my $section = reader(take($r, $n));
        if ($first && ord(substr($section->[0], 0, 1)) >> 5 == 5) {
            my $header = eval { cbor($section->[0]) };
            if (ref($header) eq 'HASH' && exists $header->{version}) {
                $first = 0;
                next;
            }
        }
        $first = 0;
        my ($key) = cid($section);
        my $node = take($section, left($section));
        $index{$key} = $node;
        next unless length($node);
        my $head = ord substr($node, 0, 1);
        my $info = $head & 31;
        next unless $head >> 5 == 4 && ($info < 28 || $info == 31);
        my $start = ($info < 24 || $info == 31) ? 1 : 1 + (1 << ($info - 24));
        $block = $node if substr($node, $start, 1) eq "\x02";
    }
    die "No Block node in CAR slice\n" unless defined $block;
    return (\%index, kind(cbor($block), 2));
}

# 'use integer' computes wraparound on native 64-bit Perl. Convert its
# signed result back to an unsigned scalar before comparing or shifting.
sub add64 { use integer; my $n = $_[0] + $_[1]; return unpack 'Q', pack 'q', $n }
sub mul64 { use integer; my $n = $_[0] * $_[1]; return unpack 'Q', pack 'q', $n }
my @crc_table = map {
    my $v = $_;
    $v = ($v >> 1) ^ ($v & 1 ? 0xD800000000000000 : 0) for 1 .. 8;
    $v;
} 0 .. 255;
sub crc64 {
    my $crc = U64;
    my $data = $_[0];
    for (my $p = 0; $p < length($data); $p++) {
        $crc = ($crc >> 8) ^ $crc_table[($crc & 255) ^ vec($data, $p, 8)];
    }
    return $crc ^ U64;
}
sub fnv1a {
    my $h = 0xcbf29ce484222325;
    my $data = $_[0];
    for (my $p = 0; $p < length($data); $p++) {
        $h = mul64($h ^ vec($data, $p, 8), 0x100000001b3);
    }
    return $h;
}
sub frame_payload {
    my ($index, $root) = @_;
    kind($root, 6);
    my $data = bytes($root->[4]) // '';
    my @stack = reverse @{links($root->[5])};
    my %seen;
    while (@stack) {
        my $key = pop @stack;
        die "Repeated DataFrame CID\n" if $seen{$key}++;
        my $node = indexed($index, $key, 6);
        my $chunk = bytes($node->[4]) // '';
        die "Oversize DataFrame\n" if length($data) + length($chunk) > 128 << 20;
        $data .= $chunk;
        push @stack, reverse @{links($node->[5])};
    }
    my $expected = unsigned($root->[1]);
    die "DataFrame hash mismatch\n"
        if defined($expected) && crc64($data) != $expected && fnv1a($data) != $expected;
    return $data;
}
sub instruction {
    my ($r, $height) = @_;
    return {programIdIndex => u8($r), accounts => take($r, compact($r)),
            data => take($r, compact($r)), stackHeight => $height};
}
sub transaction_v1 {
    my ($r) = @_;
    my $header = {numRequiredSignatures => u8($r), numReadonlySignedAccounts => u8($r),
                  numReadonlyUnsignedAccounts => u8($r)};
    my $mask = u32($r);
    my $priority_bits = $mask & 0x03;
    die "Invalid v1 transaction config mask\n" if $mask > 0x1f || ($priority_bits && $priority_bits != 0x03);
    my $recent = pubkey(take($r, 32));
    my $instruction_count = u8($r);
    my $keys = items($r, u8($r), 32, sub { pubkey(take($_[0], 32)) });
    my $config = {
        priorityFee => $priority_bits == 0x03 ? scalar u64($r) : undef,
        computeUnitLimit => $mask & 0x04 ? scalar u32($r) : undef,
        loadedAccountsDataSizeLimit => $mask & 0x08 ? scalar u32($r) : undef,
        heapSize => $mask & 0x10 ? scalar u32($r) : undef,
    };
    # All headers precede the payloads, which are laid out in instruction order.
    my $headers = items($r, $instruction_count, 4, sub { [unpack 'CCv', take($_[0], 4)] });
    my @instructions = map {
        my ($program, $account_count, $data_length) = @$_;
        {programIdIndex => $program, accounts => take($r, $account_count),
         data => take($r, $data_length), stackHeight => 1};
    } @$headers;
    my $signatures = items($r, $header->{numRequiredSignatures}, 64, sub { take($_[0], 64) });
    my $message = {header => $header, accountKeys => $keys, recentBlockhash => $recent,
                   instructions => \@instructions, transactionConfig => $config};
    return (1, $signatures, $message, substr($r->[0], 0, $r->[1]));
}

sub transaction {
    my $r = reader($_[0]);
    my $discriminator = u8($r);
    return transaction_v1($r) if $discriminator == 0x81;
    die "Invalid transaction discriminator\n" if $discriminator >= 0x80;
    my $signatures = items($r, $discriminator, 64, sub { take($_[0], 64) });
    my $prefix = u8($r);
    die "Unsupported wire transaction version\n" if $prefix > 128;
    my $v0 = $prefix == 128;
    my $header = {numRequiredSignatures => $v0 ? u8($r) : $prefix,
                  numReadonlySignedAccounts => u8($r), numReadonlyUnsignedAccounts => u8($r)};
    my $message = {
        header => $header, accountKeys => items($r, compact($r), 32, sub { pubkey(take($_[0], 32)) }),
        recentBlockhash => pubkey(take($r, 32)),
        instructions => items($r, compact($r), 3, sub { instruction($_[0], 1) }),
    };
    if ($v0) {
        $message->{addressTableLookups} = items($r, compact($r), 34, sub {
            return {accountKey => pubkey(take($r, 32)), writableIndexes => [unpack 'C*', take($r, compact($r))],
                    readonlyIndexes => [unpack 'C*', take($r, compact($r))]};
        });
    }
    return ($v0 ? 0 : 'legacy', $signatures, $message, substr($_[0], 0, $r->[1]));
}
1;
