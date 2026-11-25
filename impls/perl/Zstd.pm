package Zstd;
use strict;
use warnings;
no warnings 'portable';
use Wire qw(add64 mul64);
use constant CAP => 512 << 20;
use constant BLOCK => 128 << 10;

my @ll_base = (0..16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536);
my @ll_bits = ((0) x 16, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6..16);
my @ml_base = (3..34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539);
my @ml_bits = ((0) x 32, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7..16);
my @defaults = (
    [4, 3, (2) x 11, (1) x 3, (2) x 9, 3, 2, (1) x 5, (-1) x 4],
    [(1) x 6, (2) x 3, (1) x 15, (-1) x 5],
    [1, 4, 3, (2) x 6, (1) x 37, (-1) x 7],
);
my @logs = (6, 5, 6);
my @max_symbols = (35, 31, 52);
my @max_logs = (9, 8, 9);

sub min { my $m = shift; for (@_) { $m = $_ if $_ < $m } $m }
sub bw { my $n = 0; for (my $v = $_[0]; $v; $v >>= 1) { $n++ } $n }
sub little {
    my ($data, $pos, $size, $end) = @_;
    $end //= length($$data);
    die "Truncated Zstd input\n" if $pos < 0 || $size > $end - $pos;
    return unpack 'Q<', substr($$data, $pos, $size) . ("\0" x (8 - $size));
}
sub back {
    my ($data, $start, $end) = @_;
    die "Empty Zstd bitstream\n" if $end <= $start;
    my $last = little($data, $end - 1, 1);
    die "Missing bitstream end marker\n" unless $last;
    return [$data, $start, 8 * ($end - $start - 1) + bw($last) - 1];
}
sub peek_back {
    my ($b, $n) = @_;
    my ($data, $start, $bits) = @$b;
    return 0 if !$n || $bits <= 0;
    my $low = $bits > $n ? $bits - $n : 0;
    my $word = little($data, $start + ($low >> 3), (($bits - 1) >> 3) - ($low >> 3) + 1);
    my $value = ($word >> ($low & 7)) & ((1 << ($bits - $low)) - 1);
    return $bits < $n ? $value << ($n - $bits) : $value;
}
sub rb { my $v = peek_back(@_); $_[0][2] -= $_[1]; $v }
sub peek_fwd {
    my ($data, $pos, $end, $n) = @_;
    my $value = 0;
    for my $i (0 .. $n - 1) {
        my $bit = $pos + $i;
        last if $bit >= $end;
        $value |= ((vec($$data, $bit >> 3, 8) >> ($bit & 7)) & 1) << $i;
    }
    return $value;
}
sub fse_desc {
    my ($data, $start, $finish, $max_symbol, $max_log) = @_;
    my ($pos, $end) = ($start * 8, $finish * 8);
    my $read = sub {
        my ($n) = @_;
        die "Truncated FSE description\n" if $n > $end - $pos;
        my $value = peek_fwd($data, $pos, $end, $n);
        $pos += $n;
        return $value;
    };
    my $log = $read->(4) + 5;
    die "FSE accuracy log too large\n" if $log > $max_log;
    my ($threshold, $width) = (1 << $log, $log + 1);
    my $remaining = $threshold + 1;
    my @weights;
    while ($remaining > 1) {
        die "Too many FSE symbols\n" if @weights > $max_symbol;
        my $maximum = 2 * $threshold - 1 - $remaining;
        my $value;
        if (peek_fwd($data, $pos, $end, $width - 1) < $maximum) {
            $value = $read->($width - 1);
        } else {
            $value = $read->($width);
            $value -= $maximum if $value >= $threshold;
        }
        my $weight = $value - 1;
        push @weights, $weight;
        $remaining -= abs($weight);
        die "Invalid FSE probability\n" if $remaining < 1;
        if (!$weight) {
            my $n;
            do {
                $n = $read->(2);
                push @weights, (0) x $n;
                die "Too many FSE symbols\n" if @weights > $max_symbol + 1;
            } while ($n == 3);
        }
        while ($remaining < $threshold) {
            --$width;
            $threshold >>= 1;
        }
    }
    return (\@weights, $log, ($pos + 7) >> 3);
}
sub fse_table {
    my ($weights, $log) = @_;
    my $size = 1 << $log;
    my @counts = map { abs($_) } @$weights;
    my $sum = 0;
    $sum += $_ for @counts;
    die "Invalid FSE distribution\n" if $sum != $size;
    my @cells;
    my $high = $size - 1;
    for my $i (0 .. $#$weights) {
        $cells[$high--] = $i if $weights->[$i] == -1;
    }
    my ($pos, $step) = (0, ($size >> 1) + ($size >> 3) + 3);
    for my $i (0 .. $#$weights) {
        for (1 .. $weights->[$i]) {
            $cells[$pos] = $i;
            do { $pos = ($pos + $step) & ($size - 1) } while $pos > $high;
        }
    }
    die "Invalid FSE spread\n" if $pos;
    return [map {
        my $count = $counts[$_]++;
        my $width = $log + 1 - bw($count);
        [$_, $width, ($count << $width) - $size];
    } @cells];
}
my @predefined = map { [fse_table($defaults[$_], $logs[$_]), $logs[$_]] } 0..2;

sub huffman_desc {
    my ($data, $pos, $limit) = @_;
    my $head = little($data, $pos++, 1, $limit);
    my (@weights, $end);
    if ($head < 128) {
        $end = $pos + $head;
        die "Huffman description overruns block\n" if $end > $limit;
        my ($p, $log, $start) = fse_desc($data, $pos, $end, 255, 6);
        my $table = fse_table($p, $log);
        my $bits = back($data, $start, $end);
        my @states = (rb($bits, $log), rb($bits, $log));
        die "Truncated Huffman initial states\n" if $bits->[2] < 0;
        my $turn = 0;
        while (1) {
            die "Too many Huffman weights\n" if @weights >= 255;
            my ($symbol, $width, $base) = @{$table->[$states[$turn]]};
            push @weights, $symbol;
            $states[$turn] = $base + rb($bits, $width);
            $turn ^= 1;
            if ($bits->[2] < 0) {
                push @weights, $table->[$states[$turn]][0];
                last;
            }
        }
    } else {
        my $count = $head - 127;
        $end = $pos + (($count + 1) >> 1);
        die "Huffman description overruns block\n" if $end > $limit;
        for my $i (0 .. $count - 1) {
            my $v = vec($$data, $pos + ($i >> 1), 8);
            push @weights, $i & 1 ? $v & 15 : $v >> 4;
        }
    }
    my $sum = 0;
    for my $w (@weights) {
        die "Invalid Huffman weight\n" if $w > 11;
        $sum += 1 << ($w - 1) if $w;
    }
    my $width = bw($sum);
    die "Invalid Huffman width\n" if ! $width || $width > 11 || @weights > 255;
    my $rest = (1 << $width) - $sum;
    die "Invalid implied Huffman weight\n" if $rest & ($rest - 1);
    push @weights, bw($rest);
    my @table;
    for my $w (1 .. $width) {
        for my $symbol (0 .. $#weights) {
            push @table, ([$symbol, $width + 1 - $w]) x (1 << ($w - 1)) if $weights[$symbol] == $w;
        }
    }
    return ([\@table, $width], $end);
}
sub huffman_stream {
    my ($data, $start, $finish, $tree, $n) = @_;
    my ($table, $width) = @$tree;
    my $bits = back($data, $start, $finish);
    my $out = '';
    for (1 .. $n) {
        my ($symbol, $drop) = @{$table->[peek_back($bits, $width)]};
        $out .= chr $symbol;
        $bits->[2] -= $drop;
    }
    die "Huffman bitstream not fully consumed\n" if $bits->[2];
    return $out;
}
sub literals {
    my ($data, $pos, $end, $frame, $cap) = @_;
    my $first = little($data, $pos, 1, $end);
    my ($type, $format) = ($first & 3, ($first >> 2) & 3);
    if ($type < 2) {
        my $width = (1, 2, 1, 3)[$format];
        my $n = little($data, $pos, $width, $end) >> ($width == 1 ? 3 : 4);
        $pos += $width;
        die "Literal output exceeds block limit\n" if $n > $cap;
        return (chr(little($data, $pos, 1, $end)) x $n, $pos + 1) if $type;
        die "Raw literals overrun block\n" if $n > $end - $pos;
        return (substr($$data, $pos, $n), $pos + $n);
    }
    my ($length, $width) = @{([3, 10], [3, 10], [4, 14], [5, 18])[$format]};
    my $header = little($data, $pos, $length, $end);
    my $mask = (1 << $width) - 1;
    my $n = ($header >> 4) & $mask;
    $pos += $length;
    my $finish = $pos + (($header >> (4 + $width)) & $mask);
    die "Invalid compressed literals size\n" if $finish > $end || $n > $cap;
    ($frame->{tree}, $pos) = huffman_desc($data, $pos, $finish) if $type == 2;
    my $tree = $frame->{tree} or die "Missing previous Huffman table\n";
    return (huffman_stream($data, $pos, $finish, $tree, $n), $finish) if !$format;
    my @sizes = map { little($data, $pos + $_, 2, $finish) } (0, 2, 4);
    $pos += 6;
    push @sizes, $finish - $pos - $sizes[0] - $sizes[1] - $sizes[2];
    my $quarter = ($n + 3) >> 2;
    my @counts = ($quarter, $quarter, $quarter, $n - 3 * $quarter);
    die "Invalid Huffman stream sizes\n" if $counts[3] < 0 || grep { $_ <= 0 } @sizes;
    my $out = '';
    for my $i (0..3) {
        $out .= huffman_stream($data, $pos, $pos + $sizes[$i], $tree, $counts[$i]);
        $pos += $sizes[$i];
    }
    return ($out, $finish);
}
sub sequence_table {
    my ($data, $pos, $end, $mode, $i, $frame) = @_;
    my $table;
    if ($mode == 0) {
        $table = $predefined[$i];
    } elsif ($mode == 1) {
        my $symbol = little($data, $pos++, 1, $end);
        die "Invalid RLE sequence symbol\n" if $symbol > $max_symbols[$i];
        $table = [[[$symbol, 0, 0]], 0];
    } elsif ($mode == 2) {
        my ($p, $log, $next) = fse_desc($data, $pos, $end, $max_symbols[$i], $max_logs[$i]);
        $table = [fse_table($p, $log), $log];
        $pos = $next;
    } else {
        $table = $frame->{seq}[$i] or die "Missing previous FSE table\n";
    }
    $frame->{seq}[$i] = $table;
    return ($table, $pos);
}
sub offset {
    my ($v, $ll, $offsets) = @_;
    my $i = $v - 1 + !$ll;
    my $d;
    if ($v > 3 || $i == 3) {
        $d = $v > 3 ? $v - 3 : $offsets->[0] - 1;
        pop @$offsets;
    } else {
        ($d) = splice @$offsets, $i, 1;
    }
    unshift @$offsets, $d;
    return $d;
}
sub compressed {
    my ($data, $pos, $end, $frame, $out, $start, $window, $cap) = @_;
    my $literal;
    ($literal, $pos) = literals($data, $pos, $end, $frame, $cap);
    my $count = little($data, $pos++, 1, $end);
    if (!$count) {
        die "Trailing bytes after empty sequence section\n" if $pos != $end;
        $$out .= $literal;
        return;
    }
    if ($count == 255) {
        $count = little($data, $pos, 2, $end) + 0x7f00;
        $pos += 2;
    } elsif ($count >= 128) {
        $count = (($count - 128) << 8) + little($data, $pos++, 1, $end);
    }
    die "Invalid sequence count\n" if !$count || $count * 3 > $cap;
    my $modes = little($data, $pos++, 1, $end);
    die "Reserved sequence mode bits\n" if $modes & 3;
    my @tables;
    for my $i (0..2) {
        ($tables[$i], $pos) = sequence_table($data, $pos, $end, ($modes >> (6 - 2 * $i)) & 3, $i, $frame);
    }
    my $bits = back($data, $pos, $end);
    my @states = map { rb($bits, $_->[1]) } @tables;
    my $lit = 0;
    my $max_end = length($$out) + $cap;
    for my $i (1 .. $count) {
        my ($ll, $of, $ml) = map { $tables[$_][0][$states[$_]] } 0..2;
        my $value = (1 << $of->[0]) + rb($bits, $of->[0]);
        my $match = $ml_base[$ml->[0]] + rb($bits, $ml_bits[$ml->[0]]);
        my $n = $ll_base[$ll->[0]] + rb($bits, $ll_bits[$ll->[0]]);
        die "Invalid sequence length\n" if $bits->[2] < 0 || $lit + $n > length($literal)
            || length($$out) + $n + $match > $max_end;
        $$out .= substr($literal, $lit, $n);
        $lit += $n;
        my $d = offset($value, $n, $frame->{offsets});
        die "Invalid match offset\n" if $d <= 0 || $d > $window || $d > length($$out) - $start;
        if ($match <= $d) {
            $$out .= substr($$out, -$d, $match);
        } else {
            my $pattern = substr($$out, -$d);
            $$out .= ($pattern x int($match / $d)) . substr($pattern, 0, $match % $d);
        }
        if ($i < $count) {
            $states[0] = $ll->[2] + rb($bits, $ll->[1]);
            $states[2] = $ml->[2] + rb($bits, $ml->[1]);
            $states[1] = $of->[2] + rb($bits, $of->[1]);
        }
    }
    die "Invalid trailing literals\n" if $bits->[2] || length($$out) + length($literal) - $lit > $max_end;
    $$out .= substr($literal, $lit);
}

use constant P1 => 0x9e3779b185ebca87;
use constant P2 => 0xc2b2ae3d27d4eb4f;
use constant P3 => 0x165667b19e3779f9;
use constant P4 => 0x85ebca77c2b2ae63;
use constant P5 => 0x27d4eb2f165667c5;
sub rotl { ($_[0] << $_[1]) | ($_[0] >> (64 - $_[1])) }
sub round { mul64(rotl(add64($_[0], mul64($_[1], P2)), 31), P1) }
sub xxh64 {
    my ($data, $start) = @_;
    my ($pos, $end, $h) = ($start, length($$data), P5);
    if ($end - $start >= 32) {
        my @a = (add64(P1, P2), P2, 0, add64(~P1, 1));
        while ($pos + 32 <= $end) {
            for my $i (0..3) { $a[$i] = round($a[$i], little($data, $pos + 8 * $i, 8)) }
            $pos += 32;
        }
        $h = 0;
        for my $i (0..3) { $h = add64($h, rotl($a[$i], (1, 7, 12, 18)[$i])) }
        for (@a) { $h = add64(mul64($h ^ round(0, $_), P1), P4) }
    }
    $h = add64($h, $end - $start);
    while ($pos + 8 <= $end) {
        $h = add64(mul64(rotl($h ^ round(0, little($data, $pos, 8)), 27), P1), P4);
        $pos += 8;
    }
    if ($pos + 4 <= $end) {
        $h = add64(mul64(rotl($h ^ mul64(little($data, $pos, 4), P1), 23), P2), P3);
        $pos += 4;
    }
    while ($pos < $end) {
        $h = mul64(rotl($h ^ mul64(vec($$data, $pos++, 8), P5), 11), P1);
    }
    $h = mul64($h ^ ($h >> 33), P2);
    $h = mul64($h ^ ($h >> 29), P3);
    return $h ^ ($h >> 32);
}
sub decompress {
    my ($data) = @_;
    my ($pos, $out) = (0, '');
    while ($pos < length($data)) {
        my $magic = little(\$data, $pos, 4);
        $pos += 4;
        if (($magic & 0xfffffff0) == 0x184d2a50) {
            $pos += 4 + little(\$data, $pos, 4);
            die "Truncated skippable frame\n" if $pos > length($data);
            next;
        }
        die "Unknown Zstd frame magic\n" if $magic != 0xfd2fb528;
        my $desc = little(\$data, $pos++, 1);
        die "Reserved frame header bit\n" if $desc & 8;
        my $single = $desc & 32;
        my $window;
        if (!$single) {
            my $wd = little(\$data, $pos++, 1);
            my $base = 1 << (10 + ($wd >> 3));
            $window = $base + ($base >> 3) * ($wd & 7);
        }
        my $dict = (0, 1, 2, 4)[$desc & 3];
        die "Zstd dictionaries unsupported\n" if little(\$data, $pos, $dict);
        $pos += $dict;
        my $n = ($single ? 1 : 0, 2, 4, 8)[$desc >> 6];
        my $size;
        if ($n) {
            $size = little(\$data, $pos, $n) + ($n == 2 ? 256 : 0);
            $pos += $n;
            die "Decompressed size limit exceeded\n" if $size > CAP - length($out);
        }
        $window = $size if $single;
        my $max = min($window, BLOCK);
        my $start = length($out);
        my $frame = {offsets => [1, 4, 8]};
        my $head;
        do {
            $head = little(\$data, $pos, 3);
            $pos += 3;
            my ($type, $count) = (($head >> 1) & 3, $head >> 3);
            my $end = $pos + ($type == 1 ? 1 : $count);
            die "Invalid Zstd block\n" if $type == 3 || $count > $max || $end > length($data);
            my $cap = min($max, CAP - length($out));
            $cap = min($cap, $size - (length($out) - $start)) if defined $size;
            if ($type == 2) {
                compressed(\$data, $pos, $end, $frame, \$out, $start, $window, $cap);
            } else {
                die "Zstd block output exceeds limit\n" if $count > $cap;
                $out .= $type ? substr($data, $pos, 1) x $count : substr($data, $pos, $count);
            }
            $pos = $end;
        } until $head & 1;
        die "Frame content size mismatch\n" if defined($size) && length($out) - $start != $size;
        if ($desc & 4) {
            die "Content checksum mismatch\n" if (xxh64(\$out, $start) & 0xffffffff) != little(\$data, $pos, 4);
            $pos += 4;
        }
    }
    return $out;
}
1;
