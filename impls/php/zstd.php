<?php
declare(strict_types=1);

// RFC 8878 backward stream. Reads before the beginning are zero-padded;
// only the FSE-compressed Huffman weight stream may terminate on overflow.
final class BackwardBits
{
    public int $bits;

    public function __construct(private readonly string $data)
    {
        require_valid($data !== '' && ord($data[-1]) !== 0, 'Missing Zstd bitstream marker');
        $this->bits = (strlen($data) - 1) * 8 + Zstd::high(ord($data[-1]));
    }

    public function peek(int $width): int
    {
        if ($width === 0 || $this->bits <= 0) return 0;
        $low = max(0, $this->bits - $width);
        $first = $low >> 3;
        $last = ($this->bits - 1) >> 3;
        $word = 0;
        for ($i = $last; $i >= $first; $i--) $word = ($word << 8) | ord($this->data[$i]);
        $value = ($word >> ($low & 7)) & ((1 << ($this->bits - $low)) - 1);
        return $value << max(0, $width - $this->bits);
    }

    public function read(int $width): int
    {
        $value = $this->peek($width);
        $this->bits -= $width;
        return $value;
    }
}

final class ZstdFrame
{
    public ?array $huffman = null;
    public array $tables = [null, null, null];
    public array $offsets = [1, 4, 8];
}

final class Zstd
{
    private const LIMIT = 512 * 1024 * 1024;
    private const BLOCK_MAX = 128 * 1024;

    private const LL_BASE = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
    ];
    private const LL_BITS = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    ];
    private const ML_BASE = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539
    ];
    private const ML_BITS = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    ];
    private const LL_DEFAULT = [
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1
    ];
    private const ML_DEFAULT = [
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1
    ];
    private const OF_DEFAULT = [
        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1
    ];
    private const MAX_SYMBOL = [35, 31, 52];
    private const MAX_LOG = [9, 8, 9];

    public static function high(int $value): int
    {
        $result = 0;
        while ($value > 1) {
            $value >>= 1;
            $result++;
        }
        return $result;
    }

    private static function readFse(Reader $r, int $maxSymbol, int $maxLog): array
    {
        $start = $r->pos * 8;
        $bit = $start;
        $end = $start + $r->left() * 8;
        $peek = static function (int $width) use (&$bit, $end, $r): int {
            $value = 0;
            for ($i = 0; $i < $width && $bit + $i < $end; $i++) {
                $p = $bit + $i;
                $value |= ((ord($r->data[$p >> 3]) >> ($p & 7)) & 1) << $i;
            }
            return $value;
        };
        $take = static function (int $width) use (&$bit, $end, $peek): int {
            $value = $peek($width);
            $bit += $width;
            require_valid($bit <= $end, 'Truncated Zstd FSE description');
            return $value;
        };

        $log = $take(4) + 5;
        require_valid($log <= $maxLog, 'Zstd FSE accuracy log too large');
        $threshold = 1 << $log;
        $remaining = $threshold + 1;
        $width = $log + 1;
        $probabilities = [];
        while ($remaining > 1) {
            require_valid(count($probabilities) <= $maxSymbol, 'Too many Zstd FSE symbols');
            $maximum = 2 * $threshold - 1 - $remaining;
            $low = $peek($width - 1);
            $value = $take($low < $maximum ? $width - 1 : $width);
            if ($value >= $threshold) $value -= $maximum;
            $p = $value - 1;
            $probabilities[] = $p;
            $remaining -= abs($p);
            require_valid($remaining >= 1, 'Invalid Zstd FSE distribution');
            if ($p === 0) {
                do {
                    $repeat = $take(2);
                    for ($i = 0; $i < $repeat; $i++) $probabilities[] = 0;
                    require_valid(count($probabilities) <= $maxSymbol + 1, 'Too many Zstd FSE symbols');
                } while ($repeat === 3);
            }
            while ($remaining < $threshold) {
                $width--;
                $threshold >>= 1;
            }
        }
        $r->skip(($bit - $start + 7) >> 3);
        return self::buildFse($probabilities, $log);
    }

    private static function buildFse(array $probabilities, int $log): array
    {
        $size = 1 << $log;
        $high = $size - 1;
        $symbols = array_fill(0, $size, 0);
        $next = [];
        foreach ($probabilities as $symbol => $p) {
            if ($p === -1) $symbols[$high--] = $symbol;
            $next[] = abs($p);
        }
        $step = ($size >> 1) + ($size >> 3) + 3;
        $pos = 0;
        foreach ($probabilities as $symbol => $p) {
            for ($i = 0; $i < $p; $i++) {
                $symbols[$pos] = $symbol;
                do { $pos = ($pos + $step) & ($size - 1); } while ($pos > $high);
            }
        }
        require_valid($pos === 0, 'Invalid Zstd FSE distribution');
        $cells = [];
        foreach ($symbols as $symbol) {
            $n = $next[$symbol]++;
            $bits = $log - self::high($n);
            $cells[] = [$symbol, $bits, ($n << $bits) - $size];
        }
        return [$cells, $log];
    }

    private static function readHuffman(Reader $r): array
    {
        $first = $r->u8();
        $weights = [];
        if ($first >= 128) {
            $count = $first - 127;
            $packed = $r->take(intdiv($count + 1, 2));
            for ($i = 0; $i < $count; $i++) {
                $byte = ord($packed[$i >> 1]);
                $weights[] = ($i & 1) ? $byte & 15 : $byte >> 4;
            }
        } else {
            $section = $r->section($first);
            [$table, $log] = self::readFse($section, 255, 6);
            $bits = new BackwardBits($section->take($section->left()));
            $a = $bits->read($log);
            $b = $bits->read($log);
            require_valid($bits->bits >= 0, 'Truncated Zstd Huffman initial states');
            while (true) {
                require_valid(count($weights) < 255, 'Too many Zstd Huffman weights');
                [$symbol, $width, $base] = $table[$a];
                $weights[] = $symbol;
                $a = $base + $bits->read($width);
                if ($bits->bits < 0) {
                    $weights[] = $table[$b][0];
                    break;
                }
                [$a, $b] = [$b, $a];
            }
        }
        require_valid(count($weights) <= 255, 'Too many Zstd Huffman weights');
        $sum = 0;
        foreach ($weights as $w) {
            require_valid($w <= 11, 'Invalid Zstd Huffman weight');
            if ($w > 0) $sum += 1 << ($w - 1);
        }
        $log = self::high($sum) + 1;
        require_valid($sum > 0 && $log <= 11, 'Invalid Zstd Huffman length');
        $rest = (1 << $log) - $sum;
        require_valid(($rest & ($rest - 1)) === 0, 'Invalid Zstd Huffman distribution');
        $weights[] = self::high($rest) + 1;
        $cells = [];
        for ($w = 1; $w <= $log; $w++) {
            foreach ($weights as $i => $weight) {
                if ($weight !== $w) continue;
                $cell = [chr($i), $log + 1 - $w];
                for ($n = 1 << ($w - 1); $n > 0; $n--) $cells[] = $cell;
            }
        }
        return [$cells, $log];
    }

    private static function huffStream(string $data, array $huf, int $count): string
    {
        [$cells, $log] = $huf;
        $bits = new BackwardBits($data);
        $out = '';
        for ($i = 0; $i < $count; $i++) {
            [$symbol, $width] = $cells[$bits->peek($log)];
            $out .= $symbol;
            $bits->bits -= $width;
            require_valid($bits->bits >= 0, 'Truncated Zstd Huffman stream');
        }
        require_valid($bits->bits === 0, 'Trailing Zstd Huffman bits');
        return $out;
    }

    private static function literals(Reader $r, ZstdFrame $frame, int $maxBlock): string
    {
        $first = $r->u8();
        $type = $first & 3;
        $format = ($first >> 2) & 3;
        if ($type <= 1) {
            $size = $format === 0 || $format === 2 ? $first >> 3 : ($first >> 4) + ($r->le($format === 1 ? 1 : 2) << 4);
            require_valid($size <= $maxBlock, 'Zstd literals exceed block size');
            return $type === 0 ? $r->take($size) : str_repeat($r->take(1), $size);
        }
        $width = $format <= 1 ? 10 : ($format === 2 ? 14 : 18);
        $header = $first | ($r->le($format <= 1 ? 2 : $format + 1) << 8);
        $mask = (1 << $width) - 1;
        $count = ($header >> 4) & $mask;
        require_valid($count <= $maxBlock, 'Zstd literals exceed block size');
        $lit = $r->section(($header >> (4 + $width)) & $mask);
        if ($type === 2) $frame->huffman = self::readHuffman($lit);
        require_valid($frame->huffman !== null, 'Missing previous Zstd Huffman table');
        if ($format === 0) return self::huffStream($lit->take($lit->left()), $frame->huffman, $count);

        $sizes = [$lit->le(2), $lit->le(2), $lit->le(2)];
        $sizes[] = $lit->left() - array_sum($sizes);
        $part = intdiv($count + 3, 4);
        require_valid($part * 3 <= $count, 'Invalid Zstd Huffman stream sizes');
        $out = '';
        foreach ($sizes as $i => $size)
            $out .= self::huffStream($lit->take($size), $frame->huffman, $i === 3 ? $count - 3 * $part : $part);
        return $out;
    }

    private static function sequenceTable(Reader $r, ZstdFrame $frame, int $mode, int $kind): array
    {
        static $defaults = null;
        $defaults ??= [
            self::buildFse(self::LL_DEFAULT, 6), self::buildFse(self::OF_DEFAULT, 5), self::buildFse(self::ML_DEFAULT, 6),
        ];
        if ($mode === 1) {
            $symbol = $r->u8();
            require_valid($symbol <= self::MAX_SYMBOL[$kind], 'Invalid Zstd RLE symbol');
            $table = [[[$symbol, 0, 0]], 0];
        } else {
            $table = match ($mode) {
                0 => $defaults[$kind],
                2 => self::readFse($r, self::MAX_SYMBOL[$kind], self::MAX_LOG[$kind]),
                3 => $frame->tables[$kind] ?? throw new FormatError('Missing previous Zstd sequence table'),
            };
        }
        return $frame->tables[$kind] = $table;
    }

    private static function matchOffset(ZstdFrame $frame, int $code, int $literal): int
    {
        $rep = &$frame->offsets;
        if ($code > 3) {
            $offset = $code - 3;
            $rep = [$offset, $rep[0], $rep[1]];
        } else {
            $index = $code - 1 + ($literal === 0 ? 1 : 0);
            $offset = $index === 3 ? $rep[0] - 1 : $rep[$index];
            if ($index >= 2) $rep[2] = $rep[1];
            if ($index >= 1) {
                $rep[1] = $rep[0];
                $rep[0] = $offset;
            }
        }
        return $offset;
    }

    private static function compressed(Reader $r, ZstdFrame $frame, string &$out, int $start, int $maxBlock, int $window): void
    {
        $blockStart = strlen($out);
        $literals = self::literals($r, $frame, $maxBlock);
        $count = $r->u8();
        if ($count === 0) {
            require_valid($r->left() === 0, 'Trailing data after empty Zstd sequences');
            self::grow($out, strlen($literals));
            $out .= $literals;
            return;
        }
        if ($count === 255) $count = $r->le(2) + 0x7f00;
        elseif ($count >= 128) $count = (($count - 128) << 8) + $r->u8();
        $modes = $r->u8();
        require_valid(($modes & 3) === 0, 'Reserved Zstd sequence bits');
        [$ll, $llLog] = self::sequenceTable($r, $frame, $modes >> 6, 0);
        [$of, $ofLog] = self::sequenceTable($r, $frame, ($modes >> 4) & 3, 1);
        [$ml, $mlLog] = self::sequenceTable($r, $frame, ($modes >> 2) & 3, 2);
        $bits = new BackwardBits($r->take($r->left()));
        $ls = $bits->read($llLog);
        $os = $bits->read($ofLog);
        $ms = $bits->read($mlLog);
        $lit = 0;
        $litSize = strlen($literals);
        for ($i = 0; $i < $count; $i++) {
            [$l, $lb, $ln] = $ll[$ls];
            [$o, $ob, $on] = $of[$os];
            [$m, $mb, $mn] = $ml[$ms];
            $code = (1 << $o) + $bits->read($o);
            $match = self::ML_BASE[$m] + $bits->read(self::ML_BITS[$m]);
            $literal = self::LL_BASE[$l] + $bits->read(self::LL_BITS[$l]);
            require_valid($bits->bits >= 0 && $literal <= $litSize - $lit &&
                $literal + $match <= $maxBlock - (strlen($out) - $blockStart), 'Invalid Zstd sequence lengths');
            self::grow($out, $literal + $match);
            $out .= substr($literals, $lit, $literal);
            $lit += $literal;
            $offset = self::matchOffset($frame, $code, $literal);
            require_valid($offset > 0 && $offset <= strlen($out) - $start && $offset <= $window, 'Zstd offset outside frame window');

            // An overlapping match repeats the initial available bytes.
            $source = strlen($out) - $offset;
            if ($offset >= $match) $out .= substr($out, $source, $match);
            else {
                $pattern = substr($out, $source, $offset);
                $out .= str_repeat($pattern, intdiv($match, $offset)) . substr($pattern, 0, $match % $offset);
            }
            if ($i + 1 < $count) {
                $ls = $ln + $bits->read($lb);
                $ms = $mn + $bits->read($mb);
                $os = $on + $bits->read($ob);
                require_valid($bits->bits >= 0, 'Truncated Zstd sequence states');
            }
        }
        require_valid($bits->bits === 0 && $litSize - $lit <= $maxBlock - (strlen($out) - $blockStart),
            'Invalid Zstd block ending');
        self::grow($out, $litSize - $lit);
        $out .= substr($literals, $lit);
    }

    private static function grow(string $out, int $size): void
    {
        require_valid($size <= self::LIMIT - strlen($out), 'Zstd output exceeds 512 MiB');
    }

    public static function decode(string $data): string
    {
        $r = new Reader($data);
        $out = '';
        while ($r->left() > 0) {
            $magic = $r->u32();
            if (($magic & 0xfffffff0) === 0x184d2a50) {
                $r->skip($r->u32());
                continue;
            }
            require_valid($magic === 0xfd2fb528, 'Unknown Zstd frame magic');
            $descriptor = $r->u8();
            require_valid(($descriptor & 8) === 0, 'Reserved Zstd frame bit');
            $single = ($descriptor & 32) !== 0;
            $window = 0;
            if (!$single) {
                $wd = $r->u8();
                $base = 1 << (10 + ($wd >> 3));
                $window = $base + ($base >> 3) * ($wd & 7);
            }
            $dict = $descriptor & 3;
            require_valid($r->le($dict === 0 ? 0 : 1 << ($dict - 1)) === 0, 'Zstd dictionaries are unsupported');
            $flag = $descriptor >> 6;
            $length = $flag === 0 ? ($single ? 1 : 0) : 1 << $flag;
            $size = $r->le($length) + ($length === 2 ? 256 : 0);
            require_valid($size >= 0 && $size <= self::LIMIT - strlen($out), 'Zstd frame too large');
            if ($single) $window = $size;
            $maxBlock = min($window, self::BLOCK_MAX);
            $start = strlen($out);
            $frame = new ZstdFrame();
            do {
                $header = $r->le(3);
                $blockSize = $header >> 3;
                require_valid($blockSize <= $maxBlock, 'Zstd block too large');
                switch (($header >> 1) & 3) {
                    case 0:
                        self::grow($out, $blockSize);
                        $out .= $r->take($blockSize);
                        break;
                    case 1:
                        self::grow($out, $blockSize);
                        $out .= str_repeat($r->take(1), $blockSize);
                        break;
                    case 2:
                        self::compressed($r->section($blockSize), $frame, $out, $start, $maxBlock, $window);
                        break;
                    default: throw new FormatError('Reserved Zstd block type');
                }
            } while (($header & 1) === 0);
            require_valid($length === 0 || strlen($out) - $start === $size, 'Zstd content size mismatch');
            if (($descriptor & 4) !== 0)
                require_valid($r->u32() === (self::xxh64($out, $start) & 0xffffffff), 'Zstd checksum mismatch');
        }
        return $out;
    }

    private const P1 = -0x61c8864e7a143579;
    private const P2 = -0x3d4d51c2d82b14b1;
    private const P3 = 0x165667b19e3779f9;
    private const P4 = -0x7a1435883d4d519d;
    private const P5 = 0x27d4eb2f165667c5;

    private static function rol(int $v, int $n): int { return ($v << $n) | shr64($v, 64 - $n); }

    private static function round(int $acc, int $lane): int
    {
        return mul64(self::rol(add64($acc, mul64($lane, self::P2)), 31), self::P1);
    }

    private static function xxh64(string $data, int $i): int
    {
        $end = strlen($data);
        $n = $end - $i;
        $hash = self::P5;
        if ($n >= 32) {
            $lanes = [add64(self::P1, self::P2), self::P2, 0, -self::P1];
            while ($i <= $end - 32) {
                for ($j = 0; $j < 4; $j++, $i += 8)
                    $lanes[$j] = self::round($lanes[$j], unpack('P', $data, $i)[1]);
            }
            $hash = add64(add64(self::rol($lanes[0], 1), self::rol($lanes[1], 7)),
                add64(self::rol($lanes[2], 12), self::rol($lanes[3], 18)));
            foreach ($lanes as $lane)
                $hash = add64(mul64($hash ^ self::round(0, $lane), self::P1), self::P4);
        }
        $hash = add64($hash, $n);
        while ($i <= $end - 8) {
            $hash = add64(mul64(self::rol($hash ^ self::round(0, unpack('P', $data, $i)[1]), 27), self::P1), self::P4);
            $i += 8;
        }
        if ($i <= $end - 4) {
            $hash = add64(mul64(self::rol($hash ^ mul64(unpack('V', $data, $i)[1], self::P1), 23), self::P2), self::P3);
            $i += 4;
        }
        while ($i < $end) {
            $hash = mul64(self::rol($hash ^ mul64(ord($data[$i++]), self::P5), 11), self::P1);
        }
        $hash = mul64($hash ^ shr64($hash, 33), self::P2);
        $hash = mul64($hash ^ shr64($hash, 29), self::P3);
        return $hash ^ shr64($hash, 32);
    }
}
