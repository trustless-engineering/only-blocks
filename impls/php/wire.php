<?php
declare(strict_types=1);

final class FormatError extends RuntimeException {}
final class CborBytes { public function __construct(public readonly string $data) {} }
final class CborMap { public function __construct(public readonly bool $hasVersion) {} }

// PHP stores a u64's bits in a signed int. RawNumber preserves its unsigned JSON spelling.
final class RawNumber { public function __construct(public readonly string $text) {} }

function require_valid(bool $condition, string $message = 'Invalid archive data'): void
{
    if (!$condition) throw new FormatError($message);
}

function unsigned_json(int $bits): int|RawNumber
{
    return $bits < 0 ? new RawNumber(sprintf('%u', $bits)) : $bits;
}

function unsigned_decimal(string $text): ?int
{
    if (!preg_match('/\A\+?[0-9]+\z/D', $text)) return null;
    $digits = ltrim($text, '+0');
    if (strlen($digits) > 20 || (strlen($digits) === 20 && strcmp($digits, '18446744073709551615') > 0)) return null;
    $low = $high = 0;
    for ($i = 0; $i < strlen($digits); $i++) {
        $low = $low * 10 + ord($digits[$i]) - 48;
        $high = $high * 10 + ($low >> 32);
        $low &= 0xffffffff;
    }
    return ($high << 32) | $low;
}

function shr64(int $value, int $bits): int
{
    return ($value >> $bits) & (PHP_INT_MAX >> ($bits - 1));
}

function add64(int $a, int $b): int
{
    $low = ($a & 0xffffffff) + ($b & 0xffffffff);
    return ((($a >> 32) + ($b >> 32) + ($low >> 32)) << 32) | ($low & 0xffffffff);
}

function mul64(int $a, int $b): int
{
    // The product of two 32-bit halves may exceed PHP_INT_MAX. Split the low
    // product into 16-bit limbs and accumulate the cross products modulo 2^32.
    $a0 = $a & 0xffff;
    $a1 = ($a >> 16) & 0xffff;
    $b0 = $b & 0xffff;
    $b1 = ($b >> 16) & 0xffff;
    $bottom = $a0 * $b0;
    $middle = ($bottom >> 16) + $a0 * $b1 + $a1 * $b0;
    $crossA = ($a >> 32) * (($b << 32) >> 32);
    $crossB = ($b >> 32) * (($a << 32) >> 32);
    $top = ($middle >> 16) + $a1 * $b1 + ($crossA & 0xffffffff) + ($crossB & 0xffffffff);
    return ($top << 32) | (($middle & 0xffff) << 16) | ($bottom & 0xffff);
}

function utf8(string $data): string
{
    require_valid(preg_match('//u', $data) === 1, 'Invalid UTF-8');
    return $data;
}

final class Reader
{
    public int $pos;
    private readonly int $end;

    public function __construct(public readonly string $data, int $start = 0, ?int $end = null)
    {
        $this->pos = $start;
        $this->end = $end ?? strlen($data);
    }

    public function left(): int { return $this->end - $this->pos; }
    public function peek(): int
    {
        require_valid($this->left() > 0, 'Truncated input');
        return ord($this->data[$this->pos]);
    }

    public function skip(int $n): int
    {
        require_valid($n >= 0 && $n <= $this->left(), 'Truncated input');
        $start = $this->pos;
        $this->pos += $n;
        return $start;
    }

    public function take(int $n): string { return substr($this->data, $this->skip($n), $n); }
    public function section(int $n): self
    {
        $start = $this->skip($n);
        return new self($this->data, $start, $start + $n);
    }
    public function u8(): int { return ord($this->data[$this->skip(1)]); }
    public function u32(): int { return unpack('V', $this->data, $this->skip(4))[1]; }
    public function u64(): int { return unpack('P', $this->data, $this->skip(8))[1]; }
    public function f64(): float { return unpack('e', $this->data, $this->skip(8))[1]; }

    public function le(int $n): int
    {
        $start = $this->skip($n);
        $v = 0;
        for ($i = $n - 1; $i >= 0; $i--) $v = ($v << 8) | ord($this->data[$start + $i]);
        return $v;
    }

    public function varint(): int
    {
        $v = 0;
        for ($i = 0; $i < 10; $i++) {
            $b = $this->u8();
            require_valid($i !== 9 || $b <= 1, 'Varint overflow');
            $v |= ($b & 127) << ($i * 7);
            if ($b < 128) return $v;
        }
        throw new FormatError('Varint overflow');
    }

    public function compact(): int
    {
        $v = 0;
        for ($i = 0; $i < 3; $i++) {
            $b = $this->u8();
            require_valid(($i === 0 || $b !== 0) && ($i !== 2 || $b <= 3), 'Invalid compact-u16');
            $v |= ($b & 127) << ($i * 7);
            if ($b < 128) return $v;
        }
        throw new FormatError('Invalid compact-u16');
    }

    public function count(int $n, int $minimum = 1): int
    {
        require_valid($n >= 0 && $n <= intdiv($this->left(), $minimum), 'Length exceeds enclosing value');
        return $n;
    }

    public function items(int $n, int $minimum, callable $read): array
    {
        $this->count($n, $minimum);
        $result = [];
        for ($i = 0; $i < $n; $i++) $result[] = $read();
        return $result;
    }
}

function base58(string $bytes): string
{
    $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    $zero = strspn($bytes, "\0");
    // Limbs in base 58^5 avoid a division per character for each input byte.
    $digits = [];
    for ($i = $zero, $length = strlen($bytes); $i < $length; $i++) {
        $carry = ord($bytes[$i]);
        for ($j = 0, $n = count($digits); $j < $n; $j++) {
            $carry += $digits[$j] << 8;
            $digits[$j] = $carry % 656356768;
            $carry = intdiv($carry, 656356768);
        }
        if ($carry > 0) $digits[] = $carry;
    }
    $out = '';
    for ($i = count($digits) - 1; $i >= 0; $i--) {
        $value = $digits[$i];
        $group = '11111';
        for ($j = 4; $j >= 0; $j--) {
            $group[$j] = $alphabet[$value % 58];
            $value = intdiv($value, 58);
        }
        $out .= $i === count($digits) - 1 ? ltrim($group, '1') : $group;
    }
    return str_repeat('1', $zero) . $out;
}

function hash_matches(string $data, int $expected): bool
{
    static $table = [];
    if ($table === []) {
        // D800000000000000 as a signed two's-complement value.
        $polynomial = -0x2800000000000000;
        for ($i = 0; $i < 256; $i++) {
            $value = $i;
            for ($j = 0; $j < 8; $j++) $value = shr64($value, 1) ^ (($value & 1) ? $polynomial : 0);
            $table[] = $value;
        }
    }
    $crc = -1;
    for ($i = 0, $length = strlen($data); $i < $length; $i++)
        $crc = (($crc >> 8) & 0x00ffffffffffffff) ^ $table[($crc ^ ord($data[$i])) & 255];
    if (~$crc === $expected) return true;
    $fnv = -0x340d631b7bdddcdb;
    for ($i = 0; $i < $length; $i++) {
        $fnv ^= ord($data[$i]);
        // FNV prime = (1 << 40) + 435.
        $low = ($fnv & 0xffffffff) * 435;
        $high = ($fnv >> 32) * 435 + ($low >> 32);
        $fnv = add64(($high << 32) | ($low & 0xffffffff), $fnv << 40);
    }
    return $fnv === $expected;
}

function cbor(Reader $r, int $depth = 0): mixed
{
    require_valid($depth < 128, 'CBOR nesting too deep');
    $initial = $r->u8();
    $major = $initial >> 5;
    $info = $initial & 31;
    $indefinite = $info === 31;
    require_valid($info < 28 || ($indefinite && $major >= 2 && $major <= 5));
    $arg = $info < 24 ? $info : 0;
    if ($info >= 24 && !$indefinite)
        for ($i = 0, $n = 1 << ($info - 24); $i < $n; $i++) $arg = ($arg << 8) | $r->u8();

    switch ($major) {
        case 0: return unsigned_json($arg);
        case 1: return $arg >= 0 ? -1 - $arg : null;
        case 2:
        case 3:
            $text = '';
            if ($indefinite) {
                while ($r->peek() !== 255) {
                    $next = $r->peek();
                    require_valid(($next >> 5) === $major && ($next & 31) !== 31, 'Invalid CBOR string chunk');
                    $part = cbor($r, $depth + 1);
                    $text .= $major === 2 ? $part->data : $part;
                }
                $r->u8();
            } else $text = $r->take($r->count($arg));
            return $major === 2 ? new CborBytes($text) : utf8($text);
        case 4:
            if (!$indefinite) return $r->items($arg, 1, fn() => cbor($r, $depth + 1));
            $items = [];
            while ($r->peek() !== 255) $items[] = cbor($r, $depth + 1);
            $r->u8();
            return $items;
        case 5:
            $version = false;
            $count = $indefinite ? 0 : $r->count($arg, 2);
            while ($indefinite ? $r->peek() !== 255 : $count-- > 0) {
                if (cbor($r, $depth + 1) === 'version') $version = true;
                cbor($r, $depth + 1);
            }
            if ($indefinite) $r->u8();
            return new CborMap($version);
        case 6: return cbor($r, $depth + 1);
        default:
            return match ($info) {
                20 => false, 21 => true, 22, 23 => null,
                25 => half_float($arg), 26 => unpack('G', pack('N', $arg))[1],
                27 => unpack('e', pack('P', $arg))[1],
                default => throw new FormatError('Unknown CBOR simple value'),
            };
    }
}

function half_float(int $bits): float
{
    $exp = ($bits >> 10) & 31;
    $mantissa = $bits & 1023;
    $value = match ($exp) {
        0 => $mantissa * 2 ** -24,
        31 => $mantissa === 0 ? INF : NAN,
        default => (1024 + $mantissa) * 2 ** ($exp - 25),
    };
    return ($bits & 32768) ? -$value : $value;
}

function cbor_exact(Reader $r): mixed
{
    $value = cbor($r);
    require_valid($r->left() === 0, 'Trailing CBOR data');
    return $value;
}

function cbor_uint(mixed $value): ?int
{
    if ($value instanceof RawNumber) return unsigned_decimal($value->text);
    return is_int($value) && $value >= 0 ? $value : null;
}

function cid(Reader $r): array
{
    $start = $r->pos;
    $version = $r->varint();
    $codec = $r->varint();
    $absent = false;
    if ($version === 18 && $codec === 32) $r->skip(32);
    else {
        require_valid($version === 1, 'Unsupported CID version');
        $hash = $r->varint();
        $length = $r->varint();
        require_valid($length >= 0 && $length <= 64, 'CID digest too large');
        $r->skip($length);
        $absent = $hash === 0 && $length === 0;
    }
    return [substr($r->data, $start, $r->pos - $start), $absent];
}

function cid_link(mixed $value): array
{
    require_valid($value instanceof CborBytes && str_starts_with($value->data, "\0"), 'Invalid CAR link');
    return cid(new Reader($value->data, 1));
}

function links(mixed $value): array
{
    return is_array($value) ? array_map(fn($link) => cid_link($link)[0], $value) : [];
}

final class Car
{
    public const ZERO_HASH = '11111111111111111111111111111111';
    private array $nodes = [];
    public readonly int $slot;
    public readonly int $parent;
    public readonly ?int $time;
    public readonly int|RawNumber|null $height;
    public readonly array $entries;
    public readonly ?string $rewards;

    public function __construct(private readonly string $data)
    {
        $reader = new Reader($data);
        $first = true;
        $block = null;
        while ($reader->left() > 0) {
            $size = $reader->varint();
            if ($size === 0) continue;
            require_valid($size > 0 && $size <= 32 * 1024 * 1024, 'CAR section too large');
            $section = $reader->section($size);
            $isHeader = false;
            if ($first && $section->peek() >> 5 === 5) {
                try {
                    $header = cbor_exact(clone $section);
                    $isHeader = $header instanceof CborMap && $header->hasVersion;
                } catch (FormatError) {}
            }
            $first = false;
            if ($isHeader) continue;

            [$key] = cid($section);
            $this->nodes[$key] = [$section->pos, $section->pos + $section->left()];
            if ($section->left() < 2 || $section->peek() >> 5 !== 4) continue;
            $info = $section->peek() & 31;
            if ($info >= 28 && $info <= 30) continue;
            $offset = $info < 24 || $info === 31 ? 1 : 1 + (1 << ($info - 24));
            if ($section->left() > $offset && ord($data[$section->pos + $offset]) === 2) $block = $section;
        }
        require_valid($block !== null, 'Missing block node');
        $node = self::kind(cbor_exact($block), 2);
        $this->slot = cbor_uint($node[1] ?? null) ?? throw new FormatError('Missing block slot');
        $this->entries = links($node[3] ?? null);
        $meta = is_array($node[4] ?? null) ? $node[4] : [];
        $this->parent = cbor_uint($meta[0] ?? null) ?? 0;
        $time = $meta[1] ?? null;
        $this->time = is_int($time) && $time !== 0 ? $time : null;
        $height = cbor_uint($meta[2] ?? null);
        $this->height = $height === null ? null : unsigned_json($height);
        $link = $node[5] ?? null;
        [$key, $absent] = $link instanceof CborBytes ? cid_link($link) : [null, true];
        $this->rewards = $absent ? null : $key;
    }

    private static function kind(mixed $node, int $kind): array
    {
        require_valid(is_array($node) && ($node[0] ?? null) === $kind, 'Unexpected CAR node kind');
        return $node;
    }

    public function contains(string $key): bool { return isset($this->nodes[$key]); }

    public function node(string $key, int $kind): array
    {
        require_valid(isset($this->nodes[$key]), 'Missing CAR link');
        [$start, $end] = $this->nodes[$key];
        return self::kind(cbor_exact(new Reader($this->data, $start, $end)), $kind);
    }

    private static function entryHash(array $entry): string
    {
        $hash = $entry[2] ?? null;
        require_valid($hash instanceof CborBytes && strlen($hash->data) === 32, 'Invalid entry hash');
        return $hash->data;
    }

    public function hash(): string
    {
        if ($this->entries === []) return self::ZERO_HASH;
        $entry = $this->node($this->entries[array_key_last($this->entries)], 1);
        links($entry[3] ?? null);
        return base58(self::entryHash($entry));
    }

    public function transactions(): Generator
    {
        foreach ($this->entries as $key) {
            $entry = $this->node($key, 1);
            self::entryHash($entry);
            yield from links($entry[3] ?? null);
        }
    }

    public function frame(mixed $value): string
    {
        $node = self::kind($value, 6);
        $bytes = static fn(array $frame) => ($frame[4] ?? null) instanceof CborBytes ? $frame[4]->data : '';
        $out = $bytes($node);
        $expected = cbor_uint($node[1] ?? null);
        $stack = array_reverse(links($node[5] ?? null));
        $visited = [];
        while ($stack !== []) {
            $key = array_pop($stack);
            require_valid(!isset($visited[$key]), 'Repeated DataFrame CID');
            $visited[$key] = true;
            $frame = $this->node($key, 6);
            $part = $bytes($frame);
            require_valid(strlen($out) + strlen($part) <= 512 * 1024 * 1024, 'DataFrame too large');
            $out .= $part;
            foreach (array_reverse(links($frame[5] ?? null)) as $continuation) $stack[] = $continuation;
        }
        require_valid($expected === null || hash_matches($out, $expected), 'DataFrame hash mismatch');
        return $out;
    }
}
