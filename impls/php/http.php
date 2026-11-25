<?php
declare(strict_types=1);

final class TransportError extends RuntimeException {}
final class HttpError extends RuntimeException {}

final class HttpStream
{
    // The stream API handles native TCP, buffering and TLS. Framing remains
    // explicit so a short body differs from a complete body of the wrong length.
    public function __construct(private $socket, private readonly float $deadline) {}

    private function timeLeft(): void
    {
        $left = $this->deadline - hrtime(true) / 1e9;
        if ($left <= 0) throw new TransportError('HTTP deadline exceeded');
        $micros = max(1, (int)($left * 1_000_000));
        stream_set_timeout($this->socket, intdiv($micros, 1_000_000), $micros % 1_000_000);
    }

    public function write(string $body): void
    {
        for ($i = 0, $n = strlen($body); $i < $n;) {
            $this->timeLeft();
            $written = @fwrite($this->socket, substr($body, $i, 65536));
            if ($written === false || $written === 0) throw new TransportError('HTTP write failed');
            $i += $written;
        }
    }

    public function line(): string
    {
        $this->timeLeft();
        $line = @fgets($this->socket, 8194);
        if ($line === false) throw new TransportError('Incomplete HTTP line');
        if (!str_ends_with($line, "\r\n")) {
            if (strlen($line) === 8193) throw new HttpError('HTTP line too large', 400);
            throw new TransportError('Incomplete HTTP line');
        }
        return substr($line, 0, -2);
    }

    public function headers(): array
    {
        $headers = [];
        for ($used = 0; ($line = $this->line()) !== '';) {
            $used += strlen($line) + 2;
            $pos = strpos($line, ':');
            if ($used > 32768 || $pos === false || $pos === 0)
                throw new HttpError('Invalid HTTP header', 400);
            $key = strtolower(substr($line, 0, $pos));
            $value = trim(substr($line, $pos + 1), " \t");
            if (!preg_match("/\\A[!#\$%&'*+.^_\x60|~0-9a-z-]+\\z/D", $key))
                throw new HttpError('Invalid HTTP header name', 400);
            $headers[$key][] = $value;
        }
        return $headers;
    }

    private function read(int $n): string
    {
        $this->timeLeft();
        $bytes = @fread($this->socket, min(65536, $n));
        if ($bytes === false || ($bytes === '' && !feof($this->socket)))
            throw new TransportError('HTTP read failed');
        return $bytes;
    }

    private function append(string &$body, int $n): void
    {
        while ($n > 0) {
            $bytes = $this->read($n);
            if ($bytes === '') throw new TransportError('Incomplete HTTP body');
            $body .= $bytes;
            $n -= strlen($bytes);
        }
    }

    public function body(array $headers, int $cap, bool $readToClose = false): string
    {
        $lengths = $headers['content-length'] ?? [];
        $encodings = $headers['transfer-encoding'] ?? [];
        if (count($lengths) > 1 || ($encodings !== [] && ($lengths !== [] ||
            count($encodings) !== 1 || strcasecmp($encodings[0], 'chunked') !== 0)))
            throw new HttpError('Invalid HTTP framing', 400);

        $body = '';
        if ($lengths !== []) {
            if (!preg_match('/\A[0-9]+\z/D', $lengths[0])) throw new HttpError('Invalid Content-Length', 400);
            $digits = ltrim($lengths[0], '0');
            if (strlen($digits) > 9 || (int)$digits > $cap) throw new HttpError('HTTP body exceeds limit', 413);
            $this->append($body, (int)$digits);
        } elseif ($encodings !== []) {
            while (true) {
                $line = explode(';', $this->line(), 2)[0];
                if (!preg_match('/\A[0-9a-fA-F]+\z/D', $line)) throw new HttpError('Invalid chunk length', 400);
                $digits = ltrim($line, '0');
                if (strlen($digits) > 7) throw new HttpError('HTTP body exceeds limit', 413);
                $size = (int)hexdec($digits);
                if ($size === 0) {
                    $this->headers();
                    break;
                }
                if ($size > $cap - strlen($body)) throw new HttpError('HTTP body exceeds limit', 413);
                $this->append($body, $size);
                if ($this->line() !== '') throw new HttpError('Invalid chunk boundary', 400);
            }
        } elseif ($readToClose) {
            while (($chunk = $this->read($cap - strlen($body) + 1)) !== '') {
                if (strlen($chunk) > $cap - strlen($body)) throw new HttpError('HTTP body exceeds limit', 413);
                $body .= $chunk;
            }
        }
        return $body;
    }
}

final class RangeOrigin
{
    private readonly string $endpoint, $authority, $prefix;
    private readonly bool $secure;

    public function __construct(string $url)
    {
        $url = rtrim(trim($url), '/');
        $parts = parse_url($url);
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = $parts['host'] ?? '';
        if ($host === '' || !in_array($scheme, ['http', 'https'], true) ||
            isset($parts['query']) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass']) ||
            preg_match('/[\x00-\x20\x7f]/', $url))
            throw new InvalidArgumentException('--base-url requires an HTTP or HTTPS origin');
        $this->secure = $scheme === 'https';
        $port = $parts['port'] ?? ($this->secure ? 443 : 80);
        $this->endpoint = ($this->secure ? 'tls://' : 'tcp://') . $host . ':' . $port;
        $this->authority = $host . (isset($parts['port']) ? ':' . $port : '');
        $this->prefix = $parts['path'] ?? '';
    }

    private function attempt(string $path, int $start, int $end, int $cap): array
    {
        $deadline = hrtime(true) / 1e9 + 60;
        $context = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $socket = @stream_socket_client($this->endpoint, $code, $message, 10, STREAM_CLIENT_CONNECT, $context);
        if ($socket === false) throw new TransportError("Old Faithful connection failed");
        try {
            $connection = new HttpStream($socket, $deadline);
            $range = sprintf('bytes=%u-%u', $start, $end);
            $connection->write("GET {$this->prefix}{$path} HTTP/1.1\r\nHost: {$this->authority}\r\n" .
                "Range: $range\r\nUser-Agent: onlyblocks/php\r\nConnection: close\r\n\r\n");
            do {
                $line = $connection->line();
                if (!preg_match('/\AHTTP\/1\.[01] ([1-5][0-9]{2})(?: .*)?\z/D', $line, $m))
                    throw new HttpError('Invalid upstream status line', 400);
                $status = (int)$m[1];
                $headers = $connection->headers();
            } while ($status < 200 && $status !== 101);

            return [$status, $headers['retry-after'][0] ?? null,
                $status === 206 ? $connection->body($headers, $cap, true) : ''];
        } finally {
            fclose($socket);
        }
    }

    private static function delay(?string $retry, int $attempt): float
    {
        if ($retry !== null) {
            if (preg_match('/\A[0-9]+\z/D', $retry)) return min(10, (int)$retry);
            if (preg_match('/\A[A-Za-z]{3,9}[, ]/', $retry) && ($when = strtotime($retry)) !== false)
                return max(0, min(10, $when - time()));
        }
        return 0.2 * (1 << $attempt) * random_int(500, 1000) / 1000;
    }

    public function get(string $path, int $slot, int $start, int $length, int $cap): string
    {
        $end = add64($start, $length - 1);
        require_valid(!(($end ^ PHP_INT_MIN) < ($start ^ PHP_INT_MIN)), 'Range end overflow');
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $retry = null;
            try {
                [$status, $retry, $body] = $this->attempt($path, $start, $end, $cap);
                if ($status === 404) throw new RpcError('Block not available for slot ' . sprintf('%u', $slot), -32004);
                if ($status === 206) {
                    require_valid(strlen($body) === $length, 'Range body length mismatch');
                    return $body;
                }
                require_valid($status === 429 || $status >= 500, "Unexpected upstream HTTP $status");
            } catch (TransportError) {
                // Retry an incomplete response as well as a failed connection.
            }
            if ($attempt < 4) usleep((int)(self::delay($retry, $attempt) * 1_000_000));
        }
        throw new FormatError('Old Faithful retries exhausted');
    }
}
