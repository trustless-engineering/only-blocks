<?php
declare(strict_types=1);

require __DIR__ . '/wire.php';
require __DIR__ . '/zstd.php';
require __DIR__ . '/metadata.php';
require __DIR__ . '/transaction.php';
require __DIR__ . '/http.php';

final class RpcError extends RuntimeException {}

final class Options
{
    public function __construct(
        public readonly string $encoding,
        public readonly string $details,
        public readonly bool $rewards,
        public readonly bool $hasVersion,
    ) {}
}

final class CacheNode
{
    public ?self $older = null, $newer = null;
    public function __construct(public readonly int $key, public mixed $value) {}
}

final class Lru
{
    private const CAPACITY = 100_000;
    private array $index = [];
    private ?CacheNode $oldest = null, $newest = null;

    private function unlink(CacheNode $node): void
    {
        if ($node->older !== null) $node->older->newer = $node->newer;
        else $this->oldest = $node->newer;
        if ($node->newer !== null) $node->newer->older = $node->older;
        else $this->newest = $node->older;
        $node->older = $node->newer = null;
    }

    private function touch(CacheNode $node): void
    {
        $node->older = $this->newest;
        if ($this->newest === null) $this->oldest = $node;
        else $this->newest->newer = $node;
        $this->newest = $node;
    }

    public function get(int $key): mixed
    {
        $node = $this->index[$key] ?? null;
        if ($node === null) return null;
        $this->unlink($node);
        $this->touch($node);
        return $node->value;
    }

    public function set(int $key, mixed $value): void
    {
        if (isset($this->index[$key])) {
            $node = $this->index[$key];
            $this->unlink($node);
            $node->value = $value;
        } else $node = $this->index[$key] = new CacheNode($key, $value);
        $this->touch($node);

        if (count($this->index) > self::CAPACITY) {
            $old = $this->oldest;
            $this->unlink($old);
            unset($this->index[$old->key]);
        }
    }
}

final class Archive
{
    private const SLICE_LIMIT = 128 * 1024 * 1024;
    private readonly Lru $ranges, $hashes;

    public function __construct(private readonly RangeOrigin $origin)
    {
        $this->ranges = new Lru();
        $this->hashes = new Lru();
    }

    private function load(int $slot): Car
    {
        // Unsigned division by an even divisor without converting to double.
        $half = shr64($slot, 1);
        $epoch = intdiv($half, 216_000);
        $slotIndex = ($half % 216_000) * 2 + ($slot & 1);
        $prefix = "/$epoch/epoch-$epoch";
        $range = $this->ranges->get($slot);
        if ($range === null) {
            $reader = new Reader($this->origin->get($prefix . '-slot-ranges.raw', $slot, $slotIndex * 12, 12, 12));
            $range = [$reader->u64(), $reader->u32()];
            $this->ranges->set($slot, $range);
        }
        [$offset, $length] = $range;
        if ($length === 0) throw new RpcError('Slot ' . sprintf('%u', $slot) . ' was skipped', -32007);
        require_valid($length <= self::SLICE_LIMIT, 'CAR slice exceeds limit');
        return new Car($this->origin->get($prefix . '.car', $slot, $offset, $length, self::SLICE_LIMIT));
    }

    public function block(int $slot, Options $options): array
    {
        $car = $this->load($slot);
        require_valid($car->slot === $slot, 'CAR slot mismatch');
        $hash = $car->hash();
        $this->hashes->set($slot, $hash);

        if ($slot === 0) $previous = Car::ZERO_HASH;
        else {
            $previous = $this->hashes->get($car->parent);
            if ($previous === null) {
                $previous = $this->load($car->parent)->hash();
                $this->hashes->set($car->parent, $previous);
            }
        }

        $result = [
            'previousBlockhash' => $previous, 'blockhash' => $hash, 'parentSlot' => unsigned_json($car->parent),
            'blockTime' => $car->time, 'blockHeight' => $car->height,
        ];
        if ($options->details !== 'none') {
            $transactions = [];
            $signatures = $options->details === 'signatures';
            foreach ($car->transactions() as $key) {
                $node = $car->node($key, 0);
                $tx = new Transaction($car->frame($node[1] ?? null));
                if ($signatures) {
                    require_valid($tx->signatures !== [], 'Transaction has no signatures');
                    $transactions[] = base58($tx->signatures[0]);
                    continue;
                }
                $frame = $node[2] ?? null;
                $meta = is_array($frame) ? Metadata::meta($slot, $car->frame($frame)) : null;
                if ($tx->v0) {
                    if (!$options->hasVersion) throw new RpcError('Transaction version 0 requires maxSupportedTransactionVersion', -32015);
                    $meta ??= new Meta();
                }
                $transactions[] = $tx->json($meta, $options);
            }
            $result[$signatures ? 'signatures' : 'transactions'] = $transactions;
        }
        if ($options->rewards) {
            $rewards = [];
            if ($car->rewards !== null && $car->contains($car->rewards)) {
                $node = $car->node($car->rewards, 5);
                if (array_key_exists(2, $node)) {
                    [$rewards, $partitions] = Metadata::rewards($slot, $car->frame($node[2]));
                    if ($partitions !== null) $result['numRewardPartitions'] = $partitions;
                }
            }
            $result['rewards'] = $rewards;
        }
        return $result;
    }
}

final class Rpc
{
    public function __construct(private readonly Archive $archive) {}

    private static function parse(string $body): mixed
    {
        // Preserve every numeric token, including exponent and fractional spelling.
        // Prefix strings and object keys with ~s so they cannot collide with ~n.
        // json_decode still validates nesting, UTF-8, escapes and the JSON grammar.
        $pattern = <<<'REGEX'
~\G(?:"[^"\\]*+(?:\\.[^"\\]*+)*+"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|[][{}:,\x20\t\r\n]++)~s
REGEX;
        $used = 0;
        $tagged = preg_replace_callback($pattern, static function (array $match) use (&$used, $body): string {
            $token = $match[0];
            $used += strlen($token);
            $first = $token[0];
            if ($first === '"') return '"~s' . substr($token, 1);
            if ($first === '-' || ($first >= '0' && $first <= '9')) {
                $next = $used + strspn($body, " \t\r\n", $used);
                if (($body[$next] ?? '') === ':') throw new JsonException('Invalid JSON object key');
                return '"~n' . $token . '"';
            }
            return $token;
        }, $body);
        if ($tagged === null || $used !== strlen($body)) throw new JsonException('Invalid JSON');
        return json_decode($tagged, false, 129, JSON_THROW_ON_ERROR);
    }

    private static function encode(mixed $value): string
    {
        if ($value instanceof RawNumber) return $value->text;
        if (!is_array($value)) return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        if (array_is_list($value)) {
            $out = '[';
            foreach ($value as $i => $item) $out .= ($i === 0 ? '' : ',') . self::encode($item);
            return $out . ']';
        }
        $out = '{';
        $separator = '';
        foreach ($value as $key => $item) {
            $out .= $separator . self::encode((string)$key) . ':' . self::encode($item);
            $separator = ',';
        }
        return $out . '}';
    }

    private static function text(mixed $value): ?string
    {
        return is_string($value) && str_starts_with($value, '~s') ? substr($value, 2) : null;
    }

    private static function error(int $code, string $message, mixed $id = null): array
    {
        return ['jsonrpc' => '2.0', 'error' => compact('code', 'message'), 'id' => $id];
    }

    private static function invalidParams(): RpcError { return new RpcError('Invalid params', -32602); }

    private static function uint(mixed $value, ?int $max = null): int
    {
        if (!is_string($value) || !str_starts_with($value, '~n')) throw self::invalidParams();
        $raw = substr($value, 2);
        if (!preg_match('/\A(?:0|[1-9][0-9]{0,19})\z/D', $raw)) throw self::invalidParams();
        $integer = unsigned_decimal($raw);
        if ($integer === null || ($max !== null && ($integer < 0 || $integer > $max))) throw self::invalidParams();
        return $integer;
    }

    private static function blockParams(mixed $params): array
    {
        if (!is_array($params) || count($params) < 1 || count($params) > 2) throw self::invalidParams();
        $slot = self::uint($params[0]);
        $config = $params[1] ?? null;
        if ($config !== null && !is_object($config) && self::text($config) === null) throw self::invalidParams();

        $option = static function (string $key, string $default) use ($config): string {
            $value = is_object($config) ? ($config->{'~s' . $key} ?? null) : null;
            return $value === null ? $default : (self::text($value) ?? throw self::invalidParams());
        };
        $encoding = self::text($config) ?? $option('encoding', 'json');
        $details = $option('transactionDetails', 'full');
        $rewards = is_object($config) ? ($config->{'~srewards'} ?? true) : true;
        $version = is_object($config) ? ($config->{'~smaxSupportedTransactionVersion'} ?? null) : null;
        if (!in_array($encoding, ['json', 'jsonParsed', 'base64', 'base58'], true) ||
            !in_array($details, ['full', 'accounts', 'signatures', 'none'], true) ||
            ($details === 'accounts' && $encoding !== 'json') || !is_bool($rewards) ||
            !in_array($option('commitment', 'finalized'), ['finalized', 'confirmed'], true))
            throw self::invalidParams();
        if ($version !== null) self::uint($version, 255);
        return [$slot, new Options($encoding, $details, $rewards, $version !== null)];
    }

    private function dispatch(mixed $request): array
    {
        if (!is_object($request)) return self::error(-32600, 'Invalid Request');
        $version = $request->{'~sjsonrpc'} ?? null;
        $method = $request->{'~smethod'} ?? null;
        $name = self::text($method);
        if (($version !== null && self::text($version) === null) || ($method !== null && $name === null))
            return self::error(-32600, 'Invalid Request');

        $id = $request->{'~sid'} ?? null;
        if (is_string($id) && str_starts_with($id, '~n')) $id = new RawNumber(substr($id, 2));
        elseif ($id !== null && ($id = self::text($id)) === null) return self::error(-32600, 'Invalid Request');
        if (self::text($version) !== '2.0' || $name === null) return self::error(-32600, 'Invalid Request', $id);
        try {
            if ($name === 'getHealth') {
                $params = $request->{'~sparams'} ?? null;
                if ($params !== null && $params !== []) throw self::invalidParams();
                $result = 'ok';
            } elseif ($name === 'getBlock') {
                $result = $this->archive->block(...self::blockParams($request->{'~sparams'} ?? null));
            } else return self::error(-32601, "Method not found: $name", $id);
            return ['jsonrpc' => '2.0', 'result' => $result, 'id' => $id];
        } catch (RpcError $error) {
            return self::error($error->getCode(), $error->getMessage(), $id);
        } catch (Throwable $error) {
            return self::error(-32603, $error->getMessage() ?: 'Internal error', $id);
        }
    }

    public function handle(string $body): string
    {
        try { $input = self::parse($body); }
        catch (JsonException) { return self::encode(self::error(-32700, 'Parse error')); }
        if (is_array($input)) {
            $answer = count($input) >= 1 && count($input) <= 100
                ? array_map($this->dispatch(...), $input) : self::error(-32600, 'Invalid batch size');
        } else $answer = $this->dispatch($input);
        return self::encode($answer);
    }
}

function serve($socket, Rpc $rpc): void
{
    $body = '';
    try {
        $connection = new HttpStream($socket, hrtime(true) / 1e9 + 10);
        $line = $connection->line();
        if (!preg_match('/\A([^ ]+) ([^ ]+) HTTP\/1\.[01]\z/D', $line, $matches))
            throw new HttpError('Bad request line', 400);
        if ($matches[1] !== 'POST' || $matches[2] !== '/') throw new HttpError('Not found', 404);
        $raw = $connection->body($connection->headers(), 1024 * 1024);
        $body = $rpc->handle($raw);
        $status = '200 OK';
    } catch (HttpError $error) {
        $status = match ($error->getCode()) {
            404 => '404 Not Found', 413 => '413 Payload Too Large', default => '400 Bad Request',
        };
    } catch (TransportError) {
        return;
    }

    $response = new HttpStream($socket, hrtime(true) / 1e9 + 10);
    try {
        $response->write("HTTP/1.1 $status\r\nConnection: close\r\nContent-Length: " . strlen($body) .
            ($body === '' ? '' : "\r\nContent-Type: application/json") . "\r\n\r\n");
        if ($body !== '') $response->write($body);
    } catch (TransportError) {}
}

function run(array $args): void
{
    $values = [
        '--bind' => getenv('ONLYBLOCKS_BIND') !== false ? getenv('ONLYBLOCKS_BIND') : '127.0.0.1:8899',
        '--base-url' => getenv('OLD_FAITHFUL_BASE_URL') !== false ? getenv('OLD_FAITHFUL_BASE_URL') : 'https://files.old-faithful.net',
    ];
    for ($i = 1; $i < count($args); $i++) {
        $parts = explode('=', $args[$i], 2);
        if (!array_key_exists($parts[0], $values)) throw new InvalidArgumentException('Unknown flag ' . $parts[0]);
        $values[$parts[0]] = $parts[1] ?? $args[++$i] ?? throw new InvalidArgumentException('Missing flag value');
    }
    $address = $values['--bind'];
    if (!preg_match('/\A(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):([0-9]{1,5})\z/D', $address, $port) ||
        (int)$port[1] < 1 || (int)$port[1] > 65535)
        throw new InvalidArgumentException('--bind requires HOST:PORT');
    $rpc = new Rpc(new Archive(new RangeOrigin($values['--base-url'])));
    $server = @stream_socket_server('tcp://' . $address, $code, $message);
    if ($server === false) throw new RuntimeException("Listen failed: $message");

    pcntl_async_signals(true);
    pcntl_signal(SIGTERM, static fn() => exit(0));
    pcntl_signal(SIGINT, static fn() => exit(0));
    while (true) {
        $socket = @stream_socket_accept($server, -1);
        if ($socket === false) continue;
        try { serve($socket, $rpc); }
        catch (Throwable $error) { fwrite(STDERR, $error->getMessage() . "\n"); }
        finally { fclose($socket); }
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    try { run($argv); }
    catch (Throwable $error) {
        fwrite(STDERR, $error->getMessage() . "\n");
        exit(1);
    }
}
