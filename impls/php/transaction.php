<?php
declare(strict_types=1);

final class Transaction
{
    private const UPGRADEABLE_LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111';
    private const RESERVED = [
        'AddressLookupTab1e1111111111111111111111111', 'BPFLoader2111111111111111111111111111111111',
        'BPFLoader1111111111111111111111111111111111', 'BPFLoaderUpgradeab1e11111111111111111111111',
        'ComputeBudget111111111111111111111111111111', 'Config1111111111111111111111111111111111111',
        'Ed25519SigVerify111111111111111111111111111', 'Feature111111111111111111111111111111111111',
        'LoaderV411111111111111111111111111111111111', 'KeccakSecp256k11111111111111111111111111111',
        'Secp256r1SigVerify1111111111111111111111111', 'StakeConfig11111111111111111111111111111111',
        'Stake11111111111111111111111111111111111111', '11111111111111111111111111111111',
        'Vote111111111111111111111111111111111111111', 'ZkE1Gama1Proof11111111111111111111111111111',
        'ZkTokenProof1111111111111111111111111111111', 'SysvarC1ock11111111111111111111111111111111',
        'SysvarEpochRewards1111111111111111111111111', 'SysvarEpochSchedu1e111111111111111111111111',
        'SysvarFees111111111111111111111111111111111', 'Sysvar1nstructions1111111111111111111111111',
        'SysvarLastRestartS1ot1111111111111111111111', 'SysvarRecentB1ockHashes11111111111111111111',
        'SysvarRent111111111111111111111111111111111', 'SysvarRewards111111111111111111111111111111',
        'SysvarS1otHashes111111111111111111111111111', 'SysvarS1otHistory11111111111111111111111111',
        'SysvarStakeHistory1111111111111111111111111', 'NativeLoader1111111111111111111111111111111',
        'Sysvar1111111111111111111111111111111111111',
    ];

    public readonly array $signatures;
    public readonly int|string $version;
    private readonly int $required, $readonlySigned, $readonlyUnsigned;
    private readonly array $keys, $instructions, $lookups;
    private readonly ?array $transactionConfig;
    private readonly string $recent, $raw;

    public function __construct(string $bytes)
    {
        $r = new Reader($bytes);
        $discriminator = $r->u8();
        if ($discriminator === 0x81) {
            $this->readV1($r);
        } else {
            require_valid($discriminator < 0x80, 'Invalid transaction discriminator');
            $this->readLegacyOrV0($r, $discriminator);
        }
        $this->raw = substr($bytes, 0, $r->pos);
    }

    private function readLegacyOrV0(Reader $r, int $signatureCount): void
    {
        $this->signatures = $r->items($signatureCount, 64, fn() => $r->take(64));
        $prefix = $r->u8();
        require_valid($prefix <= 0x80, 'Unsupported transaction message version');
        $v0 = $prefix === 0x80;
        $this->version = $v0 ? 0 : 'legacy';
        $this->required = $v0 ? $r->u8() : $prefix;
        $this->readonlySigned = $r->u8();
        $this->readonlyUnsigned = $r->u8();
        $this->keys = $r->items($r->compact(), 32, fn() => $r->take(32));
        $this->recent = $r->take(32);
        $this->instructions = $r->items($r->compact(), 3, fn() => Instruction::read($r, 1));
        $this->lookups = $v0 ? $r->items($r->compact(), 34, fn() => [
            'accountKey' => $r->take(32),
            'writableIndexes' => $r->take($r->compact()),
            'readonlyIndexes' => $r->take($r->compact()),
        ]) : [];
        $this->transactionConfig = null;
    }

    private function readV1(Reader $r): void
    {
        $this->version = 1;
        $this->required = $r->u8();
        $this->readonlySigned = $r->u8();
        $this->readonlyUnsigned = $r->u8();
        $mask = $r->u32();
        $priorityBits = $mask & 0x03;
        require_valid($mask <= 0x1f && ($priorityBits === 0 || $priorityBits === 0x03),
            'Invalid v1 transaction config mask');
        $this->recent = $r->take(32);
        $instructionCount = $r->u8();
        $this->keys = $r->items($r->u8(), 32, fn() => $r->take(32));
        $this->transactionConfig = [
            'priorityFee' => $priorityBits === 0x03 ? unsigned_json($r->u64()) : null,
            'computeUnitLimit' => ($mask & 0x04) ? $r->u32() : null,
            'loadedAccountsDataSizeLimit' => ($mask & 0x08) ? $r->u32() : null,
            'heapSize' => ($mask & 0x10) ? $r->u32() : null,
        ];
        // All headers precede the payloads, which are laid out in instruction order.
        $headers = $r->items($instructionCount, 4, fn() => [$r->u8(), $r->u8(), $r->le(2)]);
        $instructions = [];
        foreach ($headers as [$program, $accountCount, $dataLength]) {
            $instructions[] = new Instruction($program, $r->take($accountCount), $r->take($dataLength), 1);
        }
        $this->instructions = $instructions;
        $this->signatures = $r->items($this->required, 64, fn() => $r->take(64));
        $this->lookups = [];
    }

    private function accounts(array $combined, int $writableLoaded): array
    {
        $upgradeable = in_array(self::UPGRADEABLE_LOADER, $combined, true);
        $invoked = [];
        foreach ($this->instructions as $instruction) $invoked[$instruction->program] = true;
        $result = [];
        $staticCount = count($this->keys);
        foreach ($combined as $i => $pubkey) {
            $isStatic = $i < $staticCount;
            $signer = $i < $this->required;
            $writable = $isStatic
                ? ($signer ? $i < $this->required - $this->readonlySigned : $i < $staticCount - $this->readonlyUnsigned)
                : $i - $staticCount < $writableLoaded;
            $writable = $writable && !in_array($pubkey, self::RESERVED, true) && ($upgradeable || !isset($invoked[$i]));
            $source = $isStatic ? 'transaction' : 'lookupTable';
            $result[] = compact('pubkey', 'writable', 'signer', 'source');
        }
        return $result;
    }

    public function json(?Meta $meta, Options $options): array
    {
        $accounts = $options->details === 'accounts';
        $parsed = $options->encoding === 'jsonParsed';
        $parsedKeys = null;
        if ($options->encoding === 'base64' || $options->encoding === 'base58') {
            $raw = $options->encoding === 'base64' ? base64_encode($this->raw) : base58($this->raw);
            $transaction = [$raw, $options->encoding];
        } else {
            $signatures = array_map('base58', $this->signatures);
            $statics = array_map('base58', $this->keys);
            $v0 = $this->version === 0;
            $combined = $v0 && $meta !== null && ($accounts || $parsed)
                ? array_merge($statics, $meta->writable, $meta->readonly) : $statics;
            if ($parsed) $parsedKeys = $combined;
            $accountKeys = $accounts || $parsed ? $this->accounts($combined, $v0 ? count($meta?->writable ?? []) : 0) : $statics;
            if ($accounts) $transaction = compact('signatures', 'accountKeys');
            else {
                $message = [
                    'accountKeys' => $accountKeys, 'recentBlockhash' => base58($this->recent),
                    'instructions' => array_map(fn(Instruction $i) => $i->json($parsedKeys), $this->instructions),
                ];
                if (!$parsed) $message['header'] = [
                    'numRequiredSignatures' => $this->required,
                    'numReadonlySignedAccounts' => $this->readonlySigned,
                    'numReadonlyUnsignedAccounts' => $this->readonlyUnsigned,
                ];
                if ($v0) $message['addressTableLookups'] = array_map(static fn(array $lookup) => [
                    'accountKey' => base58($lookup['accountKey']),
                    'writableIndexes' => Instruction::indices($lookup['writableIndexes']),
                    'readonlyIndexes' => Instruction::indices($lookup['readonlyIndexes']),
                ], $this->lookups);
                if ($this->transactionConfig !== null) $message['transactionConfig'] = $this->transactionConfig;
                $transaction = compact('signatures', 'message');
            }
        }
        $result = ['transaction' => $transaction, 'meta' => $meta?->json($accounts, $parsedKeys, $options->rewards)];
        if ($meta !== null && $options->maxVersion !== null) $result['version'] = $this->version;
        return $result;
    }
}
