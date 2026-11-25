"""OnlyBlocks JSON-RPC server and bounded Old Faithful range transport."""
import argparse
from collections import OrderedDict
from datetime import timezone
from email.utils import parsedate_to_datetime
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import random
import re
import signal
import socket
import struct
import threading
import time
from urllib.parse import urlsplit

from metadata import empty_meta, metadata, rewards
from wire import (DecodeError, U64_MAX, ZERO_HASH, at, b64, base58, frame_payload,
                  index_car, indexed, link, links, pubkey, require, signed, transaction, unsigned)

MAX_BODY = 1 << 20
MAX_SLICE = 128 << 20
EPOCH_SLOTS = 432000
UPGRADEABLE = 'BPFLoaderUpgradeab1e11111111111111111111111'
RESERVED = frozenset('''
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
'''.split())


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def account_objects(version, message, loaded):
    static = message['accountKeys']
    writable = loaded['writable'] if version == 0 else []
    readonly = loaded['readonly'] if version == 0 else []
    keys = static + writable + readonly
    header = message['header']
    signers = header['numRequiredSignatures']
    programs = {ix['programIdIndex'] for ix in message['instructions']}
    upgradeable = UPGRADEABLE in keys
    for i, key in enumerate(keys):
        lookup = i >= len(static)
        if lookup:
            can_write = i - len(static) < len(writable)
        elif i < signers:
            can_write = i < signers - header['numReadonlySignedAccounts']
        else:
            can_write = i < len(static) - header['numReadonlyUnsignedAccounts']
        yield dict(pubkey=key, signer=i < signers,
                   writable=can_write and key not in RESERVED and (upgradeable or i not in programs),
                   source='lookupTable' if lookup else 'transaction')


def instruction_json(ix, keys):
    result = dict(data=base58(ix['data']), stackHeight=ix['stackHeight'])
    if keys is None:
        result.update(programIdIndex=ix['programIdIndex'], accounts=list(ix['accounts']))
    else:
        def address(index):
            require(index < len(keys), 'Instruction account index out of range')
            return keys[index]
        result.update(programId=address(ix['programIdIndex']), accounts=list(map(address, ix['accounts'])))
    return result


def transaction_json(tx, meta, encoding, details, include_rewards, max_version):
    version, signatures, message, raw = tx
    if isinstance(version, int):
        if max_version is None or version > max_version:
            raise RpcError(-32015, f'Transaction version ({version}) is not supported by the requesting client. '
                                   f'Please try the request again with the following configuration parameter: '
                                   f'"maxSupportedTransactionVersion": {version}')
        if meta is None:
            meta = empty_meta()

    parsed, accounts_only = encoding == 'jsonParsed', details == 'accounts'
    keys = None
    if encoding in ('base64', 'base58'):
        output = [(b64 if encoding == 'base64' else base58)(raw), encoding]
    else:
        accounts = message['accountKeys']
        if parsed or accounts_only:
            loaded = meta['loadedAddresses'] if meta is not None else dict(writable=[], readonly=[])
            accounts = list(account_objects(version, message, loaded))
        if parsed:
            keys = [account['pubkey'] for account in accounts]
        output = dict(signatures=list(map(base58, signatures)))
        if accounts_only:
            output['accountKeys'] = accounts
        else:
            output['message'] = dict(message, accountKeys=accounts,
                                     instructions=[instruction_json(ix, keys) for ix in message['instructions']])
            if parsed:
                del output['message']['header']

    if meta is not None:
        meta = meta.copy()
        error = meta['err']
        meta['status'] = {'Ok': None} if error is None else {'Err': error}
        if not include_rewards:
            meta['rewards'] = None
        if accounts_only:
            for field in ('innerInstructions', 'logMessages', 'loadedAddresses', 'returnData',
                          'computeUnitsConsumed', 'costUnits'):
                meta.pop(field, None)
            if not include_rewards:
                del meta['rewards']
        else:
            if parsed:
                del meta['loadedAddresses']
            if meta['innerInstructions'] is not None:
                meta['innerInstructions'] = [
                    dict(index=group['index'],
                         instructions=[instruction_json(ix, keys) for ix in group['instructions']])
                    for group in meta['innerInstructions']
                ]
    result = dict(transaction=output, meta=meta)
    if meta is not None and max_version is not None:
        result['version'] = version
    return result


class Lru:
    def __init__(self, capacity=100_000):
        self.entries = OrderedDict()
        self.capacity = capacity
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            if key in self.entries:
                self.entries.move_to_end(key)
                return self.entries[key]
            return None

    def put(self, key, value):
        with self.lock:
            self.entries[key] = value
            self.entries.move_to_end(key)
            if len(self.entries) > self.capacity:
                self.entries.popitem(last=False)


def retry_delay(header, attempt):
    if header:
        if re.fullmatch(r'[0-9]+', header):
            digits = header.lstrip('0')
            return 10 if len(digits) > 2 else min(10, int(digits or '0'))
        try:
            date = parsedate_to_datetime(header)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            return max(0, min(10, date.timestamp() - time.time()))
        except (ValueError, OverflowError):
            pass
    return min(10, 0.2 * 2 ** attempt) * random.uniform(0.5, 1)


class Archive:
    def __init__(self, base):
        self.base = base
        self.ranges = Lru()
        self.hashes = Lru()
        self.concurrent = threading.BoundedSemaphore(32)

    def attempt(self, path, start, end, size, cap):
        factory = http.client.HTTPSConnection if self.base.scheme == 'https' else http.client.HTTPConnection
        connection = factory(self.base.hostname, self.base.port, timeout=10)
        deadline = time.monotonic() + 60
        timer = None
        try:
            connection.connect()
            sock = connection.sock
            # An inactivity timeout alone cannot bound a response that
            # continually trickles a few header or body bytes.
            def expire():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(max(0, deadline - time.monotonic()), expire)
            timer.daemon = True
            timer.start()
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            connection.request('GET', path, headers={
                'Range': f'bytes={start}-{end}', 'User-Agent': 'onlyblocks/python',
                'Connection': 'close', 'Accept-Encoding': 'identity',
            })
            with connection.getresponse() as response:
                if response.status != 206:
                    return response.status, response.getheader('Retry-After')
                lengths = response.headers.get_all('Content-Length', [])
                if lengths:
                    require(len(lengths) == 1 and re.fullmatch(r'[0-9]+', lengths[0]),
                            'Invalid archive Content-Length')
                    digits = lengths[0].lstrip('0')
                    require(len(digits) <= 9 and int(digits or '0') <= cap,
                            'Archive Content-Length exceeds range cap')
                chunks, received = [], 0
                while not response.isclosed():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('Archive attempt timed out')
                    sock.settimeout(remaining)
                    chunk = response.read1(min(65536, cap + 1 - received))
                    if not chunk:
                        break
                    received += len(chunk)
                    require(received <= cap, 'Archive body exceeds range cap')
                    if received <= size:
                        chunks.append(chunk)
                if time.monotonic() >= deadline:
                    raise TimeoutError('Archive attempt timed out')
                if response.length:
                    raise http.client.IncompleteRead(b'', response.length)
                require(received == size, 'Archive range body has wrong length')
                return 206, b''.join(chunks)
        finally:
            if timer is not None:
                timer.cancel()
            connection.close()

    def read_range(self, slot, suffix, start, size, cap):
        end = start + size - 1
        require(end <= U64_MAX, 'Archive range end overflows u64')
        epoch = slot // EPOCH_SLOTS
        path = f'{self.base.path}/{epoch}/epoch-{epoch}{suffix}'
        for attempt in range(5):
            try:
                with self.concurrent:
                    status, value = self.attempt(path, start, end, size, cap)
            except (OSError, http.client.HTTPException):
                status, value = None, None
            if status == 206:
                return value
            if status == 404:
                raise RpcError(-32004, f'Block not available for slot {slot}')
            if status is not None and status != 429 and not 500 <= status < 600:
                raise DecodeError(f'Unexpected archive HTTP status {status}')
            if attempt < 4:
                time.sleep(retry_delay(value, attempt))
        raise DecodeError('Archive range retries exhausted')

    def load_block(self, slot):
        record = self.ranges.get(slot)
        if record is None:
            raw = self.read_range(slot, '-slot-ranges.raw', (slot % EPOCH_SLOTS) * 12, 12, 12)
            record = struct.unpack('<QI', raw)
            self.ranges.put(slot, record)
        offset, size = record
        if not size:
            raise RpcError(-32007, f'Slot {slot} was skipped, or missing in long-term storage')
        require(size <= MAX_SLICE, 'Archive slice exceeds 128 MiB')
        return index_car(self.read_range(slot, '.car', offset, size, MAX_SLICE))

    def blockhash(self, slot, index, entries):
        value = pubkey(at(indexed(index, entries[-1], 1), 2)) if entries else ZERO_HASH
        self.hashes.put(slot, value)
        return value

    def previous_hash(self, slot, parent):
        if slot == 0:
            return ZERO_HASH
        cached = self.hashes.get(parent)
        if cached is not None:
            return cached
        index, block = self.load_block(parent)
        require(unsigned(at(block, 1)) is not None, 'Missing parent Block slot')
        return self.blockhash(parent, index, links(at(block, 3)))

    def get_block(self, slot, encoding, details, include_rewards, max_version):
        index, block = self.load_block(slot)
        require(unsigned(at(block, 1)) == slot, 'Block slot differs from requested slot')
        entries = links(at(block, 3))
        info = at(block, 4)
        if not isinstance(info, list):
            info = []
        parent = unsigned(at(info, 0)) or 0
        blockhash = self.blockhash(slot, index, entries)
        result = dict(previousBlockhash=self.previous_hash(slot, parent), blockhash=blockhash,
                      parentSlot=parent, blockTime=signed(at(info, 1)) or None, blockHeight=unsigned(at(info, 2)))
        if details != 'none':
            items = []
            for key in entries:
                entry = indexed(index, key, 1)
                entry_hash = at(entry, 2)
                require(isinstance(entry_hash, bytes) and len(entry_hash) == 32, 'Invalid Entry hash')
                for tx_key in links(at(entry, 3)):
                    node = indexed(index, tx_key, 0)
                    tx = transaction(frame_payload(index, at(node, 1)))
                    if details == 'signatures':
                        require(tx[1], 'Transaction has no signature')
                        items.append(base58(tx[1][0]))
                    else:
                        frame = at(node, 2)
                        meta = metadata(slot, frame_payload(index, frame)) if isinstance(frame, list) else None
                        items.append(transaction_json(tx, meta, encoding, details, include_rewards, max_version))
            result['signatures' if details == 'signatures' else 'transactions'] = items
        if include_rewards:
            value = at(block, 5)
            data = b''
            if isinstance(value, bytes):
                key, absent = link(value)
                if not absent and key in index:
                    node = indexed(index, key, 5)
                    if len(node) > 2:
                        data = frame_payload(index, node[2])
            result.update(rewards(slot, data))
        return result


class Number:
    """A validated JSON number token. Used to validate slot literals and echo IDs."""
    def __init__(self, text):
        self.text = text


def uint_parameter(value, maximum):
    if isinstance(value, Number) and re.fullmatch(r'0|[1-9][0-9]{0,19}', value.text):
        number = int(value.text)
        if number <= maximum:
            return number
    raise RpcError(-32602, 'Invalid unsigned integer parameter')


def block_params(params):
    invalid = RpcError(-32602, 'Invalid getBlock params')
    if not isinstance(params, list) or not 1 <= len(params) <= 2:
        raise invalid
    slot = uint_parameter(params[0], U64_MAX)
    config = at(params, 1)
    if config is None:
        config = {}
    elif isinstance(config, str):
        config = {'encoding': config}
    if not isinstance(config, dict):
        raise invalid

    def option(name, default):
        value = config.get(name)
        return default if value is None else value

    encoding = option('encoding', 'json')
    details = option('transactionDetails', 'full')
    include_rewards = option('rewards', True)
    max_version = config.get('maxSupportedTransactionVersion')
    parsed_max_version = None if max_version is None else uint_parameter(max_version, 255)
    if (encoding not in ('json', 'jsonParsed', 'base64', 'base58')
            or details not in ('full', 'accounts', 'signatures', 'none')
            or (details == 'accounts' and encoding != 'json')
            or (encoding == 'base58' and parsed_max_version is not None and parsed_max_version >= 1)
            or type(include_rewards) is not bool
            or config.get('commitment') not in (None, 'finalized', 'confirmed')):
        raise invalid
    return slot, encoding, details, include_rewards, parsed_max_version


def response(request_id, **value):
    # Number tokens are emitted only in the ID position, after JSON validation.
    id_text = request_id.text if isinstance(request_id, Number) else json.dumps(request_id)
    fields = json.dumps(dict(jsonrpc='2.0', **value), allow_nan=False, separators=(',', ':'))
    return fields[:-1] + ',"id":' + id_text + '}'


def error(request_id, code, message):
    return response(request_id, error=dict(code=code, message=message))


def dispatch(archive, request):
    if not isinstance(request, dict):
        return error(None, -32600, 'Invalid Request')
    version, method, request_id = (request.get(k) for k in ('jsonrpc', 'method', 'id'))
    if (not isinstance(version, (str, type(None))) or not isinstance(method, (str, type(None)))
            or not isinstance(request_id, (str, Number, type(None)))):
        return error(None, -32600, 'Invalid Request')
    if version != '2.0' or method is None:
        return error(request_id, -32600, 'Invalid Request')
    params = request.get('params')
    try:
        if method == 'getHealth':
            if params is not None and params != []:
                raise RpcError(-32602, 'Invalid getHealth params')
            result = 'ok'
        elif method == 'getBlock':
            result = archive.get_block(*block_params(params))
        else:
            raise RpcError(-32601, f'Method not found: {method}')
        return response(request_id, result=result)
    except RpcError as exc:
        return error(request_id, exc.code, str(exc))
    except Exception as exc:
        return error(request_id, -32603, str(exc) or 'Internal error')


def invalid_constant(text):
    raise ValueError(f'Invalid JSON constant: {text}')


def check_strings(value):
    if isinstance(value, str):
        value.encode('utf-8')
    elif isinstance(value, list):
        for item in value:
            check_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            check_strings(key)
            check_strings(item)


def rpc(archive, raw):
    try:
        request = json.loads(raw.decode('utf-8'), parse_int=Number, parse_float=Number,
                             parse_constant=invalid_constant)
        if re.search(rb'\\u[dD]', raw):
            check_strings(request)
    except (ValueError, RecursionError):
        return error(None, -32700, 'Parse error')
    if isinstance(request, list):
        if not 1 <= len(request) <= 100:
            return error(None, -32600, 'Invalid batch size')
        return '[' + ','.join(dispatch(archive, item) for item in request) + ']'
    return dispatch(archive, request)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = 10

    def log_message(self, *_):
        pass

    def send_data(self, status, data=b''):
        self.close_connection = True
        self.send_response(status)
        self.send_header('Connection', 'close')
        self.send_header('Content-Length', str(len(data)))
        if status == 200:
            self.send_header('Content-Type', 'application/json')
        self.end_headers()
        if data:
            self.wfile.write(data)

    def chunked_body(self):
        body = bytearray()
        while True:
            line = self.rfile.readline(4097)
            size_text = line.partition(b';')[0].strip()
            if not line.endswith(b'\r\n') or not re.fullmatch(rb'[0-9A-Fa-f]+', size_text):
                raise ValueError('Invalid chunk header')
            size = int(size_text, 16)
            if size > MAX_BODY - len(body):
                raise OverflowError('RPC body exceeds 1 MiB')
            if not size:
                remaining = 65536
                while True:
                    trailer = self.rfile.readline(min(remaining + 1, 4097))
                    remaining -= len(trailer)
                    if remaining < 0 or not trailer.endswith(b'\r\n'):
                        raise ValueError('Invalid chunk trailers')
                    if trailer == b'\r\n':
                        break
                return body
            chunk = self.rfile.read(size)
            if len(chunk) != size or self.rfile.read(2) != b'\r\n':
                raise ValueError('Incomplete chunk')
            body.extend(chunk)

    def do_POST(self):
        if self.path != '/':
            self.send_data(404)
            return
        try:
            transfer = self.headers.get('Transfer-Encoding')
            lengths = self.headers.get_all('Content-Length', [])
            if transfer is not None:
                if transfer.lower() != 'chunked' or lengths:
                    raise ValueError('Invalid request framing')
                raw = self.chunked_body()
            else:
                if len(lengths) > 1 or (lengths and not re.fullmatch(r'[0-9]+', lengths[0])):
                    raise ValueError('Invalid Content-Length')
                digits = lengths[0].lstrip('0') if lengths else ''
                if len(digits) > 7 or int(digits or '0') > MAX_BODY:
                    raise OverflowError('RPC body exceeds 1 MiB')
                length = int(digits or '0')
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError('Incomplete body')
        except OverflowError:
            self.send_data(413)
            return
        except ValueError:
            self.send_data(400)
            return
        self.send_data(200, rpc(self.server.archive, raw).encode('ascii'))

    def do_GET(self):
        self.send_data(404)

    do_HEAD = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_PATCH = do_GET


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bind', default=os.environ.get('ONLYBLOCKS_BIND', '127.0.0.1:8899'))
    parser.add_argument('--base-url', default=os.environ.get('OLD_FAITHFUL_BASE_URL',
                                                           'https://files.old-faithful.net'))
    args = parser.parse_args()
    base = urlsplit(args.base_url.strip().rstrip('/'))
    if base.scheme not in ('http', 'https') or not base.hostname:
        parser.error('--base-url requires an HTTP or HTTPS origin')
    # Force port validation at startup.
    _ = base.port
    host, port = args.bind.rsplit(':', 1)
    import socketserver

    class Server(ThreadingHTTPServer):
        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = self.server_address[:2]

    server = Server((host, int(port)), Handler)
    server.archive = Archive(base)

    def stop(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    with server:
        server.serve_forever()


if __name__ == '__main__':
    main()
