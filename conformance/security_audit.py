#!/usr/bin/env python3
"""Run loopback-only defensive boundary checks against OnlyBlocks servers.

Assumptions made by this harness:

* every implementation follows SPEC.md's ``run.sh`` flag/environment contract;
* build-time writes are allowed, while start-up/request/shutdown writes are not;
* the private mock origin is the only upstream and all hostile archive slices fit
  in memory (large sizes are declared, or represented by a tiny valid RLE frame);
* a dropped connection is a safe rejection for an oversized inbound HTTP body,
  matching the existing conformance runner, but every later health check must pass.

The harness never constructs a large archive slice or decompressed output.  Its one
large inbound request is 1.5 MiB + 1 byte, and the zstd RLE bomb is about 16 KiB.
"""

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import re
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
SLOTS_PER_EPOCH = 432_000
MAX_CAR_SECTION = 32 * 1024 * 1024
MAX_ZSTD_OUTPUT = 512 * 1024 * 1024
OVERSIZED_BODY = 1536 * 1024 + 1
DEEPLY_NESTED_BODY = 1024 * 1024
ENTRY = struct.Struct("<QI")
ROUTE = re.compile(r"/([0-9]{1,20})/epoch-\1(-slot-ranges\.raw|\.car)")
RANGE = re.compile(r"bytes=([0-9]+)-([0-9]+)", re.IGNORECASE)


class AuditFailure(Exception):
    pass


class Link:
    def __init__(self, cid):
        self.cid = cid


def uvarint(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def cbor_head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor(value):
    if value is None:
        return b"\xf6"
    if type(value) is int and value >= 0:
        return cbor_head(0, value)
    if isinstance(value, bytes):
        return cbor_head(2, len(value)) + value
    if isinstance(value, list):
        return cbor_head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, Link):
        raw = b"\0" + value.cid
        return b"\xd8\x2a" + cbor(raw)
    raise TypeError(f"unsupported synthetic CBOR value: {value!r}")


def cid(number):
    # CIDv1, dag-cbor, identity multihash with a one-byte digest.  The tiny
    # valid CID keeps the complete cycle fixture below 200 bytes.
    if not 0 <= number <= 255:
        raise ValueError("synthetic CID number is one byte")
    return b"\x01\x71\x00\x01" + bytes([number])


def section(key, node):
    body = key + node
    return uvarint(len(body)) + body


def block_node(slot, entries=None, rewards=None):
    return cbor([2, slot, None, [Link(key) for key in entries or []],
                 [slot, None, None], Link(rewards) if rewards else None])


def dataframe(payload=b"", checksum=None, following=None):
    links = None if following is None else [Link(key) for key in following]
    return [6, checksum, None, None, payload, links]


def crc64_go_iso(data):
    value = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = ((value >> 1) ^ 0xD800000000000000) if value & 1 else value >> 1
    return value ^ 0xFFFFFFFFFFFFFFFF


def fnv1a_64(data):
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


def minimal_transaction():
    # Zero signatures, a legacy message with an all-zero header, no accounts,
    # a zero recent blockhash, and no instructions.  Sanitization is explicitly
    # outside the wire decoder contract, so this is a valid decoded transaction.
    return b"\0\0\0\0\0" + bytes(32) + b"\0"


def empty_block_car(slot):
    return section(cid(1), block_node(slot))


def cycle_car(slot):
    block, entry, transaction, frame_a, frame_b = map(cid, range(10, 15))
    parts = [
        section(block, block_node(slot, [entry])),
        section(entry, cbor([1, None, bytes(32), [Link(transaction)]])),
        section(transaction, cbor([0, dataframe(following=[frame_a])])),
        section(frame_a, cbor(dataframe(following=[frame_b]))),
        section(frame_b, cbor(dataframe(following=[frame_a]))),
    ]
    result = b"".join(parts)
    if len(result) >= 200:
        raise AssertionError(f"cycle fixture unexpectedly grew to {len(result)} bytes")
    return result


def checksum_car(slot):
    block, entry, transaction = map(cid, range(20, 23))
    payload = minimal_transaction()
    if crc64_go_iso(payload) == 0 or fnv1a_64(payload) == 0:
        raise AssertionError("checksum fixture unexpectedly matches zero")
    result = b"".join([
        section(block, block_node(slot, [entry])),
        section(entry, cbor([1, None, bytes(32), [Link(transaction)]])),
        section(transaction, cbor([0, dataframe(payload, checksum=0)])),
    ])
    if len(result) >= 200:
        raise AssertionError(f"checksum fixture unexpectedly grew to {len(result)} bytes")
    return result


def rewards_car(slot, payload):
    block, rewards = cid(30), cid(31)
    return b"".join([
        section(block, block_node(slot, rewards=rewards)),
        section(rewards, cbor([5, slot, dataframe(payload)])),
    ])


def rle_zstd_bomb():
    """A valid ~16 KiB zstd frame that expands to MAX_ZSTD_OUTPUT + 1 bytes."""
    output_size = MAX_ZSTD_OUTPUT + 1
    # Magic, then FHD=0xe0: single segment and an eight-byte content size.
    frame = bytearray(b"\x28\xb5\x2f\xfd\xe0" + output_size.to_bytes(8, "little"))
    remaining = output_size
    while remaining:
        block_size = min(remaining, 128 * 1024)
        remaining -= block_size
        # Three-byte little-endian block header: last bit, RLE type=1, size.
        header = (block_size << 3) | (1 << 1) | (not remaining)
        frame.extend(int(header).to_bytes(3, "little"))
        frame.append(0x41)
    if len(frame) >= 20_000:
        raise AssertionError(f"zstd bomb fixture unexpectedly grew to {len(frame)} bytes")
    return bytes(frame)


def security_cases():
    # Single-segment + 8-byte Frame_Content_Size.  The trailing invalid
    # protobuf key makes the raw-codec fallback fail too.  Total: 14 bytes.
    oversized_zstd = (b"\x28\xb5\x2f\xfd\xe0"
                      + (MAX_ZSTD_OUTPUT + 1).to_bytes(8, "little") + b"\x0f")
    invalid_zstd = b"\x28\xb5\x2f\xfe\xff\xff\xff\x7f\x0f"
    cases = [
        ("valid_block", empty_block_car(10)),
        ("dataframe_cycle", cycle_car(11)),
        ("dataframe_checksum", checksum_car(12)),
        ("truncated_car_varint", b"\x80\x80\x80"),
        ("oversized_car_section", uvarint(MAX_CAR_SECTION + 1)),
        ("truncated_cbor_array", section(cid(40), b"\x86\x02")),
        ("zstd_declared_oversize", rewards_car(16, oversized_zstd)),
        ("zstd_invalid_magic", rewards_car(17, invalid_zstd)),
        ("zstd_rle_bomb", rewards_car(18, rle_zstd_bomb())),
    ]
    return {name: {"slot": slot, "body": body}
            for slot, (name, body) in enumerate(cases, start=10)}


class AuditOrigin(ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def __init__(self):
        self.cases = security_cases()
        self.ranges = {}
        archive = bytearray()
        for case in self.cases.values():
            case["offset"] = len(archive)
            archive.extend(case["body"])
            self.ranges[case["slot"]] = (case["offset"], len(case["body"]))
        self.oversize_slot = 100
        self.ranges[self.oversize_slot] = (0, 200_000_000)
        self.archive = bytes(archive)
        self.lock = threading.Lock()
        self.reset()
        super().__init__(("127.0.0.1", 0), AuditOriginHandler)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server_port}"

    def __enter__(self):
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.shutdown()
        self.server_close()
        self.thread.join()

    def reset(self):
        with self.lock:
            self.total_requests = 0
            self.slot_requests = 0
            self.car_requests = 0
            self.car_slots = []

    def stats(self):
        with self.lock:
            return {
                "total_requests": self.total_requests,
                "slot_requests": self.slot_requests,
                "car_requests": self.car_requests,
                "car_slots": list(self.car_slots),
            }


class AuditOriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def reply(self, status, body=b"", **headers):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), str(value))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        match = ROUTE.fullmatch(self.path)
        byte_range = RANGE.fullmatch(self.headers.get("Range", ""))
        if match is None or byte_range is None or int(match[1]) != 0:
            self.reply(404)
            return
        start, end = map(int, byte_range.groups())
        suffix = match[2]
        with self.server.lock:
            self.server.total_requests += 1
            if suffix == "-slot-ranges.raw":
                self.server.slot_requests += 1
            else:
                self.server.car_requests += 1
        if suffix == "-slot-ranges.raw":
            if end - start != 11 or start % ENTRY.size:
                self.reply(416)
                return
            slot = start // ENTRY.size
            offset, length = self.server.ranges.get(slot, (0, 0))
            body = ENTRY.pack(offset, length)
            self.reply(206, body, Content_Range=f"bytes {start}-{end}/{SLOTS_PER_EPOCH * ENTRY.size}")
            return
        if not 0 <= start <= end < len(self.server.archive):
            self.reply(416, Content_Range=f"bytes */{len(self.server.archive)}")
            return
        slot = next((slot for slot, pair in self.server.ranges.items()
                     if pair == (start, end - start + 1)), None)
        with self.server.lock:
            self.server.car_slots.append(slot)
        body = self.server.archive[start:end + 1]
        self.reply(206, body, Content_Range=f"bytes {start}-{end}/{len(self.server.archive)}")


def child_env():
    env = os.environ.copy()
    prefixes = [
        "/opt/homebrew/opt/openjdk@17/bin",
        str(Path.home() / ".cargo/bin"),
        str(Path.home() / ".nix-profile/bin"),
        "/opt/homebrew/bin",
        env.get("PATH", os.defpath),
    ]
    env["PATH"] = os.pathsep.join(prefixes)
    bypass = env.get("NO_PROXY", env.get("no_proxy", ""))
    env["NO_PROXY"] = env["no_proxy"] = ",".join(filter(None, (bypass, "127.0.0.1", "localhost")))
    return env


def signal_group(process, sig):
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def stop(process):
    if process.poll() is not None:
        return
    signal_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        signal_group(process, signal.SIGKILL)
        process.wait()


def log_tail(log):
    log.seek(max(0, log.seek(0, os.SEEK_END) - 4096))
    return log.read().decode("utf-8", "replace").strip()


def build(implementation):
    script = implementation / "build.sh"
    if not script.is_file():
        return
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            ["bash", str(script)], cwd=implementation, env=child_env(), stdout=log,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            try:
                code = process.wait(timeout=240)
            except subprocess.TimeoutExpired as error:
                raise AuditFailure("build.sh timed out after 240 seconds") from error
            if code:
                raise AuditFailure(f"build.sh exited {code}\n{log_tail(log)}".rstrip())
        finally:
            stop(process)


def tree_snapshot(root):
    snapshot = {}
    root_info = root.lstat()
    snapshot["."] = ("dir", stat.S_IMODE(root_info.st_mode), root_info.st_mtime_ns)
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        relative = str(path.relative_to(root))
        if stat.S_ISLNK(info.st_mode):
            detail = ("link", stat.S_IMODE(info.st_mode), os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            detail = ("dir", stat.S_IMODE(info.st_mode), info.st_mtime_ns)
        elif stat.S_ISREG(info.st_mode):
            # Hash small source/configuration files.  Size and nanosecond mtime
            # cover large build artifacts without repeatedly reading them.
            digest = None
            if info.st_size <= 1024 * 1024:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            detail = ("file", stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, digest)
        else:
            detail = ("other", info.st_mode, info.st_size, info.st_mtime_ns)
        snapshot[relative] = detail
    return snapshot


def assert_tree_unchanged(root, before, label):
    after = tree_snapshot(root)
    if before == after:
        return
    changed = sorted(set(before) | set(after))
    changed = [path for path in changed if before.get(path) != after.get(path)]
    raise AuditFailure(f"{label} changed on disk: {', '.join(changed[:8])}")


def assert_tmpdir_empty(tmpdir):
    entries = list(tmpdir.rglob("*"))
    if entries:
        raise AuditFailure("TMPDIR contains: " + ", ".join(str(p.relative_to(tmpdir)) for p in entries[:8]))


def http_request(bind, method, body=b"", timeout=20):
    connection = http.client.HTTPConnection(*bind, timeout=timeout)
    try:
        headers = {"Connection": "close"}
        if method == "POST":
            headers["Content-Type"] = "application/json"
        connection.request(method, "/", body, headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, raw
    except (OSError, http.client.HTTPException) as error:
        raise AuditFailure(f"HTTP request failed: {error}") from error
    finally:
        connection.close()


def raw_post_status(bind, body, timeout=20):
    """Return an HTTP status, or None when the peer safely drops the request."""
    head = (
        f"POST / HTTP/1.1\r\nHost: {bind[0]}:{bind[1]}\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    reply = b""
    try:
        with socket.create_connection(bind, timeout=timeout) as connection:
            try:
                connection.sendall(head + body)
            except OSError:
                pass
            while len(reply) < 4096:
                chunk = connection.recv(4096 - len(reply))
                if not chunk:
                    break
                reply += chunk
    except OSError:
        return None
    match = re.match(rb"HTTP/1\.[01] ([0-9]{3})", reply)
    return int(match[1]) if match else None


def rpc(bind, value, timeout=20):
    body = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
    status, raw = http_request(bind, "POST", body, timeout)
    if status != 200:
        raise AuditFailure(f"RPC returned HTTP {status}, expected 200")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise AuditFailure(f"RPC returned invalid JSON: {raw[:160]!r}") from error


def request(method, params=None, request_id="audit"):
    value = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        value["params"] = params
    return value


def assert_error(reply, code, request_id="audit"):
    if not isinstance(reply, dict):
        raise AuditFailure(f"expected one JSON-RPC error object, got {reply!r}")
    error = reply.get("error")
    if (reply.get("jsonrpc") != "2.0" or reply.get("id") != request_id
            or not isinstance(error, dict) or error.get("code") != code
            or not isinstance(error.get("message"), str) or not error["message"]):
        raise AuditFailure(f"expected JSON-RPC error {code} with id {request_id!r}, got {reply!r}")


def assert_health(bind):
    reply = rpc(bind, request("getHealth", request_id="health"))
    expected = {"jsonrpc": "2.0", "result": "ok", "id": "health"}
    if reply != expected:
        raise AuditFailure(f"getHealth expected {expected!r}, got {reply!r}")


def wait_ready(bind, process):
    deadline = time.monotonic() + 20
    last = "no response"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AuditFailure(f"run.sh exited {process.returncode} before readiness")
        try:
            assert_health(bind)
            return
        except AuditFailure as error:
            last = str(error)
            time.sleep(0.05)
    raise AuditFailure(f"getHealth was not ready after 20 seconds ({last})")


@contextlib.contextmanager
def running_server(implementation, base_url):
    with tempfile.TemporaryDirectory(prefix="onlyblocks-security-") as directory, tempfile.TemporaryFile() as log:
        tmpdir = Path(directory)
        tmpdir_before = tree_snapshot(tmpdir)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            bind = reservation.getsockname()
        address = f"{bind[0]}:{bind[1]}"
        env = child_env()
        env.update(ONLYBLOCKS_BIND=address, OLD_FAITHFUL_BASE_URL=base_url, TMPDIR=str(tmpdir))
        process = subprocess.Popen(
            ["bash", str(implementation / "run.sh"), "--bind", address, "--base-url", base_url],
            cwd=implementation, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            wait_ready(bind, process)
            assert_tmpdir_empty(tmpdir)
            yield bind, tmpdir, process
        except AuditFailure as error:
            tail = log_tail(log)
            if tail:
                raise AuditFailure(f"{error}\nserver log:\n{tail}") from error
            raise
        finally:
            stop(process)
        assert_tmpdir_empty(tmpdir)
        assert_tree_unchanged(tmpdir, tmpdir_before, "TMPDIR")


def record(results, name, check):
    try:
        check()
    except AuditFailure as error:
        results[name] = {"passed": False, "detail": str(error)}
    else:
        results[name] = {"passed": True, "detail": "ok"}


def audit_implementation(implementation, origin, skip_build=False):
    if not (implementation / "run.sh").is_file():
        return {"build_launch": {"passed": False, "detail": "missing run.sh"}}
    if not skip_build:
        try:
            build(implementation)
        except AuditFailure as error:
            return {"build_launch": {"passed": False, "detail": str(error)}}
    before = tree_snapshot(implementation)
    results = {"build_launch": {"passed": True, "detail": "ok"}}
    try:
        with running_server(implementation, origin.base_url) as (bind, tmpdir, process):
            record(results, "valid_block", lambda: valid_block_probe(bind, origin))
            for name in ("dataframe_cycle", "dataframe_checksum", "truncated_car_varint",
                         "oversized_car_section", "truncated_cbor_array",
                         "zstd_declared_oversize", "zstd_invalid_magic", "zstd_rle_bomb"):
                record(results, name, lambda name=name: archive_error_probe(bind, origin, name))
            record(results, "oversized_slice", lambda: oversized_slice_probe(bind, origin))
            record(results, "batch_limit", lambda: batch_probe(bind, origin))
            record(results, "oversized_body", lambda: oversized_body_probe(bind, origin))
            record(results, "deep_json", lambda: deep_json_probe(bind, origin))
            record(results, "slot_parameters", lambda: slot_parameter_probe(bind, origin))
            record(results, "removed_method", lambda: removed_method_probe(bind, origin))
            record(results, "malformed_json", lambda: malformed_json_probe(bind, origin))
            record(results, "http_get", lambda: get_probe(bind, origin))
            record(results, "tmpdir", lambda: assert_tmpdir_empty(tmpdir))
            if process.poll() is not None:
                results["process_survival"] = {
                    "passed": False, "detail": f"server exited {process.returncode}",
                }
            else:
                record(results, "process_survival", lambda: assert_health(bind))
    except AuditFailure as error:
        results.setdefault("build_launch", {"passed": False, "detail": str(error)})
    try:
        assert_tree_unchanged(implementation, before, "implementation directory")
    except AuditFailure as error:
        results["implementation_disk"] = {"passed": False, "detail": str(error)}
    else:
        results["implementation_disk"] = {"passed": True, "detail": "ok"}
    return results


def valid_block_probe(bind, origin):
    case = origin.cases["valid_block"]
    reply = rpc(bind, request("getBlock", [case["slot"], {"transactionDetails": "none", "rewards": False}]))
    if not isinstance(reply, dict) or not isinstance(reply.get("result"), dict) or "error" in reply:
        raise AuditFailure(f"valid synthetic block did not succeed: {reply!r}")
    assert_health(bind)


def archive_error_probe(bind, origin, name):
    case = origin.cases[name]
    reply = rpc(bind, request("getBlock", [case["slot"]]))
    assert_error(reply, -32603)
    assert_health(bind)


def oversized_slice_probe(bind, origin):
    before = origin.stats()["car_requests"]
    reply = rpc(bind, request("getBlock", [origin.oversize_slot]))
    assert_error(reply, -32603)
    after = origin.stats()["car_requests"]
    if after != before:
        raise AuditFailure("server fetched .car after the 12-byte slot entry exceeded max_slice_bytes")
    assert_health(bind)


def no_upstream(origin, action):
    before = origin.stats()["total_requests"]
    action()
    after = origin.stats()["total_requests"]
    if after != before:
        raise AuditFailure(f"probe made {after - before} unexpected upstream request(s)")


def batch_probe(bind, origin):
    batch = [request("getHealth", request_id=index) for index in range(105)]
    def check():
        assert_error(rpc(bind, batch), -32600, None)
    no_upstream(origin, check)
    assert_health(bind)


def oversized_body_probe(bind, origin):
    prefix = b'{"jsonrpc":"2.0","id":"audit","method":"getHealth","pad":"'
    body = prefix + b"a" * (OVERSIZED_BODY - len(prefix) - 2) + b'"}'

    def check():
        status = raw_post_status(bind, body)
        if status not in (413, None):
            raise AuditFailure(
                f"{len(body)}-byte POST returned HTTP {status}, expected 413 or a dropped connection"
            )

    no_upstream(origin, check)
    assert_health(bind)


def deep_json_probe(bind, origin):
    body = b"[" * (DEEPLY_NESTED_BODY // 2) + b"]" * (DEEPLY_NESTED_BODY // 2)

    def check():
        reply = rpc(bind, body)
        errors = reply if isinstance(reply, list) else [reply]
        if len(errors) != 1 or not isinstance(errors[0], dict):
            raise AuditFailure(f"deep JSON expected one error, got {reply!r}")
        code = errors[0].get("error", {}).get("code")
        if code not in (-32700, -32600):
            raise AuditFailure(f"deep JSON expected -32700 or -32600, got {reply!r}")
        assert_error(errors[0], code, None)

    no_upstream(origin, check)
    assert_health(bind)


def slot_parameter_probe(bind, origin):
    probes = (b'18446744073709551616', b'-1', b'1.5')
    for literal in probes:
        body = (b'{"jsonrpc":"2.0","id":"audit","method":"getBlock","params":['
                + literal + b']}')
        no_upstream(origin, lambda body=body: assert_error(rpc(bind, body), -32602))
        assert_health(bind)


def removed_method_probe(bind, origin):
    call = request("getTransaction", ["1" * 64, {"slot": 10}])
    no_upstream(origin, lambda: assert_error(rpc(bind, call), -32601))
    assert_health(bind)


def malformed_json_probe(bind, origin):
    no_upstream(origin, lambda: assert_error(rpc(bind, b"{"), -32700, None))
    assert_health(bind)


def get_probe(bind, origin):
    def check():
        status, _body = http_request(bind, "GET")
        if status not in (404, 405):
            raise AuditFailure(f"GET / returned HTTP {status}, expected 404 or 405")
    no_upstream(origin, check)
    assert_health(bind)


REPORT_GROUPS = {
    "CAR / CBOR / DataFrame": (
        "valid_block", "dataframe_cycle", "dataframe_checksum", "truncated_car_varint",
        "oversized_car_section", "truncated_cbor_array",
    ),
    "Memory caps / zstd": (
        "oversized_slice", "zstd_declared_oversize", "zstd_invalid_magic", "zstd_rle_bomb",
    ),
    "JSON-RPC / HTTP": (
        "batch_limit", "oversized_body", "deep_json", "slot_parameters", "removed_method",
        "malformed_json", "http_get",
    ),
    "Zero disk": ("tmpdir", "implementation_disk"),
    "Liveness": ("process_survival",),
}


def group_result(checks, names):
    selected = [checks.get(name) for name in names]
    if not all(selected):
        return "NOT RUN"
    return "PASS" if all(item["passed"] for item in selected) else "FAIL"


def markdown_cell(value):
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def render_report(summary):
    implementations = summary["implementations"]
    passed = sum(item["passed"] for item in implementations.values())
    lines = [
        "# OnlyBlocks defensive security audit",
        "",
        f"**Observed result:** {passed}/{len(implementations)} implementations passed every probe.",
        "",
        "This is a local, loopback-only adversarial audit. It proves only the implementations built and "
        "executed on this machine; it is not deployment or production-origin validation.",
        "",
        "## Audit assumptions",
        "",
        "- Build-time writes are excluded. Start-up, request-time, and shutdown mutations under the private "
        "`TMPDIR` and each `impls/<slug>/` tree are failures.",
        "- Directory metadata and file size/mtime/content snapshots detect retained writes and ordinary "
        "create-then-delete behavior. Writes elsewhere on the host are outside this task's stated scope.",
        "- An HTTP 413 or an immediate dropped connection safely rejects the 1.5 MiB + 1 byte POST, matching "
        "the existing hostile-input conformance check. The server must answer `getHealth` afterward.",
        "- The zstd bomb is a valid roughly 16 KiB RLE frame declaring and encoding 512 MiB + 1 byte of "
        "output; the harness never materializes that output.",
        "",
        "## Pass/fail matrix",
        "",
        "| Implementation | Overall | Build / launch | " + " | ".join(REPORT_GROUPS) + " |",
        "|---|---|---|" + "---|" * len(REPORT_GROUPS),
    ]
    for slug, result in implementations.items():
        checks = result["checks"]
        row = [slug, "PASS" if result["passed"] else "FAIL"]
        build_result = checks.get("build_launch")
        row.append("PASS" if build_result and build_result["passed"] else "FAIL")
        row.extend(group_result(checks, names) for names in REPORT_GROUPS.values())
        lines.append("| " + " | ".join(map(markdown_cell, row)) + " |")

    lines.extend([
        "",
        "## Exact failure reproductions",
        "",
    ])
    failures_found = False
    for slug, result in implementations.items():
        failures = [(name, item["detail"]) for name, item in result["checks"].items()
                    if not item["passed"]]
        if not failures:
            continue
        failures_found = True
        lines.extend([
            f"### `{slug}`",
            "",
            f"Reproduce with: `python3 -I -B conformance/security_audit.py --impl {slug}`",
            "",
        ])
        for name, detail in failures:
            lines.append(f"- `{name}`: {markdown_cell(detail)}")
        lines.append("")
    if not failures_found:
        lines.extend(["No builder rework was required by this run.", ""])

    lines.extend([
        "## Probe inventory",
        "",
        "- Headerless CAR sections: valid control, cyclic DataFrame links, bad CRC64/FNV checksum, "
        "truncated uvarint, section length above 32 MiB, and truncated CBOR.",
        "- Resource caps: a 200,000,000-byte advertised slice rejected before `.car` fetch, an oversized "
        "zstd content size, a valid high-ratio RLE frame, and invalid zstd bytes.",
        "- RPC/HTTP: 1.5 MiB + 1 byte POST, 105-item batch, 1 MiB deeply nested JSON, malformed JSON, "
        "negative/fractional/u64-overflow slots, removed `getTransaction`, and `GET /`.",
        "- Every archive/RPC failure is followed immediately by `getHealth`; final liveness and zero-disk "
        "checks run before shutdown, with disk snapshots compared again after shutdown.",
        "",
    ])
    return "\n".join(lines)


def run(args):
    implementations = sorted((ROOT / "impls").iterdir())
    implementations = [path for path in implementations if path.is_dir() and (path / "run.sh").is_file()]
    if args.impl:
        selected = set(args.impl)
        known = {path.name for path in implementations}
        unknown = sorted(selected - known)
        if unknown:
            raise AuditFailure("unknown implementation(s): " + ", ".join(unknown))
        implementations = [path for path in implementations if path.name in selected]
    summary = {"scope": "tiny loopback defensive parser bounds", "implementations": {}}
    with AuditOrigin() as origin:
        for implementation in implementations:
            origin.reset()
            checks = audit_implementation(implementation, origin, args.skip_build)
            passed = bool(checks) and all(item["passed"] for item in checks.values())
            summary["implementations"][implementation.name] = {"passed": passed, "checks": checks}
            failures = [f"{name}: {item['detail']}" for name, item in checks.items() if not item["passed"]]
            print(f"{implementation.name}: {'PASS' if passed else 'FAIL'}")
            for failure in failures:
                print(f"  {failure}")
    summary["passed"] = all(item["passed"] for item in summary["implementations"].values())
    if args.json_out:
        args.json_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.report_out:
        args.report_out.write_text(render_report(summary), encoding="utf-8")
    return 0 if summary["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--impl", action="append", help="implementation slug (repeatable)")
    parser.add_argument("--skip-build", action="store_true", help="use existing build outputs")
    parser.add_argument("--json-out", type=Path, help="write a machine-readable result summary")
    parser.add_argument("--report-out", type=Path, help="write a Markdown pass/fail report")
    args = parser.parse_args()
    try:
        return run(args)
    except (AuditFailure, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"security audit: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
