#!/usr/bin/env python3
"""Run OnlyBlocks golden JSON-RPC cases and online or offline behavioral checks."""

import argparse
import contextlib
import http.client
import json
import math
import os
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# Running the harness should leave the checkout clean.
sys.dont_write_bytecode = True
from mock_old_faithful import ENTRY, SLOTS_PER_EPOCH, MockOldFaithful


ROOT = Path(__file__).resolve().parent.parent
LIVE_URL = "https://files.old-faithful.net"
MISSING = object()
META_PATH = r"\$\.transactions\[\d+\]\.meta"
MESSAGE_PATH = r"\$\.transactions\[\d+\]\.transaction\.message"
TOP_INSTRUCTION = re.compile(MESSAGE_PATH + r"\.instructions\[\d+\]")
INNER_INSTRUCTION = re.compile(META_PATH + r"\.innerInstructions\[\d+\]\.instructions\[\d+\]")
OPTIONAL_META = {
    "innerInstructions", "logMessages", "preTokenBalances", "postTokenBalances",
    "loadedAddresses", "returnData", "computeUnitsConsumed", "costUnits", "rewards",
}
PARSABLE_PROGRAMS = {
    "11111111111111111111111111111111": "system",
    "Vote111111111111111111111111111111111111111": "vote",
    "Stake11111111111111111111111111111111111111": "stake",
    "AddressLookupTab1e1111111111111111111111111": "address-lookup-table",
    "BPFLoader2111111111111111111111111111111111": "bpf-loader",
    "BPFLoaderUpgradeab1e11111111111111111111111": "bpf-upgradeable-loader",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "spl-associated-token-account",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "spl-token",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "spl-token",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr": "spl-memo",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo": "spl-memo",
}


class CheckFailed(Exception):
    pass


def describe(value):
    if value is MISSING:
        return "<missing>"
    rendered = json.dumps(value, separators=(",", ":"))
    return rendered if len(rendered) <= 180 else rendered[:177] + "..."


def mismatch(path, expected, actual):
    raise CheckFailed(f"{path}: expected {describe(expected)}, got {describe(actual)}")


def key_path(path, key):
    return f"{path}.{key}" if key.isidentifier() else f"{path}[{json.dumps(key)}]"


def equal_scalar(expected, actual):
    if expected is MISSING or actual is MISSING:
        return expected is actual
    if type(expected) in (int, float) and type(actual) in (int, float):
        return expected == actual
    return type(expected) is type(actual) and expected == actual


def optional_field(path, key):
    if re.fullmatch(META_PATH, path):
        return key in OPTIONAL_META
    if TOP_INSTRUCTION.fullmatch(path) or INNER_INSTRUCTION.fullmatch(path):
        return key == "stackHeight"
    if re.fullmatch(META_PATH + r"\.(pre|post)TokenBalances\[\d+\]", path):
        return key in ("owner", "programId")
    return False


def alternate_instructions(left, right):
    """Compare the shared fields of a parsed and partially decoded instruction."""
    if "accounts" not in left:
        left, right = right, left
    program_id = left.get("programId")
    if not isinstance(program_id, str) or program_id not in PARSABLE_PROGRAMS:
        return False
    raw_keys = set(left) - {"stackHeight"}
    parsed_keys = set(right) - {"stackHeight"}
    return (
        raw_keys == {"programId", "accounts", "data"}
        and parsed_keys == {"program", "programId", "parsed"}
        and right["programId"] == program_id
        and right["program"] == PARSABLE_PROGRAMS[program_id]
        and isinstance(right["parsed"], str if right["program"] == "spl-memo" else dict)
        and isinstance(left["accounts"], list)
        and all(isinstance(account, str) for account in left["accounts"])
        and isinstance(left["data"], str)
    )


def compare(expected, actual, path="$", strict_parsed=False):
    if isinstance(expected, dict) and isinstance(actual, dict):
        if not strict_parsed and TOP_INSTRUCTION.fullmatch(path) and alternate_instructions(expected, actual):
            if "stackHeight" in expected and "stackHeight" in actual:
                compare(expected["stackHeight"], actual["stackHeight"], path + ".stackHeight")
            return
        for key in sorted(expected.keys() | actual.keys()):
            want, got = expected.get(key, MISSING), actual.get(key, MISSING)
            if ((want is MISSING and got is None) or (got is MISSING and want is None)) and optional_field(path, key):
                continue
            compare(want, got, key_path(path, key), strict_parsed)
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            mismatch(path + ".length", len(expected), len(actual))
        for index, (want, got) in enumerate(zip(expected, actual)):
            compare(want, got, f"{path}[{index}]", strict_parsed)
    elif (path.endswith(".uiAmount") and type(expected) in (float, int)
          and type(actual) in (float, int)):
        try:
            within_tolerance = abs(expected - actual) <= 1e-9
        except OverflowError:
            within_tolerance = False
        if not within_tolerance:
            mismatch(path, expected, actual)
    elif not equal_scalar(expected, actual):
        mismatch(path, expected, actual)


def validate(expectation, response, strict_parsed, path="$"):
    kind = expectation["expect_kind"]
    if kind == "batch":
        if not isinstance(response, list):
            mismatch(path, "batch array", response)
        expected_batch = expectation["expected_batch"]
        if len(response) != len(expected_batch):
            mismatch(path + ".length", len(expected_batch), len(response))
        unmatched = list(enumerate(response))
        for item in expected_batch:
            first_error = None
            # JSON-RPC permits responses in any order. Match each once,
            # including repeated IDs and null IDs for invalid requests.
            for index, candidate in unmatched:
                if not isinstance(candidate, dict) or not equal_scalar(
                    item["expected_id"], candidate.get("id", MISSING)
                ):
                    continue
                try:
                    validate(item, candidate, strict_parsed, f"{path}[{index}]")
                except CheckFailed as error:
                    first_error = first_error or error
                else:
                    unmatched.remove((index, candidate))
                    break
            else:
                if first_error is not None:
                    raise first_error
                raise CheckFailed(f"{path}: no unmatched batch response with id {describe(item['expected_id'])}")
        return
    if not isinstance(response, dict):
        mismatch(path, "JSON-RPC object", response)
    compare("2.0", response.get("jsonrpc", MISSING), path + ".jsonrpc")
    compare(expectation["expected_id"], response.get("id", MISSING), path + ".id")
    if kind == "result":
        if "error" in response:
            mismatch(path + ".error", MISSING, response["error"])
        # Single-result diffs are rooted at the block. Batch diffs include the response index.
        try:
            compare(expectation["expected_result"], response.get("result", MISSING), "$", strict_parsed)
        except CheckFailed as error:
            if path == "$":
                raise
            raise CheckFailed(path + ".result" + str(error)[1:]) from error
    elif kind == "error":
        if "result" in response:
            mismatch(path + ".result", MISSING, response["result"])
        error = response.get("error", MISSING)
        if not isinstance(error, dict):
            mismatch(path + ".error", "error object", error)
        code = error.get("code", MISSING)
        if type(code) is not int or code != expectation["expected_error_code"]:
            mismatch(path + ".error.code", expectation["expected_error_code"], code)
        message = error.get("message", MISSING)
        if not isinstance(message, str) or not message:
            mismatch(path + ".error.message", "nonempty string", message)
    else:
        raise CheckFailed(f"unsupported fixture expectation {kind!r}")


def reject_constant(value):
    raise ValueError(f"{value} is not JSON")


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"non-finite JSON number {value}")
    return number


def rpc(bind, body, timeout=30):
    if not isinstance(body, str):
        body = json.dumps(body)
    host, port = bind
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("POST", "/", body.encode("utf-8"), {"Content-Type": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise CheckFailed(f"HTTP status: expected 200, got {response.status}")
        return json.loads(response.read().decode("utf-8"),
                          parse_constant=reject_constant, parse_float=finite_float)
    except (OSError, http.client.HTTPException, ValueError) as error:
        raise CheckFailed(f"RPC request failed: {error}") from error
    finally:
        connection.close()


def request(method, params=None):
    body = {"jsonrpc": "2.0", "id": "probe", "method": method}
    if params is not None:
        body["params"] = params
    return body


def error_expected(code):
    return {"expect_kind": "error", "expected_id": "probe", "expected_error_code": code}


def result_expected(result):
    return {"expect_kind": "result", "expected_id": "probe", "expected_result": result}


def behavior_case(mock):
    """Find a golden result whose requested slot has a nonempty CAR slice."""
    for case in mock.manifest["cases"]:
        if case["expect_kind"] != "result" or not isinstance(case["expected_result"], dict):
            continue
        try:
            body = json.loads(case["raw_body"])
        except ValueError:
            continue
        if not isinstance(body, dict) or body.get("method") != "getBlock":
            continue
        params = body.get("params")
        if not isinstance(params, list) or not params or type(params[0]) is not int:
            continue
        slot = params[0]
        epoch = mock.epochs.get(slot // SLOTS_PER_EPOCH)
        if epoch is not None and epoch[0].get(str(slot), {}).get("length", 0) > 0:
            return case
    raise CheckFailed("fixtures need a successful getBlock case for an archived nonempty slot")


def child_env():
    env = os.environ.copy()
    paths = [Path.home() / ".cargo/bin", Path.home() / ".nix-profile/bin", "/opt/homebrew/bin",
             env.get("PATH", os.defpath)]
    env["PATH"] = os.pathsep.join(map(str, paths))
    no_proxy = env.get("no_proxy", env.get("NO_PROXY", ""))
    env["NO_PROXY"] = env["no_proxy"] = ",".join(filter(None, (no_proxy, "127.0.0.1", "localhost")))
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


def run_build(implementation):
    script = implementation / "build.sh"
    if not script.is_file():
        return None
    with tempfile.TemporaryFile() as log:
        start = time.perf_counter()
        process = subprocess.Popen(
            ["bash", str(script)], cwd=implementation, env=child_env(), stdout=log,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            try:
                code = process.wait(timeout=240)
            except subprocess.TimeoutExpired as error:
                raise CheckFailed("build.sh timed out after 240s") from error
            if code:
                raise CheckFailed(f"build.sh exited {code}")
            return time.perf_counter() - start
        except CheckFailed as error:
            tail = log_tail(log)
            raise CheckFailed(f"{error}\n{tail}".rstrip()) from error
        finally:
            stop(process)


def wait_ready(bind, process):
    deadline = time.monotonic() + 20
    last_error = "no reply"
    while (remaining := deadline - time.monotonic()) > 0:
        started = time.monotonic()
        if process.poll() is not None:
            raise CheckFailed(f"run.sh exited {process.returncode} before readiness")
        try:
            validate(result_expected("ok"), rpc(bind, request("getHealth"), min(remaining, 0.05)), True)
        except CheckFailed as error:
            last_error = str(error)
            time.sleep(max(0, min(started + 0.05, deadline) - time.monotonic()))
        else:
            if process.poll() is None:
                return
    raise CheckFailed(f"getHealth was not ready after 20s ({last_error})")


class PeakRSS:
    """Sample aggregate launcher process-group RSS in KiB on POSIX."""

    def __init__(self, group):
        self.group = group
        self.peak = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()

    def collect(self):
        while not self.done.is_set():
            self.sample()
            self.done.wait(0.10)

    def sample(self):
        try:
            rows = subprocess.check_output(
                ["ps", "-axo", "pgid=,rss="], text=True, stderr=subprocess.DEVNULL, timeout=2,
            )
            rss = sum(int(kib) for pgid, kib in map(str.split, rows.splitlines()) if int(pgid) == self.group)
            if rss:
                self.peak = max(self.peak or 0, rss)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass

    def close(self):
        self.done.set()
        self.thread.join()


def check_tmpdir(tmpdir):
    for path in tmpdir.rglob("*"):
        if path.is_symlink() or not path.is_dir():
            raise CheckFailed(f"server left an entry in TMPDIR: {path.relative_to(tmpdir)}")


@contextlib.contextmanager
def running_server(implementation, base_url, bench=False):
    with tempfile.TemporaryDirectory(prefix="onlyblocks-") as directory, tempfile.TemporaryFile() as log:
        tmpdir = Path(directory)
        env = child_env()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            bind = reservation.getsockname()
        address = f"{bind[0]}:{bind[1]}"
        env.update(ONLYBLOCKS_BIND=address, OLD_FAITHFUL_BASE_URL=base_url, TMPDIR=str(tmpdir))
        process = subprocess.Popen(
            ["bash", str(implementation / "run.sh"), "--bind", address, "--base-url", base_url],
            cwd=implementation, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
        )
        rss = PeakRSS(process.pid) if bench else None
        try:
            wait_ready(bind, process)
            check_tmpdir(tmpdir)
            yield bind, tmpdir, rss
        except CheckFailed as error:
            tail = log_tail(log)
            raise CheckFailed(f"{error}\nserver log:\n{tail}" if tail else str(error)) from error
        finally:
            if rss is not None:
                rss.close()
                rss.sample()
            stop(process)
        check_tmpdir(tmpdir)


def run_case(bind, case, strict_parsed):
    validate(case, rpc(bind, case["raw_body"]), strict_parsed)


def removed_transaction(slot):
    return request("getTransaction", ["1" * 64, {"slot": slot}])


def golden_and_removed(implementation, mock, case_for_slot, strict_parsed):
    failures = []
    with running_server(implementation, mock.base_url) as (bind, tmpdir, _):
        for case in mock.manifest["cases"]:
            try:
                run_case(bind, case, strict_parsed)
                check_tmpdir(tmpdir)
            except CheckFailed as error:
                failures.append(f"{case['id']}: {error}")
        try:
            mock.reset()
            slot = json.loads(case_for_slot["raw_body"])["params"][0]
            validate(error_expected(-32601), rpc(bind, removed_transaction(slot)), True)
            check_tmpdir(tmpdir)
            compare(0, mock.stats()["total_requests"], "getTransaction upstream requests")
        except CheckFailed as error:
            failures.append(f"getTransaction zero-network: {error}")
    return failures


def cache_probe(implementation, mock, case, strict_parsed, bench, stats):
    def fetch():
        start = time.perf_counter()
        reply = rpc(bind, case["raw_body"])
        elapsed_ms = (time.perf_counter() - start) * 1000
        validate(case, reply, strict_parsed)
        check_tmpdir(tmpdir)
        return elapsed_ms

    with running_server(implementation, mock.base_url, bench) as (bind, tmpdir, rss):
        mock.reset()
        cold = fetch()
        cold_range_reqs = mock.stats()["slot_range_requests"]
        if cold_range_reqs < 1:
            raise CheckFailed("cold getBlock made no slot-range requests")
        mock.reset()
        fetch()
        compare(0, mock.stats()["slot_range_requests"], "warm getBlock slot-range requests")
        stats.update(cold_range_reqs=cold_range_reqs, warm_range_reqs=0)
        if bench:
            warm = [fetch() for _ in range(20)]
            compare(0, mock.stats()["slot_range_requests"], "benchmark warm getBlock slot-range requests")
            stats.update(
                cold_ms=cold,
                warm_p50_ms=statistics.median(warm),
                warm_p95_ms=statistics.quantiles(warm, n=100, method="inclusive")[94],
            )
    if bench:
        if rss.peak is None:
            raise CheckFailed("could not sample implementation RSS with ps")
        stats["peak_rss_kib"] = rss.peak


def retry_probe(implementation, mock, case, strict_parsed):
    with running_server(implementation, mock.base_url) as (bind, tmpdir, _):
        mock.reset()
        mock.inject_429(retry_after=0)
        run_case(bind, case, strict_parsed)
        check_tmpdir(tmpdir)
        stats = mock.stats()
        compare(1, stats["injected_429"], "consumed injected HTTP 429 responses")
        if stats["slot_range_requests"] < 2 or stats["car_requests"] < 1:
            raise CheckFailed(f"expected a cold retry followed by a CAR request, got {stats}")


def live_probe(implementation):
    with running_server(implementation, LIVE_URL) as (bind, tmpdir, _):
        config = {"encoding": "json", "maxSupportedTransactionVersion": 0}
        for slot in (302400001, 302400004, 43200000):
            time.sleep(1)
            try:
                response = rpc(bind, request("getBlock", [slot, config]))
                if slot == 302400004:
                    validate(error_expected(-32007), response, True)
                else:
                    block = response.get("result") if isinstance(response, dict) else None
                    if not isinstance(block, dict):
                        mismatch("$.result", "block object", response)
                    validate(result_expected(block), response, True)
                    if not isinstance(block.get("blockhash"), str) or not block["blockhash"]:
                        mismatch("$.result.blockhash", "nonempty string", block.get("blockhash", MISSING))
                    transactions = block.get("transactions")
                    if not isinstance(transactions, list) or not transactions:
                        mismatch("$.result.transactions", "nonempty array", transactions)
                    if slot == 302400001 and not any(
                        isinstance(tx, dict) and type(tx.get("version")) is int and tx["version"] == 0
                        for tx in transactions
                    ):
                        raise CheckFailed("$.result.transactions has no v0 transaction")
                check_tmpdir(tmpdir)
            except CheckFailed as error:
                raise CheckFailed(f"live slot {slot}: {error}") from error
        validate(error_expected(-32601), rpc(bind, removed_transaction(302400001)), True)
        check_tmpdir(tmpdir)


SOURCE_TYPES = frozenset("""
asm bash c cc clj cljs cob cpp cs d dart elm erl ex exs f f90 fish fs fsx go groovy h hh hpp hs
hx java jl js jsx kt kts lisp lua m mjs ml mli nim odin pas php pl pm py r rb rs scala scm sh
swift tcl ts tsx v vala wat zig
""".split())
HASH_COMMENTS = frozenset("bash ex exs fish jl nim php pl pm py r rb sh tcl".split())
DASH_COMMENTS = frozenset("elm hs lua".split())
SEMICOLON_COMMENTS = frozenset("asm clj cljs lisp scm wat".split())
BLOCK_COMMENTS = {
    "elm": ("{-", "-}"), "hs": ("{-", "-}"), "lua": ("--[[", "]]"),
    "ml": ("(*", "*)"), "mli": ("(*", "*)"), "nim": ("#[", "]#"),
    "wat": ("(;", ";)"),
}
GENERATED_DIRS = {"bin", "build", "dist", "node_modules", "obj", "out", "target", "__pycache__"}
BINARY_MAGIC = {
    b"\x7fELF", b"\x00asm", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}


def source_loc(path):
    suffix = path.suffix.lower()[1:]
    line_comment = "//"
    if suffix in HASH_COMMENTS:
        line_comment = ("#", "//") if suffix == "php" else "#"
    elif suffix in DASH_COMMENTS:
        line_comment = "--"
    elif suffix in SEMICOLON_COMMENTS:
        line_comment = ";"
    elif suffix == "erl":
        line_comment = "%"
    elif suffix in ("f", "f90"):
        line_comment = "!"
    block_start, block_end = BLOCK_COMMENTS.get(suffix, ("/*", "*/"))
    in_comment = False
    count = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        while in_comment or line.startswith(block_start):
            if not in_comment:
                line = line[len(block_start):]
            _, end, rest = line.partition(block_end)
            in_comment = not end
            if in_comment:
                break
            line = rest.lstrip()
        if not in_comment and line and not line.startswith(line_comment):
            count += 1
    return count


def benchmark_files(implementation):
    sources = []
    for root, dirs, files in os.walk(implementation):
        dirs[:] = [name for name in dirs if not name.startswith(".") and name not in GENERATED_DIRS]
        for name in files:
            path = Path(root) / name
            if (path.suffix.lower()[1:] in SOURCE_TYPES and not name.startswith(".")
                    and name not in ("build.sh", "run.sh") and not path.is_symlink()):
                sources.append(path)
    if not sources:
        sources.append(implementation / "run.sh")
    candidates = list(implementation.iterdir())
    for build_dir in ("bin", "build", "dist", "out", "target/release"):
        candidates.extend((implementation / build_dir).glob("*"))
    artifacts = []
    for path in candidates:
        if path.is_symlink() or not path.is_file() or path.suffix.lower()[1:] in SOURCE_TYPES:
            continue
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic in BINARY_MAGIC or path.suffix.lower() in (".jar", ".exe", ".dll"):
            artifacts.append(path)
    if artifacts:
        artifact = max(artifacts, key=lambda path: (path.stat().st_size, str(path)))
        size = artifact.stat().st_size
        artifact_path = str(artifact.relative_to(implementation))
    else:
        size = sum(path.stat().st_size for path in sources)
        artifact_path = None
    return {
        "source_loc": sum(source_loc(path) for path in sources),
        "artifact_bytes": size,
        "artifact_path": artifact_path,
    }


def run_implementation(implementation, mock, case, args):
    failures = []
    stats = {}
    try:
        if not (implementation / "run.sh").is_file():
            raise CheckFailed("missing run.sh")
        stats["build_seconds"] = run_build(implementation)
    except (OSError, CheckFailed) as error:
        return stats, [f"build/launch: {error}"]
    checks = [
        ("golden cases", lambda: golden_and_removed(implementation, mock, case, args.strict_parsed)),
        ("RAM cache", lambda: cache_probe(implementation, mock, case, args.strict_parsed, args.bench, stats)),
        ("HTTP 429 retry", lambda: retry_probe(implementation, mock, case, args.strict_parsed)),
    ]
    if args.bench:
        checks.append(("benchmark files", lambda: stats.update(benchmark_files(implementation))))
    if args.live:
        checks.append(("live smoke", lambda: live_probe(implementation)))
    for label, check in checks:
        try:
            failures.extend(check() or [])
        except (OSError, CheckFailed) as error:
            failures.append(f"{label}: {error}")
    return stats, failures


def run(args):
    impls = ROOT / "impls"
    slugs = args.impl or sorted(path.parent.name for path in impls.glob("*/run.sh"))
    if not slugs:
        raise CheckFailed(f"no implementations found in {impls}")
    if any(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.+-]*", slug) is None for slug in slugs):
        raise CheckFailed("expected an implementation slug with no path components")
    results = []
    with MockOldFaithful(args.fixtures) as mock:
        case = behavior_case(mock)
        for slug in dict.fromkeys(slugs):
            print(f"Testing {slug}...", flush=True)
            stats, failures = run_implementation(impls / slug, mock, case, args)
            results.append({"impl": slug, "passed": not failures, "failures": failures, **stats})
    width = max(len("Implementation"), *(len(row["impl"]) for row in results))
    print(f"{'Implementation':<{width}}  Result")
    for row in results:
        status = "PASS" if row["passed"] else "FAIL"
        print(f"{row['impl']:<{width}}  {status}")
        for failure in row["failures"]:
            print(f"  {failure}")
        if args.bench and "peak_rss_kib" in row:
            print(f"  cold {row['cold_ms']:.2f} ms, warm p50 {row['warm_p50_ms']:.2f} ms, "
                  f"p95 {row['warm_p95_ms']:.2f} ms, peak RSS {row['peak_rss_kib']} KiB")
        if args.bench and "source_loc" in row:
            print(f"  {row['source_loc']} source LOC, {row['artifact_bytes']} artifact bytes")
            if row["build_seconds"] is not None:
                print(f"  build {row['build_seconds']:.2f} s")
    if args.json_out is not None:
        args.json_out.write_text(json.dumps({"implementations": results}, indent=2) + "\n", encoding="utf-8")
    return 0 if all(row["passed"] for row in results) else 1


DUMMY_SERVER = """\
import http.client, json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

bind, base = sys.argv[2], sys.argv[4]
assert bind == os.environ["ONLYBLOCKS_BIND"]
assert base == os.environ["OLD_FAITHFUL_BASE_URL"]
assert not os.listdir(os.environ["TMPDIR"])
archive = base.split("//")[1]
cached = set()

def read_range(path, start, end):
    for _ in range(2):
        conn = http.client.HTTPConnection(archive, timeout=2)
        conn.request("GET", path, headers={"Range": f"bytes={start}-{end}"})
        reply = conn.getresponse()
        data = reply.read()
        conn.close()
        if reply.status == 206:
            return data
        assert reply.status == 429 and reply.getheader("Retry-After") in ("0", "1")
    raise RuntimeError("retry failed")

def handle(req):
    if isinstance(req, list):
        return [handle(item) for item in reversed(req)]
    r = {"jsonrpc": "2.0", "id": req.get("id")}
    if req.get("method") == "getHealth":
        r["result"] = "ok"
    elif req.get("method") == "getBlock":
        if req["params"][0] not in cached:
            assert len(read_range("/100/epoch-100-slot-ranges.raw", 0, 11)) == 12
            cached.add(req["params"][0])
        assert read_range("/100/epoch-100.car", 0, 2) == b"CAR"
        r["result"] = {"transactions": [{"meta": {"fee": 5000}}]}
    else:
        r["error"] = {"code": -32601 if req else -32700, "message": "dummy"}
    return r

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        try:
            req = json.loads(raw)
        except ValueError:
            req = {}
        data = json.dumps(handle(req)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

ThreadingHTTPServer(("127.0.0.1", int(bind.split(":")[1])), Handler).serve_forever()
"""


def self_test():
    check_comparison()
    health = request("getHealth")
    dropped = dict(request("getTransaction"), id=4)
    batch_error = dict(error_expected(-32601), expected_id=4)
    block = result_expected({"transactions": [{"meta": {"fee": 5000}}]})
    manifest = {
        "version": 1, "archived_epochs": [100],
        "epochs": {"100": {"car_file": "epoch-100.car",
                           "slot_ranges": {"43200000": {"offset": 0, "length": 3}}}},
        "cases": [
            dict(result_expected("ok"), id="health", raw_body=json.dumps(health)),
            dict(block, id="block", raw_body=json.dumps(request("getBlock", [43200000]))),
            dict(batch_error, id="removed", raw_body=json.dumps(dropped)),
            dict(error_expected(-32700), expected_id=None, id="parse_error", raw_body="{"),
            {"id": "batch", "raw_body": json.dumps([health, dropped]), "expect_kind": "batch",
             "expected_batch": [result_expected("ok"), batch_error]},
        ],
    }
    with tempfile.TemporaryDirectory(prefix="onlyblocks-self-test-") as directory:
        root = Path(directory)
        fixture = root / "manifest.json"
        fixture.write_text(json.dumps(manifest), encoding="utf-8")
        (root / "epoch-100.car").write_bytes(b"CAR")
        with MockOldFaithful(fixture) as mock:
            check_range_origin(mock)
        scripts = root / "conformance"
        scripts.mkdir()
        for script in ("runner.py", "mock_old_faithful.py"):
            shutil.copyfile(Path(__file__).with_name(script), scripts / script)
        dummy = root / "impls" / "dummy"
        dummy.mkdir(parents=True)
        (dummy / "server.py").write_text(DUMMY_SERVER, encoding="utf-8")
        (dummy / "run.sh").write_text('exec "$DUMMY_PYTHON" server.py "$@"\n', encoding="utf-8")
        (dummy / "build.sh").write_text('test -f server.py\n', encoding="utf-8")
        output = root / "benchmark.json"
        cmd = [sys.executable, str(scripts / "runner.py"), "--fixtures", str(fixture),
               "--bench", "--json-out", str(output)]
        env = dict(os.environ, DUMMY_PYTHON=sys.executable)
        passing = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=45)
        if passing.returncode != 0 or "PASS" not in passing.stdout:
            raise CheckFailed(f"self-test passing fixture did not pass:\n{passing.stdout}{passing.stderr}")
        summary = json.loads(output.read_text(encoding="utf-8"))["implementations"][0]
        if not (summary["passed"] and summary["cold_range_reqs"] == 1
                and summary["warm_range_reqs"] == 0 and summary["build_seconds"] >= 0
                and summary["source_loc"] > 0 and summary["artifact_bytes"] > 0
                and 0 <= summary["warm_p50_ms"] <= summary["warm_p95_ms"]
                and summary["peak_rss_kib"] > 0):
            raise CheckFailed(f"self-test incomplete benchmark summary: {summary}")

        block["expected_result"]["transactions"][0]["meta"]["fee"] = 1
        fixture.write_text(json.dumps(manifest), encoding="utf-8")
        failing = subprocess.run([*cmd, "--impl", "dummy"], env=env,
                                 capture_output=True, text=True, timeout=45)
        diff = "$.transactions[0].meta.fee: expected 1, got 5000"
        if failing.returncode != 1 or "FAIL" not in failing.stdout or diff not in failing.stdout:
            raise CheckFailed(f"self-test failing fixture did not report {diff!r}:\n"
                              f"{failing.stdout}{failing.stderr}")
    print("Self-test PASS: Range origin, golden cases, parsed comparison, zero-network getTransaction, "
          "RAM cache, HTTP 429 retry, benchmarks")
    print(f"Self-test PASS: failing golden case exited 1 with {diff}")


def check_comparison():
    program_id = "11111111111111111111111111111111"
    raw = {"programId": program_id, "accounts": ["a", "b"], "data": "2", "stackHeight": 1}
    parsed = {"program": "system", "programId": program_id, "parsed": {"type": "transfer"}}
    instructions = "$.transactions[0].transaction.message.instructions[0]"
    meta = "$.transactions[0].meta"
    compare(raw, parsed, instructions)
    compare(parsed, raw, instructions)
    compare({}, {"returnData": None}, meta)
    compare(0.5, 0.5000000001, meta + ".preTokenBalances[0].uiTokenAmount.uiAmount")
    for want, got, path, strict in (
        (raw, parsed, instructions, True),
        (raw, parsed, meta + ".innerInstructions[0].instructions[0]", False),
        (["a"], ["b"], "$.transactions[0].transaction.message.accountKeys", False),
        ({}, {"fee": None}, meta, False),
        (1, True, "$.id", False),
    ):
        try:
            compare(want, got, path, strict)
        except CheckFailed:
            continue
        raise CheckFailed(f"self-test comparison accepted differing values at {path}")


def check_range_origin(mock):
    connection = http.client.HTTPConnection("127.0.0.1", mock.server_port, timeout=2)

    def call(method, path, status, body=None, **headers):
        connection.request(method, path, body, headers)
        reply = connection.getresponse()
        data = reply.read()
        compare(status, reply.status, path + " status")
        compare(len(data), int(reply.getheader("Content-Length")), path + " Content-Length")
        return data, reply

    try:
        ranges = "/100/epoch-100-slot-ranges.raw"
        car = "/100/epoch-100.car"
        call("GET", ranges, 400)
        call("GET", "/101/epoch-101.car", 404, Range="bytes=0-0")
        data, reply = call("GET", ranges, 206, Range="bytes=1-23")
        expected = ENTRY.pack(0, 3)[1:] + ENTRY.pack(0, 0)
        if data != expected or reply.getheader("Content-Range") != "bytes 1-23/5184000":
            raise CheckFailed("self-test mock returned incorrect unaligned multi-slot range")
        call("GET", car, 416, Range="bytes=0-3")
        call("POST", "/__reset", 200)
        call("POST", "/__inject_429", 200, b'{"count": 2, "retry_after": 1}')
        for _ in range(2):
            _, reply = call("GET", car, 429, Range="bytes=1-2")
            compare("1", reply.getheader("Retry-After"), "Retry-After")
        data, reply = call("GET", car, 206, Range="bytes=1-2")
        if data != b"AR" or reply.getheader("Content-Range") != "bytes 1-2/3":
            raise CheckFailed("self-test mock returned incorrect CAR slice")
        stats, _ = call("GET", "/__stats", 200, Connection="close")
        compare(dict(total_requests=3, slot_range_requests=0, car_requests=3,
                     injected_429=2, pending_429=0), json.loads(stats))
        if connection.sock is not None:
            raise CheckFailed("self-test mock ignored Connection: close")
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--impl", action="append", help="implementation slug (repeatable)")
    parser.add_argument("--fixtures", type=Path, default=ROOT / "conformance/fixtures/manifest.json")
    parser.add_argument("--strict-parsed", action="store_true", help="require golden instruction shapes")
    parser.add_argument("--live", action="store_true", help="also smoke-test live Old Faithful")
    parser.add_argument("--bench", action="store_true", help="collect size, latency and RSS metrics")
    parser.add_argument("--json-out", type=Path, help="write the result summary as JSON")
    parser.add_argument("--self-test", action="store_true", help="exercise the harness with a temporary implementation")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        return run(args)
    except (CheckFailed, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f"conformance: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
