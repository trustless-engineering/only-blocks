#!/usr/bin/env python3
"""Measure a clean OnlyBlocks snapshot and compare direct HTTPS mainnet responses."""

import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
import runner


WARM_REQUESTS = 30
LIVE_RPC_PAUSE = 3
FIXTURES = runner.ROOT / "conformance/fixtures/manifest.json"
SOURCES = runner.SOURCE_TYPES | {"awk", "s"}
ARTIFACTS = {
    "arm64-asm": "bin/onlyblocks",
    "c": "build/onlyblocks",
    "cpp": "build/onlyblocks",
    "csharp": "build/OnlyBlocks.dll",
    "elixir": "_build/ebin/*.beam",
    "erlang": "ebin/*.beam",
    "fortran": "bin/onlyblocks",
    "go": "bin/onlyblocks",
    "haskell": "bin/onlyblocks",
    "java": "build/**/*.class",
    "kotlin": "build/onlyblocks.jar",
    "ocaml": "bin/onlyblocks",
    "rust": "target/release/onlyblocks",
    "swift": "build/onlyblocks",
    "zig": "bin/onlyblocks",
}


def command(*args, cwd=runner.ROOT):
    return subprocess.check_output(args, cwd=cwd, env=runner.child_env())


def footprint(implementation):
    sources = sorted(
        path.relative_to(implementation)
        for path in implementation.rglob("*")
        if path.is_file() and path.suffix[1:] in SOURCES
        and path.name not in {"build.sh", "run.sh"}
    )
    counts = json.loads(command(
        "cloc", "--json", "--quiet", "--skip-uniqueness", "--",
        *map(str, sources), cwd=implementation,
    ))["SUM"]
    runner.compare(len(sources), counts["nFiles"], "source files counted by cloc")
    return {
        "loc": counts["code"],
        "source_kib": sum((implementation / path).stat().st_size for path in sources) / 1024,
    }


def offline(implementation, mock, case):
    metrics = footprint(implementation)
    metrics["build_seconds"] = runner.run_build(implementation)
    spec = ARTIFACTS.get(implementation.name)
    if spec:
        artifacts = sorted(path for path in implementation.glob(spec) if path.is_file())
        if not artifacts:
            raise runner.CheckFailed(f"build produced no files matching {spec}")
        metrics["binary_kib"] = sum(path.stat().st_size for path in artifacts) / 1024
        metrics["artifact_files"] = [str(path.relative_to(implementation)) for path in artifacts]
    else:
        metrics["binary_kib"] = None

    def sample():
        start = time.perf_counter()
        response = runner.rpc(bind, case["raw_body"])
        elapsed = (time.perf_counter() - start) * 1000
        runner.validate(case, response, True)
        return elapsed

    mock.reset()
    start = time.perf_counter()
    with runner.running_server(implementation, mock.base_url, bench=True) as (bind, _, rss):
        metrics["startup_to_health_ms"] = (time.perf_counter() - start) * 1000
        runner.compare(0, mock.stats()["total_requests"], "startup upstream requests")
        metrics["cold_getblock_ms"] = sample()
        metrics["cold_upstream"] = mock.stats()
        if metrics["cold_upstream"]["slot_range_requests"] < 1:
            raise runner.CheckFailed("cold getBlock made no slot-range requests")
        mock.reset()
        samples = [sample() for _ in range(WARM_REQUESTS)]
        metrics["warm_upstream"] = mock.stats()
        runner.compare(0, metrics["warm_upstream"]["slot_range_requests"], "warm slot-range reads")
    if rss.peak is None:
        raise runner.CheckFailed("could not sample peak RSS")
    metrics.update(
        warm_getblock_samples_ms=samples,
        warm_getblock_p50_ms=statistics.median(samples),
        warm_getblock_p95_ms=statistics.quantiles(samples, n=100, method="inclusive")[94],
        peak_rss_mib=rss.peak / 1024,
    )
    return {"status": "passed", **metrics}


def block_facts(response, slot):
    block = response.get("result") if isinstance(response, dict) else None
    if not isinstance(block, dict):
        runner.mismatch("$.result", "block object", response)
    runner.validate(runner.result_expected(block), response, True)
    expected = runner.LIVE_BLOCKS[slot]
    facts = {key: block.get(key, runner.MISSING) for key in runner.BLOCK_HEADER_KEYS}
    for key, value in facts.items():
        runner.compare(expected[key], value, key)
        if type(value) is not type(expected[key]):
            raise runner.CheckFailed(f"{key}: expected {type(expected[key]).__name__}")
    transactions = block.get("transactions")
    if not isinstance(transactions, list):
        runner.mismatch("$.transactions", "array", transactions)
    runner.compare(expected["transactions"], len(transactions), "$.transactions.length")
    try:
        fee = transactions[0]["meta"]["fee"]
    except (KeyError, TypeError) as error:
        raise runner.CheckFailed("first transaction is missing meta.fee") from error
    if type(fee) is not int or fee < 0:
        runner.mismatch("$.transactions[0].meta.fee", "nonnegative integer", fee)
    return dict(facts, transaction_count=len(transactions), first_transaction_fee=fee)


def live(implementation):
    checks = {}
    try:
        with runner.running_server(implementation, runner.LIVE_URL) as (bind, _, _):
            for slot in (302400001, 302400004, 43200000, None):
                label = str(slot) if slot is not None else "getTransaction"
                try:
                    if slot is None:
                        request = runner.removed_transaction(302400001)
                    else:
                        time.sleep(LIVE_RPC_PAUSE)
                        request = runner.request("getBlock", [
                            slot, {"encoding": "json", "maxSupportedTransactionVersion": 0},
                        ])
                    response = runner.rpc(bind, request, runner.LIVE_TIMEOUT)
                    if slot is None or slot == 302400004:
                        code = -32601 if slot is None else -32007
                        runner.validate(runner.error_expected(code), response, True)
                        checks[label] = {"status": "passed", "error_code": code}
                    else:
                        checks[label] = {"status": "passed", "facts": block_facts(response, slot)}
                except runner.CheckFailed as error:
                    checks[label] = {"status": "failed", "error": str(error)}
                    # A transport failure can leave work in flight. Stop this server
                    # before sending any more requests to the upstream.
                    if error.__cause__ is not None:
                        break
    except (OSError, runner.CheckFailed) as error:
        return {"status": "failed", "checks": checks, "error": str(error)}
    passed = len(checks) == 4 and all(check["status"] == "passed" for check in checks.values())
    return {"status": "passed" if passed else "failed", "checks": checks}


def parity(rows):
    slots = {}
    for slot in ("302400001", "43200000"):
        matching = {}
        missing = []
        for row in rows:
            facts = row["live"].get("checks", {}).get(slot, {}).get("facts")
            if facts is None:
                missing.append(row["impl"])
            else:
                matching.setdefault(tuple(facts.items()), []).append(row["impl"])
        slots[slot] = {
            "status": "passed" if not missing and len(matching) == 1 else "failed",
            "matching_groups": [
                {"facts": dict(facts), "implementations": slugs} for facts, slugs in matching.items()
            ],
            "missing": missing,
        }
    passed = all(slot["status"] == "passed" for slot in slots.values())
    return {"status": "passed" if passed else "failed", "slots": slots}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=runner.ROOT / "conformance/results.json")
    args = parser.parse_args()
    cloc_version = command("cloc", "--version").decode().strip()
    revision = command("git", "rev-parse", "HEAD").decode().strip()
    snapshot = command("git", "archive", revision, "impls")
    results = {
        "schema_version": 1,
        "source_revision": revision,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count(),
                 "python": platform.python_version(), "cloc": cloc_version},
        "method": {
            "offline_fixture": "modern_json_full",
            "offline_slot": 302400011,
            "warm_requests": WARM_REQUESTS,
            "latency": "One loopback HTTP connection per RPC, including client JSON decoding. p95 uses linear interpolation.",
            "startup": "Launcher setup through first valid getHealth, with a 50 ms readiness polling interval.",
            "loc": "cloc over tracked source files including tests, excluding build.sh and run.sh.",
            "size": "Uncompressed tracked code and runnable binary/module files. Runtime installations and build intermediates are excluded.",
            "build": "One build.sh invocation from a clean source tree with existing toolchain caches.",
            "rss": "Peak sampled aggregate process-group RSS via ps at 100 ms intervals plus a post-workload sample. Short-lived peaks can be missed and shared pages can be counted twice.",
            "isolation": "One implementation at a time. Ambient host activity was not controlled.",
            "live": "Direct HTTPS. One RPC at a time with a pause before every getBlock. Internal range requests and retries are governed by each implementation.",
            "live_origin": runner.LIVE_URL,
            "live_pause_before_getblock_seconds": LIVE_RPC_PAUSE,
        },
        "implementations": [],
    }
    with tempfile.TemporaryDirectory(prefix="onlyblocks-bench-") as workspace:
        with tarfile.open(fileobj=io.BytesIO(snapshot)) as archive:
            archive.extractall(workspace, filter="data")
        implementations = sorted(path for path in (Path(workspace) / "impls").iterdir() if path.is_dir())
        rows = [{"impl": path.name} for path in implementations]
        results["implementations"] = rows
        with runner.MockOldFaithful(FIXTURES) as mock:
            case, = (case for case in mock.manifest["cases"] if case["id"] == "modern_json_full")
            for implementation, row in zip(implementations, rows):
                try:
                    row["offline"] = offline(implementation, mock, case)
                except (OSError, subprocess.SubprocessError, runner.CheckFailed) as error:
                    row["offline"] = {"status": "failed", "error": str(error)}
                print(f"{implementation.name} offline {row['offline']['status']}", flush=True)
        for implementation, row in zip(implementations, rows):
            row["live"] = live(implementation)
            print(f"{implementation.name} live {row['live']['status']}", flush=True)
        results["cross_language_live_parity"] = parity(rows)
    results["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    results["passed"] = (
        results["cross_language_live_parity"]["status"] == "passed"
        and all(row[mode]["status"] == "passed" for row in rows for mode in ("offline", "live"))
    )
    args.output.write_text(json.dumps(results, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
