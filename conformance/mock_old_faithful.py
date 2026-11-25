#!/usr/bin/env python3
"""Loopback Old Faithful Range origin for the offline conformance runner."""

import argparse
import json
import re
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SLOTS_PER_EPOCH = 432_000
ENTRY = struct.Struct("<QI")
ROUTE = re.compile(r"/([0-9]{1,20})/epoch-\1(-slot-ranges\.raw|\.car)")
BYTE_RANGE = re.compile(r"bytes=([0-9]{1,20})-([0-9]{1,20})", re.IGNORECASE)


class MockOldFaithful(ThreadingHTTPServer):
    def __init__(self, manifest_path):
        with manifest_path.open(encoding="utf-8") as stream:
            self.manifest = json.load(stream)
        if type(self.manifest["version"]) is not int or self.manifest["version"] != 1:
            raise ValueError("unsupported fixture manifest version")
        self.epochs = {}
        for epoch in self.manifest["archived_epochs"]:
            fixture = self.manifest["epochs"][str(epoch)]
            car = (manifest_path.parent / fixture["car_file"]).read_bytes()
            self.epochs[epoch] = fixture["slot_ranges"], car
        self.lock = threading.Lock()
        self.reset()
        super().__init__(("127.0.0.1", 0), RangeHandler)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server_port}"

    def __enter__(self):
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc_info):
        self.shutdown()
        self.server_close()
        self.thread.join()

    def stats(self):
        with self.lock:
            return dict(self.counters, pending_429=self.pending_429)

    def reset(self):
        with self.lock:
            self.counters = dict.fromkeys(
                ("slot_range_requests", "car_requests", "total_requests", "injected_429"), 0
            )
            self.pending_429 = 0
            self.retry_after = 0

    def inject_429(self, count=1, retry_after=0):
        if type(count) is not int or count < 1:
            raise ValueError("count must be a positive integer")
        if type(retry_after) is not int or retry_after not in (0, 1):
            raise ValueError("retry_after must be 0 or 1")
        with self.lock:
            self.pending_429 += count
            self.retry_after = retry_after

    def record_request(self, counter, can_inject):
        with self.lock:
            self.counters["total_requests"] += 1
            if counter is not None:
                self.counters[counter] += 1
            if can_inject and self.pending_429:
                self.pending_429 -= 1
                self.counters["injected_429"] += 1
                return self.retry_after
        return None


class RangeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, *_args):
        pass

    def send_error(self, code, message=None, explain=None):
        if code == 501:
            self.server.record_request(None, can_inject=False)
        super().send_error(code, message, explain)

    def reply(self, status, body=b"", content_type="application/octet-stream", **headers):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), str(value))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def reply_json(self, status, value):
        self.reply(status, json.dumps(value).encode(), "application/json")

    def do_GET(self):
        if self.path == "/__stats":
            self.reply_json(200, self.server.stats())
            return
        match = ROUTE.fullmatch(self.path)
        if match is None:
            self.server.record_request(None, can_inject=False)
            self.reply(404)
            return

        epoch = int(match[1])
        slot_ranges = match[2] == "-slot-ranges.raw"
        counter = "slot_range_requests" if slot_ranges else "car_requests"
        fixture = self.server.epochs.get(epoch)
        header = self.headers.get_all("Range", [])
        byte_range = BYTE_RANGE.fullmatch(header[0]) if len(header) == 1 else None
        if fixture is None:
            self.server.record_request(counter, can_inject=False)
            self.reply(404)
            return
        if byte_range is None:
            self.server.record_request(counter, can_inject=False)
            self.reply(400)
            return
        start, end = map(int, byte_range.groups())
        ranges, car = fixture
        size = SLOTS_PER_EPOCH * ENTRY.size if slot_ranges else len(car)
        in_bounds = start <= end < size
        retry_after = self.server.record_request(counter, can_inject=in_bounds)
        if not in_bounds:
            self.reply(416, Content_Range=f"bytes */{size}")
            return
        if retry_after is not None:
            self.reply(429, Retry_After=retry_after)
            return
        if slot_ranges:
            first, last = start // ENTRY.size, end // ENTRY.size
            data = bytearray((last - first + 1) * ENTRY.size)
            for index in range(first, last + 1):
                record = ranges.get(str(epoch * SLOTS_PER_EPOCH + index))
                if record is not None:
                    ENTRY.pack_into(data, (index - first) * ENTRY.size,
                                    record["offset"], record["length"])
            cut = start % ENTRY.size
            body = data[cut:cut + end - start + 1]
        else:
            body = car[start:end + 1]
        self.reply(206, body, Content_Range=f"bytes {start}-{end}/{size}")

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if self.headers.get("Transfer-Encoding") or not 0 <= length <= 4096:
                raise ValueError("expected up to 4096 bytes with Content-Length")
            body = self.rfile.read(length) if length else b"{}"
            if self.path == "/__reset":
                self.server.reset()
            elif self.path == "/__inject_429":
                params = json.loads(body)
                self.server.inject_429(params.get("count", 1), params.get("retry_after", 0))
            else:
                self.server.record_request(None, can_inject=False)
                self.reply(404)
                return
        except (ValueError, AttributeError) as error:
            self.close_connection = True
            self.reply_json(400, {"error": str(error)})
            return
        self.reply_json(200, self.server.stats())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).parent / "fixtures/manifest.json")
    args = parser.parse_args()
    with MockOldFaithful(args.fixtures) as mock:
        print(mock.base_url, flush=True)
        try:
            mock.thread.join()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
