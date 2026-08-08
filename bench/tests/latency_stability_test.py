#!/usr/bin/env python3

import importlib.util
import io
import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "latency_stability.py"
SPEC = importlib.util.spec_from_file_location("latency_stability", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
latency_stability = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(latency_stability)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class SlowHandler(Handler):
    def do_GET(self) -> None:
        time.sleep(0.15)
        super().do_GET()



class ErrorHandler(Handler):
    def do_GET(self) -> None:
        self.send_response(503)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

class LatencyStabilityTests(unittest.TestCase):
    def test_nearest_rank(self) -> None:
        values = [5.0, 1.0, 4.0, 2.0, 3.0]
        self.assertEqual(latency_stability.nearest_rank(values, 0.50), 3.0)
        self.assertEqual(latency_stability.nearest_rank(values, 0.95), 5.0)
        self.assertIsNone(latency_stability.nearest_rank([], 0.99))

    def test_collects_successful_samples_and_ordered_quantiles(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        sink = io.StringIO()
        try:
            summary = latency_stability.collect(
                target="127.0.0.1",
                port=server.server_address[1],
                path="/",
                samples=7,
                interval_ms=1,
                timeout=1.0,
                engine="test",
                protocol="direct",
                sink=sink,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        self.assertEqual(summary["attempts"], 7)
        self.assertEqual(summary["successes"], 7)
        self.assertEqual(summary["failures"], 0)
        self.assertLessEqual(summary["p50_ms"], summary["p95_ms"])
        self.assertLessEqual(summary["p95_ms"], summary["p99_ms"])
        self.assertEqual(len(sink.getvalue().splitlines()), 7)

    def test_slow_requests_do_not_serialize_the_schedule(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        sink = io.StringIO()
        try:
            summary = latency_stability.collect(
                target="127.0.0.1",
                port=server.server_address[1],
                path="/",
                samples=5,
                interval_ms=25,
                timeout=1.0,
                engine="test",
                protocol="direct",
                sink=sink,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        self.assertEqual(summary["successes"], 5)
        self.assertLess(summary["duration_s"], 0.6)
        self.assertLess(summary["schedule_lag_max_ms"], 100)
        self.assertTrue(
            all('"schedule_lag_ms"' in row for row in sink.getvalue().splitlines())
        )

    def test_http_error_status_remains_a_failure(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), ErrorHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        sink = io.StringIO()
        try:
            summary = latency_stability.collect(
                target="127.0.0.1",
                port=server.server_address[1],
                path="/",
                samples=3,
                interval_ms=1,
                timeout=1.0,
                engine="test",
                protocol="direct",
                sink=sink,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        rows = [json.loads(row) for row in sink.getvalue().splitlines()]
        self.assertEqual(summary["successes"], 0)
        self.assertEqual(summary["failures"], 3)
        self.assertIsNone(summary["p99_ms"])
        self.assertTrue(all(row["error"] == "http_status_503" for row in rows))

    def test_failures_remain_counted_without_latency_quantiles(self) -> None:
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        summary = latency_stability.collect(
            target="127.0.0.1",
            port=port,
            path="/",
            samples=2,
            interval_ms=0,
            timeout=0.05,
            engine="test",
            protocol="direct",
            sink=io.StringIO(),
        )
        self.assertEqual(summary["failures"], 2)
        self.assertEqual(summary["failure_rate"], 1.0)
        self.assertIsNone(summary["p99_ms"])


if __name__ == "__main__":
    unittest.main()
