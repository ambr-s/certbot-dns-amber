"""Local HTTP contract fixture only: production has no HTTP/insecure option."""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def test_recovery_in_three_processes_with_real_http(tmp_path):
    calls = []
    results = {}
    failed = set()
    zone = "59ade904-17bc-4e76-9c7e-a0fead90db67"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.reply(200, {"zone": {"id": zone, "domain": "example.com"}})

        def do_POST(self):
            self.mutate("POST")

        def do_DELETE(self):
            self.mutate("DELETE")

        def mutate(self, method):
            assert self.headers["Authorization"] == "Bearer fixture-only"
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append((method, self.path, body))
            key = body["request_key"]
            if key not in results:
                results[key] = {"success": True}
                if method == "POST":
                    results[key]["record"] = {
                        "Id": "cf:opaque/record",
                        "Revision": "a" * 64,
                        **body,
                    }
            if method not in failed:
                failed.add(method)
                self.reply(502, None)
            else:
                self.reply(201 if method == "POST" else 200, results[key])

        def reply(self, status, data):
            payload = json.dumps({"data": data}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    script = """
import sys
from certbot_dns_amber.client import Client
from certbot_dns_amber.core import Engine
client = Client('fixture-only')
original = client.session.request
# Test-only transport rewrite; there is no production insecure configuration.
client.session.request = lambda method, url, **kw: original(method, sys.argv[2] + url.removeprefix(client.endpoint), **kw)
engine = Engine(sys.argv[1], client, client.endpoint, {'example.com': '59ade904-17bc-4e76-9c7e-a0fead90db67'})
if sys.argv[3] == 'perform':
    engine.perform('_acme-challenge.example.com', 'ExactCase')
else:
    engine.recover()
"""
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    try:
        runs = [
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    script,
                    str(tmp_path / "state"),
                    f"http://127.0.0.1:{server.server_port}",
                    action,
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            for action in ("perform", "recover", "recover")
        ]
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert [r.returncode == 0 for r in runs] == [False, False, True]
    assert [c[0] for c in calls] == ["POST", "POST", "DELETE", "DELETE"]
    assert calls[0] == calls[1]
    assert calls[2] == calls[3]
    assert calls[2][1].endswith("/records/cf%3Aopaque%2Frecord")
    assert calls[2][2]["baseline"] == "a" * 64
    assert calls[2][2]["request_key"] != calls[0][2]["request_key"]
    journal = json.loads((tmp_path / "state/journal.json").read_text())
    assert next(iter(journal["entries"].values()))["status"] == "deleted"
    assert (tmp_path / "state").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "state/journal.json").stat().st_mode & 0o777 == 0o600
