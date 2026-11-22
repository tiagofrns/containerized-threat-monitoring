"""Loopback-only HTTP fixtures and process-output inputs for the DNS client."""
from contextlib import contextmanager
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

APPROVED = "127.0.0.1"
SECONDARY = "127.0.0.2"


def reply(name, addresses=(), status="NOERROR"):
    rows = [f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 42",
            ";; ANSWER SECTION:"]
    rows.extend(f"{name}.\t0\tIN\tA\t{address}" for address in addresses)
    return subprocess.CompletedProcess([], 0, "\n".join(rows) + "\n", "")


def resolve_from(client, result):
    if isinstance(result, Exception):
        options = {"side_effect": result}
    else:
        options = {"return_value": result}
    with patch.object(client.subprocess, "run", **options):
        return client.resolve()


@contextmanager
def http_endpoints():
    counts = {"approved": 0, "secondary": 0}
    lock = threading.Lock()

    def handler(label, temperature):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/average":
                    self.send_error(404)
                    return
                with lock:
                    counts[label] += 1
                body = json.dumps({"average_temperature": temperature, "fixture": label}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        return Handler

    def snapshot():
        with lock:
            return dict(counts)

    with ThreadingHTTPServer((APPROVED, 0), handler("approved", 25.0)) as approved:
        port = approved.server_port
        with ThreadingHTTPServer((SECONDARY, port), handler("secondary", 12.0)) as secondary:
            servers = (approved, secondary)
            threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
            for thread in threads:
                thread.start()
            try:
                yield port, snapshot
            finally:
                for server in servers:
                    server.shutdown()
                for thread in threads:
                    thread.join()
