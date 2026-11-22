#!/usr/bin/python3
"""Read the real analytics service through an explicit, guarded DNS lookup.

The address policy is local and root-managed, not server authentication.
No fixture resolver or DNS mutation is provided by this client.
"""
import argparse
import datetime
import http.client
import json
import logging
import logging.handlers
import math
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address

DNS_NAME = "analytics.lab.test"
EXPECTED_IP = "10.255.255.74"
HTTP_PORT = 30503
INTERVAL = 5
OUTCOMES = ("success", "dns_failure", "dns_rejected", "http_error", "invalid_response")


def resolve():
    result = subprocess.run(
        ["/usr/bin/dig", "@127.0.0.1", "-p", "53", DNS_NAME, "A",
         "+comments", "+answer", "+noauthority", "+noadditional", "+time=1", "+tries=1"],
        capture_output=True, text=True, timeout=3, check=False)
    match = re.search(r"^;; ->>HEADER<<- opcode: QUERY, status: ([A-Z]+),", result.stdout, re.MULTILINE)
    if result.returncode or not match or match[1] != "NOERROR":
        raise OSError("DNS query failed or returned no usable name")
    addresses = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and not line.startswith(";") and fields[3] == "A":
            if (len(fields) != 5 or fields[2] != "IN"
                    or fields[0].rstrip(".").lower() != DNS_NAME):
                raise OSError("Malformed DNS A record or unexpected owner")
            try:
                addresses.append(str(IPv4Address(fields[4])))
            except ValueError as error:
                raise OSError("Malformed IPv4 address in DNS answer") from error
    if not addresses:
        raise OSError("DNS returned no A address")
    return sorted(set(addresses))


def fetch(address):
    # Connect to the accepted IP, not the hostname: there is no second DNS lookup.
    connection = http.client.HTTPConnection(address, HTTP_PORT, timeout=1)
    try:
        connection.connect()
        peer = connection.sock.getpeername()[0]
        if peer != EXPECTED_IP:
            raise OSError("Connected peer differs from approved IP")
        connection.sock.settimeout(5)
        connection.request("GET", "/average", headers={"Host": f"{DNS_NAME}:{HTTP_PORT}"})
        response = connection.getresponse()
        if response.status != 200:
            raise OSError(f"Analytics returned HTTP {response.status}")
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError("Response exceeds the read limit")
        data = json.loads(body)
        if not isinstance(data, dict) or "average_temperature" not in data:
            raise ValueError("Missing average_temperature")
        average = data["average_temperature"]
        if average is not None and (type(average) not in (int, float) or not math.isfinite(average)):
            raise ValueError("Invalid average_temperature")
        return {"average_temperature": average, "peer_ip": peer, "http_status": 200}
    finally:
        connection.close()


def probe(resolver=None, reader=None):
    resolver, reader = resolver or resolve, reader or fetch
    started = time.monotonic()
    event = {"integration": "dns_client", "event": "check",
             "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "dns_name": DNS_NAME, "dns_expected": False, "outcome": "dns_failure"}
    try:
        addresses = resolver()
        event["observed_addresses"] = addresses
        if addresses != [EXPECTED_IP]:
            event["outcome"] = "dns_rejected"
        else:
            event["dns_expected"] = True
            try:
                event.update(reader(addresses[0]))
                event["outcome"] = "success"
            except (ValueError, TypeError) as error:
                event.update(outcome="invalid_response", error=str(error)[:200])
            except (OSError, http.client.HTTPException, subprocess.SubprocessError) as error:
                event.update(outcome="http_error", error=str(error)[:200])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        event["error"] = str(error)[:200]
    event["duration_seconds"] = time.monotonic() - started
    return event


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts = dict.fromkeys(OUTCOMES, 0)
        self.total_seconds = 0.0
        self.last_check = 0.0
        self.dns_expected = 0
        self.success = 0

    def observe(self, event):
        with self.lock:
            self.counts[event["outcome"]] += 1
            self.total_seconds += event["duration_seconds"]
            self.last_check = time.time()
            self.dns_expected = int(event["dns_expected"])
            self.success = int(event["outcome"] == "success")

    def render(self):
        # Fixed labels only. This endpoint uses the Prometheus text exposition format.
        with self.lock:
            lines = ["# TYPE dns_sec_client_requests_total counter"]
            lines += [f'dns_sec_client_requests_total{{outcome="{k}"}} {v}' for k, v in self.counts.items()]
            lines += ["# TYPE dns_sec_client_request_duration_seconds summary",
                      f"dns_sec_client_request_duration_seconds_sum {self.total_seconds}",
                      f"dns_sec_client_request_duration_seconds_count {sum(self.counts.values())}"]
            for name, value in (("dns_sec_resolution_expected", self.dns_expected),
                                ("dns_sec_client_last_request_success", self.success),
                                ("dns_sec_last_check_timestamp_seconds", self.last_check)):
                lines += [f"# TYPE {name} gauge", f"{name} {value}"]
            return ("\n".join(lines) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="Perform one real read, emit JSON and exit")
    args = parser.parse_args()
    if args.once:
        event = probe()
        print(json.dumps(event, allow_nan=False))
        return int(event["outcome"] != "success")
    logger = logging.getLogger("dns_client")
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        "/var/log/dns_sec/client.jsonl", maxBytes=1024 * 1024, backupCount=2)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    metrics = Metrics()

    def worker():
        previous = None
        while True:
            event = probe()
            metrics.observe(event)
            if previous != event["outcome"]:
                logger.info(json.dumps(event, allow_nan=False))
            previous = event["outcome"]
            time.sleep(INTERVAL)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_error(404)
                return
            body = metrics.render()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", 8004), Handler)
    threading.Thread(target=worker, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())
