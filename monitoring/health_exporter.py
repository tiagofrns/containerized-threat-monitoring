"""Availability checks based on the Guide 3 exporter skeleton."""
import os
import socket
import time
from urllib.parse import urlparse

import requests
from prometheus_client import Gauge, start_http_server

SERVICE_UP = Gauge("service_up", "Application probe result: 1=success, 0=failure", ["service", "probe"])
DURATION = Gauge("service_probe_duration_seconds", "Duration of the most recent application probe", ["service"])
HTTP_STATUS = Gauge("service_probe_http_status", "Most recent HTTP response status; 0 means no response", ["service"])
MEASUREMENTS = Gauge("storage_measurements", "Measurement count reported by storage; NaN when unavailable")
TARGETS = [
    ("registry", "http", "http://registry:5050/services"),
    ("ingestion", "tcp", "tcp://ingestion:5001"),
    ("storage", "http", "http://storage:5002/stats"),
    ("analytics", "http", "http://analytics:5003/average"),
]


def probe(service, kind, address):
    started = time.monotonic()
    ok = 0
    if kind == "http":
        HTTP_STATUS.labels(service=service).set(0)
    try:
        if kind == "tcp":
            target = urlparse(address)
            with socket.create_connection((target.hostname, target.port), timeout=2):
                pass
        else:
            response = requests.get(address, timeout=(1, 2))
            HTTP_STATUS.labels(service=service).set(response.status_code)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object")
            if service == "storage":
                MEASUREMENTS.set(data["measurements"])
            elif service == "analytics" and "average_temperature" not in data:
                raise ValueError("Missing average_temperature")
        ok = 1
    except (requests.RequestException, OSError, ValueError, KeyError, TypeError):
        if service == "storage":
            MEASUREMENTS.set(float("nan"))
    SERVICE_UP.labels(service=service, probe=kind).set(ok)
    DURATION.labels(service=service).set(time.monotonic() - started)
    return ok


def main():
    start_http_server(8000, addr="0.0.0.0")
    previous = {}
    while True:
        for service, kind, address in TARGETS:
            result = probe(service, kind, address)
            if previous.get(service) != result:
                print(f"{service}: {'UP' if result else 'DOWN'} ({kind} probe)", flush=True)
            previous[service] = result
        time.sleep(float(os.getenv("PROBE_INTERVAL_SECONDS", "10")))


if __name__ == "__main__":
    main()
