"""Guide 3 Pushgateway publisher with bounded retries and explicit freshness."""
import argparse
import os
import signal
from threading import Event
import time

import requests
from prometheus_client import CollectorRegistry, Counter, Gauge
from prometheus_client import delete_from_gateway, push_to_gateway

GATEWAY = os.getenv("PUSHGATEWAY_URL", "http://127.0.0.1:9091")
TARGET = os.getenv("ANALYTICS_URL", "http://k3s-master.incus:30503/average")
JOB = "push-health"
GROUP = {"publisher": "analytics-probe"}
INTERVAL = 10
STOP = Event()

REGISTRY = CollectorRegistry()
UP = Gauge("push_service_up", "Latest application probe: 1=success, 0=failure",
           ["service"], registry=REGISTRY)
OBSERVED = Gauge("push_observation_timestamp_seconds",
                 "Unix time of the most recent application observation", registry=REGISTRY)
FAILURES = Counter("push_publish_failures_total",
                   "Failed publication attempts in this publisher process", registry=REGISTRY)


def collect_and_publish():
    healthy = 0
    try:
        response = requests.get(TARGET, timeout=(1, 2))
        response.raise_for_status()
        if "average_temperature" not in response.json():
            raise ValueError("Missing average_temperature")
        healthy = 1
    except (requests.RequestException, ValueError, TypeError):
        pass
    UP.labels(service="analytics").set(healthy)
    OBSERVED.set(time.time())
    for attempt in range(3):
        try:
            push_to_gateway(GATEWAY, job=JOB, grouping_key=GROUP,
                            registry=REGISTRY, timeout=5)
            return healthy
        except (OSError, ValueError) as error:
            FAILURES.inc()
            print("Publication failed (attempt %d/3): %s" %
                  (attempt + 1, type(error).__name__), flush=True)
            if STOP.wait(2 ** attempt):
                break
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--delete", action="store_true",
                        help="Remove this publisher's metrics when retiring it")
    args = parser.parse_args()
    if args.delete:
        delete_from_gateway(GATEWAY, job=JOB, grouping_key=GROUP, timeout=5)
        print("Publisher group deleted.", flush=True)
        return
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    previous = object()
    while not STOP.is_set():
        result = collect_and_publish()
        if result != previous:
            print("Publisher result: " + str(result), flush=True)
            previous = result
        if args.once:
            if result is None:
                raise SystemExit(1)
            return
        STOP.wait(INTERVAL)


if __name__ == "__main__":
    main()
