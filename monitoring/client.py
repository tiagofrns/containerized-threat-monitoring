"""The separate continuous client requested in Guide 3. It only reads analytics."""
import os
import time

import requests
from prometheus_client import Counter, Gauge, Histogram, start_http_server

HTTP_TIMEOUT = (1, 5)  # Connect/read timeouts, not an end-to-end deadline.

REQUESTS = Counter("client_requests_total", "Requests made by the legitimate test client", ["outcome"])
DURATION = Histogram("client_request_duration_seconds", "Latency observed by the legitimate test client", buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5))
SUCCESS = Gauge("client_last_request_success", "1 when the most recent client request succeeded")
OUTCOMES = ["success", "http_error", "timeout", "connection_error", "invalid_response"]


def main():
    for outcome in OUTCOMES:
        REQUESTS.labels(outcome=outcome).inc(0)
    start_http_server(8002, addr="0.0.0.0")
    previous = None
    while True:
        started = time.monotonic()
        try:
            response = requests.get(os.getenv("ANALYTICS_URL", "http://analytics:5003/average"), timeout=HTTP_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            if "average_temperature" not in data:
                raise ValueError("Missing average_temperature")
            outcome = "success"
        except requests.HTTPError:
            outcome = "http_error"
        except requests.Timeout:
            outcome = "timeout"
        except (ValueError, TypeError):
            outcome = "invalid_response"
        except requests.RequestException:
            outcome = "connection_error"
        DURATION.observe(time.monotonic() - started)
        REQUESTS.labels(outcome=outcome).inc()
        SUCCESS.set(int(outcome == "success"))
        if outcome != previous:
            print(f"Legitimate client: {outcome}", flush=True)
        previous = outcome
        time.sleep(float(os.getenv("CLIENT_INTERVAL_SECONDS", "5")))


if __name__ == "__main__":
    main()
