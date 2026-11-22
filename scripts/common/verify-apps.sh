#!/usr/bin/env bash
# Run on the VM after applying deploy/k8s/apps.yaml. Inserts one test measurement.
set -euo pipefail

for app in registry storage ingestion analytics sensor; do
  incus exec k3s-master -- k3s kubectl -n ssle \
    rollout status "deployment/$app" --timeout=180s
done

incus exec k3s-master -- k3s kubectl -n ssle wait \
  --for=jsonpath='{.status.phase}'=Bound pvc/storage-data --timeout=120s

incus exec k3s-master -- k3s kubectl -n ssle \
  get pods,services,pvc -o wide

sensor_replicas="$(incus exec k3s-master -- k3s kubectl -n ssle get deployment sensor -o jsonpath='{.spec.replicas}')"

# Run in a Pod to check DNS, the real APIs and the data path.
incus exec k3s-master -- k3s kubectl -n ssle exec -i \
  deployment/analytics -- env SENSOR_REPLICAS="$sensor_replicas" python - <<'PY'
import os
import time
import requests

def stats():
    response = requests.get("http://storage:5002/stats", timeout=10)
    response.raise_for_status()
    return response.json()

response = requests.get("http://registry:5050/services", timeout=10)
response.raise_for_status()
print("Registry:", response.json(), flush=True)
assert "ingestion.ssle.svc.cluster.local:5001" in response.text, \
    "Registry does not advertise the Kubernetes ingestion address"

if int(os.environ["SENSOR_REPLICAS"]) > 0:
    baseline = stats()["measurements"]
    for attempt in range(15):
        time.sleep(1)
        current = stats()["measurements"]
        if current > baseline:
            print("Automatic measurements:", baseline, "->", current, flush=True)
            break
    else:
        raise SystemExit("No new measurements in 15 seconds: inspect sensor and ingestion logs")
else:
    print("Sensor paused: automatic generation was not tested.", flush=True)

before = stats()["measurements"]
response = requests.post(
    "http://ingestion:5001/ingest",
    json={"device_id": "k3s-smoke-test", "temperature": 25},
    timeout=10,
)
response.raise_for_status()
after = stats()
assert after["measurements"] >= before + 1, "Measurement count did not increase"
print("POST /ingest:", response.status_code, response.json(), flush=True)
print("Storage:", after, flush=True)

response = requests.get("http://analytics:5003/average", timeout=10)
response.raise_for_status()
result = response.json()
assert isinstance(result["average_temperature"], (int, float)), \
    "Average is not numeric"
print("Analytics:", result, flush=True)
print("HTTP verification complete.", flush=True)
PY
