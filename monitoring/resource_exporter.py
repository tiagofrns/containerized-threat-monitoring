"""Read pod resource metrics with namespace-scoped Kubernetes permissions."""
from decimal import Decimal
import os
from pathlib import Path
import time

import requests
from prometheus_client import Gauge, start_http_server

LABELS = ["namespace", "pod", "container", "node", "app"]
CPU = Gauge("container_cpu_usage_cores", "CPU usage from the Kubernetes resource metrics API, in cores", LABELS)
MEMORY = Gauge("container_memory_working_set_bytes", "Container memory working set from Kubernetes, in bytes", LABELS)
POD_READY = Gauge("pod_ready", "Kubernetes Pod Ready condition", ["namespace", "pod", "node", "app"])
DESIRED = Gauge("deployment_replicas_desired", "Configured replica count", ["namespace", "deployment"])
READY = Gauge("deployment_replicas_ready", "Ready replica count", ["namespace", "deployment"])
COLLECTION_UP = Gauge("resource_collection_up", "1 when Kubernetes resource collection succeeds")
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
NAMESPACE = os.getenv("MONITORED_NAMESPACE", "ssle")
API = "https://kubernetes.default.svc"


def quantity(value, factors):
    for suffix in sorted(factors, key=len, reverse=True):
        if value.endswith(suffix):
            return float(Decimal(value[:-len(suffix)]) * factors[suffix])
    return float(Decimal(value))


def cpu_cores(value):
    return quantity(value, {"n": Decimal("1e-9"), "u": Decimal("1e-6"), "m": Decimal("1e-3")})


def memory_bytes(value):
    factors = {unit + "i": Decimal(1024) ** power for power, unit in enumerate(["K", "M", "G", "T", "P", "E"], 1)}
    factors.update({unit: Decimal(1000) ** power for power, unit in enumerate(["k", "M", "G", "T", "P", "E"], 1)})
    return quantity(value, factors)


def get(path, token):
    response = requests.get(API + path, headers={"Authorization": "Bearer " + token}, verify=CA, timeout=(2, 5))
    response.raise_for_status()
    return response.json()


def collect():
    token = TOKEN.read_text().strip()
    pods = get(f"/api/v1/namespaces/{NAMESPACE}/pods", token)["items"]
    deployments = get(f"/apis/apps/v1/namespaces/{NAMESPACE}/deployments", token)["items"]
    metrics = get(f"/apis/metrics.k8s.io/v1beta1/namespaces/{NAMESPACE}/pods", token)["items"]
    locations = {pod["metadata"]["name"]: (pod["spec"].get("nodeName", "pending"), pod["metadata"].get("labels", {}).get("app", "unknown")) for pod in pods}
    for gauge in [CPU, MEMORY, POD_READY, DESIRED, READY]:
        gauge.clear()
    for pod in pods:
        name = pod["metadata"]["name"]
        node, app = locations[name]
        ready = any(condition["type"] == "Ready" and condition["status"] == "True" for condition in pod.get("status", {}).get("conditions", []))
        POD_READY.labels(NAMESPACE, name, node, app).set(int(ready))
    for item in metrics:
        name = item["metadata"]["name"]
        if name not in locations:
            continue
        node, app = locations[name]
        for container in item["containers"]:
            labels = (NAMESPACE, name, container["name"], node, app)
            CPU.labels(*labels).set(cpu_cores(container["usage"]["cpu"]))
            MEMORY.labels(*labels).set(memory_bytes(container["usage"]["memory"]))
    for deployment in deployments:
        name = deployment["metadata"]["name"]
        DESIRED.labels(NAMESPACE, name).set(deployment["spec"].get("replicas", 1))
        READY.labels(NAMESPACE, name).set(deployment.get("status", {}).get("readyReplicas", 0))


def main():
    start_http_server(8001, addr="0.0.0.0")
    previous = None
    while True:
        try:
            collect()
            success = 1
        except (requests.RequestException, OSError, ValueError, KeyError, TypeError, ArithmeticError) as error:
            success = 0
            if previous != 0:
                print(f"Kubernetes resource collection failed: {type(error).__name__}", flush=True)
        COLLECTION_UP.set(success)
        if success and previous != 1:
            print("Kubernetes resource collection available", flush=True)
        previous = success
        time.sleep(15)


if __name__ == "__main__":
    main()
