"""Record a read-only baseline using the existing client and exporters.

Run on the Debian VM: python3 ~/ssle/scripts/monitoring/record-baseline.py
No application replicas, traffic generators or deployments are changed.
"""
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PROMETHEUS = "http://10.255.255.21:9090"
CLIENT_METRICS = "http://10.255.255.74:30802/metrics"
ANALYTICS = "http://10.255.255.74:30503/average"
DURATION_SECONDS = 300
SAMPLE_INTERVAL_SECONDS = 15
APPLICATIONS = {"registry", "ingestion", "storage", "analytics"}
QUERY = ('{__name__=~"service_up|resource_collection_up|'
         'client_last_request_success|container_cpu_usage_cores|'
         'container_memory_working_set_bytes|storage_measurements|'
         'deployment_replicas_desired|up",job=~".*"}')


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read_url(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode()


def query(expression):
    data = json.loads(read_url(PROMETHEUS + "/api/v1/query?" +
                               urllib.parse.urlencode({"query": expression})))
    if data["status"] != "success":
        raise RuntimeError("Prometheus query failed")
    return data["data"]["result"]


def cluster_snapshot():
    raw = subprocess.check_output(
        ["incus", "exec", "k3s-master", "--", "k3s", "kubectl",
         "-n", "ssle", "get", "deployments,pods", "-o", "json"], timeout=30)
    return json.loads(raw)


def client_snapshot():
    raw = read_url(CLIENT_METRICS)
    counters = {}
    values = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'client_requests_total\{outcome="([^"]+)"\} ([^ ]+)', line)
        if match:
            counters[match.group(1)] = float(match.group(2))
        for name in ("client_request_duration_seconds_sum",
                     "client_request_duration_seconds_count",
                     "process_start_time_seconds"):
            if line.startswith(name + " "):
                values[name] = float(line.split()[1])
    if len(counters) != 5 or len(values) != 3:
        raise RuntimeError("Required client metrics are missing")
    return {"recorded_at": utc_now(), "requests": counters, **values, "raw_metrics": raw}


def sample():
    return {"recorded_at": utc_now(), "monotonic_time": time.monotonic(),
            "values": query(QUERY)}


def metric_values(snapshot, name):
    return [item for item in snapshot["values"]
            if item["metric"]["__name__"] == name]


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")


def main():
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder = ROOT / "evidence" / ("baseline-" + stamp)
    folder.mkdir(parents=True, exist_ok=False)
    config = {
        "experiment": "Read-only normal-operation baseline; no attack",
        "planned_duration_seconds": DURATION_SECONDS,
        "sample_interval_seconds": SAMPLE_INTERVAL_SECONDS,
        "client_interval_seconds": 5,
        "client_request": "GET /average",
        "prometheus": PROMETHEUS,
        "client_metrics": CLIENT_METRICS,
        "sensor_expected_replicas": 0,
        "collector_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "deployment_sources_sha256": {
            name: hashlib.sha256((ROOT / "deploy" / "k8s" / name).read_bytes()).hexdigest()
            for name in ("apps.yaml", "monitoring.yaml")
        },
        "application_sources_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [ROOT / "apps" / (name + ".py") for name in APPLICATIONS]
        },
        "monitoring_source_sha256": {
            name: hashlib.sha256((ROOT / "monitoring" / name).read_bytes()).hexdigest()
            for name in ("client.py", "health_exporter.py", "resource_exporter.py",
                         "prometheus.yml")
        },
        "limitations": [
            "Read-only workload: no sensor generation and no ingestion write test.",
            "The client validates the response structure, not the numerical average independently.",
            "Resource measurements are periodic metrics-server observations collected by Prometheus.",
            "Probe success is not a complete functional or security proof.",
            "A five-minute low-rate run is not a scalability or capacity benchmark.",
            "Client boundary snapshots occur around, not atomically with, Prometheus samples."
        ]
    }
    save_json(folder / "conditions.json", config)
    initial_cluster = cluster_snapshot()
    save_json(folder / "cluster-before.json", initial_cluster)
    deployments = {item["metadata"]["name"]: item for item in initial_cluster["items"]
                   if item["kind"] == "Deployment"}
    if deployments["sensor"]["spec"]["replicas"] != 0:
        raise RuntimeError("Pause the K3s sensor before this read-only baseline")
    required = APPLICATIONS | {"health-exporter", "resource-exporter", "temperature-client"}
    for name in required:
        if deployments[name]["spec"]["replicas"] != 1 or deployments[name]["status"].get("availableReplicas", 0) != 1:
            raise RuntimeError("Required deployment is not available: " + name)
    analytics_before = json.loads(read_url(ANALYTICS))
    save_json(folder / "analytics-before.json", analytics_before)
    initial_client = client_snapshot()
    save_json(folder / "client-before.json", initial_client)
    started_at = utc_now()
    started = time.monotonic()
    snapshots = []
    print("Baseline started: " + started_at, flush=True)
    print("Results directory: " + str(folder), flush=True)
    with (folder / "samples.jsonl").open("w") as stream:
        for index in range(DURATION_SECONDS // SAMPLE_INTERVAL_SECONDS + 1):
            due = started + index * SAMPLE_INTERVAL_SECONDS
            time.sleep(max(0, due - time.monotonic()))
            current = sample()
            current["elapsed_seconds"] = time.monotonic() - started
            snapshots.append(current)
            stream.write(json.dumps(current) + "\n")
            stream.flush()
            if index % 4 == 0:
                healthy = sum(float(item["value"][1]) == 1 for item in metric_values(current, "service_up"))
                print("Elapsed %ds: %d/4 application probes passing" %
                      (round(current["elapsed_seconds"]), healthy), flush=True)
    final_client = client_snapshot()
    elapsed = time.monotonic() - started
    save_json(folder / "client-after.json", final_client)
    save_json(folder / "cluster-after.json", cluster_snapshot())
    analytics_after = json.loads(read_url(ANALYTICS))
    save_json(folder / "analytics-after.json", analytics_after)

    if final_client["process_start_time_seconds"] != initial_client["process_start_time_seconds"]:
        raise RuntimeError("Client restarted: boundary counter comparison is invalid")
    counts = {outcome: final_client["requests"][outcome] - initial_client["requests"][outcome]
              for outcome in initial_client["requests"]}
    if any(value < 0 for value in counts.values()):
        raise RuntimeError("Client counters reset during the baseline")
    total = sum(counts.values())
    duration_count = (final_client["client_request_duration_seconds_count"] -
                      initial_client["client_request_duration_seconds_count"])
    duration_sum = (final_client["client_request_duration_seconds_sum"] -
                    initial_client["client_request_duration_seconds_sum"])
    if total <= 0 or duration_count != total or duration_sum < 0:
        raise RuntimeError("Client boundary snapshots are inconsistent")

    resources = {}
    for app in sorted(APPLICATIONS):
        resources[app] = {}
        for name, label in (("container_cpu_usage_cores", "cpu_cores"),
                            ("container_memory_working_set_bytes", "memory_working_set_bytes")):
            values = [float(item["value"][1]) for snap in snapshots
                      for item in metric_values(snap, name)
                      if item["metric"].get("app") == app and math.isfinite(float(item["value"][1]))]
            if not values:
                raise RuntimeError("Missing resource samples for " + app)
            resources[app][label] = {"sample_count": len(values), "mean": statistics.mean(values),
                                     "min": min(values), "max": max(values)}
    availability = {}
    for app in sorted(APPLICATIONS):
        values = [float(item["value"][1]) for snap in snapshots
                  for item in metric_values(snap, "service_up")
                  if item["metric"].get("service") == app]
        availability[app] = {"sample_count": len(values),
                             "all_observed_probes_passed": len(values) == len(snapshots) and all(v == 1 for v in values)}
    scrape_checks = {}
    for job in ("health", "resources", "client"):
        values = [float(item["value"][1]) for snap in snapshots for item in metric_values(snap, "up")
                  if item["metric"].get("job") == job]
        scrape_checks[job] = len(values) == len(snapshots) and all(v == 1 for v in values)
    db_counts = [float(item["value"][1]) for snap in snapshots
                 for item in metric_values(snap, "storage_measurements")]
    summary = {
        "experiment": config["experiment"], "started_at": started_at, "finished_at": utc_now(),
        "actual_elapsed_seconds": elapsed, "prometheus_snapshot_count": len(snapshots),
        "client_requests_by_outcome": counts, "total_client_requests": total,
        "successful_client_requests": counts["success"],
        "client_error_count": total - counts["success"],
        "client_success_ratio": counts["success"] / total,
        "client_average_duration_seconds": duration_sum / duration_count,
        "observed_client_requests_per_second": total / elapsed,
        "client_process_unchanged": True, "service_probes": availability,
        "scrape_targets_all_observed_up": scrape_checks,
        "resources": resources,
        "database_measurements_first_observed": db_counts[0] if db_counts else None,
        "database_measurements_last_observed": db_counts[-1] if db_counts else None,
        "database_count_unchanged_in_samples": bool(db_counts) and all(v == db_counts[0] for v in db_counts),
        "average_temperature_before": analytics_before.get("average_temperature"),
        "average_temperature_after": analytics_after.get("average_temperature"),
        "limitations": config["limitations"]
    }
    save_json(folder / "summary.json", summary)
    lines = [
        "# Normal-operation baseline", "",
        "This is a five-minute read-only experiment using the existing legitimate client.",
        "No load generator or configuration change was applied; existing defenses stayed configured.", "",
        "- Started (UTC): " + started_at,
        "- Duration: %.2f seconds" % elapsed,
        "- Client requests: %d" % total,
        "- Successful requests: %d" % counts["success"],
        "- Failed requests: %d" % (total - counts["success"]),
        "- Average observed client request duration: %.3f ms" % (1000 * duration_sum / duration_count),
        "- Prometheus snapshots: %d" % len(snapshots), "",
        "| Application | Mean CPU (cores) | Mean memory working set (MiB) |",
        "|---|---:|---:|"
    ]
    for app, metrics in resources.items():
        lines.append("| %s | %.6f | %.2f |" % (app, metrics["cpu_cores"]["mean"],
                     metrics["memory_working_set_bytes"]["mean"] / 1024 / 1024))
    lines += ["", "## Evidence", "",
              "- conditions.json: workload, intervals, source hashes and limitations.",
              "- samples.jsonl: periodic Prometheus API observations.",
              "- client-before.json and client-after.json: direct cumulative metric snapshots.",
              "- cluster-before.json and cluster-after.json: deployments, images and Pod state.",
              "- analytics-before.json and analytics-after.json: read-only API responses.",
              "- summary.json: calculated results.", "", "## Limitations", ""]
    lines += ["- " + item for item in config["limitations"]]
    (folder / "README.md").write_text("\n".join(lines) + "\n")
    print("Baseline complete.", flush=True)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
