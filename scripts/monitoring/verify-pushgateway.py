"""Verify pull/push freshness and publication recovery without application load."""
import datetime
import json
from pathlib import Path
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PROMETHEUS = "http://10.255.255.21:9090"
QUERIES = {
    "gateway_up": 'up{job="pushgateway"}',
    "exporter_up": 'up{job="health"}',
    "analytics_up": 'service_up{service="analytics"}',
    "client_success": "client_last_request_success",
    "cached_health": 'push_service_up{service="analytics",publisher="analytics-probe"}',
    "observation_age_seconds": 'time() - push_observation_timestamp_seconds{publisher="analytics-probe"}',
    "publication_failures": 'push_publish_failures_total{publisher="analytics-probe"}',
    "stale_alert_firing": 'ALERTS{alertname="PushPublisherStale",alertstate="firing"}',
}


def service(action, name):
    subprocess.run(["incus", "exec", "prometheus-container", "--",
                    "systemctl", action, name], check=True, timeout=25)


def snapshot():
    result = {"recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    for key, expression in QUERIES.items():
        url = PROMETHEUS + "/api/v1/query?" + urllib.parse.urlencode({"query": expression})
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.load(response)
        if data["status"] != "success":
            raise RuntimeError("Query failed: " + expression)
        series = data["data"]["result"]
        result[key] = float(series[0]["value"][1]) if series else None
    return result


def wait_for(predicate, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        current = snapshot()
        if predicate(current):
            return current
        time.sleep(5)
    raise RuntimeError("Expected condition not observed: " + json.dumps(current))


def main():
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder = ROOT / "evidence" / ("pushgateway-comparison-" + stamp)
    folder.mkdir(parents=True, exist_ok=False)
    result = {
        "scope": "Monitoring availability/freshness experiment; no attack or application load",
        "queries": QUERIES,
        "observations": [],
    }
    def save():
        (folder / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    try:
        initial = wait_for(lambda s: s["gateway_up"] == s["exporter_up"] ==
                           s["analytics_up"] == s["cached_health"] == 1 and
                           s["observation_age_seconds"] is not None and
                           s["observation_age_seconds"] < 20)
        result["initial"] = initial
        print("Initial state: exporter, gateway and application are healthy.", flush=True)

        service("stop", "push-publisher")
        result["publisher_stopped_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        for elapsed in range(0, 76, 15):
            if elapsed:
                time.sleep(15)
            current = snapshot()
            current["phase"] = "publisher_stopped"
            current["elapsed_seconds"] = elapsed
            result["observations"].append(current)
            save()
            print("Publisher stopped %ds: gateway=%s cached_health=%s age=%.1fs alert=%s" %
                  (elapsed, current["gateway_up"], current["cached_health"],
                   current["observation_age_seconds"] or 0, current["stale_alert_firing"]), flush=True)
        stale = result["observations"][-1]
        assert stale["gateway_up"] == stale["exporter_up"] == stale["analytics_up"] == 1
        assert stale["cached_health"] == 1
        assert stale["observation_age_seconds"] > 30
        assert stale["stale_alert_firing"] == 1
        result["stale_value_detected"] = True

        service("start", "push-publisher")
        result["publisher_recovered"] = wait_for(
            lambda s: s["cached_health"] == 1 and s["observation_age_seconds"] is not None and
                      s["observation_age_seconds"] < 20 and s["stale_alert_firing"] is None)
        print("Publisher recovered: observation is fresh and stale alert cleared.", flush=True)
        save()

        service("stop", "prometheus-pushgateway")
        result["gateway_stopped_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result["gateway_unavailable"] = wait_for(lambda s: s["gateway_up"] == 0, timeout=40)
        time.sleep(10)
        result["publisher_during_gateway_outage"] = subprocess.check_output(
            ["incus", "exec", "prometheus-container", "--", "systemctl",
             "is-active", "push-publisher"], text=True, timeout=10).strip()
        service("start", "prometheus-pushgateway")
        result["gateway_recovered"] = wait_for(
            lambda s: s["gateway_up"] == 1 and s["publication_failures"] is not None and
                      s["publication_failures"] > 0 and
                      s["observation_age_seconds"] is not None and s["observation_age_seconds"] < 20,
            timeout=60)
        result["retry_recovery_verified"] = True
        journal = subprocess.check_output(
            ["incus", "exec", "prometheus-container", "--", "journalctl",
             "-u", "push-publisher", "--since", result["gateway_stopped_at"],
             "--no-pager", "-n", "30"], text=True, timeout=10)
        (folder / "publisher-retry.log").write_text(journal)
        print("Gateway outage detected; publisher retries and automatic recovery verified.", flush=True)
    finally:
        service("start", "prometheus-pushgateway")
        service("start", "push-publisher")
        result["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    result["passed"] = result.get("stale_value_detected", False) and result.get("retry_recovery_verified", False)
    save()
    print("Evidence: " + str(folder), flush=True)
    print("Comparison passed: " + str(result["passed"]), flush=True)


if __name__ == "__main__":
    main()
