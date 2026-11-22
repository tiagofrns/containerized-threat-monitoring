#!/usr/bin/env python3
"""Verify the deployed alert bridge with temporary labelled Prometheus test rules."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PRO = "prometheus-container"
WAZ = "wazuh-container"
MONITOR = "http://127.0.0.1:9090"
ALERTMANAGER = "http://127.0.0.1:9093"
NAMES = {"AnalyticsClientImpact": "analytics", "DNSPolicyRejections": "dns"}
RULE_FILE = "/etc/prometheus/bridge-validation.yml"
CONFIG = "/etc/prometheus/prometheus.yml"


def incus(container, *args, data=None):
    result = subprocess.run(["incus", "exec", container, "--", *args], input=data,
                            text=True, check=True, capture_output=True, timeout=30)
    return result.stdout


def fetch(url):
    return json.loads(incus(PRO, "curl", "-fsS", "--max-time", "4", url))


def lines(raw):
    for ln in raw.splitlines():
        try:
            yield json.loads(ln)
        except ValueError:
            continue


def until(check, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for {check.__name__}")


def main():
    run = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "evidence" / "alert-bridge" / run
    out.mkdir(parents=True)
    print(out, flush=True)
    summary = {"run": run, "mode": "labelled Prometheus vector fixtures through real services",
               "production_metric_thresholds_exercised_live": False, "checks": {}, "passed": False}

    def save(name, data):
        (out / name).write_text(data if isinstance(data, str) else json.dumps(data, indent=2) + "\n")

    def agents_active():
        listing = incus(WAZ, "/var/ossec/bin/agent_control", "-l")
        return all(f"ID: {agent}, Name: {name}, IP: any, Active" in listing
                   for agent, name in (("002", "k3s-node1"), ("004", "dns-server-container"),
                                       ("005", PRO)))

    def fixture_alerts():
        return [a for a in fetch(MONITOR + "/api/v1/alerts")["data"]["alerts"]
                if a["labels"].get("test_run") == run and a["state"] == "firing"]

    def bridge_events():
        names = {a["labels"]["alertname"]: a["activeAt"] for a in fixture_alerts()}
        episodes = {hashlib.sha256(f"{name}/{active}".encode()).hexdigest() for name, active in names.items()}
        rows = [e for e in lines(incus(PRO, "tail", "-n", "100", "/var/log/alert-bridge/events.jsonl"))
                if e.get("episode") in episodes]
        return rows if len(rows) >= 2 else None

    def record_response(alert_rows):
        dns_events = list(lines(incus("dns-server-container", "tail", "-n", "60",
                                     "/var/ossec/logs/dns_restore.jsonl")))
        cache_events = list(lines(incus("k3s-node1", "tail", "-n", "70",
                                       "/var/ossec/logs/active-responses.log")))
        audits = [a for a in dns_events + cache_events if a.get("bridge_episode") in alert_rows]
        return audits if len({a["bridge_episode"] for a in audits}) == 2 else None

    original = incus(PRO, "cat", CONFIG)
    assert RULE_FILE not in original
    fixture = """groups:
  - name: response-bridge-validation
    rules:
"""
    for name, scope in NAMES.items():
        fixture += f"""      - alert: {name}
        expr: vector(1)
        for: 15s
        labels:
          bridge: wazuh
          scope: {scope}
          severity: warning
          mode: bridge-validation
          test_run: "{run}"
"""
    mounted = False
    try:
        until(agents_active, 90)
        before_dns = incus("dns-server-container", "sha256sum", "/etc/dnsmasq.d/dns_sec.conf")
        dns_pid = incus("dns-server-container", "systemctl", "show", "dnsmasq", "-p", "MainPID", "--value")
        assert int(dns_pid) > 0
        assert before_dns.startswith("0386377711b590148241a718f5791d415530e9ff4f94753529da3a40bc7d8ad6")
        assert not any(a["labels"].get("alertname") in NAMES
                       for a in fetch(MONITOR + "/api/v1/alerts")["data"]["alerts"])
        ready = incus("k3s-master", "k3s", "kubectl", "-n", "ssle", "get", "pods",
                      "-l", "app=analytics", "-o", "json")
        pods = json.loads(ready)["items"]
        assert len(pods) == 1 and pods[0]["spec"]["nodeName"] == "k3s-node1"
        save("target-pod.json", {"name": pods[0]["metadata"]["name"],
                                 "uid": pods[0]["metadata"]["uid"], "node": "k3s-node1"})
        save("validation-rules.yml", fixture)
        incus(PRO, "tee", RULE_FILE, data=fixture)
        mounted = True
        changed = original.replace("rule_files:\n", f"rule_files:\n  - {RULE_FILE}\n", 1)
        assert changed != original
        incus(PRO, "tee", CONFIG, data=changed)
        incus(PRO, "promtool", "check", "config", CONFIG)
        incus(PRO, "systemctl", "reload", "prometheus")
        records = until(bridge_events, 85)
        save("prometheus-firing.json", fixture_alerts())
        save("receiver-events.json", records)
        summary["checks"]["prometheus_alertmanager_receiver"] = len(records) == 2
        by_episode = {e["episode"]: e["alert_name"] for e in records}
        audits = until(lambda: record_response(by_episode), 35)
        save("response-audits.json", audits)
        manager = [a for a in lines(incus(WAZ, "tail", "-n", "2000", "/var/ossec/logs/alerts/alerts.json"))
                   if a.get("data", {}).get("episode") in by_episode]
        save("manager-alerts.json", manager)
        summary["checks"]["manager_100150_100151_from_agent_005"] = {
            (a["rule"]["id"], a["agent"]["id"]) for a in manager} == {("100150", "005"), ("100151", "005")}
        summary["checks"]["analytics_cache_enabled"] = any(
            a.get("rule_id") == "100150" and a.get("result") == "enabled" and a.get("node") == "k3s-node1" for a in audits)
        summary["checks"]["dns_approved_file_no_restart"] = (
            any(a.get("result") == "already_approved" and by_episode[a["bridge_episode"]] == "DNSPolicyRejections"
                for a in audits)
            and before_dns == incus("dns-server-container", "sha256sum", "/etc/dnsmasq.d/dns_sec.conf")
            and dns_pid == incus("dns-server-container", "systemctl", "show", "dnsmasq", "-p", "MainPID", "--value"))
        protected = json.loads(incus("dns-server-container", "curl", "--noproxy", "*", "-fsS",
                                     "--max-time", "5", "http://10.255.255.74:30503/average"))
        save("analytics-during.json", protected)
        summary["checks"]["real_analytics_seen_in_cache_mode"] = protected.get("protection_mode") == "cache"
        active_notifications = [a for a in fetch(ALERTMANAGER + "/api/v2/alerts")
                                if a["labels"].get("test_run") == run]
        assert len(active_notifications) == 2
        retry_payload = {"alerts": [dict(a, status="firing", endsAt="0001-01-01T00:00:00Z") for a in active_notifications]}
        verification = incus(PRO, "python3", "-c", """
import json,sys,urllib.error,urllib.request
from pathlib import Path
content=sys.stdin.buffer.read()
url='http://127.0.0.1:9095/alerts'
req=urllib.request.Request(url,data=content)
try:
    urllib.request.urlopen(req,timeout=5)
except urllib.error.HTTPError as err:
    unauthenticated=err.code
else:
    unauthenticated=200
secret=Path('/etc/prometheus/alert-bridge-secret').read_text().strip()
req.add_header('Authorization','Bearer '+secret)
with urllib.request.urlopen(req,timeout=5) as r:
    print(json.dumps({'unauthenticated_status':unauthenticated, 'retry':json.load(r)}))
""", data=json.dumps(retry_payload))
        save("webhook-controls.json", verification)
        summary["checks"]["authentication_and_retry_deduplication"] = json.loads(verification) == {
            "unauthenticated_status": 401, "retry": {"recorded": 0}}
    except Exception as error:
        summary["error"] = str(error)
        raise
    finally:
        try:
            if mounted:
                incus(PRO, "tee", CONFIG, data=original)
                incus(PRO, "promtool", "check", "config", CONFIG)
                incus(PRO, "systemctl", "reload", "prometheus")
                incus(PRO, "rm", "-f", RULE_FILE)
                until(lambda: not fixture_alerts(), 35)
                summary["checks"]["validation_rules_removed"] = True
            if summary["checks"].get("analytics_cache_enabled"):
                def normal():
                    data = json.loads(incus("dns-server-container", "curl", "--noproxy", "*",
                                            "-fsS", "--max-time", "5", "http://10.255.255.74:30503/average"))
                    return data if data.get("protection_mode") == "normal" else None
                save("analytics-recovered.json", until(normal, 75))
                summary["checks"]["analytics_recovers_after_lease"] = True
        except Exception as error:
            summary["cleanup_error"] = str(error)
            raise
        finally:
            summary["passed"] = (len(summary["checks"]) == 8 and all(summary["checks"].values())
                                 and "error" not in summary and "cleanup_error" not in summary)
            save("summary.json", summary)
            save("SHA256SUMS.json", {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in sorted(out.iterdir())})
            print(json.dumps(summary, indent=2), flush=True)
    return int(not summary["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
