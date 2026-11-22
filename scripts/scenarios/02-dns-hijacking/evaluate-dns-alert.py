#!/usr/bin/env python3
"""Exercise the existing DNS alert from measured checks in a loopback fixture."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
from unittest.mock import patch
from urllib.parse import urlencode

PROM = "prometheus-container"
MANAGER = "wazuh-container"
DNS = "dns-server-container"
CONFIG = "/etc/prometheus/prometheus.yml"
ALERT = "DNSPolicyRejections"
DEMO_MILESTONES = {
    "baseline": "Checking access at the approved address...",
    "nxdomain_observed": "The NXDOMAIN test left the rejection alert inactive.",
    "rejections": "Sending unexpected DNS answers to the test client...",
    "pending_observed": "Prometheus detected repeated rejections. Alert pending.",
    "firing_observed": "Prometheus alert DNSPolicyRejections is firing.",
    "response_observed": "Alertmanager notified Wazuh. Rule 100151 verified that the approved file was already in place.",
    "recovery": "Returning the approved DNS answer to the test client...",
    "clear_observed": "The alert cleared.",
}


def utc():
    return datetime.now(timezone.utc).isoformat()


def fixture(directory):
    sys.path.insert(0, str(directory))
    import dns_client as client
    from dns_fixture import APPROVED, SECONDARY, http_endpoints, reply, resolve_from

    name = "fixture.test"
    inputs = {
        "baseline": reply(name, [APPROVED]),
        "nxdomain": reply(name, status="NXDOMAIN"),
        "rejections": reply(name, [SECONDARY]),
        "recovery": reply(name, [APPROVED]),
    }
    metrics = client.Metrics()

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

    def check_loop(snapshot):
        with (directory / "checks.jsonl").open("a", buffering=1) as log:
            while True:
                phase = (directory / "phase").read_text().strip()
                before = snapshot()
                event = client.probe(lambda: resolve_from(client, inputs[phase]))
                metrics.observe(event)
                after = snapshot()
                print(json.dumps({"phase": phase, "event": event,
                                  "http_requests": {key: after[key] - before[key] for key in before}}),
                      file=log)
                time.sleep(client.INTERVAL)

    with http_endpoints() as (port, snapshot):
        with patch.multiple(client, DNS_NAME=name, EXPECTED_IP=APPROVED, HTTP_PORT=port):
            with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                (directory / "port").write_text(str(server.server_port))
                threading.Thread(target=check_loop, args=(snapshot,), daemon=True).start()
                server.serve_forever()


def incus(container, *args, data=None):
    cmd = ["incus", "exec", container, "--", *args]
    result = subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{container}: {args[0]}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def request(path, port=9090):
    return json.loads(incus(PROM, "curl", "-fsS", "--max-time", "4",
                           f"http://127.0.0.1:{port}{path}"))


def until(label, check, seconds=85):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if value := check():
            return value
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for {label}")


def matching_log(container, path, predicate):
    for line in reversed(incus(container, "tail", "-n", "2500", path).splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if predicate(event):
            return event
    return None


def dns_snapshot():
    return {
        "hashes": incus(DNS, "sha256sum", "/etc/dnsmasq.d/dns_sec.conf",
                        "/var/lib/dns_sec/approved.conf").splitlines(),
        "resolver_pid": int(incus(DNS, "systemctl", "show", "dnsmasq", "-p", "MainPID", "--value")),
        "client_pid": int(incus(DNS, "systemctl", "show", "dns_client", "-p", "MainPID", "--value")),
    }


def evaluate(*, demo_output=False):
    root = Path(__file__).resolve().parents[3]
    run = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = root / "evidence/scenarios/02-dns-hijacking" / f"metric-alert-{run}"
    out.mkdir(parents=True)
    print(f"Alert evidence saved in {out}" if demo_output else out, flush=True)
    unit = f"dns-metric-test-{run.lower()}.service"
    directory = incus(PROM, "mktemp", "-d", "/tmp/dns-metric-test.XXXXXX").strip()
    original = incus(PROM, "cat", CONFIG)
    summary = {"run": run, "passed": False, "timeline": {}, "source": "loopback integration fixture"}
    enabled = False

    def save(name, data):
        (out / name).write_text(json.dumps(data, indent=2) + "\n")

    def milestone(label):
        summary["timeline"][label] = utc()
        if demo_output:
            message = DEMO_MILESTONES.get(label)
            if message:
                print(f"{message} (test_run={run})" if label == "firing_observed" else message, flush=True)
        else:
            print(f"{label}: {summary['timeline'][label]}", flush=True)

    def set_phase(name):
        incus(PROM, "tee", f"{directory}/phase.next", data=name + "\n")
        incus(PROM, "mv", f"{directory}/phase.next", f"{directory}/phase")
        milestone(name)

    def alerts(only_test=True):
        return [event for event in request("/api/v1/alerts")["data"]["alerts"]
                if event["labels"]["alertname"] == ALERT
                and (not only_test or event["labels"].get("test_run") == run)]

    def query(expression):
        rows = request("/api/v1/query?" + urlencode({"query": expression}))["data"]["result"]
        return float(rows[0]["value"][1]) if len(rows) == 1 else None

    def reload_config(content, expected):
        staged = CONFIG + "." + run
        incus(PROM, "cp", "--preserve=mode,ownership", CONFIG, staged)
        try:
            incus(PROM, "tee", staged, data=content)
            incus(PROM, "promtool", "check", "config", staged)
            if incus(PROM, "cat", CONFIG) != expected:
                raise RuntimeError("Prometheus configuration changed concurrently")
            incus(PROM, "mv", staged, CONFIG)
            incus(PROM, "systemctl", "reload", "prometheus")
        finally:
            incus(PROM, "rm", "-f", staged)

    def matches_phase(phase):
        return [row for row in checks() if row["phase"] == phase]

    def checks():
        return [json.loads(line) for line in incus(PROM, "cat", f"{directory}/checks.jsonl").splitlines()]

    def expect(condition, description):
        if not condition:
            raise RuntimeError(description)

    try:
        before = dns_snapshot()
        expect(before["hashes"][0].split()[0] == before["hashes"][1].split()[0]
               and before["resolver_pid"] > 0 and before["client_pid"] > 0,
               "Live DNS approval or services are not ready")
        expect(not alerts(only_test=False), "An existing DNS policy alert is active")
        expect(incus(DNS, "cat", "/var/lib/dns_sec/auto-restore.enabled") == "enabled\n",
               "The active response is in maintenance")
        save("dns-before.json", before)
        save("live-client-before.json", json.loads(incus(DNS, "python3", "/opt/dns_sec/dns_client.py", "--once")))

        for file in (Path(__file__), root / "monitoring/dns_client.py",
                     root / "tests/scenarios/dns_integrity/dns_fixture.py"):
            incus(PROM, "tee", f"{directory}/{file.name}", data=file.read_text())
        set_phase("baseline")
        incus(PROM, "systemd-run", f"--unit={unit}", "-p", "RuntimeMaxSec=480",
              "-p", "NoNewPrivileges=yes", "-p", "ProtectSystem=strict",
              "-p", f"ReadWritePaths={directory}", "-p", "PrivateDevices=yes",
              "-p", "IPAddressDeny=any", "-p", "IPAddressAllow=localhost",
              "/usr/bin/python3", f"{directory}/{Path(__file__).name}", "--fixture", directory)

        def fixture_port():
            return incus(PROM, "sh", "-c", 'if test -s "$1"; then cat "$1"; fi',
                         "sh", f"{directory}/port").strip()

        port = int(until("fixture exporter port", fixture_port, seconds=20))
        # Insert before existing targets so their labels stay attached to them.
        marker = re.compile(r'^  - job_name: dns_client\n    static_configs:\n', re.MULTILINE)
        modified, replacements = marker.subn(
            lambda match: match[0] + f'      - targets: ["127.0.0.1:{port}"]\n'
            f'        labels:\n          mode: bridge-validation\n          test_run: "{run}"\n', original)
        expect(replacements == 1, "Could not identify exactly one deployed DNS scrape job")
        try:
            reload_config(modified, original)
        finally:
            enabled = incus(PROM, "cat", CONFIG) == modified
        selector = f'job="dns_client",test_run="{run}"'
        counter = f'dns_sec_client_requests_total{{{selector},outcome="dns_rejected"}}'
        active = f"dns_sec_resolution_expected{{{selector}}}"
        until("three baseline scrapes", lambda: (query(f"count_over_time({active}[1m])") or 0) >= 3)
        expect(query(active) == 1 and query(counter) == 0 and not alerts(), "Baseline was not quiet")
        milestone("baseline_observed")
        set_phase("nxdomain")
        until("scraped DNS failure", lambda: (query(
            f'dns_sec_client_requests_total{{{selector},outcome="dns_failure"}}') or 0) > 0)
        expect(query(active) == 0 and query(counter) == 0 and not alerts(),
               "NXDOMAIN incorrectly triggered the rejection rule")
        milestone("nxdomain_observed")
        set_phase("rejections")
        pending = until("pending rule", lambda: next((a for a in alerts() if a["state"] == "pending"), None))
        milestone("pending_observed")
        firing = until("firing rule", lambda: next((a for a in alerts() if a["state"] == "firing"), None))
        milestone("firing_observed")
        save("prometheus-rule.json", {"pending": pending, "firing": firing,
                                      "reject_increase_1m": query(f"increase({counter}[1m])")})
        notification = until("Alertmanager notification", lambda: next(
            (row for row in request("/api/v2/alerts", 9093) if row["labels"].get("test_run") == run), None))
        save("alertmanager.json", notification)
        episode = sha256(f"{ALERT}/{firing['activeAt']}".encode()).hexdigest()
        bridge = until("receiver episode", lambda: matching_log(
            PROM, "/var/log/alert-bridge/events.jsonl",
            lambda row: row.get("episode") == episode and row.get("validation") is True))
        save("receiver.json", bridge)
        alert = until("Wazuh alert", lambda: matching_log(
            MANAGER, "/var/ossec/logs/alerts/alerts.json",
            lambda row: row.get("data", {}).get("episode") == episode and row["rule"]["id"] == "100151"
            and row["agent"]["id"] == "005"))
        save("wazuh.json", alert)
        audit = until("end point audit", lambda: matching_log(
            DNS, "/var/ossec/logs/dns_restore.jsonl", lambda row: row.get("bridge_episode") == episode))
        expect(audit["result"] == "already_approved" and audit["alert_id"] == alert["id"],
               "Unexpected integrity response or mismatched event")
        save("response.json", audit)
        milestone("response_observed")

        set_phase("recovery")
        until("rule clears with approved observations", lambda: query(active) == 1 and not alerts()
              and bool(matches_phase("recovery")))
        milestone("clear_observed")
        rows = checks()
        for row in rows:
            approved = row["phase"] in ("baseline", "recovery")
            expected = "success" if approved else ("dns_failure" if row["phase"] == "nxdomain" else "dns_rejected")
            expect(row["event"]["outcome"] == expected
                   and row["http_requests"] == {"approved": int(approved), "secondary": 0},
                   f"Unexpected fixture observation: {row}")
        for phase in ("baseline", "nxdomain", "rejections", "recovery"):
            summary.setdefault("checks_by_phase", {})[phase] = len(matches_phase(phase))
        (out / "client-checks.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        after = dns_snapshot()
        save("dns-after.json", after)
        expect(before == after, "Live DNS file or process identity changed during the fixture")
        save("live-client-after.json", json.loads(incus(DNS, "python3", "/opt/dns_sec/dns_client.py", "--once")))
        summary["passed"] = True
    except Exception as error:
        summary["error"] = str(error)
        raise
    finally:
        try:
            if enabled:
                reload_config(original, modified)
            summary["original_config_restored"] = incus(PROM, "cat", CONFIG) == original
            expect(summary["original_config_restored"], "Original Prometheus configuration differs")
            until("test target removed", lambda: all(
                row.get("labels", {}).get("test_run") != run
                for row in request("/api/v1/targets")["data"]["activeTargets"]), seconds=25)
        except Exception as error:
            summary.update(passed=False, cleanup_error=str(error))
            raise
        finally:
            subprocess.run(["incus", "exec", PROM, "--", "systemctl", "stop", unit],
                           capture_output=True, timeout=15)
            incus(PROM, "rm", "-r", "--", directory)
            save("summary.json", summary)
            if demo_output and summary["passed"]:
                count = summary["checks_by_phase"]["rejections"]
                print(f"The client rejected {count} test answers and made 0 HTTP requests for them.", flush=True)
            else:
                print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--demo-output", action="store_true", help="Show a step-by-step alert trace")
    args = parser.parse_args()
    if args.fixture:
        fixture(args.fixture)
    else:
        def interrupt(*_):
            raise RuntimeError("Interrupted; restoring the monitoring configuration")

        signal.signal(signal.SIGTERM, interrupt)
        evaluate(demo_output=args.demo_output)
