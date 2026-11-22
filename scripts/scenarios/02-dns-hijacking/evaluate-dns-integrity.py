#!/usr/bin/python3
"""Record bounded defensive DNS/application checks on the student's Incus lab.

No resolver redirection or live unexpected-answer injection is performed.
Run explicitly after installing the agent, manager and Prometheus stages.
"""
import concurrent.futures
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
APPROVED = b"local=/lab.test/\nhost-record=analytics.lab.test,10.255.255.74\n"
TARGET = "/etc/dnsmasq.d/dns_sec.conf"
DNS = "dns-server-container"
MANAGER = "wazuh-container"
PROMETHEUS = "http://10.255.255.21:9090"


def run(args, timeout=35):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed: {args!r}: {result.stderr.decode(errors='replace')[:500]}")
    return result.stdout


def incus(container, *args, timeout=35):
    return run(["incus", "exec", container, "--", *args], timeout)


def one_read():
    return json.loads(incus(DNS, "/usr/bin/python3", "/opt/dns_sec/dns_client.py", "--once"))


def metrics():
    with urllib.request.urlopen("http://10.171.72.8:8004/metrics", timeout=5) as response:
        return response.read().decode()


def prom(route):
    with urllib.request.urlopen(PROMETHEUS + "/api/v1/" + route, timeout=5) as response:
        result = json.load(response)
    if result["status"] != "success":
        raise RuntimeError("Prometheus API query failed")
    return result["data"]


def until(check, timeout, message):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            value = check()
        except urllib.error.URLError:
            # Type=simple starts asynchronously: wait for HTTP readiness, not
            # merely systemd's successful process launch. Preserve the deadline.
            value = None
        if value:
            return value
        time.sleep(2)
    raise RuntimeError(message)


def audit_since(timestamp):
    records = []
    raw = incus(DNS, "tail", "-n", "100", "/var/ossec/logs/dns_restore.jsonl")
    for line in raw.decode().splitlines():
        try:
            record = json.loads(line)
            if datetime.datetime.fromisoformat(record["timestamp"]).timestamp() >= timestamp:
                records.append(record)
        except (ValueError, KeyError, TypeError):
            pass
    return records


def firing_dns_alerts():
    return [a for a in prom("alerts")["alerts"]
            if a["labels"].get("alertname", "").startswith("DNS") and a["state"] == "firing"]


def main():
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "evidence/scenarios/02-dns-hijacking" / ("final-defensive-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    summary = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "scope": "Real-service baseline and automatic file restoration; offline DNS mismatch fixtures",
               "live_dns_hijacking_performed": False, "passed": False, "checks": {}}
    modified = False
    stopped = False

    def save(name, value):
        if isinstance(value, bytes):
            (out / name).write_bytes(value)
        elif isinstance(value, str):
            (out / name).write_text(value)
        else:
            (out / name).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")

    try:
        assert incus(DNS, "cat", TARGET) == APPROVED, "Review the DNS configuration before testing"
        assert incus(DNS, "cat", "/var/lib/dns_sec/approved.conf") == APPROVED
        assert incus(DNS, "cat", "/var/lib/dns_sec/auto-restore.enabled") == b"enabled\n"
        assert incus(DNS, "systemctl", "is-active", "dns_client").strip() == b"active"
        incus(MANAGER, "/var/ossec/bin/wazuh-analysisd", "-t")
        test = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(ROOT / "tests"),
                               "-p", "test_dns_integrity.py", "-v"], capture_output=True, text=True, timeout=40)
        save("offline-tests.txt", test.stdout + test.stderr)
        assert test.returncode == 0
        summary["checks"]["offline_policy_and_response_fixtures"] = True
        baseline = one_read(); save("baseline.json", baseline)
        assert baseline["outcome"] == "success" and baseline["peer_ip"] == "10.255.255.74"
        summary["checks"]["actual_service_baseline"] = True
        save("metrics-before.txt", metrics())
        targets = until(lambda: [t for t in prom("targets")["activeTargets"]
                                 if t["labels"].get("job") == "dns_client" and t["health"] == "up"],
                        45, "Prometheus has not scraped the DNS client successfully")
        save("prometheus-target.json", targets)
        summary["checks"]["prometheus_scrape"] = True
        started = time.time()
        save("change-start.json", {"pre_command_epoch": started,
                                    "warning": "Includes Incus dispatch time; not exact FIM detection latency"})
        modified = True
        incus(DNS, "sh", "-c", "printf '\\n# AUTO_RESTORE_VALIDATION\\n' >> " + TARGET)

        def restored():
            records = [r for r in audit_since(started) if r.get("result") == "restored"]
            return records if records and incus(DNS, "cat", TARGET) == APPROVED else None

        response = until(restored, 40, "No verified automatic restoration recorded")
        modified = False
        save("restoration-audit.json", response)
        related_id = response[0]["alert_id"]
        rows = incus(MANAGER, "tail", "-n", "5000", "/var/ossec/logs/alerts/alerts.json").decode().splitlines()
        matched = []
        for line in rows:
            try:
                record = json.loads(line)
                if record.get("id") == related_id or record.get("data", {}).get("alert_id") == related_id:
                    matched.append(record)
            except ValueError:
                pass
        assert any(r["rule"]["id"] == "100141" and r["agent"]["id"] == "004" for r in matched)
        save("manager-alerts.json", matched)
        time.sleep(1.2)  # Separate diagnostics from the response script's verification read.
        recovered = one_read(); save("recovered.json", recovered)
        assert recovered["outcome"] == "success"
        summary["checks"]["wazuh_dispatched_restore_and_real_client_recovery"] = True
        summary["restored_sha256"] = hashlib.sha256(incus(DNS, "cat", TARGET)).hexdigest()

        # Exactly two ordinary diagnostic clients, not a capacity/load campaign.
        time.sleep(1.2)  # Preserve the existing five-per-second admission policy.
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            reads = list(pool.map(lambda _: one_read(), range(2)))
        save("two-client-reads.json", reads)
        assert all(r["outcome"] == "success" for r in reads)
        summary["checks"]["two_ordinary_client_processes"] = True

        # A controlled resolver-service outage, not an integrity attack.
        stopped = True
        incus(DNS, "systemctl", "stop", "dnsmasq")
        until(lambda: "dns_sec_resolution_expected 0\n" in metrics(), 15,
              "The client did not observe the resolver-service outage")
        save("metrics-during-resolver-outage.txt", metrics())
        outage_alerts = until(lambda: [a for a in firing_dns_alerts()
                                      if a["labels"]["alertname"] == "DNSResolutionNotExpected"],
                             65, "Prometheus DNS outage alert did not reach firing")
        save("prometheus-outage-alerts.json", outage_alerts)
        assert not [r for r in audit_since(started) if r.get("result") == "failed"], "A response failure was recorded"
        summary["checks"]["resolver_outage_observed_and_prometheus_alerted"] = True
        incus(DNS, "systemctl", "start", "dnsmasq")
        stopped = False
        until(lambda: "dns_sec_client_last_request_success 1\n" in metrics(), 20,
              "The continuous client did not recover")
        until(lambda: not firing_dns_alerts(), 45, "DNS Prometheus alerts did not clear after recovery")
        save("metrics-final.txt", metrics())
        save("final-read.json", one_read())
        save("final-services.txt", incus(DNS, "systemctl", "is-active", "dnsmasq", "wazuh-agent", "dns_client"))
        save("final-prometheus-alerts.json", prom("alerts"))
        summary["checks"]["resolver_and_monitoring_recovery"] = True
        summary["passed"] = True
    except Exception as error:
        summary["error"] = str(error)
    finally:
        try:
            if modified:
                incus(DNS, "/usr/bin/install", "-m", "644", "/var/lib/dns_sec/approved.conf", TARGET)
                incus(DNS, "/usr/sbin/dnsmasq", "--test")
                incus(DNS, "systemctl", "restart", "dnsmasq")
                summary["manual_cleanup_performed"] = True
            if stopped:
                incus(DNS, "systemctl", "start", "dnsmasq")
                summary["resolver_cleanup_performed"] = True
        except Exception as error:
            summary["cleanup_error"] = str(error)
        summary["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        summary["limitations"] = [
            "Unexpected-answer rejection is an offline fixture, not live DNS takeover or redirection",
            "Only one approved DNS configuration file is restored; other files require separate policies",
            "The approved node IP and local root-controlled baseline are trust assumptions, not TLS authentication",
            "The client and resolver share one container; two diagnostic reads do not prove capacity or HA",
            "HTTP connect/read timeouts are not an absolute transaction deadline",
            "Prometheus evaluates independently of Wazuh; no Alertmanager-to-SIEM bridge was installed",
            "Manager alerts are retained; independent dashboard/indexer retrieval requires separate evidence"]
        save("summary.json", summary)
        save("SHA256SUMS.json", {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS.json"})
        print(json.dumps({"evidence": str(out), **summary}, indent=2))
    return int(not summary["passed"])


def operations_main():
    """Validate monitoring independence and an explicit maintenance procedure."""
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = ROOT / 'evidence/scenarios/02-dns-hijacking' / ('operations-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    summary = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Exporter outage independence, authorized maintenance and real-client recovery',
               'passed': False, 'checks': {}}
    exporter_stopped = False
    modified = False
    paused = False
    marker = '/var/lib/dns_sec/auto-restore.enabled'
    pause_marker = '/var/lib/dns_sec/auto-restore.paused-' + stamp

    def save(name, value):
        if isinstance(value, bytes): (out / name).write_bytes(value)
        elif isinstance(value, str): (out / name).write_text(value)
        else: (out / name).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')

    try:
        assert incus(DNS, 'cat', TARGET) == APPROVED
        assert incus(DNS, 'cat', marker) == b'enabled\n'
        assert one_read()['outcome'] == 'success'
        save('metrics-before.txt', metrics())
        started = time.time()
        exporter_stopped = True
        incus(DNS, 'systemctl', 'stop', 'dns_client')
        save('exporter-stopped.txt', incus(DNS, 'systemctl', 'show', 'dns_client', '-p', 'ActiveState', '-p', 'MainPID'))
        modified = True
        incus(DNS, 'sh', '-c', "printf '\\n# EXPORTER_OUTAGE_VALIDATION\\n' >> " + TARGET)

        def independent_restore():
            rows = [r for r in audit_since(started) if r.get('result') == 'restored']
            return rows if rows and incus(DNS, 'cat', TARGET) == APPROVED else None

        restored = until(independent_restore, 40, 'Wazuh did not restore while exporter was stopped')
        modified = False
        save('independent-restoration.json', restored)
        assert restored[0]['verification']['outcome'] == 'success'
        summary['checks']['wazuh_restore_independent_of_exporter_service'] = True

        def monitoring_failure():
            alerts = firing_dns_alerts()
            names = {a['labels']['alertname'] for a in alerts}
            return alerts if {'DNSExporterUnavailable', 'DNSObservationStale'} <= names else None

        alerts = until(monitoring_failure, 75, 'Exporter outage/staleness alerts did not both fire')
        save('prometheus-exporter-outage-alerts.json', alerts)
        save('prometheus-targets-during-outage.json', prom('targets'))
        summary['checks']['exporter_outage_and_stale_data_alerts'] = True
        incus(DNS, 'systemctl', 'start', 'dns_client')
        exporter_stopped = False
        until(lambda: 'dns_sec_client_last_request_success 1\n' in metrics(), 20, 'Exporter client failed to recover')
        until(lambda: not firing_dns_alerts(), 45, 'Exporter alerts did not clear')
        save('metrics-after-exporter-recovery.txt', metrics())
        summary['checks']['exporter_recovery_and_alert_clearance'] = True

        started = time.time()
        incus(DNS, 'mv', marker, pause_marker)
        paused = True
        modified = True
        incus(DNS, 'sh', '-c', "printf '\\n# AUTHORIZED_MAINTENANCE_TEST\\n' >> " + TARGET)
        maintenance = until(lambda: [r for r in audit_since(started) if r.get('result') == 'maintenance'],
                            30, 'Maintenance marker was not respected')
        current = incus(DNS, 'cat', TARGET)
        assert b'AUTHORIZED_MAINTENANCE_TEST' in current, 'Authorized comment was unexpectedly overwritten'
        save('maintenance-audit.json', maintenance)
        save('maintenance-file.sha256', hashlib.sha256(current).hexdigest() + '\n')
        save('maintenance-client-read.json', one_read())
        incus(DNS, '/usr/bin/install', '-m', '644', '/var/lib/dns_sec/approved.conf', TARGET)
        modified = False
        incus(DNS, '/usr/sbin/dnsmasq', '--test')
        incus(DNS, 'systemctl', 'restart', 'dnsmasq')
        incus(DNS, 'mv', pause_marker, marker)
        paused = False
        time.sleep(1.2)
        save('final-client-read.json', one_read())
        assert incus(DNS, 'cat', TARGET) == APPROVED
        assert incus(DNS, 'cat', marker) == b'enabled\n'
        summary['checks']['authorized_maintenance_does_not_auto_overwrite'] = True
        summary['checks']['approved_baseline_and_protection_reenabled'] = True
        save('final-services.txt', incus(DNS, 'systemctl', 'is-active', 'dnsmasq', 'wazuh-agent', 'dns_client'))
        summary['passed'] = True
    except Exception as error:
        summary['error'] = str(error)
    finally:
        try:
            if modified:
                incus(DNS, '/usr/bin/install', '-m', '644', '/var/lib/dns_sec/approved.conf', TARGET)
                incus(DNS, '/usr/sbin/dnsmasq', '--test')
                incus(DNS, 'systemctl', 'restart', 'dnsmasq')
                summary['manual_cleanup_performed'] = True
            if paused: incus(DNS, 'mv', pause_marker, marker)
            if exporter_stopped: incus(DNS, 'systemctl', 'start', 'dns_client')
        except Exception as error:
            summary['cleanup_error'] = str(error)
        summary['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        summary['limitations'] = [
            'Maintenance test changes only a comment; no DNS redirection or credential capture',
            'FIM still reports authorized edits; maintenance context changes the response decision',
            'Stopping the exporter restarts counters on recovery; compare deltas only within one process lifetime']
        save('summary.json', summary)
        save('SHA256SUMS.json', {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in out.iterdir() if p.is_file() and p.name != 'SHA256SUMS.json'})
        print(json.dumps({'evidence': str(out), **summary}, indent=2))
    return int(not summary['passed'])


def baseline_main():
    """One minute of ordinary observation after recovery; not a capacity test."""
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = ROOT / 'evidence/scenarios/02-dns-hijacking' / ('baseline-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    summary = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Sixty-second normal observation on the shared VM, with no extra traffic',
               'passed': False}
    samples = []

    def observe():
        text = metrics()
        values = {}
        for line in text.splitlines():
            if line and not line.startswith('#'):
                key, value = line.rsplit(' ', 1)
                values[key] = float(value)
        raw = incus(DNS, 'systemctl', 'show', 'dns_client', '-p', 'MainPID', '-p', 'CPUUsageNSec',
                    '-p', 'MemoryCurrent', '-p', 'NRestarts').decode()
        unit = {key: int(value) if value.isdigit() else value for key, value in
                (line.split('=', 1) for line in raw.splitlines() if '=' in line)}
        return {'epoch': time.time(), 'metrics': values, 'unit': unit, 'raw_metrics': text}

    try:
        started = time.monotonic()
        samples.append(observe())
        while time.monotonic() - started < 60:
            time.sleep(min(5, max(0, 60 - (time.monotonic() - started))))
            samples.append(observe())
        elapsed = time.monotonic() - started
        before, after = samples[0], samples[-1]
        outcomes = ('success', 'dns_failure', 'dns_rejected', 'http_error', 'invalid_response')
        counts = {key: after['metrics'][f'dns_sec_client_requests_total{{outcome="{key}"}}'] -
                        before['metrics'][f'dns_sec_client_requests_total{{outcome="{key}"}}'] for key in outcomes}
        count = sum(counts.values())
        total = after['metrics']['dns_sec_client_request_duration_seconds_sum'] - before['metrics']['dns_sec_client_request_duration_seconds_sum']
        pids = {s['unit']['MainPID'] for s in samples}
        memory = [s['unit']['MemoryCurrent'] for s in samples if type(s['unit']['MemoryCurrent']) is int]
        cpu0, cpu1 = before['unit']['CPUUsageNSec'], after['unit']['CPUUsageNSec']
        cpu = (cpu1 - cpu0) / 1e9 / elapsed if type(cpu0) is int and type(cpu1) is int else None
        assert len(pids) == 1 and next(iter(pids)) > 0, 'The client restarted during the baseline'
        assert counts['success'] > 0 and all(counts[k] == 0 for k in outcomes if k != 'success')
        assert all(s['metrics']['dns_sec_resolution_expected'] == 1 and
                   s['metrics']['dns_sec_client_last_request_success'] == 1 and
                   s['epoch'] - s['metrics']['dns_sec_last_check_timestamp_seconds'] < 20 for s in samples)
        summary.update(passed=True, duration_seconds=elapsed, samples=len(samples), outcome_deltas=counts,
                       mean_request_ms=1000 * total / count if count else None, mean_cpu_cores=cpu,
                       mean_memory_bytes=sum(memory) / len(memory) if memory else None,
                       max_memory_bytes=max(memory) if memory else None, process_unchanged=True,
                       custom_metric_series=len(before['metrics']))
    except Exception as error:
        summary['error'] = str(error)
    finally:
        if samples:
            (out / 'metrics-before.txt').write_text(samples[0]['raw_metrics'])
            (out / 'metrics-after.txt').write_text(samples[-1]['raw_metrics'])
        (out / 'samples.json').write_text(json.dumps(samples, indent=2) + '\n')
        summary['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        summary['limitations'] = ['Shared VM observational baseline, not isolated capacity or CPU-savings proof',
                                  'Latency has sum/count only; no tail-percentile estimate is claimed']
        (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        (out / 'SHA256SUMS.json').write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                                      for p in out.iterdir() if p.is_file() and p.name != 'SHA256SUMS.json'}, indent=2) + '\n')
        print(json.dumps({'evidence': str(out), **summary}, indent=2))
    return int(not summary['passed'])


def service_outage_main():
    """Pause only the DNS host's monitoring services and verify recovery."""
    started = datetime.datetime.now(datetime.timezone.utc)
    out = ROOT / "evidence/scenarios/02-dns-hijacking" / started.strftime("service-outage-%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True)
    units = ("dns_client", "wazuh-agent")
    report = {"started_utc": started.isoformat(), "passed": False, "phases": {}}
    paused = False

    def snapshot(name, approved):
        states = {}
        for service in ("dnsmasq", *units):
            data = incus(DNS, "systemctl", "show", service, "-p", "ActiveState", "-p", "MainPID")
            states[service] = dict(line.split("=", 1) for line in data.decode().splitlines())
        agent_pids = incus(DNS, "sh", "-c", 'pgrep -x wazuh-agentd || test "$?" -eq 1')
        states["wazuh-agent"]["DaemonPIDs"] = agent_pids.decode().splitlines()
        addresses = incus(DNS, "/usr/bin/dig", "@127.0.0.1", approved["dns_name"],
                          "A", "+short", "+time=1", "+tries=1").decode().splitlines()
        if addresses != approved["observed_addresses"]:
            raise RuntimeError("The legitimate DNS answer differs from the approved control")
        exporter = subprocess.run(
            ["incus", "exec", DNS, "--", "curl", "--noproxy", "*", "-fsS", "--max-time", "2",
             "http://127.0.0.1:8004/metrics"], capture_output=True, timeout=6)
        target_hash = hashlib.sha256(incus(DNS, "cat", TARGET)).hexdigest()
        if target_hash != hashlib.sha256(APPROVED).hexdigest():
            raise RuntimeError("The live resolver file differs from the approved policy")
        address = addresses[0]
        name_and_port = f"{approved['dns_name']}:30503"
        control_read = json.loads(incus(DNS, "curl", "--noproxy", "*", "-fsS", "--max-time", "6",
                                       "--resolve", f"{name_and_port}:{address}",
                                       f"http://{name_and_port}/average"))
        if "average_temperature" not in control_read:
            raise RuntimeError("The approved analytics endpoint did not return a reading")
        report["phases"][name] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "units": states, "approved_dns_answer": addresses, "target_sha256": target_hash,
            "exporter_http_reachable": exporter.returncode == 0, "exporter_curl_exit": exporter.returncode,
            "approved_http_read": control_read,
        }
        print(f'{name}: {states}; DNS {addresses}; exporter curl exit {exporter.returncode}', flush=True)
        return states, exporter.returncode

    def manager_kept_running():
        incus(MANAGER, "systemctl", "is-active", "wazuh-manager")
        return int(incus(MANAGER, "pgrep", "-x", "wazuh-analysisd"))

    try:
        if incus(DNS, "systemctl", "is-active", *units).splitlines() != [b"active", b"active"]:
            raise RuntimeError("Start the DNS client and the DNS host's Wazuh agent first")
        approved = one_read()
        report["guarded_read_before"] = approved
        before, status = snapshot("before", approved)
        manager_pid = manager_kept_running()
        if status or not before["wazuh-agent"]["DaemonPIDs"]:
            raise RuntimeError("The exporter or manager is not ready")
        paused = True
        incus(DNS, "systemctl", "stop", *units)
        during, status = snapshot("paused", approved)
        if (status != 7 or during["dnsmasq"] != before["dnsmasq"] or during["wazuh-agent"]["DaemonPIDs"]
                or any(during[s]["ActiveState"] != "inactive" or during[s]["MainPID"] != "0" for s in units)):
            raise RuntimeError("Expected only the agent and client to be inactive and the exporter to refuse connections")
        if manager_kept_running() != manager_pid:
            raise RuntimeError("The central Wazuh manager changed process")
        incus(DNS, "systemctl", "start", *units)
        paused = False
        until(metrics, 30, "DNS client exporter did not return")
        until(lambda: b"status='connected'" in incus(DNS, "cat", "/var/ossec/var/run/wazuh-agentd.state"),
              40, "DNS host's Wazuh agent did not reconnect")
        after, status = snapshot("recovered", approved)
        if (status or after["dnsmasq"] != before["dnsmasq"] or manager_kept_running() != manager_pid
                or not after["wazuh-agent"]["DaemonPIDs"]
                or any(after[s]["ActiveState"] != "active" for s in units)):
            raise RuntimeError("Services did not recover to the expected state")
        report["guarded_read_after"] = one_read()
        report["central_manager_analysisd_pid"] = manager_pid
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
    finally:
        try:
            if paused:
                incus(DNS, "systemctl", "start", *units)
        finally:
            (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
            print(out, flush=True)
    return int(not report["passed"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--operations-only"]:
        raise SystemExit(operations_main())
    if sys.argv[1:] == ["--baseline"]:
        raise SystemExit(baseline_main())
    if sys.argv[1:] == ["--service-outage"]:
        raise SystemExit(service_outage_main())
    if sys.argv[1:]:
        raise SystemExit("Usage: evaluate-dns-integrity.py [--operations-only|--baseline|--service-outage]")
    result = main()
    if result == 0:
        result = operations_main()
    raise SystemExit(result if result else baseline_main())
