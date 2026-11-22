#!/usr/bin/env python3
"""Compare local DNS comment recovery and isolated HTTP application behavior."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "monitoring"))
from dns_client import DNS_NAME, EXPECTED_IP, probe

DNS = "dns-server-container"
FAKE_SITE = "dns-fake-site"
FAKE_SITE_URL = "http://127.0.0.1:30503/average"
TARGET = "/etc/dnsmasq.d/dns_sec.conf"
APPROVED_PATH = "/var/lib/dns_sec/approved.conf"
MARKER = "/var/lib/dns_sec/auto-restore.enabled"
AUDIT = "/var/ossec/logs/dns_restore.jsonl"
UNEXPECTED_FIXTURE = "192.0.2.10"


def incus(container, *args):
    return subprocess.run(["incus", "exec", container, "--", *args],
                          capture_output=True, check=True, timeout=25).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def now():
    return dt.datetime.now(dt.timezone.utc)


def audit_after(start, result):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        records = incus(DNS, "tail", "-n", "40", AUDIT).splitlines()
        for line in reversed(records):
            entry = json.loads(line)
            if entry.get("result") == result and dt.datetime.fromisoformat(entry["timestamp"]) >= start:
                return entry
        time.sleep(1)
    raise RuntimeError(f"No new {result} audit after {start.isoformat()}")


def live_read():
    answer = incus(DNS, "dig", "@127.0.0.1", DNS_NAME, "A", "+short", "+time=2", "+tries=1").decode().splitlines()
    event = json.loads(incus(DNS, "python3", "/opt/dns_sec/dns_client.py", "--once"))
    if answer != [EXPECTED_IP] or event["outcome"] != "success" or event["peer_ip"] != EXPECTED_IP:
        raise RuntimeError("The legitimate application path did not pass")
    return {"dns_answer": answer, "client": event}


def http_comparison(*, narrate=False):
    requests = 0

    def read_fixture(_address):
        nonlocal requests
        requests += 1
        raw = incus(FAKE_SITE, "curl", "-fsS", "--max-time", "5", "--write-out",
                    "\n%{http_code}\n%{content_type}", FAKE_SITE_URL)
        body, status, content_type = raw.rsplit(b"\n", 2)
        if status != b"200" or content_type != b"text/html; charset=utf-8" or b"<h1>FAKE SITE</h1>" not in body:
            raise RuntimeError("The loopback test site did not return the expected labelled HTML page")
        return {"http_status": int(status), "content_type": content_type.decode("ascii"), "page_title": "FAKE SITE"}

    if narrate:
        print("[Simulation] Testing access without the client's DNS check.", flush=True)
        print(f"[Simulation] The resolver returns {UNEXPECTED_FIXTURE} for {DNS_NAME}.", flush=True)
        print("Requesting the fake site in the isolated demo...", flush=True)
    without = read_fixture(UNEXPECTED_FIXTURE)
    after_without = requests
    if narrate:
        print("The fake site responded. HTTP result as JSON.", flush=True)
        print(json.dumps({**without, "http_requests": after_without}), flush=True)
        print("Retrying with the client's DNS check enabled...", flush=True)
    guarded = probe(resolver=lambda: [UNEXPECTED_FIXTURE], reader=read_fixture)
    guarded_requests = requests - after_without
    if guarded["outcome"] != "dns_rejected" or guarded_requests != 0:
        raise RuntimeError("The guarded path did not reject the fixture before calling the HTTP reader")
    if narrate:
        print(f"The client blocked access ({guarded['outcome']}, {guarded_requests} HTTP requests).", flush=True)
    return {
        "tested_utc": now().isoformat(), "hostname": DNS_NAME,
        "supplied_dns_address": UNEXPECTED_FIXTURE, "dns_answer_source": "injected application fixture",
        "http_fixture_location": f"{FAKE_SITE} / {FAKE_SITE_URL}",
        "without_check": {**without, "http_requests": after_without},
        "with_check": {"outcome": guarded["outcome"], "http_requests": guarded_requests},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--defense-demo", action="store_true",
        help="Run the isolated HTTP comparison, the alert pipeline and comment-only FIM recovery",
    )
    args = parser.parse_args()
    stamp = now().strftime("%Y%m%dT%H%M%SZ")
    prefix = "defense-demo-" if args.defense_demo else "before-after-"
    out = ROOT / "evidence/scenarios/02-dns-hijacking" / (prefix + stamp)
    out.mkdir(parents=True)
    print(out, flush=True)

    def save(name, content):
        (out / name).write_text(json.dumps(content, indent=2, sort_keys=True) + "\n")

    approved = incus(DNS, "cat", APPROVED_PATH)
    if approved != f"local=/lab.test/\nhost-record={DNS_NAME},{EXPECTED_IP}\n".encode():
        raise RuntimeError("Unexpected approved mapping")
    if incus(DNS, "cat", TARGET) != approved or incus(DNS, "cat", MARKER) != b"enabled\n":
        raise RuntimeError("Start with the approved file and restoration enabled")

    paused_marker = MARKER + ".demo-" + stamp
    comment = f"\n# RESTORE_AB_VALIDATION {stamp}\n"
    altered = approved + comment.encode()
    paused = False
    failure = None
    scope = ("Loopback HTTP comparison, DNS-policy alert delivery and comment-only FIM recovery"
             if args.defense_demo else "Real FIM comment comparison and real loopback HTTP with an injected DNS answer")
    summary = {"scope": scope, "dns_mapping_changed": False, "passed": False}
    try:
        comparison = http_comparison(narrate=args.defense_demo)
        save("http-fixture-comparison.json", comparison)
        save("baseline.json", {"config_sha256": sha(approved), **live_read()})

        if args.defense_demo:
            print("Testing the alert with repeated unexpected DNS answers...", flush=True)
            subprocess.run(
                [sys.executable, str(Path(__file__).with_name("evaluate-dns-alert.py")), "--demo-output"],
                stdin=subprocess.DEVNULL, check=True,
            )
            if incus(DNS, "cat", TARGET) != approved or incus(DNS, "cat", MARKER) != b"enabled\n":
                raise RuntimeError("DNS policy changed during the alert test")
            print("Adding a test comment to the resolver file monitored by Wazuh...", flush=True)
        else:
            incus(DNS, "mv", MARKER, paused_marker)
            paused = True
            start = now()
            incus(DNS, "sh", "-c", 'printf "%s" "$1" >> "$2"', "sh", comment, TARGET)
            maintenance = audit_after(start, "maintenance")
            paused_bytes = incus(DNS, "cat", TARGET)
            if paused_bytes != altered:
                raise RuntimeError("The maintenance comment did not remain in the file")
            save("maintenance.json", {"auto_restore": "paused", "comment_present": True,
                                      "config_sha256": sha(paused_bytes), "audit": maintenance, **live_read()})

            # Reset to the same baseline and drain the reset event before trial B.
            start = now()
            incus(DNS, "install", "-m", "644", APPROVED_PATH, TARGET)
            audit_after(start, "maintenance")
            incus(DNS, "mv", paused_marker, MARKER)
            paused = False

        start = now()
        incus(DNS, "sh", "-c", 'printf "%s" "$1" >> "$2"', "sh", comment, TARGET)
        restored = audit_after(start, "restored")
        final_bytes = incus(DNS, "cat", TARGET)
        if (final_bytes != approved or incus(DNS, "cat", MARKER) != b"enabled\n"
                or restored.get("before_sha256") != sha(altered)
                or restored.get("after_sha256") != sha(approved)):
            raise RuntimeError("The response audit and restored file did not match the A/B inputs")
        recovered = live_read()
        save("enabled.json", {"auto_restore": "enabled", "comment_present": False,
                              "config_sha256": sha(final_bytes), "audit": restored, **recovered})
        if args.defense_demo:
            print(f"Wazuh detected the change and restored the approved file "
                  f"(rule 100141, alert {restored['alert_id']}).", flush=True)
            print(f"Restored file SHA-256 {sha(final_bytes)}", flush=True)
            print(f"{DNS_NAME} resolves to {recovered['dns_answer'][0]}. "
                  f"Analytics returned HTTP {recovered['client']['http_status']}.", flush=True)
        summary["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        failure = error
        summary["error"] = str(error)
    finally:
        if failure is not None:
            try:
                current = incus(DNS, "cat", TARGET)
                if current == altered:
                    incus(DNS, "install", "-m", "644", APPROVED_PATH, TARGET)
                if paused:
                    incus(DNS, "mv", paused_marker, MARKER)
            except (OSError, subprocess.SubprocessError) as error:
                summary["cleanup_error"] = str(error)
        save("summary.json", summary)

    if failure is not None:
        raise failure
    if args.defense_demo:
        print(f"Demo complete. Evidence saved in {out}.")
    else:
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
