#!/usr/bin/env bash
set -euo pipefail

PAUSE=0
for arg in "$@"; do
  case "$arg" in
    --pause) PAUSE=1 ;;
    -h|--help) echo 'Usage: bash show-dns-flow.sh [--pause]'; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done
step() {
  printf '\n\n%s\n' '=================================================================='
  printf '  %s\n' "$*"
  printf '%s\n' '=================================================================='
}
pause() { if (( PAUSE )) && [[ -t 0 ]]; then read -r -p 'Press ENTER to continue... ' _; fi; }
progress_bar() { local x=$1 total=$2 j; printf '  ['; for ((j=0;j<total;j++)); do if ((j<x)); then printf '#'; else printf '.'; fi; done; printf '] %d/%d\n' "$x" "$total"; }

demo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
dns="dns-server-container"
domain="analytics.lab.test"
original_ip="10.255.255.74"
malicious_ip="10.171.72.52"
target="/etc/dnsmasq.d/dns_sec.conf"
approved="/var/lib/dns_sec/approved.conf"
audit="/var/ossec/logs/dns_restore.jsonl"
# Override through the environment when using a different location:
prometheus_url="${PROMETHEUS_URL:-http://10.255.255.21:9090}"
start_script="${START_DNS_PROTECTION:-$demo_dir/start-dns-protection.sh}"
prometheus_max_attempts="${PROMETHEUS_MAX_ATTEMPTS:-48}"
tampered=0
baseline_backup=""
# Store raw evidence independently of the terminal summaries.
evidence="$demo_dir/results/demo-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p -- "$evidence"
exec > >(tee "$evidence/flow.log") 2>&1
printf '  Evidence for this run: %s\n' "$evidence"

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n "$baseline_backup" ]]; then
        if ! incus exec "$dns" -- cmp -s "$approved" "$baseline_backup"; then
            printf '\n[CLEANUP] The approved configuration changed. Restoring the original copy.\n' >&2
            incus exec "$dns" -- cp -- "$baseline_backup" "$approved" || true
        fi
    fi
    if (( tampered )); then
        printf '\n[CLEANUP] Restoring the approved file and restarting dnsmasq.\n' >&2
        incus exec "$dns" -- cp -- "$approved" "$target" || true
        incus exec "$dns" -- systemctl restart dnsmasq || true
    fi
    if [[ -n "$baseline_backup" ]]; then
        incus exec "$dns" -- rm -f -- "$baseline_backup" || true
    fi
    printf '\n[RESULTS AND EVIDENCE] %s\n' "$evidence"
    if (( status == 0 )); then printf '[RESULT] Demonstration completed.\n'; else printf '[RESULT] Demonstration interrupted (exit code %d).\n' "$status"; fi
    exit "$status"
}
trap cleanup EXIT

resolve_dns() {
    incus exec "$dns" -- dig @127.0.0.1 "$domain" A +short +time=2 +tries=1 | tr -d '\r'
}

step '[0/7] INITIAL STATE: approved DNS configuration and inactive Wazuh agent'
incus exec "$dns" -- test -f "$approved"
incus exec "$dns" -- cmp "$target" "$approved"
if incus exec "$dns" -- systemctl is-active --quiet wazuh-agent; then
    printf 'ERROR: Wazuh is already active and could restore the file before the test.\n' >&2
    exit 1
fi
printf 'Wazuh: inactive (expected).\n'
baseline_backup="$(incus exec "$dns" -- mktemp /tmp/approved-dns.XXXXXX)"
incus exec "$dns" -- cp -- "$approved" "$baseline_backup"
approved_hash="$(incus exec "$dns" -- sha256sum "$approved" | awk '{print $1}')"

step "[1/7] BEFORE THE CHANGE: original DNS answer for $domain"
initial_answer="$(resolve_dns)"
printf '%s\n' "$initial_answer" >"$evidence/dns-before.txt"
printf '%s -> %s\n' "$domain" "$initial_answer"
[[ "$initial_answer" == "$original_ip" ]] || {
    printf 'Expected %s. Check the DNS rules and the queried server.\n' "$original_ip" >&2
    exit 1
}

pause
step "[2/7] SIMULATED CHANGE: $domain -> $malicious_ip"
# Limit the change to one record for the specified lab domain in this file.
changed_hash="$(incus exec "$dns" -- python3 - "$target" "$domain" "$original_ip" "$malicious_ip" <<'PY'
import hashlib
from pathlib import Path
import re
import sys

path, domain, good, bad = sys.argv[1:]
p = Path(path)
source = p.read_text()
patterns = [
    re.compile(rf'^(host-record={re.escape(domain)},){re.escape(good)}(\s*(?:#.*)?)$', re.M),
    re.compile(rf'^(address=/{re.escape(domain)}/){re.escape(good)}(\s*(?:#.*)?)$', re.M),
]
matches = sum(len(pat.findall(source)) for pat in patterns)
if matches != 1:
    sys.exit(f'ERROR: expected exactly one record for {domain} pointing to {good} in {path}; found {matches}')
for pat in patterns:
    source = pat.sub(lambda m: m.group(1) + bad + m.group(2), source)
p.write_text(source)
print(hashlib.sha256(source.encode()).hexdigest())
PY
)"
tampered=1
incus exec "$dns" -- dnsmasq --test
incus exec "$dns" -- systemctl restart dnsmasq

step '[3/7] WITHOUT PROTECTION: query the actual dnsmasq answer'
tampered_answer="$(resolve_dns)"
printf '%s\n' "$tampered_answer" >"$evidence/dns-modified.txt"
printf '%s -> %s\n' "$domain" "$tampered_answer"
if [[ "$tampered_answer" != "$malicious_ip" ]]; then
    printf 'dnsmasq did not return %s. Inspecting active rules; Wazuh restoration is unverified.\n' "$malicious_ip" >&2
    incus exec "$dns" -- grep -RnF -- "$domain" /etc/dnsmasq.conf /etc/dnsmasq.d/ 2>/dev/null || true
    exit 1
fi

pause
step '[4/7] PROTECTED CLIENT: verify eight actual DNS rejections'
incus exec "$dns" -- systemctl start dns_client
incus exec "$dns" -- systemctl is-active dns_client
rejections=0
for ((i=1; i<=8; i++)); do
    printf '  Check %d/8: ' "$i"
    check_result="$(incus exec "$dns" -- python3 /opt/dns_sec/dns_client.py --once 2>&1)" || true
    printf '%s\n' "$check_result" >>"$evidence/dns-client-responses.jsonl"
    printf '%s\n' "$check_result" | python3 -c '
import json,sys
try:
 r=json.load(sys.stdin)
 print("{} | Observed DNS: {}".format(
       "REJECTED" if r.get("outcome")=="dns_rejected" else r.get("outcome", "NO DATA"),
       ", ".join(r.get("observed_addresses", [])) or "not provided"))
except (ValueError, TypeError):
 print("unstructured result: inspect the raw log")
' 
    if [[ "$check_result" == *'"outcome": "dns_rejected"'* ]] || \
       [[ "$check_result" == *'"outcome":"dns_rejected"'* ]]; then
        ((rejections+=1))
    fi
    sleep 2
done
printf '\n  Client-confirmed rejections:\n'; progress_bar "$rejections" 8
if (( rejections == 0 )); then
    printf 'ERROR: no rejections observed. Check the client configuration.\n' >&2
    exit 1
fi

pause
step '[5/7] PROMETHEUS: DNSPolicyRejections alert in firing state'
printf 'Prometheus API: %s\n' "$prometheus_url"
prom_state=""
prom_name=""
for ((attempt=1; attempt<=prometheus_max_attempts; attempt++)); do
    if alerts="$(curl -fsS --max-time 5 "${prometheus_url%/}/api/v1/alerts" 2>/dev/null)"; then
        # Print one name|state line for each DNS alert returned by the API.
        relevant="$(printf '%s' "$alerts" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    for a in data.get("data", {}).get("alerts", []):
        n = a.get("labels", {}).get("alertname", "")
        if "dns" in n.lower() or "policyrejection" in n.lower():
            print("{}|{}".format(n, a.get("state", "unknown")))
except (ValueError, TypeError):
    pass
')"
        if [[ -n "$relevant" ]]; then
            printf '  States queried from Prometheus:\n%s\n' "$relevant"
            # Only the policy alert confirms that the rejections were detected.
            # DNSExporterUnavailable=firing indicates an exporter failure, not a successful policy check.
            if grep -q '^DNSPolicyRejections|firing$' <<< "$relevant"; then
                prom_state="firing"
                prom_name="DNSPolicyRejections"
                printf '%s\n' "$alerts" >"$evidence/prometheus-alerts.json"
                break
            fi
            if grep -q '^DNSPolicyRejections|pending$' <<< "$relevant"; then
                prom_state="pending"
            fi
        fi
    elif (( attempt == 1 )); then
        printf 'Warning: could not query the Prometheus API.\n' >&2
    fi
    # Keep rejection activity observable while waiting for scraping and rule evaluation.
    if (( attempt % 3 == 0 )); then
        incus exec "$dns" -- python3 /opt/dns_sec/dns_client.py --once || true
    fi
    sleep 5
done
if [[ "$prom_state" == "firing" ]]; then
    printf '\n  [EVIDENCE] %s is FIRING (Prometheus API).\n' "$prom_name"
else
    printf 'ERROR: DNSPolicyRejections did not reach firing state (%s).\n' "${prom_state:-not found}" >&2
    printf 'Check the rule for-duration, scrape status and exporter availability.\n' >&2
    printf 'Increase the wait using PROMETHEUS_MAX_ATTEMPTS=60 if needed.\n' >&2
    exit 1
fi

# Record the audit offset so earlier restoration events cannot satisfy this run.
audit_offset="$(incus exec "$dns" -- sh -c 'if [ -f "$1" ]; then wc -l < "$1"; else echo 0; fi' sh "$audit")"
current_approved_hash="$(incus exec "$dns" -- sha256sum "$approved" | awk '{print $1}')"
[[ "$current_approved_hash" == "$approved_hash" ]] || {
    printf 'ERROR: the approved file was modified.\n' >&2
    exit 1
}

pause
step '[6/7] WAZUH: startup integrity check (rule 100145)'
# Starting wazuh-agent alone does not detect changes made while the agent was stopped.
# The project startup script compares target and approved and requests response rule 100145.
if [[ ! -f "$start_script" ]]; then
    printf 'ERROR: start-dns-protection.sh not found at %s\n' "$start_script" >&2
    printf 'Set START_DNS_PROTECTION=/path/to/start-dns-protection.sh\n' >&2
    exit 1
fi
startup_exit=0
bash "$start_script" >"$evidence/protection-startup.log" 2>&1 || startup_exit=$?
printf '  [ACTIVATION] Protection startup exit code: %d\n' "$startup_exit"
printf '  [LOG] Original output saved in protection-startup.log\n' 
# The exit status may reflect a rejected DNS answer from dns_client.py --once.
# Validate services, the approved baseline and the actual restoration event separately.
incus exec "$dns" -- systemctl is-active --quiet wazuh-agent || {
    printf 'ERROR: Wazuh did not start.\n' >&2
    exit 1
}
current_approved_hash="$(incus exec "$dns" -- sha256sum "$approved" | awk '{print $1}')"
[[ "$current_approved_hash" == "$approved_hash" ]] || {
    printf 'ERROR: start-dns-protection changed the approved configuration.\n' >&2
    exit 1
}
restored=0
for ((attempt=0; attempt<60; attempt++)); do
    if incus exec "$dns" -- python3 - "$audit" "$changed_hash" "$approved_hash" "$audit_offset" <<'PYRESTORE'
import json
from pathlib import Path
import sys
path, before, after, offset = sys.argv[1:]
if not Path(path).exists():
    sys.exit(1)
lines = Path(path).read_text(errors='replace').splitlines()
for line in lines[int(offset):]:
    try:
        row = json.loads(line)
    except ValueError:
        continue
    if (row.get('result') == 'restored'
            and row.get('before_sha256') == before and row.get('after_sha256') == after):
        print(f'Wazuh Active Response: event {row.get("alert_id")}, restoration confirmed. bridge_episode={row.get("bridge_episode", False)}')
        sys.exit(0)
sys.exit(1)
PYRESTORE
    then
        incus exec "$dns" -- cmp "$target" "$approved"
        restored=1
        break
    fi
    sleep 1
done
if (( ! restored )); then
    printf 'No NEW restoration event was recorded for this change.\n' >&2
    printf 'Verify that start-dns-protection.sh performs the initial comparison and triggers rule 100145/Active Response.\n' >&2
    exit 1
fi

pause
step '[7/7] RECOVERY: verify the original IP and approved file'
incus exec "$dns" -- systemctl is-active dnsmasq dns_client wazuh-agent
incus exec "$dns" -- cmp "$target" "$approved"
final_answer="$(resolve_dns)"
printf '%s\n' "$final_answer" >"$evidence/dns-restored.txt"
printf '%s -> %s\n' "$domain" "$final_answer"
[[ "$final_answer" == "$original_ip" ]] || {
    printf 'The file was restored, but DNS still does not return the original IP.\n' >&2
    exit 1
}
incus exec "$dns" -- python3 /opt/dns_sec/dns_client.py --once
tampered=0
printf '\n  VERIFIED FLOW\n'
printf '    Original DNS  : %s\n' "$initial_answer"
printf '          | simulated change\n'
printf '          v\n'
printf '    Modified DNS  : %s\n' "$tampered_answer"
printf '          | %s client rejections\n' "$rejections"
printf '          | Prometheus: DNSPolicyRejections = FIRING\n'
printf '          | Wazuh: audited restoration\n'
printf '          v\n'
printf '    Restored DNS  : %s\n' "$final_answer"
printf '\n[DONE] Original DNS confirmed after restoration; rejections and alert observed.\n'
