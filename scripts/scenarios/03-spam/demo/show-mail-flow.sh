#!/usr/bin/env bash
# Scenario 3: spam demonstration with delivery, classification, alert and audit evidence.
# Run only in the Incus lab using mail-container and *.lab.test.
set -Eeuo pipefail

MAIL=mail-container
PROM=prometheus-container
WAZUH=wazuh-container
USER_MAIL=security-operations
DOMAIN=mail.lab.test
FROM_ADDR=validation@mail.lab.test
TO_ADDR=security-operations@mail.lab.test
MASTER_CF=/etc/postfix/master.cf
EVENTS=/var/log/mail-security/events.jsonl
GATEWAY=/opt/mail-security/mail_gateway.py
ALERT=MailQuarantineActivity
EXPECTED_FILTER=spamassassin:filter
RECOVERY=/opt/mail-security/mail_service_recovery.py
SERVICE_AUDIT=/var/log/mail-security/service-health.jsonl
PAUSE=0
PREFLIGHT=0
RELEASE=0

for arg in "$@"; do
  case "$arg" in
    --pause) PAUSE=1 ;;
    --preflight-only) PREFLIGHT=1 ;;
    --release) RELEASE=1 ;;
    -h|--help)
      cat <<'HELP'
Usage: bash show-mail-flow.sh [--pause] [--preflight-only] [--release]
  --pause           Pause between steps for a live presentation.
  --preflight-only  Check the configuration without modifying it.
  --release         Demonstrate authorized release of a GTUBE sample.
The SMTP filter is automatically disabled during the unprotected test and
restored afterwards. An exit trap attempts restoration if the run fails.
Step 7 stops SpamAssassin and requires Wazuh to recover it automatically.
HELP
      exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

for needed in incus python3 sha256sum awk grep mktemp flock; do
  command -v "$needed" >/dev/null 2>&1 || { echo "Missing required command '$needed'" >&2; exit 1; }
done
exec 9>"/tmp/mail-security-flow-$(id -u).lock"
flock -n 9 || { echo '[ERROR] Another mail flow or recovery installation is running.' >&2; exit 1; }

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Each run stores its evidence alongside the flow under demo/results/.
evidence_root="$script_dir/results"
token="$(python3 -c 'import uuid;print(uuid.uuid4().hex[:12])')"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$evidence_root/bash-$stamp-$token"
mkdir -p -- "$evidence" "$evidence/messages"
if (( ! PREFLIGHT )); then
  exec > >(tee "$evidence/flow.log") 2>&1
fi

backup=""
original_sha=""
filter_changed=0
restored=0
recovery_pending=0

say() { printf '%s\n' "$*"; }
step() {
  printf '\n\n%s\n' '=================================================================='
  printf '  STEP %s/8 | %s\n' "$1" "$2"
  printf '%s\n' '=================================================================='
}

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
press_enter() {
  if (( PAUSE )) && [[ -t 0 ]]; then
    read -r -p 'Press ENTER to continue...' _
  fi
}
remote() { incus exec "$MAIL" -- "$@"; }
postfix_filter() {
  remote postconf -P | awk -F '=' '
    $1 ~ /^[[:space:]]*smtp\/inet\/content_filter[[:space:]]*$/ {
      sub(/^[[:space:]]*/, "", $2); sub(/[[:space:]]*$/, "", $2); print $2; found=1; exit
    }
    END { if (!found) exit 3 }
  '
}
restore() {
  local now
  [[ -n "$backup" ]] || return 0
  now="$(remote sha256sum "$MASTER_CF" | awk '{print $1}')" || return 1
  if [[ "$now" != "$original_sha" ]]; then
    remote cp -p -- "$backup" "$MASTER_CF" || return 1
  fi
  remote postfix check && remote postfix reload || return 1
  [[ "$(remote sha256sum "$MASTER_CF" | awk '{print $1}')" == "$original_sha" ]] || return 1
  [[ "$(postfix_filter)" == "$EXPECTED_FILTER" ]] || return 1
  restored=1
}
cleanup() {
  local status=$1
  trap - EXIT INT TERM
  set +e
  if (( recovery_pending )) && ! remote systemctl is-active --quiet spamassassin; then
    printf '[CLEANUP] Attempting manual SpamAssassin recovery after an incomplete test.\n' >&2
    remote systemctl start spamassassin >"$evidence/recovery-manual-cleanup.log" 2>&1
    printf '[UNVERIFIED] Manual cleanup is not evidence of Wazuh recovery.\n' >&2
    status=1
  fi
  if [[ -n "$backup" ]]; then
    if restore; then
      printf '\n[CLEANUP] Original Postfix filter confirmed.\n'
      remote rm -f -- "$backup"
    else
      printf '\n[CRITICAL] Could not verify Postfix restoration. Backup retained: %s\n' "$backup" >&2
      status=1
    fi
  fi
  if (( ! PREFLIGHT )); then
    printf '[RESULTS AND EVIDENCE] %s\n' "$evidence"
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Use Python to construct and submit a correctly formatted RFC 5322 message.
# Bash controls the demonstration sequence and verification.
send_message() {
  local kind=$1 mid=$2 flag=${3:-}
  incus exec smtp-client -- python3 -c '
import sys,smtplib
from datetime import datetime,timezone
from email.message import EmailMessage
from email.utils import format_datetime
kind,mid,flag = sys.argv[1:]
gtube="XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
msg=EmailMessage()
msg["From"]="validation@mail.lab.test"
msg["To"]="security-operations@mail.lab.test"
msg["Subject"]="SSLE DEMO | "+kind
msg["Message-ID"]=mid
msg["Date"]=format_datetime(datetime.now(timezone.utc))
if flag: msg["X-Spam-Flag"]=flag
msg.set_content("Temperature analysis completed normally." if kind=="legitimate" else gtube)
with smtplib.SMTP("10.171.72.142",25,timeout=8) as smtp:
    refused=smtp.send_message(msg)
    if refused:
        raise RuntimeError(f"Recipients refused: {refused}")
' "$kind" "$mid" "$flag"
  local display_kind="$kind"
  case "$kind" in
    legitimate) display_kind='legitimate message' ;;
    gtube-without-filter) display_kind='GTUBE without filtering' ;;
    gtube-protected) display_kind='GTUBE with filtering' ;;
    gtube-forged-clean) display_kind='GTUBE with a forged clean header' ;;
    gtube-repeated) display_kind='repeated GTUBE sample' ;;
    gtube-recovery) display_kind='GTUBE after Wazuh service recovery' ;;
  esac
  say "[SMTP] Accepted by the server: $display_kind | Message-ID: $mid"
}

mailbox_search() {
  local folder=$1 mid=$2
  remote doveadm search -u "$USER_MAIL" mailbox "$folder" header Message-ID "$mid"
}
observe() { remote python3 "$GATEWAY" observe >/dev/null; }
await_quarantine() {
  python3 "$script_dir/record-smtp-containment.py" "$evidence/smtp-containment" "$token" \
    --source-ip "$smtp_client_ip" --acknowledge "$1" \
    || fail 'Wazuh quarantine acknowledgement is missing; no further test message was sent'
}

# Dovecot is the primary evidence source for messages stored in a mailbox.
# In addition to searching for the Message-ID, retain the doveadm fetch text output
# and verify the GTUBE signature or legitimate body in the stored message.
prove_stored_message() {
  local mid=$1 expected=$2 kind=$3 actual=$4 other=$5 event=$6
  local key raw_file uid_file opposite_file event_file
  key="$(printf '%s' "$mid" | sha256sum | awk '{print substr($1,1,16)}')"
  raw_file="$evidence/messages/${key}-doveadm-fetch.txt"
  uid_file="$evidence/messages/${key}-uids-${expected}.txt"
  opposite_file="$evidence/messages/${key}-uids-OTHER.txt"
  event_file="$evidence/messages/${key}-audit.json"

  printf '%s\n' "$actual" > "$uid_file"
  printf '%s\n' "$other" > "$opposite_file"
  printf '%s\n' "$event" > "$event_file"
  remote doveadm fetch -u "$USER_MAIL" text mailbox "$expected" header Message-ID "$mid" > "$raw_file"
  # Verify the content returned by Dovecot independently of the sender.
  python3 - "$raw_file" "$mid" "$kind" "$expected" "$event_file" <<'PYMAIL'
from pathlib import Path
import json, sys, re
raw_path, mid, kind, folder, event_path = sys.argv[1:]
raw = Path(raw_path).read_text(encoding='utf-8', errors='replace')
event = json.loads(Path(event_path).read_text())
GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
if mid not in raw:
    sys.exit(f'[FAIL] doveadm fetch did not return the expected Message-ID: {mid}')
if kind == 'gtube' and GTUBE not in raw:
    sys.exit('[FAIL] The stored email does not contain the GTUBE signature')
if kind == 'legitimate' and 'temperature' not in raw.lower():
    sys.exit('[FAIL] Legitimate body not found in the stored message')
if kind == 'notification' and ('[Security Operations]' not in raw or 'Dear Security Operations Team' not in raw):
    sys.exit('[FAIL] The stored notification does not contain the expected operational text')
if event.get('message_id') != mid or event.get('folder') != folder:
    sys.exit('[FAIL] Audit event conflicts with the Dovecot folder or Message-ID')
print(f'  [DOVECOT] Message-ID identified in the stored content: {mid}')
for line in raw.splitlines():
    if re.match(r'(?i)^\s*(?:text:\s*)?(Subject|Message-ID|X-Spam-Flag|X-Spam-Status):', line):
        print('  [STORED HEADER] ' + line.strip()[:220])
if kind == 'gtube':
    print('  [STORED BODY] GTUBE signature present in the stored email')
elif kind == 'legitimate':
    print('  [STORED BODY] Legitimate content confirmed')
else:
    print('  [STORED BODY] Security notification confirmed')
print('  [AUDIT JSON] outcome={}, folder={}, spam_status={}'.format(
    event.get('outcome'), event.get('folder'), event.get('spam_status')))
PYMAIL
  printf '%s\t%s\t%s\t%s\n' "$mid" "$expected" "$key" "$kind" >> "$evidence/messages/index.tsv"
  say "  [EVIDENCE FILES] messages/${key}-doveadm-fetch.txt | ${key}-uids-${expected}.txt | ${key}-audit.json"
}

# Require two independent evidence sources:
# 1) Dovecot: exactly one message in the expected folder and none in the other;
# 2) Observer ledger: matching Message-ID, outcome and folder.
verify_folder() {
  local mid=$1 expected=$2 max=${3:-60} kind=${4:-gtube}
  local other outcome actual wrong event i
  if [[ "$expected" == INBOX ]]; then
    other=Quarantine; outcome=delivered
  else
    other=INBOX; outcome=quarantined
  fi
  for ((i=0; i<max/2; i++)); do
    observe
    actual="$(mailbox_search "$expected" "$mid")"
    wrong="$(mailbox_search "$other" "$mid")"
    [[ -z "$wrong" ]] || fail "$mid was found in $other; expected $expected"
    event="$(remote tail -n 2000 "$EVENTS" | json_select event "$mid" "$outcome")"
    if [[ -n "$actual" && -n "$event" ]]; then
      [[ "$(printf '%s\n' "$actual" | wc -l)" -eq 1 ]] || fail "Duplicate messages in $expected for $mid"
      say "  [DOVECOT] Folder $expected | UID/GUID identifier: $actual"
      say "  [DOVECOT] Folder $other | not found (0 messages)"
      printf '%s\n' "$event" >> "$evidence/delivery-events.jsonl"
      prove_stored_message "$mid" "$expected" "$kind" "$actual" "$wrong" "$event"
      say "  [CORROBORATING EVIDENCE] Dovecot + Maildir observer: $expected (1 copy)"
      return 0
    fi
    sleep 2
  done
  fail "$mid did not appear in $expected within $max seconds"
}

# Use Python 3 JSON/JSONL selectors without a jq dependency.
# Read standard input and print only the requested fields.
json_select() {
  python3 -c '
import json, sys

mode, *args = sys.argv[1:]

def json_lines():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue

def output(row):
    print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))

if mode == "event":
    message_id, outcome = args
    matches = [r for r in json_lines() if r.get("message_id") == message_id and r.get("outcome") == outcome]
    if matches:
        output(matches[-1])
elif mode == "spam_status":
    print(json.load(sys.stdin).get("spam_status") or "unclassified")
elif mode == "alert_exists":
    name = args[0]
    rows = json.load(sys.stdin).get("data", {}).get("alerts", [])
    sys.exit(0 if any(a.get("labels", {}).get("alertname") == name for a in rows) else 1)
elif mode == "target_up":
    rows = json.load(sys.stdin).get("data", {}).get("activeTargets", [])
    sys.exit(0 if any(t.get("labels", {}).get("job") == "mail-security" and t.get("health") == "up" for t in rows) else 1)
elif mode == "alert":
    name = args[0]
    rows = json.load(sys.stdin).get("data", {}).get("alerts", [])
    for row in rows:
        if row.get("labels", {}).get("alertname") == name:
            output(row)
            break
elif mode == "state":
    print(json.load(sys.stdin).get("state", ""))
elif mode == "notification":
    episode = args[0]
    matches = [r for r in json_lines() if r.get("outcome") == "notification_submitted"
               and r.get("alert_title") == "Mail quarantine activity"
               and r.get("episode") == episode]
    if matches:
        print(matches[-1].get("message_id", ""))
elif mode == "wazuh":
    agent, *message_ids = args
    wanted = set(message_ids)
    for row in json_lines():
        if row.get("agent", {}).get("name") == agent and row.get("data", {}).get("message_id") in wanted:
            output(row)
elif mode == "rule_ids":
    for rid in sorted({str(r.get("rule", {}).get("id", "")) for r in json_lines()}):
        if rid:
            print(rid)
elif mode == "wazuh_summary":
    wanted = {"100601", "100607", "100620", "100602", "100605"}
    for row in json_lines():
        rid = str(row.get("rule", {}).get("id", ""))
        if rid in wanted:
            print("[WAZUH] rule {} | alert {} | Message-ID {} | outcome {} | agent {}".format(
                rid, row.get("id", ""), row.get("data", {}).get("message_id", ""),
                row.get("data", {}).get("outcome", ""), row.get("agent", {}).get("name", "")))
elif mode == "notification_count":
    episode = args[0]
    rows = [r for r in json_lines() if r.get("outcome") == "notification_submitted" and r.get("episode") == episode]
    print(len(rows))
elif mode == "submitted":
    print(json.load(sys.stdin).get("submitted", ""))
elif mode == "wazuh_pairs":
    mid_off, mid_good, mid_spam1, mid_spam2, mid_spam3, notification = args
    seen = {(str(row.get("rule", {}).get("id", "")), row.get("data", {}).get("message_id"))
            for row in json_lines()}
    seen |= {("100601", mid) for rid,mid in list(seen) if rid in {"100607","100620"}}
    required = {( "100602", mid_off), ("100602", mid_good),
                ("100601", mid_spam1), ("100601", mid_spam2),
                ("100601", mid_spam3), ("100602", notification),
                ("100605", notification)}
    sys.exit(0 if required.issubset(seen) else 1)
elif mode == "only_rule":
    wanted=args[0]
    matches=[r for r in json_lines() if str(r.get("rule",{}).get("id", ""))==wanted]
    if matches:
        output(matches[-1])
elif mode == "digest":
    message_id = args[0]
    matches = [r for r in json_lines() if r.get("message_id") == message_id and r.get("digest")]
    if matches:
        print(matches[-1]["digest"])
elif mode == "recovery_pair":
    started=float(args[0])
    rows=list(json_lines())
    outages={r.get("observation_id"):r for r in rows
             if r.get("integration")=="mail_service_recovery" and r.get("service")=="spamassassin"
             and r.get("outcome")=="unavailable" and float(r.get("observed_at",0))>=started}
    for row in reversed(rows):
        observation=row.get("observation_id")
        if (row.get("integration")=="mail_service_recovery" and row.get("service")=="spamassassin"
                and row.get("outcome")=="recovered" and row.get("state")=="active"
                and row.get("scanner_ready") is True and row.get("trigger_event_id")
                and observation in outages):
            output({"unavailable":outages[observation],"recovered":row})
            break
elif mode == "recovery_wazuh":
    agent,observation,trigger=args
    rows=[r for r in json_lines() if r.get("agent",{}).get("name")==agent
          and r.get("data",{}).get("observation_id")==observation]
    detected=[r for r in rows if str(r.get("rule",{}).get("id"))=="100610" and r.get("id")==trigger]
    recovered=[r for r in rows if str(r.get("rule",{}).get("id"))=="100611"
               and r.get("data",{}).get("trigger_event_id")==trigger]
    if not detected or not recovered:
        sys.exit(1)
    output(detected[-1]); output(recovered[-1])
elif mode == "message_rules":
    agent,*pairs=args
    required=set(zip(pairs[::2],pairs[1::2]))
    rows=[r for r in json_lines() if r.get("agent",{}).get("name")==agent]
    seen={(r.get("data",{}).get("message_id"),str(r.get("rule",{}).get("id"))) for r in rows}
    if not required.issubset(seen):
        sys.exit(1)
    for row in rows:
        if (row.get("data",{}).get("message_id"),str(row.get("rule",{}).get("id"))) in required:
            output(row)
else:
    sys.exit("Unknown JSON selector: " + mode)
' "$@"
}

# Query the Prometheus API from inside prometheus-container.
prom() { incus exec "$PROM" -- curl -fsS --max-time 5 "http://127.0.0.1:9090$1"; }
check_alert_clear() {
  local response i
  for ((i=0; i<72; i++)); do
    response="$(prom /api/v1/alerts)"
    if ! printf '%s' "$response" | json_select alert_exists "$ALERT"; then
      return 0
    fi
    if ((i % 5 == 0)); then say "Waiting for the previous $ALERT episode to end..."; fi
    sleep 5
  done
  fail "An $ALERT alert already exists; wait for it to clear before repeating the demo"
}

say 'SCENARIO 03: SPAM AND QUARANTINE | before/after filtering'
say 'Lab: mail-container | security-operations@mail.lab.test'
say 'Spam filtering will be disabled AUTOMATICALLY in step 1.'
step 0 'Verify services, configuration and the Prometheus baseline'
for svc in postfix dovecot spamassassin mail_gateway wazuh-agent; do
  state="$(remote systemctl is-active "$svc")" || fail "$svc is not active"
  [[ "$state" == active ]] || fail "$svc is not active: $state"
  say "  [SYSTEMD] $svc: $state"
done
[[ "$(remote postconf -h inet_interfaces)" == '127.0.0.1, 10.171.72.142' ]] || fail 'Install the dedicated SMTP client and restricted lab listener first'
smtp_client_ip="$(incus exec smtp-client -- python3 -c 'import socket; s=socket.create_connection(("10.171.72.142",25),timeout=3); address=s.getsockname()[0]; assert s.recv(512).startswith(b"220"); print(address); s.close()')" || fail 'The dedicated SMTP client is not ready'
printf '%s\n' "$smtp_client_ip" > "$evidence/smtp-client-address.txt"
say "  [SMTP CLIENT] Observed connection source: $smtp_client_ip"
remote test -x /usr/sbin/iptables || fail 'Native firewall-drop requires iptables'
remote test -x /var/ossec/active-response/bin/firewall-drop || fail 'Native firewall-drop is missing' 
[[ "$(remote postconf -h myhostname)" == "$DOMAIN" ]] || fail "Postfix is not configured for $DOMAIN"
value="$(postfix_filter)" || fail 'Cannot find smtp/inet/content_filter in master.cf'
[[ "$value" == "$EXPECTED_FILTER" ]] || fail "Unexpected filter ($value). No changes made."
say "  [POSTCONF] smtp/inet/content_filter = $value"
remote postconf -P smtp/inet/content_filter > "$evidence/postconf-original.txt"
remote sha256sum "$MASTER_CF" > "$evidence/mastercf-sha256-before.txt"
remote test -x /var/ossec/active-response/bin/mail-service-recovery.py \
  || fail 'Install Wazuh mail recovery first: bash scripts/scenarios/03-spam/install-mail-recovery.sh'
remote systemctl is-active --quiet mail-service-health.timer \
  || fail 'The SpamAssassin observation timer is not active'
remote python3 "$RECOVERY" --status > "$evidence/recovery-preflight.json"
python3 - "$evidence/recovery-preflight.json" <<'PYRECOVERY_READY'
import json,sys
status=json.load(open(sys.argv[1]))
assert status['state']=='active' and status['scanner_ready'], 'SpamAssassin did not pass its local scan check'
print('  [RECOVERY] Service observation timer and local scanner are ready.')
PYRECOVERY_READY
incus exec "$WAZUH" -- python3 -c '
from pathlib import Path
import xml.etree.ElementTree as ET
config=ET.fromstring("<root>"+Path("/var/ossec/etc/ossec.conf").read_text()+"</root>")
responses=[r for r in config.findall(".//active-response") if r.findtext("command")=="mail-service-recovery"]
assert len(responses)==1 and responses[0].findtext("disabled")=="no" and responses[0].findtext("location")=="local" and responses[0].findtext("rules_id")=="100610", "Wazuh recovery response is missing or unexpected"
commands=[r for r in config.findall(".//command") if r.findtext("name")=="mail-service-recovery"]
assert len(commands)==1 and commands[0].findtext("executable")=="mail-service-recovery.py" and commands[0].findtext("timeout_allowed")=="no", "Wazuh recovery command is missing or unexpected"
print("  [RECOVERY] Wazuh rule 100610 is configured for the local recovery command.")
'
if (( PREFLIGHT )); then
  say '[OK] Preflight completed. All protection remained enabled.'
  exit 0
fi
check_alert_clear
prom /api/v1/targets | json_select target_up \
  || fail 'The mail-security exporter is not UP in Prometheus'
backup="$(remote mktemp /tmp/ssle-postfix.XXXXXXXX)"
remote cp -p -- "$MASTER_CF" "$backup"
original_sha="$(remote sha256sum "$MASTER_CF" | awk '{print $1}')"
press_enter

step 1 'WITHOUT SPAM FILTERING: temporarily disable the SMTP filter'
filter_changed=1
remote postconf -P 'smtp/inet/content_filter='
remote postfix check
remote postfix reload
[[ -z "$(postfix_filter)" ]] || fail 'content_filter is still active'
remote postconf -P smtp/inet/content_filter | tee "$evidence/postconf-without-filter.txt"
say '  [EVIDENCE] content_filter is empty; Postfix and Dovecot remain active.'
press_enter

step 2 'Send GTUBE without filtering and verify actual INBOX delivery'
mid_off="<ssle-$token-without-filter@mail.lab.test>"
send_message gtube-without-filter "$mid_off"
verify_folder "$mid_off" INBOX 60 gtube
say '[EVIDENCE] GTUBE reached INBOX while filtering was disabled.'
press_enter

step 3 'Re-enable spam filtering and verify the original Postfix configuration'
restore || fail 'Could not re-enable the filter'
say "  [EVIDENCE] Filter restored: $(postfix_filter)"
remote postconf -P smtp/inet/content_filter | tee "$evidence/postconf-with-filter.txt"
say '  Waiting for Prometheus to collect the counter history (35 s)...'
sleep 35
press_enter

step 4 'Resend GTUBE with filtering enabled; compare folders'
mid_good="<ssle-$token-legitimate@mail.lab.test>"
mid_spam1="<ssle-$token-spam1@mail.lab.test>"
mid_spam2="<ssle-$token-spam2@mail.lab.test>"
mid_spam3="<ssle-$token-spam3@mail.lab.test>"
send_message legitimate "$mid_good"
verify_folder "$mid_good" INBOX 60 legitimate
send_message gtube-protected "$mid_spam1"
verify_folder "$mid_spam1" Quarantine
await_quarantine "$mid_spam1"
send_message gtube-forged-clean "$mid_spam2" NO
verify_folder "$mid_spam2" Quarantine
await_quarantine "$mid_spam2"
send_message gtube-repeated "$mid_spam3"
verify_folder "$mid_spam3" Quarantine
await_quarantine "$mid_spam3"
say '  [COMPARISON] GTUBE without filtering -> INBOX | GTUBE with filtering -> Quarantine'
say '  [CONTAINMENT] Verify rule 100620 and native firewall-drop (configured timeout: 20 seconds).'
python3 "$script_dir/record-smtp-containment.py" "$evidence/smtp-containment" "$token" --source-ip "$smtp_client_ip" \
  || fail 'Automatic firewall containment or recovery was not verified'
mid_after_block="<ssle-$token-after-firewall@mail.lab.test>"
send_message legitimate "$mid_after_block"
verify_folder "$mid_after_block" INBOX 60 legitimate
say '  [EVIDENCE] A legitimate message reached INBOX after automatic firewall recovery.'
press_enter

step 5 'Wait for the actual MailQuarantineActivity alert in Prometheus'
alert_json=""
previous_state=""
for ((i=0; i<90; i++)); do
  alert_json="$(prom /api/v1/alerts | json_select alert "$ALERT")"
  if [[ -n "$alert_json" ]]; then
    state="$(printf '%s' "$alert_json" | json_select state)"
    if [[ "$state" != "$previous_state" ]]; then
      say "  $ALERT: $state"
      previous_state=$state
    fi
    [[ "$state" != firing ]] || break
  fi
  sleep 3
done
[[ -n "$alert_json" && "$(printf '%s' "$alert_json" | json_select state)" == firing ]] \
  || fail "Alert $ALERT did not reach FIRING state"
printf '%s\n' "$alert_json" > "$evidence/prometheus-firing.json"
python3 - "$evidence/prometheus-firing.json" <<'PYPROM'
import json,sys
row=json.load(open(sys.argv[1]))
print('[PROMETHEUS API] alertname =', row['labels'].get('alertname'))
print('[PROMETHEUS API] state =', row['state'])
print('[PROMETHEUS API] activeAt =', row.get('activeAt'))
print('[PROMETHEUS API] labels =', json.dumps(row['labels'],sort_keys=True))
PYPROM
say "[EVIDENCE] Alert $ALERT confirmed FIRING by the API; full JSON saved."
press_enter

step 6 'Alertmanager, operational notification and Wazuh'
# The episode identifier must match the gateway calculation exactly.
episode="$(printf '%s' "$alert_json" | python3 -c '
import hashlib,json,sys
row=json.load(sys.stdin)
print(hashlib.sha256(json.dumps([row["labels"],row["activeAt"]],sort_keys=True).encode()).hexdigest())
')"
notification=""
for ((i=0; i<75; i++)); do
  notification="$(remote tail -n 3000 "$EVENTS" | json_select notification "$episode")"
  [[ -z "$notification" ]] || break
  sleep 2
done
[[ -n "$notification" ]] || fail 'No notification for this episode was found in Alertmanager/Mail gateway'
say "[MAIL GATEWAY] notification_submitted event for episode: $episode"
say "[MAIL GATEWAY] Notification Message-ID: $notification"
remote tail -n 3000 "$EVENTS" | json_select event "$notification" notification_submitted > "$evidence/notification-submitted-event.json"
# The event above originates in mail_gateway; doveadm fetch proves message receipt.

verify_folder "$notification" INBOX 90 notification
remote doveadm fetch -u "$USER_MAIL" text mailbox INBOX header Message-ID "$notification" \
  > "$evidence/notification.txt"
grep -qF '[Security Operations]' "$evidence/notification.txt" \
  || fail 'The operational email was delivered without the expected content'
say '[EVIDENCE] Notification received: Dovecot UID/GUID + email text + delivery event.'

# Verify webhook access control and duplicate prevention
# using the actual episode detected during this demonstration.
say '[WEBHOOK] Test authentication and duplicate notification suppression'
unauth_status="$(remote curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
  -X POST http://127.0.0.1:9096/alerts)"
printf '%s\n' "$unauth_status" > "$evidence/webhook-without-auth-http-status.txt"
[[ "$unauth_status" == 401 ]] || fail "Unauthenticated webhook returned HTTP $unauth_status (expected 401)"
say "  [EVIDENCE] POST without credentials -> HTTP $unauth_status"

before_notifications="$(remote tail -n 3000 "$EVENTS" | json_select notification_count "$episode")"
[[ "$before_notifications" -eq 1 ]] || fail "Expected one submission for this episode, found $before_notifications"
replay_result="$(remote python3 -c '
import json,sys,urllib.request
from pathlib import Path
row=json.loads(sys.argv[1])
replay={"status":"firing","alerts":[{"status":"firing","labels":row["labels"],"startsAt":row["activeAt"]}]}
request=urllib.request.Request("http://127.0.0.1:9096/alerts",
  data=json.dumps(replay).encode(),
  headers={"Authorization":"Bearer "+Path("/etc/mail-security/webhook-secret").read_text().strip(),
           "Content-Type":"application/json"})
with urllib.request.urlopen(request, timeout=10) as response:
    print(response.read().decode())
' "$alert_json")"
printf '%s\n' "$replay_result" > "$evidence/webhook-replayed.json"
[[ "$(printf '%s' "$replay_result" | json_select submitted)" == 0 ]] \
  || fail 'Replaying the same alert caused a new SMTP submission'
after_notifications="$(remote tail -n 3000 "$EVENTS" | json_select notification_count "$episode")"
[[ "$after_notifications" -eq 1 ]] \
  || fail "Additional notifications were recorded for the episode (total=$after_notifications)"
say "  [EVIDENCE] Authenticated replay -> submitted=0; ledger retains $after_notifications notification."

wazuh_events=""
for ((i=0; i<60; i++)); do
  wazuh_events="$(incus exec "$WAZUH" -- tail -n 6000 /var/ossec/logs/alerts/alerts.json \
      | json_select wazuh "$MAIL" "$mid_off" "$mid_good" "$mid_spam1" "$mid_spam2" "$mid_spam3" "$notification")"
  ids="$(printf '%s\n' "$wazuh_events" | json_select rule_ids)"
  if printf '%s\n' "$wazuh_events" | json_select wazuh_pairs "$mid_off" "$mid_good" "$mid_spam1" "$mid_spam2" "$mid_spam3" "$notification"; then
    break
  fi
  sleep 2
done
if ! printf '%s\n' "$wazuh_events" | json_select wazuh_pairs "$mid_off" "$mid_good" "$mid_spam1" "$mid_spam2" "$mid_spam3" "$notification"; then
  fail 'Wazuh audit events are missing for one or more Message-IDs from this run'
fi
printf '%s\n' "$wazuh_events" > "$evidence/wazuh-events.jsonl"
printf '%s\n' "$wazuh_events" | json_select wazuh_summary
say '[EVIDENCE] Wazuh Manager: actual alerts with IDs, rules, agent and Message-IDs saved in wazuh-events.jsonl'
press_enter

step 7 'WAZUH RECOVERY: stop SpamAssassin and verify automatic recovery'
say '  The SMTP filter stays configured and the Wazuh agent remains active.'
say '  The observer records the outage; only the Wazuh Active Response starts the service.'
for ((i=0; i<35; i++)); do
  status_json="$(remote python3 "$RECOVERY" --status)"
  retry_after="$(printf '%s' "$status_json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["retry_after_seconds"])')"
  (( retry_after > 0 )) || break
  say "  [COOLDOWN] Waiting for the previous recovery attempt ($retry_after seconds remaining)."
  sleep 2
done
(( retry_after == 0 )) || fail 'Recovery cooldown did not clear; no fault was introduced'
recovery_pending=1
remote python3 -c '
import json,subprocess,time
started=time.time()
subprocess.run(["systemctl","stop","spamassassin"],check=True,timeout=30)
state=subprocess.check_output(["systemctl","show","spamassassin","--property=ActiveState","--value"],text=True).strip()
agent=subprocess.check_output(["systemctl","is-active","wazuh-agent"],text=True).strip()
print(json.dumps({"started_at":started,"service_state":state,"wazuh_agent":agent}))
' > "$evidence/recovery-service-stopped.json"
recovery_started="$(python3 - "$evidence/recovery-service-stopped.json" <<'PYRECOVERY_STOP'
import json,sys
row=json.load(open(sys.argv[1]))
assert row['service_state'] in ('inactive','failed'), 'Stopped service state was not observed'
assert row['wazuh_agent']=='active', 'Wazuh must stay active during the fault'
print(row['started_at'])
PYRECOVERY_STOP
)"
say '  [EVIDENCE] SpamAssassin stopped; Wazuh remains active. Waiting for rule 100610 -> recovery.'
recovery_pair=''
for ((i=0; i<60; i++)); do
  remote cat "$SERVICE_AUDIT" > "$evidence/recovery-service-audit.jsonl"
  recovery_pair="$(json_select recovery_pair "$recovery_started" < "$evidence/recovery-service-audit.jsonl")"
  [[ -z "$recovery_pair" ]] || break
  sleep 2
done
[[ -n "$recovery_pair" ]] || fail 'No matching automatic Wazuh recovery was observed; retain the outage evidence'
printf '%s\n' "$recovery_pair" > "$evidence/recovery-pair.json"
read -r recovery_observation recovery_trigger < <(printf '%s' "$recovery_pair" | python3 -c '
import json,sys
row=json.load(sys.stdin)["recovered"]
print(row["observation_id"],row["trigger_event_id"])
')
recovery_alerts=''
for ((i=0; i<45; i++)); do
  if recovery_alerts="$(incus exec "$WAZUH" -- tail -n 6000 /var/ossec/logs/alerts/alerts.json \
      | json_select recovery_wazuh "$MAIL" "$recovery_observation" "$recovery_trigger")"; then
    break
  fi
  sleep 2
done
[[ -n "$recovery_alerts" ]] || fail 'Recovery lacks correlated Wazuh rules 100610 and 100611'
printf '%s\n' "$recovery_alerts" > "$evidence/wazuh-recovery-events.jsonl"
printf '%s\n' "$recovery_alerts"
remote python3 "$RECOVERY" --status > "$evidence/recovery-service-after.json"
python3 - "$evidence/recovery-service-after.json" <<'PYRECOVERY_ACTIVE'
import json,sys
row=json.load(open(sys.argv[1]))
assert row['state']=='active' and row['scanner_ready'], 'Recovered scanner is not healthy'
print('  [EVIDENCE] SpamAssassin active and a local message scan succeeded after the Wazuh response.')
PYRECOVERY_ACTIVE
[[ "$(postfix_filter)" == "$EXPECTED_FILTER" ]] || fail 'The SMTP filter changed during service recovery'
remote sha256sum "$MASTER_CF" > "$evidence/mastercf-sha256-after-recovery.txt"
[[ "$(awk '{print $1}' "$evidence/mastercf-sha256-before.txt")" == \
   "$(awk '{print $1}' "$evidence/mastercf-sha256-after-recovery.txt")" ]] \
  || fail 'Postfix configuration changed during Wazuh service recovery'
mid_recovery_spam="<ssle-$token-recovery-spam@mail.lab.test>"
mid_recovery_good="<ssle-$token-recovery-good@mail.lab.test>"
send_message gtube-recovery "$mid_recovery_spam"
verify_folder "$mid_recovery_spam" Quarantine
send_message legitimate "$mid_recovery_good"
verify_folder "$mid_recovery_good" INBOX 60 legitimate
recovery_deliveries=''
for ((i=0; i<45; i++)); do
  if recovery_deliveries="$(incus exec "$WAZUH" -- tail -n 6000 /var/ossec/logs/alerts/alerts.json \
      | json_select message_rules "$MAIL" "$mid_recovery_spam" 100607 "$mid_recovery_good" 100602)"; then
    break
  fi
  sleep 2
done
[[ -n "$recovery_deliveries" ]] || fail 'Post-recovery deliveries lack Wazuh audit evidence'
printf '%s\n' "$recovery_deliveries" > "$evidence/wazuh-recovery-deliveries.jsonl"
recovery_pending=0
say '  [EVIDENCE] Wazuh restored the scanner; a new GTUBE was quarantined and legitimate mail reached INBOX.'
press_enter

step 8 'Final summary and original configuration'
if (( RELEASE )); then
  digest="$(json_select digest "$mid_spam1" < "$evidence/delivery-events.jsonl")"
  [[ -n "$digest" ]] || fail 'Quarantined message digest not found'
  say 'Operator: releasing one GTUBE test message...'
  remote python3 "$GATEWAY" release "$digest"
  remote python3 "$GATEWAY" release "$digest"
  observe
  [[ "$(mailbox_search INBOX "$mid_spam1" | wc -l)" -eq 1 ]] \
    || fail 'Release did not result in exactly one INBOX message'
  [[ -z "$(mailbox_search Quarantine "$mid_spam1")" ]] \
    || fail 'The message is still in Quarantine after release'
  say '[EVIDENCE] Release: exactly one INBOX copy and none in Quarantine.'
  # Rule 100603: release event evidence after Maildir observation.
  release_alert=''
  for ((j=0; j<60; j++)); do
    release_alert="$(incus exec "$WAZUH" -- tail -n 6000 /var/ossec/logs/alerts/alerts.json \
      | json_select wazuh "$MAIL" "$mid_spam1" | json_select only_rule 100603)"
    [[ -z "$release_alert" ]] || break
    sleep 2
  done
  [[ -n "$release_alert" ]] || fail 'Release has no evidence for Wazuh rule 100603'
  printf '%s\n' "$release_alert" > "$evidence/wazuh-release-100603.json"
  say "[WAZUH] rule 100603 confirmed for $mid_spam1"
fi
restore || fail 'Original Postfix configuration could not be verified'
say '  [OK] GTUBE without filtering -> INBOX'
say '  [OK] GTUBE with filtering -> Quarantine'
say '  [OK] Legitimate email -> INBOX'
say '  [OK] Prometheus MailQuarantineActivity -> FIRING'
say '  [OK] Operational alert -> INBOX'
say '  [OK] Unauthenticated webhook -> 401; replay -> 0 new notifications'
say '  [OK] Wazuh quarantine / delivery / notification events'
say '  [OK] Wazuh 100620 -> native firewall-drop -> automatic removal after 20 seconds'
say '  [OK] Wazuh 100610 -> automatic SpamAssassin recovery -> 100611'
say '  [OK] Post-recovery GTUBE -> Quarantine; legitimate mail -> INBOX'
remote postconf -P smtp/inet/content_filter > "$evidence/postconf-final.txt"
remote sha256sum "$MASTER_CF" > "$evidence/mastercf-sha256-final.txt"
say "  [POSTFIX FINAL] $(cat "$evidence/postconf-final.txt")"
say "  [SHA-256 BEFORE] $(cat "$evidence/mastercf-sha256-before.txt")"
say "  [SHA-256 AFTER] $(cat "$evidence/mastercf-sha256-final.txt")"
[[ "$(awk '{print $1}' "$evidence/mastercf-sha256-before.txt")" == \
   "$(awk '{print $1}' "$evidence/mastercf-sha256-final.txt")" ]] \
  || fail 'Final master.cf hash differs from the original'
say '  [OK] Postfix configuration restored with an identical SHA-256 hash' 
say "[RESULTS AND EVIDENCE] $evidence"
say '  smtp-containment/                - native firewall rules, failed SMTP and recovery'
say '  flow.log                         - complete run stdout'
say '  messages/index.tsv              - Message-ID -> folder -> doveadm evidence'
say '  messages/*-doveadm-fetch.txt     - actual content read from Maildir'
say '  messages/*-uids-*                - expected/opposite Dovecot folder searches'
say '  messages/*-audit.json            - actual observer event'
say '  prometheus-firing.json           - FIRING alert from the API'
say '  notification.txt                 - actual operational email'
say '  wazuh-events.jsonl              - actual manager alerts'
say '  webhook-without-auth-http-status.txt - HTTP 401 evidence'
say '  webhook-replayed.json           - replay with submitted=0'
say '  mastercf-sha256-{before,final}.txt - Postfix integrity'
say '  recovery-service-stopped.json    - observed outage with the Wazuh agent active'
say '  recovery-pair.json               - matched outage and successful response'
say '  wazuh-recovery-events.jsonl      - correlated Wazuh 100610 / 100611 records'
say '  recovery-service-after.json      - service state and local scan verification'
say '  wazuh-recovery-deliveries.jsonl  - actual post-recovery message audit'
# Build the chart from actual Dovecot searches recorded in the index.
python3 - "$evidence/messages/index.tsv" <<'PY_MAIL_CHART'
from collections import Counter
from pathlib import Path
import sys
p=Path(sys.argv[1]); counts=Counter()
for line in p.read_text().splitlines():
    parts=line.split('\t')
    if len(parts)!=4: continue
    _,folder,_,kind=parts
    if kind=='gtube':
        counts['GTUBE -> '+folder]+=1
    elif kind=='legitimate':
        counts['Legitimate -> '+folder]+=1
    elif kind=='notification':
        counts['Notification -> '+folder]+=1
print('\n  EMAIL DISTRIBUTION (evidence: Dovecot searches by Message-ID)')
for label in ['GTUBE -> INBOX','GTUBE -> Quarantine','Legitimate -> INBOX','Notification -> INBOX']:
    n=counts[label]
    print(f'    {label:<23s}|{"█"*n}{"░"*(5-n)}| {n}')
print('  Note: shows verified deliveries before any optional release.')
PY_MAIL_CHART
say '[DONE] Demonstration completed with corroborating evidence.' 
