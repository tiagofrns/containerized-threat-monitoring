#!/usr/bin/env bash
# Extend the existing lab with one SMTP client and bounded Wazuh containment.
set -Eeuo pipefail
cd "$(dirname "$0")/../../.."
lab_network="$(incus network get incusbr0 ipv4.address | python3 -c 'import ipaddress,sys;print(ipaddress.ip_network(sys.stdin.read().strip(),strict=False))')"
bash scripts/scenarios/03-spam/install-mail-recovery.sh
exec 9>"/tmp/mail-security-flow-$(id -u).lock"
flock -n 9 || { echo '[ERROR] Another mail operation is running.' >&2; exit 1; }
if ! incus info smtp-client >/dev/null 2>&1; then
  # Reuse the local Ubuntu image; no image is downloaded implicitly.
  image=$(incus image list --format=json | python3 -c 'import json,sys; print(next(x["fingerprint"] for x in json.load(sys.stdin) if x["properties"].get("release")=="jammy"))')
  incus init "$image" smtp-client -c limits.memory=256MiB -c boot.autostart=true
  incus config device override smtp-client eth0 ipv4.address=10.171.72.60 security.ipv4_filtering=true
fi
if ! incus info smtp-client | grep -q 'Status: RUNNING'; then incus start smtp-client; fi
incus exec smtp-client -- ip -4 addr show dev eth0 | grep -q 'inet 10.171.72.60/24' || { echo '[ERROR] SMTP client has an unexpected address.' >&2; exit 1; }
incus exec smtp-client -- bash -s <<'CLIENT'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! command -v python3 >/dev/null; then apt-get update -qq; apt-get install -y --no-install-recommends python3-minimal; fi
CLIENT
for host in mail-container wazuh-container; do incus exec "$host" -- mkdir -p /root/mail-smtp-install; done
for file in monitoring/mail_origin.py monitoring/mail_gateway.py monitoring/mail_gateway.service security/mail_filter.py; do
  incus file push "$file" "mail-container/root/mail-smtp-install/$(basename "$file")" >/dev/null
done
incus file push security/wazuh-mail-smtp-config.xml wazuh-container/root/mail-smtp-install/config.xml >/dev/null
incus exec mail-container -- env SMTP_LAB_NETWORK="$lab_network" bash -s <<'MAIL'
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends iptables
backup=$(mktemp -d /root/mail-smtp-before.XXXXXXXX)
cp -p /etc/postfix/main.cf /etc/postfix/master.cf /var/ossec/etc/ossec.conf "$backup/"
cp -a /opt/mail-security "$backup/"
install -d -m 750 /etc/mail-security
if ! test -f /etc/mail-security/origin-key; then head -c 32 /dev/urandom > /etc/mail-security/origin-key; fi
chown root:spamd /etc/mail-security/origin-key
chmod 640 /etc/mail-security/origin-key
# The pipe user can read only this per-purpose key, not webhook credentials.
chmod 711 /etc/mail-security
for file in mail_origin.py mail_gateway.py mail_filter.py; do install -m 644 "/root/mail-smtp-install/$file" "/opt/mail-security/$file"; done
test -x /var/ossec/active-response/bin/firewall-drop
printf '127.0.0.1/32 DUNNO\n%s DUNNO\n0.0.0.0/0 REJECT SMTP submission is restricted to the lab network\n' \
  "$SMTP_LAB_NETWORK" > /etc/postfix/lab-clients.cidr
postconf -e 'smtpd_client_restrictions = check_client_access cidr:/etc/postfix/lab-clients.cidr'
postconf -e 'inet_interfaces = 127.0.0.1, 10.171.72.142'
postconf -e 'mynetworks = 127.0.0.0/8'
postconf -e 'smtpd_relay_restrictions = reject_unauth_destination'
postconf -e 'default_transport = error:5.7.1 External delivery disabled'
postconf -M 'spamassassin/unix=spamassassin unix - n n - 5 pipe flags=Rq user=spamd argv=/usr/bin/python3 /opt/mail-security/mail_filter.py ${client_address} ${queue_id} ${sender} ${recipient}'
postfix check
install -m 644 /root/mail-smtp-install/mail_gateway.service /etc/systemd/system/mail_gateway.service
systemd-analyze verify /etc/systemd/system/mail_gateway.service
systemctl daemon-reload
systemctl restart postfix mail_gateway wazuh-agent
printf '[BACKUP] SMTP endpoint configuration: %s\n' "$backup"
MAIL
incus exec wazuh-container -- python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
import shutil,subprocess,tempfile
p=Path('/var/ossec/etc/ossec.conf');original=p.read_text();tree=ET.fromstring('<root>'+original+'</root>')
fragment=ET.parse('/root/mail-smtp-install/config.xml').getroot()
commands=[x for x in tree.findall('.//command') if x.findtext('name')=='firewall-drop']
assert len(commands)==1 and commands[0].findtext('executable')=='firewall-drop' and commands[0].findtext('timeout_allowed')=='yes','Native firewall-drop command is missing or conflicting'
wanted=fragment.find('active-response')
matches=[x for x in tree.findall('.//active-response') if x.findtext('rules_id')=='100620']
if matches:
 assert len(matches)==1 and {x.tag:x.text for x in matches[0]}=={x.tag:x.text for x in wanted},'Conflicting firewall-drop response configuration'
else:original+='\n<ossec_config>'+ET.tostring(wanted,encoding='unicode')+'</ossec_config>\n'
backup=Path(tempfile.mkdtemp(prefix='mail-smtp-before-',dir='/root'));shutil.copy2(p,backup/'ossec.conf')
try:
 p.write_text(original)
 subprocess.run(['/var/ossec/bin/wazuh-analysisd','-t'],check=True)
 subprocess.run(['systemctl','restart','wazuh-manager'],check=True,timeout=90)
except Exception:
 shutil.copy2(backup/'ossec.conf',p);raise
print('[BACKUP] SMTP manager configuration:',backup)
PY
printf '[OK] SMTP client and 20-second containment installed. Verify with the mail flow.\n'
