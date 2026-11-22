#!/usr/bin/env bash
# On the Debian VM. Requires Alertmanager and the Wazuh agent package on prometheus-container.
set -euo pipefail
cd "$(dirname "$0")/../.."
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/root/before-alert-bridge-$stamp"
stage="/root/alert-bridge-install"
for instance in prometheus-container wazuh-container k3s-node1 k3s-master dns-server-container; do
  incus exec "$instance" -- mkdir -p "$stage" "$backup"
done
push() { incus file push "$1" "$2$stage/$3" >/dev/null; }
push monitoring/alert_receiver.py prometheus-container alert_receiver.py
push monitoring/alert_bridge.service prometheus-container alert_bridge.service
push monitoring/alertmanager.yml prometheus-container alertmanager.yml
push monitoring/bridge_alerts.yml prometheus-container bridge_alerts.yml
push security/wazuh-bridge-rules.xml wazuh-container bridge_rules.xml
push security/wazuh-bridge-response-config.xml wazuh-container bridge_response.xml
push security/dns_restore.py dns-server-container dns_restore.py
for node in k3s-master k3s-node1; do
  push security/analytics-cache.py "$node" analytics-cache.py
done

incus exec prometheus-container -- env STAGE="$stage" BACKUP="$backup" bash -s <<'MONITOR'
set -euo pipefail
cp -a /var/ossec/etc/ossec.conf /etc/default/prometheus-alertmanager /etc/prometheus/prometheus.yml "$BACKUP"
dpkg-query -W prometheus-alertmanager wazuh-agent
id alert_bridge >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin alert_bridge
install -d -m 755 /opt/alert_bridge
install -m 644 "$STAGE/alert_receiver.py" /opt/alert_bridge/alert_receiver.py
install -m 644 "$STAGE/alert_bridge.service" /etc/systemd/system/alert_bridge.service
if [[ ! -e /etc/prometheus/alert-bridge-secret ]]; then
  (umask 0077; python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > /etc/prometheus/alert-bridge-secret)
fi
chown root:prometheus /etc/prometheus/alert-bridge-secret
chmod 0640 /etc/prometheus/alert-bridge-secret
install -d -m 0750 -o root -g alert_bridge /etc/alert_bridge
install -m 0640 -o root -g alert_bridge /etc/prometheus/alert-bridge-secret /etc/alert_bridge/webhook-secret
install -m 640 -o root -g prometheus "$STAGE/alertmanager.yml" /etc/prometheus/alertmanager.yml
amtool check-config /etc/prometheus/alertmanager.yml
printf 'ARGS="--config.file=/etc/prometheus/alertmanager.yml --storage.path=/var/lib/prometheus/alertmanager --web.listen-address=127.0.0.1:9093 --cluster.listen-address="\n' > /etc/default/prometheus-alertmanager
install -d -m 0750 -o alert_bridge -g alert_bridge /var/log/alert-bridge
touch /var/log/alert-bridge/events.jsonl
chown alert_bridge:alert_bridge /var/log/alert-bridge/events.jsonl
chmod 0600 /var/log/alert-bridge/events.jsonl
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
path = Path('/var/ossec/etc/ossec.conf')
root = ET.fromstring('<conf>'+path.read_text()+'</conf>')
current = root.find('.//client')
assert current is not None and current.findtext('server/address') == '10.171.72.186'
assert current.findtext('enrollment/agent_name') == 'prometheus-container'
out = ET.Element('ossec_config')
out.append(current)
central = ET.SubElement(out, 'client_buffer')
ET.SubElement(central, 'disabled').text = 'no'
collector = ET.SubElement(out, 'localfile')
ET.SubElement(collector, 'log_format').text = 'json'
ET.SubElement(collector, 'location').text = '/var/log/alert-bridge/events.jsonl'
ET.indent(out)
path.write_text(ET.tostring(out, encoding='unicode')+'\n')
PY
/var/ossec/bin/wazuh-logcollector -t
systemctl daemon-reload
systemctl reset-failed alert_bridge || true
systemctl enable --now alert_bridge
systemctl restart alert_bridge
systemctl unmask prometheus-alertmanager
systemctl enable --now prometheus-alertmanager wazuh-agent
systemctl is-active alert_bridge prometheus-alertmanager wazuh-agent
apt-mark hold wazuh-agent
MONITOR

for (( attempts=0; attempts<20; attempts++ )); do
  agents="$(incus exec wazuh-container -- /var/ossec/bin/agent_control -l)"
  if [[ "$agents" == *"ID: 005, Name: prometheus-container, IP: any, Active"* ]]; then break; fi
  sleep 2
done
[[ "$agents" == *"ID: 005, Name: prometheus-container, IP: any, Active"* ]]
[[ "$agents" == *"ID: 002, Name: k3s-node1, IP: any, Active"* ]]
[[ "$agents" == *"ID: 004, Name: dns-server-container, IP: any, Active"* ]]

for node in k3s-master k3s-node1; do
  incus exec "$node" -- env STAGE="$stage" BACKUP="$backup" bash -s <<'NODE'
set -euo pipefail
p=/var/ossec/active-response/bin
if [[ -f "$p/ssle-analytics-cache.py" ]]; then
  name=ssle-analytics-cache.py
  sed -i 's@/var/lib/analytics-protection/@/var/lib/ssle-protection/@; s/^KEY = .*/KEY = "ssle-analytics-cache"/' "$STAGE/analytics-cache.py"
else
  name=analytics-cache.py
fi
cp -a "$p/$name" "$BACKUP/"
install -o root -g wazuh -m 750 "$STAGE/analytics-cache.py" "$p/$name"
NODE
done
incus exec dns-server-container -- env STAGE="$stage" BACKUP="$backup" bash -s <<'DNS'
set -euo pipefail
dir=/var/ossec/active-response/bin
cp -a "$dir/dns_restore.py" "$BACKUP/"
install -o root -g wazuh -m 750 "$STAGE/dns_restore.py" "$dir/dns_restore.py"
DNS

incus exec wazuh-container -- env STAGE="$stage" BACKUP="$backup" python3 - <<'PY'
import os
from pathlib import Path
import re
import shutil
import subprocess
cfg = Path('/var/ossec/etc/ossec.conf')
rules = Path('/var/ossec/etc/rules/bridge_rules.xml')
base = cfg.read_text()
assert not rules.exists() and '<rules_id>100150</rules_id>' not in base
for f in rules.parent.glob('*.xml'):
    assert not re.search(r'id=["\']10015[01]["\']', f.read_text()), f
stage, backup = (Path(os.environ[k]) for k in ('STAGE','BACKUP'))
fragment = (stage/'bridge_response.xml').read_text()
if '<name>ssle-analytics-cache</name>' in base:
    fragment = fragment.replace('<command>analytics-cache</command>', '<command>ssle-analytics-cache</command>')
shutil.copy2(cfg, backup/cfg.name)
shutil.copyfile(stage/'bridge_rules.xml', rules)
shutil.chown(rules, 'root', 'wazuh')
rules.chmod(0o640)
try:
    cfg.write_text(base+'\n'+fragment)
    subprocess.run(['/var/ossec/bin/wazuh-analysisd','-t'], check=True)
    subprocess.run(['systemctl','restart','wazuh-manager'], check=True)
except (OSError, subprocess.CalledProcessError):
    shutil.copy2(backup/cfg.name, cfg)
    rules.unlink()
    subprocess.run(['systemctl','restart','wazuh-manager'], check=True)
    raise
PY

incus exec prometheus-container -- env STAGE="$stage" BACKUP="$backup" python3 - <<'PY'
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
p = Path('/etc/prometheus/prometheus.yml')
s = p.read_text()
rule = '/etc/prometheus/bridge_alerts.yml'
assert 'alerting:' not in s and rule not in s and 'rule_files:\n' in s
shutil.copyfile(Path(os.environ['STAGE'])/'bridge_alerts.yml', rule)
s = s.replace('rule_files:\n', '''alerting:
  alertmanagers:
    - static_configs:
        - targets: ["127.0.0.1:9093"]

rule_files:
  - /etc/prometheus/bridge_alerts.yml
''', 1)
with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', dir=p.parent) as staged:
    staged.write(s)
    staged.flush()
    subprocess.run(['promtool','check','config',staged.name], check=True)
    p.write_text(s)
try:
    subprocess.run(['systemctl','reload','prometheus'], check=True)
except subprocess.CalledProcessError:
    shutil.copy2(Path(os.environ['BACKUP'])/p.name,p)
    subprocess.run(['systemctl','reload','prometheus'], check=True)
    raise
PY
printf 'Backup directory: %s\n' "$backup"
