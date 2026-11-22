#!/bin/bash
# Run explicitly on the Debian VM. This script is not executed by source preparation.
set -euo pipefail
cd "$(dirname "$0")/../../.."
stage="${1:-}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
push() { incus file push "$1" "$2"; }
case "$stage" in
  agent)
    incus exec dns-server-container -- mkdir -p /root/dns_install
    push monitoring/dns_client.py dns-server-container/root/dns_install/dns_client.py
    push security/dns_restore.py dns-server-container/root/dns_install/dns_restore.py
    push monitoring/dns_client.service dns-server-container/root/dns_install/dns_client.service
    incus exec dns-server-container -- env DNS_INSTALL_STAMP="$stamp" bash -s <<'AGENT'
set -euo pipefail
test "$(cat /etc/dnsmasq.d/dns_sec.conf)" = 'local=/lab.test/
host-record=analytics.lab.test,10.255.255.74'
apt-get update
apt-get install -y python3
id dns_client >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin dns_client
install -d -m 755 /opt/dns_sec
install -m 644 /root/dns_install/dns_client.py /opt/dns_sec/dns_client.py
install -m 750 -o root -g wazuh /root/dns_install/dns_restore.py /var/ossec/active-response/bin/dns_restore.py
install -d -m 700 /var/lib/dns_sec
install -d -m 750 -o dns_client -g dns_client /var/log/dns_sec
if test ! -e /var/lib/dns_sec/approved.conf; then
  install -m 600 /etc/dnsmasq.d/dns_sec.conf /var/lib/dns_sec/approved.conf
fi
cmp /etc/dnsmasq.d/dns_sec.conf /var/lib/dns_sec/approved.conf
printf 'enabled\n' > /var/lib/dns_sec/auto-restore.enabled
chmod 600 /var/lib/dns_sec/auto-restore.enabled
touch /var/ossec/logs/dns_restore.jsonl
chown root:wazuh /var/ossec/logs/dns_restore.jsonl
chmod 640 /var/ossec/logs/dns_restore.jsonl
cp -a /var/ossec/etc/ossec.conf "/root/ossec.conf.before-dns-$DNS_INSTALL_STAMP"
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
p=Path('/var/ossec/etc/ossec.conf');s=p.read_text()
tree=ET.fromstring('<root>'+s+'</root>')
assert any(d.text and '/etc/dnsmasq.d' in d.text and d.get('realtime')=='yes'
           for d in tree.findall('.//syscheck/directories')), 'Configure realtime DNS FIM first'
for name in ('/var/ossec/logs/dns_restore.jsonl','/var/log/dns_sec/client.jsonl'):
 if name not in s:
  s+='\n<ossec_config>\n  <localfile>\n    <log_format>json</log_format>\n    <location>'+name+'</location>\n  </localfile>\n</ossec_config>\n'
p.write_text(s)
PY
/var/ossec/bin/wazuh-logcollector -t
/var/ossec/bin/wazuh-syscheckd -t
install -m 644 /root/dns_install/dns_client.service /etc/systemd/system/dns_client.service
systemctl daemon-reload
systemctl enable --now dns_client
systemctl restart wazuh-agent
systemctl is-active dnsmasq wazuh-agent dns_client
python3 /opt/dns_sec/dns_client.py --once
AGENT
    ;;
  manager)
    incus exec wazuh-container -- mkdir -p /root/dns_install
    push security/wazuh-dns-rules.xml wazuh-container/root/dns_install/wazuh-dns-rules.xml
    push security/wazuh-dns-response-config.xml wazuh-container/root/dns_install/wazuh-dns-response-config.xml
    incus exec wazuh-container -- env DNS_INSTALL_STAMP="$stamp" python3 - <<'PY'
from pathlib import Path
import os,re,shutil,subprocess
stamp=os.environ['DNS_INSTALL_STAMP']
rules=Path('/var/ossec/etc/rules/dns_rules.xml')
for p in Path('/var/ossec/etc/rules').rglob('*.xml'):
 if p==rules:continue
 if re.search(r'''\bid\s*=\s*["']10014[1-5]["']''',p.read_text(errors='replace')):
  raise SystemExit('Rule ID conflict: '+str(p))
config = Path('/var/ossec/etc/ossec.conf')
settings = config.read_text()
fragment = Path('/root/dns_install/wazuh-dns-response-config.xml').read_text().strip()
legacy = fragment.replace('<rules_id>100141,100145</rules_id>', '<rules_id>100141</rules_id>')
if '<name>dns_restore</name>' not in settings:
    settings += '\n' + fragment + '\n'
elif legacy in settings:
    settings = settings.replace(legacy, fragment, 1)
elif fragment not in settings:
    raise SystemExit('Existing DNS response differs; inspect it before replacing')

rules_backup = Path('/root') / ('dns_rules.before-' + stamp + '.xml')
config_backup = Path('/root') / ('ossec.conf.before-dns-' + stamp)
if rules.exists():
    shutil.copy2(rules, rules_backup)
shutil.copy2(config, config_backup)
restart_attempted = False
try:
    shutil.copy2('/root/dns_install/wazuh-dns-rules.xml', rules)
    shutil.chown(rules, user='root', group='wazuh')
    rules.chmod(0o640)
    config.write_text(settings)
    subprocess.run(['/var/ossec/bin/wazuh-analysisd', '-t'], check=True)
    restart_attempted = True
    subprocess.run(['systemctl', 'restart', 'wazuh-manager'], check=True)
    subprocess.run(['systemctl', 'is-active', 'wazuh-manager'], check=True)
except (OSError, subprocess.CalledProcessError):
    shutil.copy2(config_backup, config)
    if rules_backup.exists():
        shutil.copy2(rules_backup, rules)
    else:
        rules.unlink(missing_ok=True)
    if restart_attempted:
        subprocess.run(['systemctl', 'restart', 'wazuh-manager'], check=True)
    raise
PY
    ;;
  prometheus)
    incus exec prometheus-container -- mkdir -p /root/dns_install
    push monitoring/dns_alerts.yml prometheus-container/root/dns_install/dns_alerts.yml
    incus exec prometheus-container -- env DNS_INSTALL_STAMP="$stamp" python3 - <<'PY'
from pathlib import Path
import os,shutil,subprocess,urllib.request
with urllib.request.urlopen('http://10.171.72.8:8004/metrics',timeout=5) as r:
 assert b'dns_sec_last_check_timestamp_seconds' in r.read(), 'Unexpected exporter content'
stamp=os.environ['DNS_INSTALL_STAMP'];p=Path('/etc/prometheus/prometheus.yml');s=p.read_text()
shutil.copy2(p,Path('/root')/('prometheus.yml.before-dns-'+stamp))
shutil.copy2('/root/dns_install/dns_alerts.yml','/etc/prometheus/dns_alerts.yml')
if '/etc/prometheus/dns_alerts.yml' not in s:
 assert 'rule_files:\n' in s,'Inspect rule_files layout'
 s=s.replace('rule_files:\n','rule_files:\n  - /etc/prometheus/dns_alerts.yml\n',1)
if 'job_name: dns_client' not in s:
 s+='\n  - job_name: dns_client\n    static_configs:\n      - targets: ["10.171.72.8:8004"]\n'
staged=p.with_name('prometheus-dns-staged.yml');staged.write_text(s)
subprocess.run(['promtool','check','config',str(staged)],check=True)
shutil.copyfile(staged,p);staged.unlink()
subprocess.run(['systemctl','reload','prometheus'],check=True)
subprocess.run(['systemctl','is-active','prometheus'],check=True)
PY
    ;;
  *) printf 'Usage: bash scripts/scenarios/02-dns-hijacking/install-dns-integrity.sh {agent|manager|prometheus}\n' >&2;exit 2 ;;
esac
