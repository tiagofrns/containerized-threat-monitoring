#!/usr/bin/env bash
# Incremental installation on the lab VM; preserves mailboxes and webhook secrets.
set -Eeuo pipefail
cd "$(dirname "$0")/../../.."
for command in incus python3 flock; do command -v "$command" >/dev/null; done
exec 9>"/tmp/mail-security-flow-$(id -u).lock"
flock -n 9 || { echo '[ERROR] A mail demonstration or recovery installation is running.' >&2; exit 1; }
for host in mail-container wazuh-container; do
  incus exec "$host" -- mkdir -p /root/mail-recovery-install </dev/null
done
for file in security/mail_service_recovery.py monitoring/mail-service-health.service monitoring/mail-service-health.timer; do
  incus file push "$file" "mail-container/root/mail-recovery-install/$(basename "$file")" >/dev/null
done
for file in security/wazuh-mail-rules.xml security/wazuh-mail-recovery-config.xml; do
  incus file push "$file" "wazuh-container/root/mail-recovery-install/$(basename "$file")" >/dev/null
done

incus exec mail-container -- bash -s <<'MAIL'
set -Eeuo pipefail
systemctl is-active --quiet spamassassin wazuh-agent
test "$(hostname -s)" = mail-container
test -x /usr/bin/spamc
test -x /var/ossec/bin/wazuh-execd
backup=$(mktemp -d /root/mail-recovery-before.XXXXXXXX)
cp -p /var/ossec/etc/ossec.conf "$backup/ossec.conf"
install -d -m 700 /var/lib/mail-security/recovery
install -d -m 750 /var/log/mail-security
touch /var/log/mail-security/service-health.jsonl
chown root:root /var/log/mail-security/service-health.jsonl
chmod 640 /var/log/mail-security/service-health.jsonl
install -m 750 -o root -g root /root/mail-recovery-install/mail_service_recovery.py /opt/mail-security/mail_service_recovery.py
install -m 750 -o root -g wazuh /root/mail-recovery-install/mail_service_recovery.py /var/ossec/active-response/bin/mail-service-recovery.py
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
path=Path('/var/ossec/etc/ossec.conf')
source=path.read_text()
tree=ET.fromstring('<root>'+source+'</root>')
for entry in tree.findall('.//active-response'):
    if entry.findtext('disabled') == 'yes':
        raise SystemExit('Endpoint Active Response is disabled; review the existing configuration')
audit='/var/log/mail-security/service-health.jsonl'
matches=[entry for entry in tree.findall('.//localfile') if entry.findtext('location')==audit]
if not matches:
    source+='\n<ossec_config><localfile><log_format>json</log_format><location>'+audit+'</location></localfile></ossec_config>\n'
elif len(matches)!=1 or matches[0].findtext('log_format')!='json':
    raise SystemExit('Conflicting service health log collection configuration')
path.write_text(source)
PY
if ! /var/ossec/bin/wazuh-logcollector -t; then
  cp -p "$backup/ossec.conf" /var/ossec/etc/ossec.conf
  exit 1
fi
install -m 644 /root/mail-recovery-install/mail-service-health.service /etc/systemd/system/mail-service-health.service
install -m 644 /root/mail-recovery-install/mail-service-health.timer /etc/systemd/system/mail-service-health.timer
systemd-analyze verify /etc/systemd/system/mail-service-health.service /etc/systemd/system/mail-service-health.timer
systemctl daemon-reload
printf '[BACKUP] Endpoint configuration: %s\n' "$backup"
MAIL

incus exec wazuh-container -- python3 - <<'PY'
from pathlib import Path
import json,shutil,subprocess,tempfile,time,xml.etree.ElementTree as ET
directory=Path('/var/ossec/etc/rules')
rules=Path('/root/mail-recovery-install/wazuh-mail-rules.xml')
ids={entry.get('id') for entry in ET.fromstring(rules.read_text()).iter('rule')}
targets=[]
for path in directory.glob('*.xml'):
    tree=ET.fromstring('<root>'+path.read_text()+'</root>')
    found={entry.get('id') for entry in tree.iter('rule')}
    if '100600' in found:
        targets.append(path)
    elif ids & found:
        raise SystemExit('Mail recovery rule ID conflict in '+str(path))
if len(targets)!=1:
    raise SystemExit('Expected one installed mail rule file; install base mail security first')
target=targets[0]
installed_ids={entry.get('id') for entry in ET.fromstring('<root>'+target.read_text()+'</root>').iter('rule')}
if installed_ids-ids:
    raise SystemExit('The installed mail rule file contains additional rules; merge them before installing')
config=Path('/var/ossec/etc/ossec.conf')
original=config.read_text()
tree=ET.fromstring('<root>'+original+'</root>')
fragment=Path('/root/mail-recovery-install/wazuh-mail-recovery-config.xml').read_text()
expected=ET.fromstring(fragment)
for kind in ('command','active-response'):
    def matches(entry):
        return entry.findtext('name' if kind=='command' else 'command')=='mail-service-recovery'
    existing=[entry for entry in tree.findall('.//'+kind) if matches(entry)]
    wanted=expected.find(kind)
    if existing:
        def fields(entry): return {child.tag:(child.text or '').strip() for child in entry}
        if len(existing)!=1 or fields(existing[0])!=fields(wanted):
            raise SystemExit('Conflicting mail-service-recovery '+kind+' configuration')
    else:
        original+='\n<ossec_config>'+ET.tostring(wanted,encoding='unicode')+'</ossec_config>\n'
backup=Path(tempfile.mkdtemp(prefix='mail-recovery-before-',dir='/root'))
shutil.copy2(config,backup/'ossec.conf')
shutil.copy2(target,backup/target.name)
try:
    shutil.copy2(rules,target)
    shutil.chown(target,user='root',group='wazuh')
    target.chmod(0o640)
    config.write_text(original)
    subprocess.run(['/var/ossec/bin/wazuh-analysisd','-t'],check=True,timeout=30)
    subprocess.run(['systemctl','restart','wazuh-manager'],check=True,timeout=90)
    # Remote events carry an agent prefix during location-rule matching.
    # Testing only the bare path can pass while the live rule never matches.
    for rule,level,fields in [('100610',8,{'outcome':'unavailable','state':'inactive'}),
                              ('100611',5,{'outcome':'recovered','state':'active','scanner_ready':True,'trigger_event_id':'123.456'})]:
        fixture=dict(integration='mail_service_recovery',service='spamassassin',
                     observed_at=time.time(),observation_id='a'*32,**fields)
        result=subprocess.run(['/var/ossec/bin/wazuh-logtest','-l',
                               '(mail-container) any->/var/log/mail-security/service-health.jsonl',
                               '-U',rule+':'+str(level)+':json'],input=json.dumps(fixture)+'\n\n',
                              capture_output=True,text=True,timeout=30)
        if result.returncode:
            raise RuntimeError('Remote-location rule test failed for '+rule+': '+result.stdout[-2000:])
        print('[RULE TEST] Remote-agent event matches '+rule)
except Exception:
    shutil.copy2(backup/'ossec.conf',config)
    shutil.copy2(backup/target.name,target)
    subprocess.run(['systemctl','restart','wazuh-manager'],timeout=90)
    raise
print('[BACKUP] Manager configuration:',backup)
PY

incus exec mail-container -- bash -s <<'MAIL'
set -Eeuo pipefail
systemctl restart wazuh-agent
systemctl enable --now mail-service-health.timer
systemctl start mail-service-health.service
systemctl is-active spamassassin wazuh-agent mail-service-health.timer
python3 /opt/mail-security/mail_service_recovery.py --status
MAIL
printf '[OK] Mail service recovery installed. Run the mail flow to verify rule 100610 -> 100611.\n'
