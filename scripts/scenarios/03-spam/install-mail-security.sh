#!/usr/bin/env bash
# Run from the project on the Debian VM after the base mail installation.
set -euo pipefail
cd "$(dirname "$0")/../../.."
stage=$(mktemp -d /tmp/mail-security-install.XXXXXX)
chmod 700 "$stage"
trap 'rm -rf -- "$stage"' EXIT
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$stage/webhook-secret"
for host in mail-container prometheus-container wazuh-container; do
    incus exec "$host" -- mkdir -p /root/mail-security-install </dev/null
done
incus file push "$stage/webhook-secret" mail-container/root/mail-security-install/webhook-secret >/dev/null
incus file push "$stage/webhook-secret" prometheus-container/root/mail-security-install/webhook-secret >/dev/null
incus file push security/mail_filter.py mail-container/root/mail-security-install/mail_filter.py >/dev/null
incus file push monitoring/mail_origin.py mail-container/root/mail-security-install/mail_origin.py >/dev/null
incus file push monitoring/mail_gateway.py mail-container/root/mail-security-install/mail_gateway.py >/dev/null
incus file push monitoring/mail_gateway.service mail-container/root/mail-security-install/mail_gateway.service >/dev/null
incus file push monitoring/mail_alerts.yml prometheus-container/root/mail-security-install/mail_alerts.yml >/dev/null
incus file push security/wazuh-mail-rules.xml wazuh-container/root/mail-security-install/mail_rules.xml >/dev/null
incus exec mail-container -- bash -s <<'MAIL'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends dovecot-lmtpd dovecot-sieve curl gnupg ca-certificates
id security-operations >/dev/null 2>&1 || adduser --disabled-password --gecos 'Security Operations' --shell /usr/sbin/nologin security-operations
install -d -m 755 /opt/mail-security
install -m 644 /root/mail-security-install/mail_origin.py /opt/mail-security/mail_origin.py
install -m 755 /root/mail-security-install/mail_filter.py /opt/mail-security/mail_filter.py
install -m 644 /root/mail-security-install/mail_gateway.py /opt/mail-security/mail_gateway.py
install -d -m 700 /etc/mail-security /var/lib/mail-security
install -d -m 750 /var/log/mail-security
touch /var/log/mail-security/events.jsonl
chmod 640 /var/log/mail-security/events.jsonl
if ! test -f /etc/mail-security/origin-key; then head -c 32 /dev/urandom > /etc/mail-security/origin-key; fi
chown root:spamd /etc/mail-security/origin-key
chmod 640 /etc/mail-security/origin-key
chmod 711 /etc/mail-security
install -m 600 /root/mail-security-install/webhook-secret /etc/mail-security/webhook-secret
# Preserve the existing mailbox and original configuration before migration.
backup=$(mktemp -d /root/mail-before-security.XXXXXX)
cp -a /etc/dovecot/conf.d /etc/postfix/main.cf /etc/postfix/master.cf "$backup/"
cat > /etc/dovecot/conf.d/99-mail-security.conf <<'CONF'
listen = 127.0.0.1
mail_location = mbox:~/mail:INBOX=/var/mail/%u
mail_privileged_group = mail
auth_username_format = %Ln
protocol lmtp {
  mail_plugins = $mail_plugins sieve
  postmaster_address = postmaster@mail.lab.test
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
plugin {
  sieve_before = /etc/dovecot/security-policy.sieve
}
CONF
# A static override applies Maildir only to the new dedicated account.
printf 'security-operations:{PLAIN}disabled:%s:%s::/home/security-operations::mail=maildir:~/Maildir\n' \
  "$(id -u security-operations)" "$(id -g security-operations)" > /etc/dovecot/security-users
chown root:dovecot /etc/dovecot/security-users
chmod 640 /etc/dovecot/security-users
# Ensure this lookup precedes the distribution's passwd userdb.
if ! grep -q '^!include auth-security.conf.ext' /etc/dovecot/conf.d/10-auth.conf; then
    sed -i 's@!include auth-system.conf.ext@!include auth-security.conf.ext\n!include auth-system.conf.ext@' /etc/dovecot/conf.d/10-auth.conf
fi
cat > /etc/dovecot/conf.d/auth-security.conf.ext <<'CONF'
userdb {
  driver = passwd-file
  args = /etc/dovecot/security-users
  override_fields = mail=maildir:~/Maildir
}
CONF
cat > /etc/dovecot/security-policy.sieve <<'SIEVE'
require ["fileinto", "mailbox"];
if header :is "X-Spam-Flag" "YES" {
  fileinto :create "Quarantine";
  stop;
}
keep;
SIEVE
sievec /etc/dovecot/security-policy.sieve
install -d -m 700 -o security-operations -g security-operations /home/security-operations/Maildir
for folder in cur new tmp .Quarantine .Quarantine/cur .Quarantine/new .Quarantine/tmp; do
    install -d -m 700 -o security-operations -g security-operations "/home/security-operations/Maildir/$folder"
done
printf '\nreport_safe 0\n' > /etc/spamassassin/98-mail-delivery.cf
postconf -e 'mailbox_transport = lmtp:unix:private/dovecot-lmtp'
postconf -M 'spamassassin/unix=spamassassin unix - n n - 5 pipe flags=Rq user=spamd argv=/usr/bin/python3 /opt/mail-security/mail_filter.py ${client_address} ${queue_id} ${sender} ${recipient}'
postconf -P 'smtp/inet/content_filter=spamassassin:filter'
postfix check
doveconf -n >/dev/null
systemctl restart dovecot spamassassin postfix
install -m 644 /root/mail-security-install/mail_gateway.service /etc/systemd/system/mail_gateway.service
systemctl daemon-reload
systemctl enable mail_gateway
systemctl restart mail_gateway
if ! test -x /var/ossec/bin/wazuh-agentd; then
    curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /root/mail-security-install/wazuh-key.asc
    gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg /root/mail-security-install/wazuh-key.asc
    printf 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n' > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    WAZUH_MANAGER=10.171.72.186 WAZUH_AGENT_NAME=mail-container apt-get install -y wazuh-agent=4.14.10-1
fi
python3 - <<'PY'
from pathlib import Path
p=Path('/var/ossec/etc/ossec.conf')
s=p.read_text()
if '/var/log/mail-security/events.jsonl' not in s:
 s+='\n<ossec_config><localfile><log_format>json</log_format><location>/var/log/mail-security/events.jsonl</location></localfile></ossec_config>\n'
p.write_text(s)
PY
/var/ossec/bin/wazuh-logcollector -t
systemctl enable --now wazuh-agent
systemctl restart wazuh-agent
apt-mark hold wazuh-agent
MAIL
incus exec wazuh-container -- python3 - <<'PY'
from pathlib import Path
import re,shutil,subprocess,tempfile
source=Path('/root/mail-security-install/mail_rules.xml')
target=Path('/var/ossec/etc/rules/mail_rules.xml')
for path in target.parent.glob('*.xml'):
 if path!=target and re.search(r'id=["\x27](?:10060[0-7]|10061[0-3]|100620)["\x27]',path.read_text()):
  raise SystemExit('Mail security rule ID conflict')
backup=Path(tempfile.mkdtemp(prefix='mail-rules-',dir='/root'))
if target.exists():shutil.copy2(target,backup/'mail_rules.xml')
try:
 shutil.copy2(source,target);shutil.chown(target,user='root',group='wazuh');target.chmod(0o640)
 subprocess.run(['/var/ossec/bin/wazuh-analysisd','-t'],check=True)
 subprocess.run(['systemctl','restart','wazuh-manager'],check=True)
except Exception:
 if (backup/'mail_rules.xml').exists():shutil.copy2(backup/'mail_rules.xml',target)
 else:target.unlink(missing_ok=True)
 raise
PY
incus exec prometheus-container -- bash -s <<'MON'
set -euo pipefail
apt-get install -y python3-yaml
install -m 640 -o root -g prometheus /root/mail-security-install/webhook-secret /etc/prometheus/mail-webhook-secret
install -m 644 /root/mail-security-install/mail_alerts.yml /etc/prometheus/mail_alerts.yml
python3 - <<'PY'
from pathlib import Path
import subprocess,shutil,tempfile,yaml
backup=Path(tempfile.mkdtemp(prefix='mail-monitoring-',dir='/root'))
paths=[Path('/etc/prometheus/alertmanager.yml'),Path('/etc/prometheus/prometheus.yml')]
for path in paths:shutil.copy2(path,backup/path.name)
a=yaml.safe_load(paths[0].read_text())
route={'receiver':'security-mail','matchers':['alertname=~"AnalyticsClientImpact|DNSPolicyRejections|ServiceHealthCheckFailed|MailQuarantineActivity"'],
       'group_by':['alertname'],'group_wait':'2s','group_interval':'30s','repeat_interval':'4h','continue':True}
a['route']['routes']=[r for r in a['route'].get('routes',[]) if r.get('receiver')!='security-mail']
a['route']['routes'].insert(0,route)
a['receivers']=[r for r in a['receivers'] if r['name']!='security-mail']
a['receivers'].append({'name':'security-mail','webhook_configs':[{'url':'http://10.171.72.142:9096/alerts','send_resolved':False,
 'http_config':{'authorization':{'credentials_file':'/etc/prometheus/mail-webhook-secret'}}}]})
p=yaml.safe_load(paths[1].read_text())
if '/etc/prometheus/mail_alerts.yml' not in p['rule_files']:p['rule_files'].append('/etc/prometheus/mail_alerts.yml')
p['scrape_configs']=[j for j in p['scrape_configs'] if j['job_name']!='mail-security']
p['scrape_configs'].append({'job_name':'mail-security','static_configs':[{'targets':['10.171.72.142:9096']}]})
try:
 paths[0].write_text(yaml.safe_dump(a,sort_keys=False));paths[1].write_text(yaml.safe_dump(p,sort_keys=False))
 subprocess.run(['amtool','check-config',str(paths[0])],check=True)
 subprocess.run(['promtool','check','config',str(paths[1])],check=True)
 subprocess.run(['systemctl','reload','prometheus'],check=True)
 subprocess.run(['systemctl','reload','prometheus-alertmanager'],check=True)
except Exception:
 for path in paths:shutil.copy2(backup/path.name,path)
 subprocess.run(['systemctl','reload','prometheus'])
 subprocess.run(['systemctl','reload','prometheus-alertmanager'])
 raise
PY
MON
bash scripts/scenarios/03-spam/install-smtp-containment.sh
