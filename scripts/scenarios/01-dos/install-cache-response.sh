#!/usr/bin/env bash
# Install the Wazuh side of the cache response. Build/import the app image separately.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

for node in k3s-master k3s-node1; do
  # This interpreter is needed on the node, not just inside the Python app image.
  if ! incus exec "$node" -- test -x /usr/bin/python3; then
    incus exec "$node" -- env DEBIAN_FRONTEND=noninteractive apt-get install -y python3-minimal
  fi
  incus exec "$node" -- install -d -m 0755 -o root -g root /var/lib/analytics-protection/analytics
  stage="$(incus exec "$node" -- mktemp -d /root/cache-install.XXXXXX)"
  incus file push "$root/security/analytics-cache.py" "$node$stage/response.py"
  incus exec "$node" -- install -m 0750 -o root -g wazuh \
    "$stage/response.py" /var/ossec/active-response/bin/analytics-cache.py
  incus exec "$node" -- rm -r -- "$stage"
  incus exec "$node" -- test -x /var/ossec/active-response/bin/analytics-cache.py
done

stage="$(incus exec wazuh-container -- mktemp -d /root/cache-install.XXXXXX)"
incus file push "$root/security/wazuh-cache-response-config.xml" "wazuh-container$stage/config.xml"
incus file push "$root/security/wazuh-cache-response-rules.xml" "wazuh-container$stage/rules.xml"
incus exec wazuh-container -- python3 - "$stamp" "$stage" <<'PY'
from pathlib import Path
import os
import shutil
import subprocess
import sys

stamp = sys.argv[1]
stage = Path(sys.argv[2])
config = Path('/var/ossec/etc/ossec.conf')
rule = Path('/var/ossec/etc/rules/cache_response_rules.xml')
block = (stage/'config.xml').read_text()
new_rule = (stage/'rules.xml').read_text()
shutil.rmtree(stage)
old = config.read_text()
previous_rule = rule.read_bytes() if rule.exists() else None
if '<name>analytics-cache</name>' in old and block not in old:
    raise SystemExit('An existing cache response differs. Review it before replacing it.')
if block in old and previous_rule == new_rule.encode():
    subprocess.run(['/var/ossec/bin/wazuh-analysisd', '-t'], check=True)
    print('Manager configuration already matches; no manager restart required.')
    raise SystemExit(0)
backup = Path('/root/cache-response-backup-'+stamp)
backup.mkdir()
shutil.copy2(config, backup/'ossec.conf')
if previous_rule is not None:
    shutil.copy2(rule, backup/rule.name)
try:
    if block not in old:
        config.write_text(old+'\n'+block)
    rule.write_text(new_rule)
    shutil.chown(rule, user='root', group='wazuh')
    os.chmod(rule, 0o640)
    subprocess.run(['/var/ossec/bin/wazuh-analysisd', '-t'], check=True)
except Exception:
    shutil.copy2(backup/'ossec.conf', config)
    if previous_rule is None:
        rule.unlink(missing_ok=True)
    else:
        shutil.copy2(backup/rule.name, rule)
    raise
subprocess.run(['systemctl', 'restart', 'wazuh-manager'], check=True)
subprocess.run(['systemctl', 'is-active', 'wazuh-manager'], check=True)
PY
echo 'Response installed. The analytics Deployment needs the documented read-only control mount.'
