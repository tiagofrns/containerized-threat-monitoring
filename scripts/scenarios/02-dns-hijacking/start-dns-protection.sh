#!/usr/bin/env bash
# Run on the Debian VM to start the DNS host's protection services.
set -euo pipefail

incus exec dns-server-container -- bash -eu <<'BASH'
systemctl start wazuh-agent
python3 /var/ossec/active-response/bin/dns_restore.py --check-startup
systemctl start dns_client
for service in wazuh-agent dns_client; do
  printf '%s: ' "$service"
  systemctl is-active "$service"
done

# Check a real guarded read from the approved analytics endpoint.
python3 /opt/dns_sec/dns_client.py --once
BASH
