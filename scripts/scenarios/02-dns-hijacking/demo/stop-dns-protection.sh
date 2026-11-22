#!/usr/bin/env bash
# Prepare only the DNS demonstration baseline; run start-dns-protection.sh to recover.
set -euo pipefail
incus exec dns-server-container -- bash -eu <<'BASH'
systemctl stop wazuh-agent dns_client
for service in wazuh-agent dns_client; do
  state="$(systemctl is-active "$service" || true)"
  printf '%s: %s\n' "$service" "$state"
  [[ "$state" == inactive || "$state" == failed ]]
done
BASH
