# Operations

Run commands on the Debian VM from `~/security-monitoring-platform`. This source folder operates the
existing course lab; it does not provision a blank VM or contain private keys.

## Existing infrastructure

| Incus instance | Responsibility | Recorded address |
|---|---|---|
| `docker` | Build images and run isolated tests | Discover with `incus list` |
| `k3s-master` | K3s control plane and application workloads | `10.255.255.74` |
| `k3s-node1` | K3s worker | `10.255.255.254` |
| `prometheus-container` | Prometheus, Alertmanager, bridge and publisher | `10.255.255.21` |
| `wazuh-container` | Manager, indexer and dashboard | `10.171.72.186` |
| `dns-server-container` | dnsmasq, guarded client and Wazuh agent | `10.171.72.8` |
| `dns-fake-site` | Labelled demonstration page | `10.171.72.52` |
| `smtp-client` | Dedicated SMTP test origin | `10.171.72.60` |
| `mail-container` | Postfix, Dovecot, SpamAssassin, gateway and Wazuh agent | `10.171.72.142` |

Addresses describe the retained lab. Verify them with `incus list` after a
restart or migration. Start a stopped instance with `incus start <name>`.

```bash
incus exec k3s-master -- systemctl is-active k3s
incus exec k3s-node1 -- systemctl is-active k3s-agent
incus exec k3s-master -- k3s kubectl get nodes -o wide
incus exec k3s-master -- k3s kubectl -n ssle get deployments,pods,services,pvc
```

Wait for Ready nodes before a flow. A running Incus container does not prove
that K3s or its applications are ready. Keep the lab's kernel/sysctl setup.

## Application and dashboards

The path is Sensor -> Ingestion -> Storage/SQLite, with Analytics reading the
Storage HTTP API. Storage is the single SQLite owner. The registry provides a
registration API; Kubernetes Service names supply discovery in this deployment.
Sensors normally remain at zero replicas during read-only security trials.

| Endpoint | Address / port |
|---|---|
| Ingestion | K3s NodePort `30501` |
| Analytics `/average` and `/metrics` | K3s NodePort `30503` |
| Health, resource and client metrics | NodePorts `30800`, `30801`, `30802` |
| Prometheus | `http://10.255.255.21:9090` |
| Wazuh dashboard | `https://10.171.72.186` |
| Mail gateway / exporter | Mail container port `9096` |
| SMTP submission | `10.171.72.142:25` from `smtp-client`; loopback for notifications |

If the PC cannot route to the lab, keep these SSH forwards running on the PC:

```bash
ssh -p 2222 -N -L 19090:10.255.255.21:9090 -L 18443:10.171.72.186:443 root@127.0.0.1
```

Open `http://127.0.0.1:19090` or `https://127.0.0.1:18443`. Use existing lab
credentials; credentials and private certificates are not part of this folder.

## Installation and updates

Source files are not the installed runtime. The current VM retains some
`ssle-` image/metric names; demo readers accept those names. Do not rename live
images, metrics or Wazuh commands just to match a filename in this folder.
The supplied Kubernetes/Prometheus manifests describe the generic source build.
A source cleanup does not deploy those manifests.

Build application images deliberately inside `docker`, using `apps/` as the
build context and `APP` as the selected service. Example from an accessible
copy of this source inside that container:

```bash
docker build -f apps/Dockerfile --build-arg APP=analytics -t analytics:case1-final-v1 apps
```

Repeat for the other application tags required by `scripts/common/import-images.sh`.
That script exports/imports the built images into both K3s nodes and stores
exports outside the submission folder, under `../ssle-runtime-artifacts/`.
Build the monitoring image from `monitoring/`. Apply Kubernetes manifests only
as part of an intended rollout, after checking image availability and names.

Scenario-specific installation entry points, after the corresponding base
Incus/Wazuh services from the course lab exist:

```bash
bash scripts/scenarios/01-dos/install-cache-response.sh
bash scripts/scenarios/02-dns-hijacking/install-dns-integrity.sh agent
bash scripts/scenarios/02-dns-hijacking/install-dns-integrity.sh manager
bash scripts/scenarios/02-dns-hijacking/install-dns-integrity.sh prometheus
bash scripts/monitoring/install-alert-bridge.sh
```

The DNS agent installer expects the approved record and realtime Wazuh FIM for
`/etc/dnsmasq.d`; the manager installer rejects rule conflicts. For mail, use
`install-mail.sh base`, then `install-mail.sh filter`, followed by
`install-mail-security.sh`. Existing mail installations use
`scripts/scenarios/03-spam/install-smtp-containment.sh` for the dedicated client,
source verification, native firewall-drop policy and service-recovery extension. The installers generate
notification secrets inside the containers and validate configuration changes.

The actual fake-site source and units are retained in
`scripts/scenarios/02-dns-hijacking/demo/fake-site/`. They describe the already
installed labelled page and its address-bound socket proxy, not a login site.

## Verification

```bash
bash scripts/common/verify-apps.sh
bash scripts/scenarios/01-dos/demo/show-dos-flow.sh --preflight-only
bash scripts/scenarios/03-spam/demo/show-mail-flow.sh --preflight-only
bash scripts/common/run-tests.sh
```

Run one test suite by appending `availability`, `dns-integrity`, `mail-security`,
`monitoring` or `common`. The default runner mounts source read-only inside a
network-disabled Docker test container. Isolated HTTP/SQLite tests use its
loopback and temporary database; they do not target deployed services.

```bash
promtool test rules tests/monitoring/prometheus-alerts.test.yml tests/monitoring/bridge-alerts.test.yml
```

## Current mail firewall policy

The manager configuration is `/var/ossec/etc/ossec.conf` in `wazuh-container`;
mail detection rules are in `/var/ossec/etc/rules/mail_rules.xml`. The endpoint
uses the existing `/var/ossec/active-response/bin/firewall-drop` in
`mail-container`. See the [effective XML and field mapping](scenarios/03-spam/README.md#effective-wazuh-configuration).

The observer verifies Postfix connection metadata before setting `source_ip`
and `srcip` to the same address. Rule `100607` requires a verified, blockable
source; `100620` correlates three quarantines per source in 60 seconds. The
native command blocks INPUT/FORWARD traffic for that IP, with a configured
20-second timeout. Loopback and the server's local addresses are excluded.
The client's normal `.60` address is not a rule condition; the full flow also
passed with `.61` without changing the rule.

The old course-guide AlienVault rule `100100`, its 60-second response and the
unreferenced blacklist registration/text/CDB files were retired. The shared
native command and audit rules `651`/`652` remain in use. Originals are under
`/root/retired-reputation-u7c1rivy/` inside `wazuh-container`; the
[cleanup report](../evidence/validation-20261122-dynamic-source/firewall-retirement-report.json)
records the remaining command and response.

Read-only checks during a demonstration:

```bash
incus exec mail-container -- iptables -S INPUT
incus exec mail-container -- iptables -S FORWARD
incus exec mail-container -- tail -n 20 /var/ossec/logs/active-responses.log
```

The mail flow waits for a Wazuh acknowledgement after each controlled quarantine
before sending the next test message. It retains Message-ID/source correlation
in `smtp-containment/quarantine-acknowledgements.jsonl`. On failure, inspect
`failure-summary.json` and its retained manager/native logs to distinguish a
missing detection rule from a response or observation problem. See the
[observed failure and sequencing fix](scenarios/03-spam/README.md#diagnosing-a-missing-firewall-block).

The flow retains the rule while blocked and confirms its absence after timeout,
a failed SMTP connection and a successful reconnection. No test DROP entry is
expected after recovery. Prometheus/Alertmanager notification and Wazuh scanner
recovery have separate triggers from source-IP containment.

## Retained data and limits

Only Storage's PVC contains the application's live SQLite database. No live
mailboxes, databases, credentials or container/image exports are submitted.
`evidence/` contains selected historical results with their original names,
timestamps and hashes. Embedded source snapshots there explain an observation;
execute current commands from `scripts/` instead.

Rate limiting, cache values and metrics are process-local. The cache lease is
node-local. SQLite/local-path storage and one shared VM remain failure and
scalability constraints. DNS expected-IP checks do not authenticate HTTP content.
GTUBE demonstrates a known-positive fixture, not classifier accuracy on real mail.
Scenario 3 uses native Wazuh firewall-drop with a 20-second timeout for the
observed remote source after repeated verified quarantine. The sender IP is not
embedded in the Wazuh rule. Local/loopback sources are excluded; client admission
is restricted to the lab subnet. The response blocks INPUT/FORWARD, not only SMTP.
Automatic removal requires the endpoint Wazuh response process to remain running.

The report should separate classification, policy enforcement, service recovery,
experimental observations and scalability claims. Full course material, prior
exports and superseded notes are kept outside this submission folder.

