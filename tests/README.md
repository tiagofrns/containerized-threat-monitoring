# SSLE Tests

This directory contains or supports the project's automated regression tests. Tests validate application behavior and configuration logic in repeatable conditions; they do **not** by themselves prove that every service in the live Incus/K3s infrastructure is healthy or that an automated Wazuh response occurred.

> **Run from the repository root.** The canonical test entry point is `scripts/common/run-tests.sh`. The exact set of individual test files can evolve; the runner and its discovery output are authoritative.

## Quick start

On the configured Debian laboratory VM:

```bash
cd ~/ssle
bash scripts/common/run-tests.sh
```

For the documented local email-security subset:

```bash
bash scripts/common/run-tests.sh --local mail-security
```

Before running a **live** integration scenario, also verify the infrastructure:

```bash
bash scripts/check-lab.sh
```

If the runner reports missing Docker images or dependencies, use the project provisioning/build documentation. Avoid silently changing the tests to run against production endpoints.

## Test categories

| Layer | Purpose | Typical checks | Live infrastructure required? |
|---|---|---|---|
| Application regression | Protect temperature-service behavior after code changes | Request processing, responses, rate limiting, caching, errors and recovery bounds | No, when run through the isolated fixture/runner |
| Security configuration fixtures | Validate detection rules and message parsing | Wazuh decoder/correlation fixtures, deterministic alert conditions | Depends on the fixture runner and installed tooling |
| Mail security tests | Validate the mail gateway's decision and retry logic | Webhook authentication, notification duplication, classification-related controls and release behavior | Some local tests do not; end-to-end mail delivery does |
| Live scenario evaluations | Observe actual deployed components together | Wazuh events, Prometheus metrics, delivery/quarantine, DNS restoration | **Yes** |

For the availability work, previous retained evaluations describe isolated HTTP/SQLite fixtures with real local requests and a disposable database, together with rate-limiting regressions and offline Wazuh/Prometheus checks. These are distinct from the live measurements described in the scenario evidence.

## Safety and scope

- Isolated tests may use mocked dependencies, temporary databases or a disposable Docker execution environment. Never point them at an unrelated host.
- Live demos are **not** ordinary unit tests: they can generate HTTP traffic, send test email, create Wazuh/Prometheus alerts and produce new evidence.
- Run scenario demos one at a time and avoid concurrent evaluation, as background alerts or expired leases can affect interpretation.
- Preserve previous results and identify each run by timestamp, configuration and workload.
- A `PASS` in the local regression suite is **not** proof of DoS resistance, Internet-scale load handling or a functioning end-to-end SIEM pipeline.

## Live verification and evidence

The following commands run on the previously provisioned laboratory VM. They are more invasive than an isolated test suite.

### Availability and recovery

```bash
# Bounded comparison and cache response verification
python3 scripts/scenarios/01-dos/record-cache-response.py

# Separate replica-scope experiment
python3 scripts/scenarios/01-dos/record-replica-scope.py

# Post-recovery observation, after cleanup of temporary replicas
python3 scripts/monitoring/record-baseline.py
```

The documented experiments depend on particular deployment conditions, including expected replica counts. Read their preflight output and scenario instructions before running them.

### Mail flow

```bash
# Inspect safely before sending any messages
bash scripts/scenarios/03-spam/demo/show-mail-flow.sh --preflight-only

# Interactive lab demonstration (sends controlled messages)
bash scripts/scenarios/03-spam/demo/show-mail-flow.sh --pause
```

The demo should check that `smtp/inet/content_filter` is set to `spamassassin:filter`, that legitimate messages reach `INBOX`, spam test messages reach `Quarantine`, alerts reach the mailbox and corresponding audit events are visible in Wazuh. Checking only that the SpamAssassin process is running is insufficient.

### DNS integrity

The DNS test checks the approved `dnsmasq` configuration, controlled modifications, Wazuh observation and recovery. Use the **currently committed DNS scenario script**; confirm its filename in `scripts/scenarios/` before execution. The restoration step is part of the test, not an optional cleanup.

## Reporting a test run

For each run, retain the command, date/time, source revision or image tags, test conditions, expected result, observed result, exit status, and evidence paths. Keep controlled fixture evidence separate from live Wazuh events and indexed alert documents.

Suggested output organization:

```text
evidence/
  scenarios/
    01-dos/<timestamped-run>/
    02-dns/<timestamped-run>/
    03-spam/<timestamped-run>/
```

Generated artifacts such as JSON summaries, request traces, HTTP status counts, event logs and latency charts should not be committed over older results. Use a new timestamped directory for each execution.

## Diagnosing failures

```bash

# Inspect relevant workloads
incus exec k3s-master -- k3s kubectl -n ssle get deployments,pods

# Inspect filtering without changing configuration
incus exec mail-container -- systemctl is-active postfix dovecot spamassassin mail_gateway wazuh-agent
incus exec mail-container -- postconf -P smtp/inet/content_filter

# Inspect monitoring availability
incus exec prometheus-container -- curl -fsS http://127.0.0.1:9090/-/ready
incus exec wazuh-container -- systemctl is-active wazuh-manager
```

A failed infrastructure check must be resolved before treating an integration failure as an application regression. A missing service, a misconfigured filter and a failed security policy are different categories of failure and should be reported separately.
