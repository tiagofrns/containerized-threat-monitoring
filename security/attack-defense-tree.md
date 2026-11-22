# Threat model and control scope

The assets are temperature measurements/aggregates, dependency resolution,
legitimate read availability, operational mail, monitoring and security records.
The three scenarios use different attacker assumptions. All demonstrations are
bounded to the isolated lab; an administrative test edit is not evidence of how
an attacker initially obtained that capability.

## 1. Availability

The remote client can reach exposed application endpoints without SSH, Incus
administration or direct SQLite access.

```text
Goal: degrade temperature-service availability [OR]
  Overload ingestion [AND; untested branch]
    Reach ingestion
    Exceed effective processing/storage capacity
    Available controls do not sufficiently constrain that work
  Degrade analytics reads [AND]
    Reach /average
    Cause enough shared-resource work/contention
    Legitimate reads miss their service objective
    Defences: per-source rate limiting; temporary protective cache
```

The source limiter and cache reduce admitted dependency work. Wazuh correlates
rejections and authorizes the cache; Prometheus has a separate client-impact
path. Rejection is not proof of intent and can affect legitimate bursts behind
one translated address. State is process/node-local, and Storage/SQLite and the
VM are shared constraints. Current evidence is ordinary-read and state-scope
validation, not measured DDoS capacity.

## 2. DNS integrity

A test actor can change one lab dnsmasq record. The approved baseline, response
code and monitor remain trusted. Full root control is outside that assumption.

```text
Goal: make a client consume an unexpected dependency [AND]
  Influence the answer for analytics.lab.test
  Client accepts the unexpected destination
  HTTP communication succeeds and its data is trusted
  Defences:
    Expected-address policy rejects the HTTP attempt
    FIM/startup detection restores the approved resolver file
    Metrics correlate repeated policy rejection with current DNS state
```

A changed address can affect temperature integrity and availability. The client
rejects before an HTTP read, while restoration recovers the approved file.
Other resolver paths/files, a changed trusted baseline and an allowed IP serving
false data remain residual risks. Expected IPs do not replace TLS/DNSSEC.

## 3. Mail security and protection availability

The test sender controls SMTP content and supplied headers from a separate
Incus client. Its network address is observed by Postfix and authenticated by
the local filter; sender-supplied headers cannot replace that identity.
Quarantine metadata carries the observed address as `source_ip` for correlation
and `srcip` for native firewall-drop. Rule `100607` requires verification and
source eligibility; `100620` has no fixed sender-IP condition. Local and
loopback sources are ineligible. The normal test-client address is independent
of this decision, as the complete alternate-IP run demonstrates.
The separate recovery test assumes the scanner can stop while Wazuh stays active.

```text
Goal: put unwanted content in the operations inbox [AND]
  Submit mail
  Classification/delivery protection is bypassed or ineffective
  Message is stored in INBOX
  Defences: remove supplied classification headers; scan locally;
            enforce Quarantine in Dovecot/Sieve; audit actual stored content

Goal: continue submitting spam from the same observed source [AND]
  At least three verified quarantine events occur within 60 seconds
  Defence: authenticated Postfix connection IP, excluding local/loopback sources
           -> Wazuh 100620 groups repeated quarantine by source_ip
           -> native firewall-drop -> IP-wide 20-second block
           -> timed deletion and verified legitimate SMTP recovery

Goal: leave mail protection unavailable [AND]
  SpamAssassin stops
  It stays stopped and subsequent scanning cannot resume
  Defence: observed outage -> Wazuh 100610 -> fixed-service recovery -> 100611
```

Quarantine mitigates content delivery. The Wazuh response restores service
availability; a controlled stop is not, by itself, attribution to an attacker.
GTUBE tests a known-positive fixture, and operational notification is not
containment. Native firewall-drop provides temporary IP containment; it can affect
legitimate senders sharing that IP and requires Wazuh to reverse the block.
Representative classifier-accuracy testing remains outside the implemented scope.
Privileged release requires operator review. The existing native firewall-drop
command is reused; the unrelated course-guide AlienVault rule `100100` and its
60-second response were retired. See the
[effective policy and removal record](../docs/scenarios/03-spam/README.md#effective-wazuh-configuration)
for the current XML, source fields and retained evidence.

## Risk and policy interpretation

| Risk | Control | Residual limitation |
|---|---|---|
| Repeated analytics work harms useful reads | Admission and bounded caching | Shared addresses/resources and distributed local budgets |
| Dependency resolves to an unexpected endpoint | Reject before HTTP; approved-file restoration | Other resolver paths and unauthenticated allowed endpoint |
| Spam reaches the operations inbox | Local classification and enforced folder placement | Classifier mistakes, bypassed filter, shared source IPs and temporary containment |
| Spam protection service remains stopped | Wazuh starts fixed service and verifies a scan | Active-but-unresponsive scanner and persistent root control |
| Monitoring/action becomes misleading | Freshness, correlated IDs, explicit result checks | Shared VM, telemetry loss and finite observation windows |

These are conditional qualitative risks, not measured attack probabilities.
Chosen thresholds are laboratory policies. Report the supporting observations,
legitimate-client trade-offs and limitations rather than asserting complete
prevention. Scenario pages link the retained evidence for each control.
