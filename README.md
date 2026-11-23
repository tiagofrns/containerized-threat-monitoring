# Temperature monitoring and security

A service-based temperature application with Prometheus monitoring and Wazuh
security responses. The three scenarios cover availability, DNS integrity and
spam filtering. The academic report is a separate deliverable.

```text
Sensor -> Ingestion -> Storage/SQLite <- Analytics <- Clients
Metrics -> Prometheus -> Alertmanager -> Notifications / selected Wazuh responses
Security logs -> Wazuh -> Cache activation, DNS restoration, firewall blocking or scanner recovery
```

## Run on the project VM

Requires the existing Debian/Incus lab, Python 3.13, K3s, Prometheus and Wazuh.
Setup and recorded addresses: [operations](docs/operations.md).


Run one scenario at a time from the project root:

```bash
bash scripts/scenarios/01-dos/demo/show-dos-flow.sh --pause

bash scripts/scenarios/02-dns-hijacking/demo/stop-dns-protection.sh
bash scripts/scenarios/02-dns-hijacking/demo/show-dns-flow.sh --pause

bash scripts/scenarios/03-spam/demo/show-mail-flow.sh --pause
```

The DNS flow requires the stopped-protection baseline and restores protection
at the end. After an interrupted DNS run, execute
`bash scripts/scenarios/02-dns-hijacking/start-dns-protection.sh`.
New demonstration output is saved under each `demo/results/` directory.
Scenario 3 derives the sender IP from the verified Postfix connection metadata.
After three eligible quarantines from the same source within 60 seconds, Wazuh
reuses native `firewall-drop` with a 20-second timeout. The
[effective configuration](docs/scenarios/03-spam/README.md#effective-wazuh-configuration)
explains the rules and the retirement of the old AlienVault response.



## Tests and submission

```bash
bash scripts/common/run-tests.sh
python3 scripts/common/package-project.py --output ../security-monitoring-platform.tar.gz
```

The test runner uses the existing Docker dependency image inside Incus. With
local Python dependencies installed, use `run-tests.sh --local` instead.
Latest final runs and validation: [final laboratory results](docs/final-validation.md).
The archive contains a `security-monitoring-platform/` folder and a SHA-256
manifest; temporary runs, private files, databases and image exports are excluded.

The reusable [replica comparison](tests/scalability/README.md) compares 1, 2 and 4
Analytics replicas with fixed ordinary-read workloads and retained measurements.

## Read the results

| Scenario | Implementation, commands and retained evidence |
|---|---|
| 1. Availability | [Rate limiting and protective cache](docs/scenarios/01-dos/README.md) |
| 2. DNS integrity | [Guarded reads and approved-file restoration](docs/scenarios/02-dns-hijacking/README.md) |
| 3. Mail security | [Spam quarantine, firewall containment and Wazuh recovery](docs/scenarios/03-spam/README.md) |

`apps/`, `monitoring/`, `deploy/` and `security/` contain the implementation;
`scripts/` contains the operators' entry points; `tests/` contains isolated
checks; `evidence/` retains selected original records. See the
[threat model](security/attack-defense-tree.md) for assumptions and residual risks.
Results establish bounded laboratory behaviour, not Internet-scale capacity.


## AI Usage

AI-assisted tools, including ChatGPT, were used throughout the project as supporting resources for:

- **Development:** Assisting with code implementation, refactoring, and troubleshooting.
- **Infrastructure:** Supporting configuration and integration of monitoring and security components.
- **Testing:** Assisting with test scripts, debugging, and analysis of experimental results.
- **Documentation:** Improving technical explanations, report structure, and clarity.

AI-generated suggestions were reviewed, adapted, and validated against the project's requirements and experimental evidence.

AI was used as a development assistant, not as a substitute for technical decision-making, implementation verification, or experimental validation.
