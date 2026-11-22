# Bounded Analytics scalability study

Run on the existing project VM from `~/security-monitoring-platform`.
Print the plan first, then execute the fixed study:

```bash
python3 tests/scalability/run-analytics-scaling.py
python3 tests/scalability/run-analytics-scaling.py --run
```

The study creates a temporary Deployment, ClusterIP Service and separate client
Pod. It compares 1, 2 and 4 Analytics replicas, spread across the two K3s nodes.
The production Deployment, database and Wazuh configuration are preserved.

Each configuration receives the same 60 ordinary reads at a maximum scheduled
rate of two requests per second for 30 seconds. Normal and protective-cache
modes each have three repetitions, with alternating order. The total measured
budget is 1,080 reads, plus documented warm-up/state checks and two read-only
Storage snapshots. Rate limiting stays enabled. The script never increases the
rate to find a breaking point. The default plan performs no infrastructure action.

Cache mode is authorized by labelled operator fixtures in dedicated temporary
node directories. This is not Wazuh dispatch; the scenario-1 flow separately
validates the real response. A final one-node fixture shows whether the other
node's replicas remain in normal mode.

Evidence under `evidence/scalability/` retains individual HTTP responses, phase
metrics, per-Pod request/Storage/cache counters, kubelet CPU and working-set
samples, source hashes, Pod identities/restarts, dataset snapshots and cleanup.
CPU averages use the actual kubelet sample timestamps; resource samples are
coarse and their windows can differ materially from the HTTP measurement window;
use the recorded timestamps.

All phases must retain the same dataset, only HTTP 200, the expected protection
mode, data age within 10 seconds and unchanged candidate identities. Counter
resets, lost attribution, missed dispatch cadence or missing metrics fail the
study instead of producing a successful comparison. Cleanup removes only the
resources and directories created for the unique run and verifies production.

These are low-rate horizontal-scaling observations on two nodes inside one VM.
They do not establish maximum throughput, linear speedup, overload resistance
or multi-host fault tolerance. Shared Storage/SQLite remains a common dependency;
process-local caches can increase total refresh work as replicas are added.

Offline measurement checks run through `bash scripts/common/run-tests.sh scalability`
or `bash scripts/common/run-tests.sh --local scalability`. They never start the live study.
A successful live run also writes `SUMMARY.md`, `summary.csv` and `summary.json`.
