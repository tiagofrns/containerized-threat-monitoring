# Normal-operation baseline

This is a five-minute read-only experiment using the existing legitimate client.
No load generator or configuration change was applied; existing defenses stayed configured.

- Started (UTC): 2026-11-19T11:36:06.356594+00:00
- Duration: 300.01 seconds
- Client requests: 60
- Successful requests: 60
- Failed requests: 0
- Average observed client request duration: 11.567 ms
- Prometheus snapshots: 21

| Application | Mean CPU (cores) | Mean memory working set (MiB) |
|---|---:|---:|
| analytics | 0.002691 | 33.59 |
| ingestion | 0.000497 | 29.47 |
| registry | 0.000929 | 30.65 |
| storage | 0.001899 | 27.65 |

## Evidence

- conditions.json: workload, intervals, source hashes and limitations.
- samples.jsonl: periodic Prometheus API observations.
- client-before.json and client-after.json: direct cumulative metric snapshots.
- cluster-before.json and cluster-after.json: deployments, images and Pod state.
- analytics-before.json and analytics-after.json: read-only API responses.
- summary.json: calculated results.

## Limitations

- Read-only workload: no sensor generation and no ingestion write test.
- The client validates the response structure, not the numerical average independently.
- Resource measurements are periodic metrics-server observations collected by Prometheus.
- Probe success is not a complete functional or security proof.
- A five-minute low-rate run is not a scalability or capacity benchmark.
- Client boundary snapshots occur around, not atomically with, Prometheus samples.
