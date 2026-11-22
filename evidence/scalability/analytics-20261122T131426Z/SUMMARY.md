# Analytics replica comparison

Fixed workload: 60 ordinary reads at two requests/s, 30 seconds per trial, three repetitions per configuration.
Rate limiting remains enabled. Cache mode uses operator fixtures on temporary node paths, not Wazuh activation.

| Replicas | Mode | HTTP 200 | Mean ms | Pooled p95 ms | Storage attempts | Cache hits | Mean CPU cores | Mean working set MiB |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | normal | 180 | 11.258 | 13.807 | 180 | 0 | 0.01739 | 30.99 |
| 1 | cache | 180 | 6.623 | 11.648 | 18 | 162 | 0.00684 | 33.80 |
| 2 | normal | 180 | 11.297 | 14.424 | 180 | 0 | 0.01436 | 82.40 |
| 2 | cache | 180 | 7.169 | 13.323 | 35 | 145 | 0.00662 | 84.47 |
| 4 | normal | 180 | 11.719 | 14.498 | 180 | 0 | 0.01029 | 151.98 |
| 4 | cache | 180 | 8.835 | 13.653 | 58 | 122 | 0.00830 | 152.01 |

All node containers share one VM and one Storage/SQLite dependency. These results measure bounded low-rate behavior; they do not establish maximum throughput, linear speedup, saturation resistance or multi-host fault tolerance.
CPU windows use the kubelet sample timestamps and can differ from the HTTP window. Resource samples are coarse.
Per-trial and per-Pod records, fixture provenance, dataset equality and production/cleanup verification are retained alongside this summary.
