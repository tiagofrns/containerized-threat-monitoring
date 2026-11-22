# Scenario 2 demonstration evidence

Run `20261120T205734859857Z` on the Debian VM, 20 November 2026 (UTC).
The demonstration used the local project's `show-dns-flow.sh` and the VM's
`evaluate-dns-alert.py`. The script opened the test site by direct HTTP and used
isolated responses to exercise the client. The live DNS mapping stayed on the
approved address throughout the run.

| Capture | Observation |
|---|---|
| [FAKE SITE](captures/01-fake-site.png) | The VM's demo endpoint returned HTTP 200 when accessed directly. |
| [Prometheus](captures/02-prometheus-firing.png) | `DNSPolicyRejections` in `FIRING`, with the matching `test_run` label. |
| [Wazuh Discover](captures/03-wazuh-policy-alert.png) | Indexed rule `100151`, event `1795208350.21510093`, with `data.bridge_state=firing` and `data.validation=true`. |

The client rejected nine fixture responses and issued zero HTTP requests
during those checks. The Wazuh response for the Prometheus alert recorded
`already_approved`. A subsequent comment-only file modification triggered FIM
rule `100141` and automatic restoration in the same demonstration. The final
guarded read returned HTTP 200. [Execution log](flow.log) · [Prometheus capture data](prometheus-capture.json) · [Wazuh alert](wazuh.json) · [Endpoint response](response.json) · [FIM restoration](fim-restoration.json)

The separate startup test injected a comment while the agent was stopped. Its
rule `100145` is also visible in Discover. [Wazuh startup alert](../startup-recovery-20261120T203944Z/wazuh-startup-alert.png) · [Startup restoration evidence](../startup-recovery-20261120T203944Z/summary.json)
