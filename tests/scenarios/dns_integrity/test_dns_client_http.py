"""Exercise the production DNS parser and HTTP reader through independent sinks."""
import http.client
import subprocess
import unittest
from unittest.mock import patch

import dns_client as client

from .dns_fixture import APPROVED, SECONDARY, http_endpoints, reply, resolve_from


class DNSClientHTTPTests(unittest.TestCase):
    def test_dns_policy_and_actual_http_connections(self):
        # Test-only owner and loopback addresses. No resolver is reconfigured.
        name = "fixture.test"
        cases = (
            ("approved", reply(name, [APPROVED]), "success", {"approved": 1, "secondary": 0}),
            ("duplicate", reply(name, [APPROVED, APPROVED]), "success", {"approved": 1, "secondary": 0}),
            ("unexpected", reply(name, [SECONDARY]), "dns_rejected", {"approved": 0, "secondary": 0}),
            ("mixed", reply(name, [APPROVED, SECONDARY]), "dns_rejected", {"approved": 0, "secondary": 0}),
            ("nxdomain", reply(name, status="NXDOMAIN"), "dns_failure", {"approved": 0, "secondary": 0}),
            ("no A record", reply(name), "dns_failure", {"approved": 0, "secondary": 0}),
            ("unexpected owner", reply("different.test", [APPROVED]), "dns_failure", {"approved": 0, "secondary": 0}),
            ("malformed", reply(name, ["127.0.0.999"]), "dns_failure", {"approved": 0, "secondary": 0}),
            ("trailing field", reply(name, [APPROVED + " junk"]), "dns_failure", {"approved": 0, "secondary": 0}),
            ("timeout exit", subprocess.CompletedProcess([], 9, "no servers could be reached\n", ""),
             "dns_failure", {"approved": 0, "secondary": 0}),
            ("subprocess timeout", subprocess.TimeoutExpired("dig", 3), "dns_failure", {"approved": 0, "secondary": 0}),
        )
        with http_endpoints() as (port, snapshot):
            # Positive control: the independent secondary server can answer and count a direct request.
            connection = http.client.HTTPConnection(SECONDARY, port, timeout=2)
            try:
                connection.request("GET", "/average")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
            finally:
                connection.close()
            self.assertEqual(snapshot(), {"approved": 0, "secondary": 1})
            with patch.multiple(client, DNS_NAME=name, EXPECTED_IP=APPROVED, HTTP_PORT=port):
                for label, result, expected_outcome, expected_requests in cases:
                    with self.subTest(label=label):
                        before = snapshot()
                        event = client.probe(lambda: resolve_from(client, result))
                        after = snapshot()
                        self.assertEqual(event["outcome"], expected_outcome)
                        self.assertEqual({name: after[name] - before[name] for name in before}, expected_requests)
                        if expected_outcome == "success":
                            self.assertEqual(event["peer_ip"], APPROVED)
                            self.assertEqual(event["average_temperature"], 25.0)
