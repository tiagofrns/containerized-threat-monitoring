"""Isolated defensive fixtures. Never changes or impersonates a live DNS answer."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


client = module("dns_client_under_test", ROOT / "monitoring/dns_client.py")
response = module("dns_response_under_test", ROOT / "security/dns_restore.py")


class ClientPolicyTests(unittest.TestCase):
    def test_wazuh_path_rule_matches_only_the_restoration_target(self):
        rules = ET.fromstring((ROOT / "security/wazuh-dns-rules.xml").read_text())
        field = rules.find("./rule[@id='100141']/field[@name='file']")
        self.assertIsNotNone(field)
        self.assertRegex(str(response.TARGET), field.text)
        self.assertNotRegex("/etc/hosts", field.text)
        self.assertNotRegex(str(response.TARGET) + ".backup", field.text)

    def test_approved_address_is_used_for_actual_read(self):
        reader = Mock(return_value={"average_temperature": 25.12, "peer_ip": client.EXPECTED_IP})
        event = client.probe(lambda: [client.EXPECTED_IP], reader)
        self.assertEqual(event["outcome"], "success")
        reader.assert_called_once_with(client.EXPECTED_IP)

    def test_unexpected_address_never_reaches_http_reader(self):
        reader = Mock()
        event = client.probe(lambda: ["192.0.2.10"], reader)
        self.assertEqual(event["outcome"], "dns_rejected")
        reader.assert_not_called()

    def test_mixed_answer_set_is_not_partially_accepted(self):
        reader = Mock()
        event = client.probe(lambda: [client.EXPECTED_IP, "192.0.2.10"], reader)
        self.assertEqual(event["outcome"], "dns_rejected")
        reader.assert_not_called()

    def test_empty_answer_never_reaches_http(self):
        reader = Mock()
        self.assertEqual(client.probe(lambda: [], reader)["outcome"], "dns_rejected")
        reader.assert_not_called()

    def test_resolver_failure_is_not_reported_as_malicious_answer(self):
        reader = Mock()
        resolver = Mock(side_effect=OSError("Fixture NXDOMAIN"))
        event = client.probe(resolver, reader)
        self.assertEqual(event["outcome"], "dns_failure")
        reader.assert_not_called()

    def test_http_failure_preserves_successful_dns_observation(self):
        event = client.probe(lambda: [client.EXPECTED_IP], Mock(side_effect=OSError("Fixture HTTP 502")))
        self.assertTrue(event["dns_expected"])
        self.assertEqual(event["outcome"], "http_error")

    def test_malformed_payload_has_its_own_outcome(self):
        event = client.probe(lambda: [client.EXPECTED_IP], Mock(side_effect=ValueError("Fixture invalid JSON")))
        self.assertEqual(event["outcome"], "invalid_response")

    def connection(self, payload, peer=None, status=200):
        connection = Mock()
        connection.sock.getpeername.return_value = (peer or client.EXPECTED_IP, 30503)
        connection.getresponse.return_value.status = status
        connection.getresponse.return_value.read.return_value = payload
        return connection

    def test_http_uses_pinned_ip_and_hostname_header(self):
        connection = self.connection(b'{"average_temperature":25.12}')
        with patch.object(client.http.client, "HTTPConnection", return_value=connection) as constructor:
            self.assertEqual(client.fetch(client.EXPECTED_IP)["peer_ip"], client.EXPECTED_IP)
        constructor.assert_called_once_with(client.EXPECTED_IP, 30503, timeout=1)
        connection.sock.settimeout.assert_called_once_with(5)
        connection.request.assert_called_once_with("GET", "/average", headers={"Host": "analytics.lab.test:30503"})
        connection.close.assert_called_once()

    def test_unexpected_connected_peer_is_rejected_before_http_request(self):
        connection = self.connection(b'{}', peer="192.0.2.10")
        with patch.object(client.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaises(OSError): client.fetch(client.EXPECTED_IP)
        connection.request.assert_not_called()

    def test_invalid_temperature_types_are_rejected(self):
        for value in (True, "25", {}, float("nan")):
            with self.subTest(value=value):
                connection = self.connection(json.dumps({"average_temperature": value}).encode())
                with patch.object(client.http.client, "HTTPConnection", return_value=connection):
                    with self.assertRaises(ValueError): client.fetch(client.EXPECTED_IP)

    def test_empty_database_average_is_valid(self):
        with patch.object(client.http.client, "HTTPConnection", return_value=self.connection(b'{"average_temperature":null}')):
            self.assertIsNone(client.fetch(client.EXPECTED_IP)["average_temperature"])

    def test_payload_size_is_bounded(self):
        with patch.object(client.http.client, "HTTPConnection", return_value=self.connection(b'x' * 65537)):
            with self.assertRaises(ValueError): client.fetch(client.EXPECTED_IP)

    def test_metrics_distinguish_dns_and_application_failure(self):
        metrics = client.Metrics()
        event = client.probe(lambda: [client.EXPECTED_IP], Mock(side_effect=OSError("Fixture")))
        metrics.observe(event)
        text = metrics.render().decode()
        self.assertIn('outcome="http_error"} 1', text)
        self.assertIn('dns_sec_resolution_expected 1', text)
        self.assertIn('dns_sec_client_last_request_success 0', text)
        self.assertNotIn("192.0.2.10", text)


class EvaluatorReadinessTests(unittest.TestCase):
    def test_transient_connection_refusal_is_retried_until_http_ready(self):
        evaluator = module("dns_evaluator_readiness", ROOT / "scripts/scenarios/02-dns-hijacking/evaluate-dns-integrity.py")
        callback = Mock(side_effect=[evaluator.urllib.error.URLError("Connection refused"), True])
        with patch.object(evaluator.time, "sleep") as pause:
            self.assertTrue(evaluator.until(callback, 10, "fixture deadline"))
        self.assertEqual(callback.call_count, 2)
        pause.assert_called_once_with(2)

    def test_unexpected_configuration_failure_is_not_hidden_by_retry(self):
        evaluator = module("dns_evaluator_readiness_fail", ROOT / "scripts/scenarios/02-dns-hijacking/evaluate-dns-integrity.py")
        with self.assertRaisesRegex(RuntimeError, "configuration failure"):
            evaluator.until(Mock(side_effect=RuntimeError("configuration failure")), 10, "fixture deadline")


class RestorationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.state, self.directory = root / "state", root / "configuration"
        self.state.mkdir(mode=0o700); self.directory.mkdir(mode=0o700)
        self.target = self.directory / "dns_sec.conf"
        self.target.write_bytes(response.APPROVED + b"# harmless fixture\n")
        self.target.chmod(0o644)
        for name, data in (("approved.conf", response.APPROVED), ("auto-restore.enabled", b"enabled\n")):
            (self.state / name).write_bytes(data)
            (self.state / name).chmod(0o600)
        self.message = {"command": "add", "parameters": {"alert": {
            "id": "1234.5678", "rule": {"id": "100141"},
            "agent": {"id": "004", "name": "dns-server-container"},
            "syscheck": {"path": str(response.TARGET)}}}}
        observation = {"outcome": "success", "peer_ip": client.EXPECTED_IP, "observed_addresses": [client.EXPECTED_IP]}
        self.runner = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(observation), ""))

    def call(self):
        return response.restore(self.message, self.target, self.state, os.getuid(), self.runner)

    def test_restore_verifies_syntax_service_and_real_client_path(self):
        self.assertEqual(self.call()["result"], "restored")
        self.assertEqual(self.target.read_bytes(), response.APPROVED)
        self.assertEqual(self.runner.call_count, 3)
        self.assertEqual(self.runner.call_args_list[0].args[0], ["/usr/sbin/dnsmasq", "--test"])
        self.assertIn("--once", self.runner.call_args_list[2].args[0])

    def test_already_approved_file_does_not_restart_or_rewrite(self):
        self.target.write_bytes(response.APPROVED)
        inode = self.target.stat().st_ino
        self.assertEqual(self.call()["result"], "already_approved")
        self.assertEqual(self.target.stat().st_ino, inode)
        self.runner.assert_not_called()

    def test_deleted_approved_file_can_be_restored(self):
        self.target.unlink()
        self.assertEqual(self.call()["result"], "restored")

    def test_wrong_agent_rule_path_or_command_cannot_restore(self):
        for part, key, value in ((self.message, "command", "delete"),
                                 (self.message["parameters"]["alert"]["agent"], "id", "002"),
                                 (self.message["parameters"]["alert"]["rule"], "id", "100140"),
                                 (self.message["parameters"]["alert"]["syscheck"], "path", "/etc/hosts")):
            old = part[key]; part[key] = value
            with self.subTest(key=key, value=value): self.assertEqual(self.call()["result"], "failed")
            part[key] = old
        self.runner.assert_not_called()
        self.assertIn(b"fixture", self.target.read_bytes())

    def test_unapproved_baseline_is_not_adopted(self):
        (self.state / "approved.conf").write_bytes(b"# unapproved local fixture\n")
        self.assertEqual(self.call()["result"], "failed")
        self.runner.assert_not_called()

    def test_writable_baseline_is_rejected(self):
        (self.state / "approved.conf").chmod(0o666)
        self.assertEqual(self.call()["result"], "failed")
        self.runner.assert_not_called()

    def test_writable_target_is_rejected(self):
        self.target.chmod(0o666)
        self.assertEqual(self.call()["result"], "failed")
        self.runner.assert_not_called()

    def test_symlink_baseline_is_rejected(self):
        baseline = self.state / "approved.conf"
        baseline.unlink(); baseline.symlink_to(self.target)
        self.assertEqual(self.call()["result"], "failed")
        self.runner.assert_not_called()

    def test_symlink_target_does_not_modify_another_file(self):
        other = self.directory / "other.conf"; other.write_bytes(b"untouched")
        self.target.unlink(); self.target.symlink_to(other)
        self.assertEqual(self.call()["result"], "failed")
        self.assertEqual(other.read_bytes(), b"untouched")
        self.runner.assert_not_called()

    def test_maintenance_disables_restoration(self):
        (self.state / "auto-restore.enabled").unlink()
        self.assertEqual(self.call()["result"], "maintenance")
        self.runner.assert_not_called()

    def test_invalid_global_configuration_is_reported_without_restart(self):
        self.runner.side_effect = subprocess.CalledProcessError(1, ["dnsmasq", "--test"])
        self.assertEqual(self.call()["result"], "failed")
        self.assertEqual(self.runner.call_count, 1)

    def test_wrong_post_restore_peer_is_a_failure(self):
        self.runner.return_value.stdout = json.dumps({"outcome": "success", "peer_ip": "192.0.2.10"})
        self.assertEqual(self.call()["result"], "failed")


if __name__ == "__main__":
    unittest.main()
