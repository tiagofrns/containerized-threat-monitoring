"""Publisher tests use mocks; they do not contact the network."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


class PublisherTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("publisher_under_test", os.getenv("PUSH_PUBLISHER_SOURCE", str(Path(__file__).resolve().parents[2] / "monitoring" / "push_publisher.py")))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        response = Mock()
        response.json.return_value = {"average_temperature": 25.12}
        self.get_patch = patch.object(self.module.requests, "get", return_value=response)
        self.push_patch = patch.object(self.module, "push_to_gateway")
        self.wait_patch = patch.object(self.module.STOP, "wait", return_value=False)
        self.get = self.get_patch.start()
        self.push = self.push_patch.start()
        self.wait_patch.start()
        self.addCleanup(self.get_patch.stop)
        self.addCleanup(self.push_patch.stop)
        self.addCleanup(self.wait_patch.stop)

    def test_success_publishes_a_recent_observation(self):
        self.assertEqual(self.module.collect_and_publish(), 1)
        self.push.assert_called_once()
        self.assertEqual(self.push.call_args.kwargs["timeout"], 5)
        self.assertEqual(self.push.call_args.kwargs["grouping_key"], {"publisher": "analytics-probe"})
        self.assertGreater(self.module.OBSERVED._value.get(), 0)

    def test_failed_probe_publishes_zero_instead_of_old_success(self):
        self.get.side_effect = self.module.requests.Timeout("Test timeout")
        self.assertEqual(self.module.collect_and_publish(), 0)
        self.assertEqual(self.module.UP.labels(service="analytics")._value.get(), 0)
        self.push.assert_called_once()

    def test_retry_recovers_after_a_gateway_failure(self):
        self.push.side_effect = [OSError("Test unavailable gateway"), None]
        self.assertEqual(self.module.collect_and_publish(), 1)
        self.assertEqual(self.push.call_count, 2)
        self.assertEqual(self.module.FAILURES._value.get(), 1)

    def test_permanent_failure_has_a_bounded_number_of_attempts(self):
        self.push.side_effect = OSError("Test unavailable gateway")
        self.assertIsNone(self.module.collect_and_publish())
        self.assertEqual(self.push.call_count, 3)
        self.assertEqual(self.module.FAILURES._value.get(), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
