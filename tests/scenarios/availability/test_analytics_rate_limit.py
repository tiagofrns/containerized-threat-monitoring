"""Defensive policy tests. Requests stay inside Flask; storage calls are mocked."""
import importlib.util
import os
from pathlib import Path
import time
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(os.getenv("ANALYTICS_SOURCE", str(Path(__file__).resolve().parents[3] / "apps" / "analytics.py")))


def load_application(enabled=True):
    spec = importlib.util.spec_from_file_location("analytics_under_test", SOURCE)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, {"ANALYTICS_RATE_LIMIT_ENABLED": str(enabled).lower()}):
        spec.loader.exec_module(module)
    return module


def compare_independent_source_policy():
    """Compare bounded in-process requests; every storage call is mocked."""
    cases = []
    for enabled in (False, True):
        module = load_application(enabled=enabled)
        client = module.app.test_client()
        response = Mock()
        response.json.return_value = {"measurements": 4, "sum_temperature": 100}
        started = time.monotonic()
        with patch.object(module.requests, "get", return_value=response) as storage:
            busy = [
                client.get("/average", environ_overrides={"REMOTE_ADDR": "192.0.2.10"})
                for _ in range(20)
            ]
            independent = client.get(
                "/average", environ_overrides={"REMOTE_ADDR": "192.0.2.11"}
            )
        elapsed = time.monotonic() - started
        if elapsed >= 1:
            raise AssertionError("Comparison exceeded the one-second policy window")
        cases.append({
            "policy_enabled": enabled,
            "same_source_requests": 20,
            "same_source_http_200": sum(r.status_code == 200 for r in busy),
            "same_source_http_429": sum(r.status_code == 429 for r in busy),
            "independent_source_status": independent.status_code,
            "mocked_storage_calls": storage.call_count,
        })
    return cases


class AnalyticsRateLimitTests(unittest.TestCase):
    def setUp(self):
        self.module = load_application()
        self.client = self.module.app.test_client()
        response = Mock()
        response.json.return_value = {"measurements": 4, "sum_temperature": 100}
        self.storage_patch = patch.object(self.module.requests, "get", return_value=response)
        self.storage = self.storage_patch.start()
        self.addCleanup(self.storage_patch.stop)

    def get_average(self, address="192.0.2.10", headers=None):
        return self.client.get("/average",
            environ_overrides={"REMOTE_ADDR": address}, headers=headers or {})

    def test_sixth_request_is_rejected_before_storage(self):
        responses = [self.get_average() for _ in range(6)]
        self.assertEqual([r.status_code for r in responses], [200] * 5 + [429])
        self.assertEqual(self.storage.call_count, 5)
        self.assertEqual(responses[-1].get_json(), {"error": "Too many requests"})
        self.assertIn("Retry-After", responses[-1].headers)

    def test_another_source_keeps_its_own_budget(self):
        for _ in range(6):
            self.get_average()
        self.assertEqual(self.get_average("192.0.2.11").status_code, 200)

    def test_untrusted_forwarded_header_does_not_change_the_key(self):
        responses = [
            self.get_average(headers={"X-Forwarded-For": "192.0.2." + str(i)})
            for i in range(1, 7)
        ]
        self.assertEqual([r.status_code for r in responses], [200] * 5 + [429])

    def test_budget_recovers_after_the_window(self):
        for _ in range(6):
            self.get_average()
        time.sleep(1.05)
        self.assertEqual(self.get_average().status_code, 200)

    def test_disabled_policy_is_a_functional_control(self):
        module = load_application(enabled=False)
        client = module.app.test_client()
        responses = [client.get("/average") for _ in range(6)]
        self.assertEqual([r.status_code for r in responses], [200] * 6)
        self.assertEqual(self.storage.call_count, 6)

    def test_storage_failure_still_returns_502(self):
        self.storage.side_effect = self.module.requests.Timeout("Test timeout")
        self.assertEqual(self.get_average().status_code, 502)

    def test_metrics_distinguish_received_and_forwarded_requests(self):
        for _ in range(6):
            self.get_average()
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn('analytics_requests_total{status="200"} 5.0', text)
        self.assertIn('analytics_requests_total{status="429"} 1.0', text)
        self.assertIn("analytics_storage_requests_total 5.0", text)
        self.assertEqual(self.storage.call_count, 5)

    def test_policy_sheds_downstream_work_and_preserves_an_independent_source(self):
        without_policy, with_policy = compare_independent_source_policy()
        self.assertEqual(without_policy["same_source_http_200"], 20)
        self.assertEqual(without_policy["same_source_http_429"], 0)
        self.assertEqual(without_policy["mocked_storage_calls"], 21)
        self.assertEqual(with_policy["same_source_http_200"], 5)
        self.assertEqual(with_policy["same_source_http_429"], 15)
        self.assertEqual(with_policy["mocked_storage_calls"], 6)
        self.assertEqual(without_policy["independent_source_status"], 200)
        self.assertEqual(with_policy["independent_source_status"], 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
