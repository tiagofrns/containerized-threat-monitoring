"""Contract checks for the monitoring helpers, using no network."""
import unittest
from unittest.mock import patch

import requests
from prometheus_client import generate_latest
from prometheus_client.parser import text_string_to_metric_families

import health_exporter
import resource_exporter


def sample_value(name, labels):
    for family in text_string_to_metric_families(generate_latest().decode()):
        for sample in family.samples:
            if sample.name == name and sample.labels == labels:
                return sample.value
    raise AssertionError(f"Missing metric: {name} {labels}")


class ExporterTests(unittest.TestCase):
    def test_cpu_quantities_are_cores(self):
        self.assertEqual(resource_exporter.cpu_cores("250m"), 0.25)
        self.assertEqual(resource_exporter.cpu_cores("1000000000n"), 1.0)
        self.assertEqual(resource_exporter.cpu_cores("1000000u"), 1.0)

    def test_memory_quantities_are_bytes(self):
        self.assertEqual(resource_exporter.memory_bytes("16Mi"), 16 * 1024 * 1024)
        self.assertEqual(resource_exporter.memory_bytes("1024Ki"), 1024 * 1024)
        self.assertEqual(resource_exporter.memory_bytes("4096"), 4096)

    def check_storage_response(self, status, payload, expected):
        response = requests.Response()
        response.status_code = status
        response._content = payload
        response.url = "http://storage:5002/stats"
        with patch.object(health_exporter.requests, "get", return_value=response):
            result = health_exporter.probe("storage", "http", response.url)
        self.assertEqual(result, expected)
        self.assertEqual(sample_value("service_up", {"service": "storage", "probe": "http"}), expected)

    def test_successful_storage_is_up(self):
        self.check_storage_response(200, b'{"measurements":42,"sum_temperature":1050}', 1)

    def test_http_error_marks_storage_down(self):
        self.check_storage_response(500, b'{"error":"storage failed"}', 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
