import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


source = Path(__file__).resolve().parents[2] / "apps" / "ingestion.py"
spec = importlib.util.spec_from_file_location("ingestion", source)
ingestion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ingestion)


class IngestionResponseTests(unittest.TestCase):
    def setUp(self):
        self.client = ingestion.app.test_client()
        self.payload = {"device_id": "regression-test", "temperature": 25}

    def post_with_storage_status(self, status):
        with patch.object(
            ingestion.requests, "post",
            return_value=SimpleNamespace(status_code=status),
        ):
            return self.client.post("/ingest", json=self.payload)

    def test_confirms_a_successful_write(self):
        response = self.post_with_storage_status(200)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"stored": True})

    def test_rejects_a_storage_client_error(self):
        response = self.post_with_storage_status(400)
        self.assertEqual(response.status_code, 400)
        self.assertIs(response.get_json()["stored"], False)

    def test_rejects_a_storage_server_error(self):
        response = self.post_with_storage_status(500)
        self.assertEqual(response.status_code, 500)
        self.assertIs(response.get_json()["stored"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
