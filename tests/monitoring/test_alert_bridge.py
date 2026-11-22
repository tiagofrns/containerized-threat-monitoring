"""Isolated transport checks without contacting application or resolver endpoints."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import tempfile
import unittest

from alert_receiver import events, record


class AlertBridgeTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.started = self.now - timedelta(seconds=30)
        self.labels = {"alertname": "AnalyticsClientImpact", "scope": "analytics", "bridge": "wazuh"}
        self.alert = {"labels": self.labels, "status": "firing",
                      "startsAt": self.started.isoformat(),
                      "endsAt": (self.now + timedelta(minutes=1)).isoformat()}
        self.active = {"labels": self.labels, "state": "firing", "activeAt": self.started.isoformat()}

    def test_only_known_current_firing_episode_is_recorded(self):
        self.assertEqual(len(events({"alerts": [self.alert]}, [self.active], self.now)), 1)
        for alert, active in [
            (dict(self.alert, status="resolved"), self.active),
            (self.alert, dict(self.active, state="pending")),
            (self.alert, dict(self.active, activeAt=(self.now - timedelta(minutes=4)).isoformat())),
            (dict(self.alert, labels=dict(self.labels, scope="dns")), self.active),
            (dict(self.alert, endsAt=self.now.isoformat()), self.active),
        ]:
            self.assertEqual(events({"alerts": [alert]}, [active], self.now), [])

    def test_retry_receipt_survives_fresh_database_connection(self):
        rows = events({"alerts": [self.alert]}, [self.active], self.now)
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)
            db, log = path / "db", path / "out"
            self.assertEqual(record(rows, db, log, self.now), 1)
            self.assertEqual(record(rows, db, log, self.now), 0)
            self.assertEqual(json.loads(log.read_text()), rows[0])

    def test_firing_webhook_uses_zero_end_time(self):
        webhook = dict(self.alert, endsAt="0001-01-01T00:00:00Z")
        self.assertEqual(len(events({"alerts": [webhook]}, [self.active], self.now)), 1)
