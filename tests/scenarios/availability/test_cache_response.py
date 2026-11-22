"""Local response controls; no Wazuh daemon or network connection is used."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

SOURCE = Path(os.getenv('CACHE_RESPONSE_SOURCE',
              str(Path(__file__).resolve().parents[3]/'security'/'analytics-cache.py')))
spec = importlib.util.spec_from_file_location('cache_response', SOURCE)
response = importlib.util.module_from_spec(spec)
spec.loader.exec_module(response)

ALERT = {'id': '123.4', 'rule': {'id': '100121'}, 'agent': {'name': 'k3s-node1'},
         'location': '/var/log/pods/ssle_analytics-test_uuid/analytics/5.log',
         'data': {'http': {'method': 'GET', 'status_code': '429'}, 'url': '/average?source=test'}}


class ResponseTests(unittest.TestCase):
    def test_expected_alert_is_accepted(self):
        self.assertTrue(response.valid_alert(ALERT, 'k3s-node1'))

    def test_other_rule_service_node_and_request_are_rejected(self):
        for key, value in [('rule', {'id': '199999'}), ('agent', {'name': 'unrelated-agent'}),
                           ('location', '/var/log/pods/ssle_storage-test/storage/1.log'),
                           ('id', '../bad'), ('data', {'http': {'status_code': '200'}, 'url': '/average'}),
                           ('rule', None), ('data', [])]:
            with self.subTest(key=key, value=value):
                alert = copy.deepcopy(ALERT)
                alert[key] = value
                self.assertFalse(response.valid_alert(alert, 'k3s-node1'))
        self.assertFalse(response.valid_alert(ALERT, 'k3s-master'))

    def test_duplicate_does_not_extend_and_old_delete_cannot_remove_new_lease(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            actual_lstat, actual_fstat = Path.lstat, os.fstat
            def owned(info):
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
            with patch.object(Path, 'lstat', lambda p: owned(actual_lstat(p))), \
                 patch.object(os, 'fstat', lambda fd: owned(actual_fstat(fd))):
                self.assertEqual(response.apply('add', ALERT, directory, now=100)['result'], 'enabled')
                original = json.loads((directory/'cache.json').read_text())
                newer = dict(ALERT, id='123.5')
                self.assertEqual(response.apply('add', newer, directory, now=110)['result'], 'unchanged')
                self.assertEqual(json.loads((directory/'cache.json').read_text()), original)
                self.assertEqual(response.apply('delete', newer, directory, now=111)['result'], 'unchanged')
                self.assertEqual(response.apply('delete', ALERT, directory, now=112)['result'], 'disabled')
                self.assertFalse((directory/'cache.json').exists())

    def test_untrusted_control_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40777, st_uid=0)):
                with self.assertRaises(ValueError):
                    response.apply('add', ALERT, Path(temp), now=100)

    def test_bridge_requires_expected_source_and_shares_recent_activation_guard(self):
        bridge = {
            'id': '123.5', 'rule': {'id': '100150'},
            'agent': {'id': '005', 'name': 'prometheus-container'},
            'location': '/var/log/alert-bridge/events.jsonl',
            'data': {'integration': 'alert_bridge', 'alert_name': 'AnalyticsClientImpact',
                     'scope': 'analytics', 'bridge_state': 'firing', 'episode': 'a' * 64,
                     'observed_at': datetime.now(timezone.utc).isoformat()},
        }
        self.assertTrue(response.valid_alert(bridge, 'k3s-node1'))
        self.assertFalse(response.valid_alert(bridge, 'k3s-master'))
        self.assertFalse(response.valid_alert(dict(bridge, agent={'id': '003'}), 'k3s-node1'))
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            lstat, fstat = Path.lstat, os.fstat
            with patch.object(response, 'CONTROL_DIR', directory), \
                 patch.object(Path, 'lstat', lambda p: SimpleNamespace(st_uid=0, st_mode=lstat(p).st_mode)), \
                 patch.object(os, 'fstat', lambda fd: SimpleNamespace(st_uid=0, st_mode=fstat(fd).st_mode)), \
                 patch.object(response, 'apply', return_value={'result': 'enabled'}) as apply, \
                 patch.object(response, 'bridge_target_ready', return_value=False) as ready:
                response.locked_apply('add', ALERT)
                self.assertEqual(response.locked_apply('add', bridge)['reason'], 'Recent cache activation')
                apply.assert_called_once_with('add', ALERT)
                ready.assert_not_called()
                (directory / '.response.lock').write_text('')
                self.assertIn('not confirmed', response.locked_apply('add', bridge)['reason'])
                apply.assert_called_once()


if __name__ == '__main__':
    unittest.main()
