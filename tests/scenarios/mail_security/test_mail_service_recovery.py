"""Recovery policy tests use temporary files and mocked service control."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('mail_service_recovery', ROOT/'security/mail_service_recovery.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)
        self.audit = self.directory/'audit.jsonl'
        self.audit.touch(mode=0o600)
        self.addCleanup(patch.stopall)
        patch.object(recovery, 'AUDIT', self.audit).start()
        # Production requires root ownership. Preserve real modes in local tests.
        lstat, fstat = Path.lstat, os.fstat
        patch.object(Path, 'lstat', lambda path: SimpleNamespace(st_uid=0, st_mode=lstat(path).st_mode)).start()
        patch.object(os, 'fstat', lambda fd: SimpleNamespace(st_uid=0, st_mode=fstat(fd).st_mode)).start()
        self.alert = {'id': '123.456', 'rule': {'id': '100610'}, 'agent': {'name': 'mail-container'},
                      'location': str(self.audit), 'data': {'integration': recovery.INTEGRATION,
                      'service': 'spamassassin', 'outcome': 'unavailable', 'state': 'inactive',
                      'observed_at': '1000', 'observation_id': 'a'*32}}

    def test_observer_records_outage_without_service_control(self):
        with patch.object(recovery, 'service_state', return_value='inactive'), patch.object(recovery.subprocess, 'run') as run:
            row = recovery.observe()
        self.assertEqual(row['outcome'], 'unavailable')
        self.assertEqual(row['service'], 'spamassassin')
        self.assertEqual(len(row['observation_id']), 32)
        run.assert_not_called()

    def test_observer_leaves_active_service_untouched(self):
        with patch.object(recovery, 'service_state', return_value='active'):
            self.assertEqual(recovery.observe()['state'], 'active')
        self.assertEqual(self.audit.read_text(), '')

    def test_only_fresh_local_fixed_service_alert_is_accepted(self):
        self.assertTrue(recovery.valid_alert(self.alert, 'mail-container', 1010))
        for key, value in [('service', 'postfix'), ('outcome', 'recovered'), ('state', 'active'),
                           ('integration', 'other'), ('observed_at', '900'), ('observed_at', 'nan'),
                           ('observed_at', '1020'), ('observation_id', '../other')]:
            with self.subTest(key=key, value=value):
                alert = copy.deepcopy(self.alert)
                alert['data'][key] = value
                self.assertFalse(recovery.valid_alert(alert, 'mail-container', 1010))
        for key, value in [('rule', {'id': '100601'}), ('agent', {'name': 'other'}),
                           ('location', '/var/log/other'), ('id', 'arbitrary'), ('data', [])]:
            alert = dict(self.alert, **{key: value})
            self.assertFalse(recovery.valid_alert(alert, 'mail-container', 1010))
        self.assertFalse(recovery.valid_alert(self.alert, 'other', 1010))

    def test_recovery_starts_only_spamassassin_and_verifies_scan(self):
        with patch.object(recovery, 'service_state', side_effect=['inactive', 'active']), \
             patch.object(recovery, 'scanner_ready', return_value=True) as scanner, \
             patch.object(recovery.subprocess, 'run') as start:
            row = recovery.recover(self.alert, 'mail-container', self.directory, now=1010)
        start.assert_called_once_with(['/usr/bin/systemctl', 'start', 'spamassassin'], check=True,
                                      capture_output=True, timeout=30)
        scanner.assert_called_once()
        self.assertEqual(row['outcome'], 'recovered')
        self.assertEqual(row['trigger_event_id'], self.alert['id'])
        self.assertEqual(row['observation_id'], self.alert['data']['observation_id'])
        self.assertTrue(row['scanner_ready'])

    def test_an_already_active_service_is_not_restarted(self):
        with patch.object(recovery, 'service_state', return_value='active'), patch.object(recovery.subprocess, 'run') as start:
            row = recovery.recover(self.alert, 'mail-container', self.directory, now=1010)
        self.assertEqual(row['outcome'], 'unchanged')
        start.assert_not_called()

    def test_start_failure_is_audited_and_cooldown_survives_next_call(self):
        with patch.object(recovery, 'service_state', return_value='failed'), \
             patch.object(recovery.subprocess, 'run', side_effect=subprocess.TimeoutExpired('systemctl',30)) as start:
            failed = recovery.recover(self.alert, 'mail-container', self.directory, now=1010)
            later = copy.deepcopy(self.alert)
            later['data'].update(observed_at=1020, observation_id='b'*32)
            suppressed = recovery.recover(later, 'mail-container', self.directory, now=1025)
        self.assertEqual(failed['outcome'], 'recovery_failed')
        self.assertEqual(suppressed['outcome'], 'suppressed')
        start.assert_called_once()

    def test_active_without_working_scanner_is_not_success(self):
        with patch.object(recovery, 'service_state', side_effect=['inactive','active','active','active']), \
             patch.object(recovery, 'scanner_ready', return_value=False), \
             patch.object(recovery.subprocess, 'run'), patch.object(recovery.time, 'sleep'):
            row = recovery.recover(self.alert, 'mail-container', self.directory, now=1010)
        self.assertEqual(row['outcome'], 'recovery_failed')

    def test_corrupt_or_symlinked_state_prevents_service_start(self):
        state = self.directory/'last-attempt.json'
        state.write_text('not json')
        state.chmod(0o600)
        with patch.object(recovery.subprocess, 'run') as start:
            with self.assertRaises(ValueError):
                recovery.recover(self.alert, 'mail-container', self.directory, now=1010)
            state.unlink()
            state.symlink_to(self.audit)
            with self.assertRaises(OSError):
                recovery.recover(self.alert, 'mail-container', self.directory, now=1010)
        start.assert_not_called()

    def test_untrusted_directory_is_rejected(self):
        self.directory.chmod(0o777)
        with self.assertRaises(ValueError):
            recovery.read_state(self.directory)


class RecoveryWiringTests(unittest.TestCase):
    def test_location_rule_accepts_remote_agent_prefix(self):
        rules = ET.parse(ROOT/'security/wazuh-mail-rules.xml').getroot()
        base = next(rule for rule in rules if rule.get('id') == '100606')
        pattern = base.findtext('location')
        self.assertIsNotNone(re.search(pattern, '(mail-container) any->/var/log/mail-security/service-health.jsonl'))
        self.assertIsNone(re.search(pattern, '(mail-container) any->/var/log/mail-security/service-health.jsonl.old'))

    def test_response_is_stateless_local_and_only_for_outage_rule(self):
        tree = ET.parse(ROOT/'security/wazuh-mail-recovery-config.xml').getroot()
        self.assertEqual(tree.findtext('command/timeout_allowed'), 'no')
        self.assertEqual(tree.findtext('active-response/location'), 'local')
        self.assertEqual(tree.findtext('active-response/rules_id'), '100610')
        self.assertIsNone(tree.find('active-response/timeout'))

    def selector(self, mode, *args, rows):
        source = (ROOT/'scripts/scenarios/03-spam/demo/show-mail-flow.sh').read_text()
        code = source.split("json_select() {\n  python3 -c '\n",1)[1].split("\n' \"$@\"",1)[0]
        return subprocess.run(['python3','-c',code,mode,*args],
                              input='\n'.join(json.dumps(row) for row in rows),
                              text=True,capture_output=True,check=False)

    def test_flow_rejects_stale_or_unpaired_recovery(self):
        outage = {'integration': recovery.INTEGRATION, 'service': 'spamassassin',
                  'outcome':'unavailable','observation_id':'a'*32,'observed_at':1000}
        restored = dict(outage, outcome='recovered', state='active', scanner_ready=True,
                        trigger_event_id='123.456', observed_at=1010)
        result = self.selector('recovery_pair','999',rows=[outage,restored])
        self.assertEqual(json.loads(result.stdout)['recovered']['trigger_event_id'],'123.456')
        self.assertEqual(self.selector('recovery_pair','1005',rows=[outage,restored]).stdout,'')
        self.assertEqual(self.selector('recovery_pair','999',rows=[restored]).stdout,'')

    def test_flow_requires_wazuh_detection_and_response_for_same_event(self):
        detection = {'id':'123.456','agent':{'name':'mail-container'},'rule':{'id':'100610'},
                     'data':{'observation_id':'a'*32}}
        restored = {'id':'123.457','agent':{'name':'mail-container'},'rule':{'id':'100611'},
                    'data':{'observation_id':'a'*32,'trigger_event_id':'123.456'}}
        self.assertEqual(self.selector('recovery_wazuh','mail-container','a'*32,'123.456',rows=[detection,restored]).returncode,0)
        restored['data']['trigger_event_id']='other-event'
        self.assertNotEqual(self.selector('recovery_wazuh','mail-container','a'*32,'123.456',rows=[detection,restored]).returncode,0)


if __name__ == '__main__':
    unittest.main()
