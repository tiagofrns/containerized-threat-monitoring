"""Regression controls for observed mailbox state and SMTP duplicate handling."""
import importlib.util
from email.message import EmailMessage
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('mail_gateway', ROOT / 'monitoring/mail_gateway.py')
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class MailGatewayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        gateway.STATE = root / 'state'
        gateway.STATE.mkdir()
        gateway.MAILDIR = root / 'mail'
        gateway.AUDIT = root / 'audit.jsonl'
        for folder in ('new','cur','.Quarantine/new','.Quarantine/cur'):
            (gateway.MAILDIR / folder).mkdir(parents=True)
        message = EmailMessage()
        message['Message-ID'] = '<fixture@mail.lab.test>'
        message.set_content('Local test message')
        self.file = gateway.MAILDIR / '.Quarantine/new/message'
        self.file.write_bytes(message.as_bytes())

    def test_observation_release_and_retry_record_each_transition_once(self):
        gateway.observe()
        gateway.observe()
        rows = [json.loads(line) for line in gateway.AUDIT.read_text().splitlines()]
        self.assertEqual([r['outcome'] for r in rows], ['quarantined'])
        digest = rows[0]['digest']
        gateway.release(digest)
        gateway.release(digest)
        rows = [json.loads(line) for line in gateway.AUDIT.read_text().splitlines()]
        self.assertEqual([r['outcome'] for r in rows], ['quarantined','released'])
        self.assertTrue((gateway.MAILDIR / 'new/message').is_file())
        self.assertFalse(self.file.exists())

    def test_unknown_release_does_not_move_messages(self):
        with self.assertRaisesRegex(ValueError, 'Unknown message'):
            gateway.release('a' * 64)
        self.assertTrue(self.file.exists())

    def test_unverified_notification_cannot_submit_mail(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data":{"alerts":[]}}'
        with patch.object(gateway.urllib.request, 'urlopen', return_value=response), patch.object(gateway.smtplib, 'SMTP') as smtp:
            with self.assertRaisesRegex(ValueError, 'active Prometheus'):
                gateway.notify({'status':'firing','alerts':[{'status':'firing','labels':{'alertname':'MailQuarantineActivity'}}]})
        smtp.assert_not_called()

    def test_duplicate_verified_episode_submits_only_one_message(self):
        active = {'labels': {'alertname': 'MailQuarantineActivity'}, 'state': 'firing',
                  'activeAt': '2026-11-21T13:31:05.003950993Z'}
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({'data':{'alerts':[active]}}).encode()
        payload = {'status':'firing','alerts':[{'labels':active['labels'],'status':'firing',
                    'startsAt':'2026-11-21T13:31:20.003Z'}]}
        with patch.object(gateway.urllib.request, 'urlopen', return_value=response), patch.object(gateway.smtplib, 'SMTP') as smtp:
            self.assertEqual(gateway.notify(payload), 1)
            self.assertEqual(gateway.notify(payload), 0)
        smtp.return_value.__enter__.return_value.send_message.assert_called_once()

    def test_ambiguous_smtp_failure_stays_visible_on_retry(self):
        active = {'labels': {'alertname': 'MailQuarantineActivity'}, 'state': 'firing',
                  'activeAt': '2026-11-21T13:31:05Z'}
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({'data':{'alerts':[active]}}).encode()
        payload = {'status':'firing','alerts':[{'labels':active['labels'],'status':'firing',
                    'startsAt':active['activeAt']}]}
        with patch.object(gateway.urllib.request, 'urlopen', return_value=response), patch.object(gateway.smtplib, 'SMTP', side_effect=OSError('Fixture connection loss')) as smtp:
            with self.assertRaises(OSError):
                gateway.notify(payload)
            with self.assertRaisesRegex(ValueError, 'operator review'):
                gateway.notify(payload)
        self.assertEqual(smtp.call_count, 1)
        self.assertIn('notification_failed', gateway.AUDIT.read_text())

    def test_prometheus_nanoseconds_are_accepted_on_supported_python(self):
        parsed = gateway.parse_time('2026-11-21T13:31:05.003950993Z')
        self.assertEqual(parsed.microsecond, 3950)
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)

    def test_invalid_payload_is_rejected(self):
        for payload in ([], {'status':'firing','alerts':None}):
            with self.assertRaises(ValueError):
                gateway.notify(payload)


if __name__ == '__main__':
    unittest.main()
