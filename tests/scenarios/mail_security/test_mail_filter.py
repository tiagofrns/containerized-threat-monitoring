"""Exercise filtering at the trusted Postfix boundary without a real scanner."""
import importlib.util
import io
from email import policy
from email.parser import BytesParser
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import mail_origin

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('mail_filter',ROOT/'security/mail_filter.py')
filter_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(filter_module)


class FilterBoundaryTests(unittest.TestCase):
    def test_forged_classification_and_origin_are_removed_before_scanning(self):
        raw=b'Message-ID: <fixture@mail.lab.test>\nFrom: forged@example.invalid\nX-Spam-Flag: NO\nX-Mail-Filter-Origin: forged\nX-Mail-Filter-Signature: forged\n\nFixture body\n'
        scanned=b'Message-ID: <fixture@mail.lab.test>\r\nX-Spam-Flag: YES\r\n\r\nFixture body\r\n'
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'key';key.write_bytes(b'fixture-only')
            with patch.object(mail_origin,'local_addresses',return_value={'10.171.72.142'}),patch.object(mail_origin,'KEY',key),patch.object(filter_module.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(raw))),patch.object(filter_module.sys,'argv',['filter','10.171.72.60','ABC123456','','security-operations@mail.lab.test']),patch.object(filter_module.subprocess,'run',side_effect=[SimpleNamespace(returncode=0,stdout=scanned),SimpleNamespace(returncode=0)]) as run:
                self.assertEqual(filter_module.main(),0)
                submitted_to_scanner=BytesParser(policy=policy.default).parsebytes(run.call_args_list[0].kwargs['input'])
                self.assertIsNone(submitted_to_scanner['X-Spam-Flag'])
                self.assertIsNone(submitted_to_scanner[mail_origin.HEADER])
                delivered=BytesParser(policy=policy.default).parsebytes(run.call_args_list[1].kwargs['input'])
                self.assertEqual(mail_origin.verified(delivered)['source_ip'],'10.171.72.60')
                self.assertEqual(run.call_args_list[1].args[0],['/usr/sbin/sendmail','-G','-i','-f','','--','security-operations@mail.lab.test'])

    def test_failed_scanner_never_reinjects_mail(self):
        with patch.object(filter_module.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'\nFixture'))),patch.object(filter_module.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=b'')) as run:
            self.assertEqual(filter_module.main(),75)
            self.assertEqual(run.call_count,1)
