"""Trusted connection metadata must survive delivery and reject sender forgery."""
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import mail_origin


class OriginTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        key=Path(self.temp.name)/'key';key.write_bytes(b'fixture-key-only')
        self.patch=patch.object(mail_origin,'KEY',key);self.patch.start();self.addCleanup(self.patch.stop)
        self.local_patch=patch.object(mail_origin,'local_addresses',return_value={'10.171.72.142'})
        self.local_patch.start();self.addCleanup(self.local_patch.stop)
        self.message=EmailMessage(policy=policy.SMTP)
        self.message['Message-ID']='<fixture@mail.lab.test>'
        self.message['X-Spam-Flag']='YES'
        self.message.set_content('GTUBE fixture body')

    def test_signed_source_survives_smtp_and_maildir_line_endings(self):
        self.message=BytesParser(policy=policy.SMTP).parsebytes(self.message.as_bytes())
        mail_origin.attach(self.message,'10.171.72.60','ABC123456')
        delivered=BytesParser(policy=policy.default).parsebytes(self.message.as_bytes().replace(b'\r\n',b'\n'))
        self.assertEqual(mail_origin.verified(delivered),{'source_ip':'10.171.72.60','smtp_queue_id':'ABC123456','source_verified':'yes','srcip':'10.171.72.60','source_blockable':'yes'})

    def test_unsigned_sender_headers_do_not_provide_a_trusted_source(self):
        self.message[mail_origin.HEADER]='forged'
        self.message[mail_origin.SIGNATURE]='0'*64
        self.assertEqual(mail_origin.verified(self.message),{})

    def test_body_or_message_identifier_changes_invalidate_origin(self):
        mail_origin.attach(self.message,'10.171.72.60','ABC123456')
        self.message.replace_header('Message-ID','<changed@mail.lab.test>')
        self.assertEqual(mail_origin.verified(self.message),{})
        self.message.replace_header('Message-ID','<fixture@mail.lab.test>')
        self.message.set_content('Different content')
        self.assertEqual(mail_origin.verified(self.message),{})

    def test_duplicate_trust_headers_are_rejected(self):
        mail_origin.attach(self.message,'10.171.72.60','ABC123456')
        self.message[mail_origin.HEADER]=self.message[mail_origin.HEADER]
        self.assertEqual(mail_origin.verified(self.message),{})

    def test_legitimate_mail_is_never_verified_as_quarantined_spam(self):
        self.message.replace_header('X-Spam-Flag','NO')
        mail_origin.attach(self.message,'10.171.72.60','ABC123456')
        self.assertEqual(mail_origin.verified(self.message),{})

    def test_unknown_local_submission_does_not_invent_a_network_source(self):
        mail_origin.attach(self.message,'unknown','ABC123456')
        self.assertNotIn(mail_origin.HEADER,self.message)

    def test_source_is_dynamic_across_distinct_remote_addresses(self):
        for address in ('10.171.72.61','192.0.2.73'):
            message=EmailMessage();message['Message-ID']='<dynamic@mail.lab.test>'
            message['X-Spam-Flag']='YES';message.set_content('Fixture body')
            mail_origin.attach(message,address,'ABC123456')
            result=mail_origin.verified(message)
            self.assertEqual(result['srcip'],address)
            self.assertEqual(result['source_blockable'],'yes')

    def test_loopback_and_server_addresses_cannot_request_containment(self):
        for address in ('127.0.0.1','127.0.1.1','10.171.72.142','0.0.0.0','224.0.0.1','169.254.1.1'):
            self.assertFalse(mail_origin.blockable(address),address)

    def test_address_discovery_failure_disables_containment(self):
        with patch.object(mail_origin,'local_addresses',side_effect=OSError('fixture')):
            self.assertFalse(mail_origin.blockable('10.171.72.61'))
