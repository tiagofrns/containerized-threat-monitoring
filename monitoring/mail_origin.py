"""Authenticate Postfix connection metadata carried through local delivery."""
import base64
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import subprocess

KEY = Path('/etc/mail-security/origin-key')
HEADER = 'X-Mail-Filter-Origin'
SIGNATURE = 'X-Mail-Filter-Signature'


def body_digest(message):
    return hashlib.sha256(b'\0'.join((part.get_payload(decode=True) or b'').replace(b'\r\n', b'\n')
                                    for part in message.walk())).hexdigest()


def attach(message, address, queue_id):
    try:
        address = str(ipaddress.IPv4Address(address))
    except ipaddress.AddressValueError:
        return
    if not re.fullmatch(r'[A-Za-z0-9]{5,80}', queue_id):
        raise ValueError('Invalid Postfix queue identifier')
    record = {'source_ip': address, 'smtp_queue_id': queue_id,
              'message_id': str(message.get('Message-ID', '')),
              'spam': str(message.get('X-Spam-Flag', '')).strip().upper() == 'YES',
              'body_sha256': body_digest(message)}
    payload = base64.b64encode(json.dumps(record, sort_keys=True).encode()).decode()
    message[HEADER] = payload
    message[SIGNATURE] = hmac.new(KEY.read_bytes(), payload.encode(), hashlib.sha256).hexdigest()


def local_addresses():
    result = subprocess.check_output(['/usr/sbin/ip', '-j', '-4', 'address', 'show'],
                                     text=True, timeout=2)
    return {info['local'] for interface in json.loads(result)
            for info in interface.get('addr_info', []) if info.get('family') == 'inet'}


def blockable(address):
    ip = ipaddress.IPv4Address(address)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        return False
    try:
        return str(ip) not in local_addresses()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # If local addresses cannot be established, retain classification without containment.
        return False


def verified(message):
    if len(message.get_all(HEADER, [])) != 1 or len(message.get_all(SIGNATURE, [])) != 1:
        return {}
    payload = str(message[HEADER]).replace(' ', '').replace('\r', '').replace('\n', '')
    try:
        expected = hmac.new(KEY.read_bytes(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(message[SIGNATURE]).strip()):
            return {}
        record = json.loads(base64.b64decode(payload, validate=True))
        ipaddress.IPv4Address(record['source_ip'])
        if (record['message_id'] != str(message.get('Message-ID', ''))
                or record['body_sha256'] != body_digest(message)
                or record['spam'] is not True):
            return {}
        return {'source_ip': record['source_ip'], 'smtp_queue_id': record['smtp_queue_id'],
                'source_verified': 'yes', 'srcip': record['source_ip'],
                'source_blockable': 'yes' if blockable(record['source_ip']) else 'no'}
    except (OSError, ValueError, KeyError, TypeError):
        return {}
