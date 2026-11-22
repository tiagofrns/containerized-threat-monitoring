#!/usr/bin/python3
"""Authenticated alert notifications and delivery observations for a local mailbox."""
from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime
import fcntl
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import smtplib
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from mail_origin import verified

STATE = Path('/var/lib/mail-security')
AUDIT = Path('/var/log/mail-security/events.jsonl')
MAILDIR = Path('/home/security-operations/Maildir')
RECIPIENT = 'security-operations@mail.lab.test'
ALERTS = {'AnalyticsClientImpact', 'DNSPolicyRejections', 'ServiceHealthCheckFailed', 'MailQuarantineActivity'}
DISPLAY = {'ServiceHealthCheckFailed': 'Service health check failed',
           'AnalyticsClientImpact': 'Analytics service degradation',
           'DNSPolicyRejections': 'DNS policy violations',
           'MailQuarantineActivity': 'Mail quarantine activity'}
PROMETHEUS = os.environ.get('MAIL_PROMETHEUS_URL', 'http://10.255.255.21:9090')
LOCK = threading.RLock()


def now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection():
    conn = sqlite3.connect(STATE / 'events.db', timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.executescript('''CREATE TABLE IF NOT EXISTS deliveries
        (digest TEXT PRIMARY KEY, folder TEXT NOT NULL, message_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events
        (id INTEGER PRIMARY KEY, payload TEXT NOT NULL, logged INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS notifications
        (episode TEXT PRIMARY KEY, status TEXT NOT NULL, message_id TEXT NOT NULL);''')
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def event(conn, outcome, **fields):
    record = dict(integration='mail_security', outcome=outcome, timestamp=now(), **fields)
    conn.execute('INSERT INTO events(payload) VALUES (?)', (json.dumps(record),))


def flush(conn):
    # Events remain in the durable ledger until appended. A crash can replay a
    # record with the same event_id, which downstream consumers can deduplicate.
    for row in conn.execute('SELECT id,payload FROM events WHERE logged=0 ORDER BY id').fetchall():
        record = dict(json.loads(row['payload']), event_id=str(row['id']))
        with AUDIT.open('a') as stream:
            stream.write(json.dumps(record) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        conn.execute('UPDATE events SET logged=1 WHERE id=?', (row['id'],))
        conn.commit()


@contextmanager
def mailbox_lock():
    with (STATE / 'mailbox.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def observe():
    with LOCK, mailbox_lock(), connection() as conn:
        for folder, directory in (('INBOX', MAILDIR), ('Quarantine', MAILDIR / '.Quarantine')):
            for location in ('new', 'cur'):
                for file in sorted((directory / location).glob('*')):
                    if not file.is_file() or file.is_symlink():
                        continue
                    try:
                        raw = file.read_bytes()
                    except FileNotFoundError:
                        continue
                    digest = hashlib.sha256(raw).hexdigest()
                    message = BytesParser(policy=policy.default).parsebytes(raw)
                    identifier = str(message.get('Message-ID', '')).strip()[:250]
                    previous = conn.execute('SELECT folder FROM deliveries WHERE digest=?', (digest,)).fetchone()
                    if previous is None:
                        conn.execute('INSERT INTO deliveries VALUES (?,?,?)', (digest, folder, identifier))
                        event(conn, 'quarantined' if folder == 'Quarantine' else 'delivered',
                              message_id=identifier, digest=digest, folder=folder,
                              spam_status=' '.join(str(message.get('X-Spam-Status', '')).split())[:500],
                              **(verified(message) if folder == 'Quarantine' else {}))
                    elif previous['folder'] != folder:
                        conn.execute('UPDATE deliveries SET folder=? WHERE digest=?', (folder, digest))
                        event(conn, 'released' if folder == 'INBOX' else 'quarantined',
                              message_id=identifier, digest=digest, folder=folder)
        conn.commit()
        flush(conn)


def parse_time(value):
    # Python 3.10 accepts microseconds. Prometheus can return nanoseconds.
    normalized = re.sub(r'(\.\d{6})\d+', r'\1', value.replace('Z', '+00:00'))
    return datetime.fromisoformat(normalized)


def notify(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('alerts', []), list):
        raise ValueError('Invalid notification payload')
    if payload.get('status') != 'firing':
        return 0
    with urllib.request.urlopen(PROMETHEUS + '/api/v1/alerts', timeout=5) as response:
        active = json.load(response)['data']['alerts']
    sent = 0
    for alert in payload.get('alerts', []):
        if not isinstance(alert, dict) or not isinstance(alert.get('labels', {}), dict):
            raise ValueError('Invalid notification alert')
        labels = alert.get('labels', {})
        name = labels.get('alertname')
        if name not in ALERTS or alert.get('status') != 'firing':
            continue
        match = next((entry for entry in active if entry['state'] == 'firing' and entry['labels'] == labels), None)
        if match is None:
            raise ValueError('Notification does not match an active Prometheus alert')
        start = parse_time(alert['startsAt'])
        observed = parse_time(match['activeAt'])
        # Alertmanager startsAt is the firing time, after the configured pending period.
        if not -1 <= (start - observed).total_seconds() <= 60:
            raise ValueError('Notification activation time does not match Prometheus')
        episode = hashlib.sha256(json.dumps([labels, match['activeAt']], sort_keys=True).encode()).hexdigest()
        identifier = f'<incident-{episode}@mail.lab.test>'
        with LOCK, connection() as conn:
            added = conn.execute('INSERT OR IGNORE INTO notifications VALUES (?,?,?)',
                                 (episode, 'pending', identifier)).rowcount
            conn.commit()
            if not added:
                previous = conn.execute('SELECT status FROM notifications WHERE episode=?', (episode,)).fetchone()
                if previous['status'] != 'submitted':
                    raise ValueError('An earlier SMTP attempt requires operator review')
                continue
        message = EmailMessage()
        message['From'] = 'Monitoring Service <monitoring@mail.lab.test>'
        message['To'] = RECIPIENT
        message['Date'] = format_datetime(datetime.now(timezone.utc))
        message['Message-ID'] = identifier
        message['Subject'] = '[Security Operations] ' + DISPLAY[name]
        body = ['Dear Security Operations Team,', '',
                'Monitoring has detected a condition requiring review.', '',
                'Incident: ' + DISPLAY[name], 'Severity: ' + labels.get('severity', 'warning'),
                'Detected at: ' + match['activeAt'],
                'Affected target: ' + labels.get('instance', labels.get('service', 'application platform')), '']
        if name in {'AnalyticsClientImpact', 'DNSPolicyRejections'}:
            body += ['This alert is configured for forwarding to Wazuh. Confirm the response outcome',
                     'in the security event record before concluding that remediation completed.', '']
        body += ['Please review the monitoring dashboard and the associated security events.', '',
                 'Regards,', 'Monitoring Service']
        message.set_content('\n'.join(body))
        try:
            with smtplib.SMTP('127.0.0.1', 25, timeout=8) as smtp:
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException):
            # Preserve ambiguous SMTP results for operator review instead of
            # automatically duplicating a message after a lost acknowledgement.
            with LOCK, connection() as conn:
                conn.execute('UPDATE notifications SET status=? WHERE episode=?', ('uncertain', episode))
                event(conn, 'notification_failed', episode=episode, message_id=identifier)
                conn.commit()
                flush(conn)
            raise
        with LOCK, connection() as conn:
            conn.execute('UPDATE notifications SET status=? WHERE episode=?', ('submitted', episode))
            event(conn, 'notification_submitted', episode=episode, message_id=identifier,
                  alert_title=DISPLAY[name])
            conn.commit()
            flush(conn)
        sent += 1
    return sent


def metrics():
    observe()
    with LOCK, connection() as conn:
        records = [json.loads(row[0]) for row in conn.execute('SELECT payload FROM events')]
        lines = ['# TYPE mail_security_events_total counter']
        for outcome in ('delivered', 'quarantined', 'released', 'notification_submitted', 'notification_failed'):
            lines.append(f'mail_security_events_total{{outcome="{outcome}"}} {sum(r["outcome"] == outcome for r in records)}')
        lines.append('# TYPE mail_quarantine_messages gauge')
        lines.append('mail_quarantine_messages ' + str(sum(1 for location in ('new', 'cur') for file in (MAILDIR / '.Quarantine' / location).glob('*') if file.is_file())))
        return ('\n'.join(lines) + '\n').encode()


def release(digest):
    if not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('Expected a quarantined message SHA-256')
    observe()
    with LOCK, mailbox_lock(), connection() as conn:
        row = conn.execute('SELECT * FROM deliveries WHERE digest=?', (digest,)).fetchone()
        if row is None:
            raise ValueError('Unknown message')
        if row['folder'] == 'INBOX':
            return
        matches = []
        for location in ('new', 'cur'):
            for file in (MAILDIR / '.Quarantine' / location).glob('*'):
                if file.is_file() and hashlib.sha256(file.read_bytes()).hexdigest() == digest:
                    matches.append(file)
        if len(matches) != 1:
            raise ValueError('Expected exactly one quarantined message')
        file = matches[0]
        destination = MAILDIR / 'new' / file.name
        # Link and unlink keep the release within one filesystem. The hard link
        # makes an interrupted move retryable without creating another copy.
        try:
            os.link(file, destination)
        except FileExistsError:
            if not os.path.samefile(file, destination):
                raise ValueError('Release destination already exists')
        file.unlink()
    observe()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/metrics':
            self.send_error(404)
            return
        data = metrics()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        expected = 'Bearer ' + Path('/etc/mail-security/webhook-secret').read_text().strip()
        if not hmac.compare_digest(self.headers.get('Authorization', ''), expected):
            self.send_error(401)
            return
        if self.path != '/alerts':
            self.send_error(404)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 65536:
                raise ValueError('Invalid payload length')
            payload = json.loads(self.rfile.read(length))
            sent = notify(payload)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({'submitted': sent}).encode())
        except (ValueError, KeyError, TypeError, OSError, smtplib.SMTPException):
            self.send_error(503, 'Notification could not be verified or submitted')

    def log_message(self, *_):
        pass


def main():
    if sys.argv[1:2] == ['release'] and len(sys.argv) == 3:
        release(sys.argv[2])
        return
    if sys.argv[1:] == ['observe']:
        observe()
        return
    server = ThreadingHTTPServer(('0.0.0.0', 9096), Handler)
    server.serve_forever()


if __name__ == '__main__':
    main()
