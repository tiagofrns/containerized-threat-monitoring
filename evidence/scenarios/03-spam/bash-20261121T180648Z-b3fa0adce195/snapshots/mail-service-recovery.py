#!/usr/bin/python3
"""Observe one fixed service or handle its stateless Wazuh recovery response."""
import argparse
from email import policy
from email.parser import BytesParser
import fcntl
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

SERVICE = 'spamassassin'
AUDIT = Path('/var/log/mail-security/service-health.jsonl')
STATE = Path('/var/lib/mail-security/recovery')
INTEGRATION = 'mail_service_recovery'
COOLDOWN = 60


def service_state():
    result = subprocess.run(['/usr/bin/systemctl', 'show', SERVICE, '--property=ActiveState', '--value'],
                            capture_output=True, text=True, timeout=5, check=True)
    value = result.stdout.strip()
    if value not in {'active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'}:
        raise ValueError('Unrecognized SpamAssassin service state')
    return value


def scanner_ready():
    """Scan a benign local fixture without submitting an SMTP message."""
    result = subprocess.run(['/usr/bin/spamc', '-x', '-t', '5', '-d', '127.0.0.1'],
                            input=b'Subject: Service health check\n\nTemperature service health check.\n',
                            capture_output=True, timeout=8)
    message = BytesParser(policy=policy.default).parsebytes(result.stdout)
    return result.returncode == 0 and bool(message.get('X-Spam-Status'))


def audit(outcome, **fields):
    record = dict(integration=INTEGRATION, service=SERVICE, outcome=outcome,
                  observed_at=time.time(), **fields)
    raw = (json.dumps(record, allow_nan=False) + '\n').encode()
    fd = os.open(AUDIT, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(fd, 'wb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe service audit file')
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return record


def observe():
    state = service_state()
    if state in {'inactive', 'failed'}:
        return audit('unavailable', state=state, observation_id=uuid.uuid4().hex)
    return {'service': SERVICE, 'state': state}


def valid_alert(alert, hostname, now):
    if not isinstance(alert, dict) or any(not isinstance(alert.get(k), dict) for k in ('rule', 'agent', 'data')):
        return False
    data = alert['data']
    try:
        age = now - float(data.get('observed_at', 'nan'))
    except (TypeError, ValueError):
        return False
    return (hostname == 'mail-container' and alert['agent'].get('name') == hostname
            and str(alert['rule'].get('id')) == '100610'
            and alert.get('location') == str(AUDIT)
            and data.get('integration') == INTEGRATION and data.get('service') == SERVICE
            and data.get('outcome') == 'unavailable' and data.get('state') in {'inactive', 'failed'}
            and re.fullmatch(r'\d+\.\d+', str(alert.get('id', ''))) is not None
            and re.fullmatch(r'[0-9a-f]{32}', str(data.get('observation_id', ''))) is not None
            and math.isfinite(age) and -5 <= age <= 90)


def read_state(directory):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Recovery directory must be private and root-owned')
    path = directory / 'last-attempt.json'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Unsafe recovery state file')
        raw = stream.read(4097)
    value = json.loads(raw)
    if len(raw) > 4096 or not isinstance(value, dict):
        raise ValueError('Invalid recovery state')
    attempted = value.get('last_attempt_at')
    if type(attempted) not in (int, float) or not math.isfinite(attempted):
        raise ValueError('Invalid recovery attempt timestamp')
    return value


def save_attempt(directory, observed, now):
    with tempfile.NamedTemporaryFile(mode='w', dir=directory, delete=False) as stream:
        temporary = Path(stream.name)
        json.dump({'last_attempt_at': now, 'observation_id': observed}, stream, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, directory / 'last-attempt.json')
    finally:
        temporary.unlink(missing_ok=True)


def recover(alert, hostname, directory=STATE, now=None):
    now = time.time() if now is None else now
    if not valid_alert(alert, hostname, now):
        raise ValueError('Recovery requires a fresh local SpamAssassin outage alert')
    # Validate the directory before opening its lock, even on the first attempt.
    read_state(directory)
    fd = os.open(directory / 'response.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = read_state(directory)
        fields = {'trigger_event_id': alert['id'], 'observation_id': alert['data']['observation_id']}
        if previous and (now - previous['last_attempt_at'] < COOLDOWN
                         or previous.get('observation_id') == fields['observation_id']):
            return audit('suppressed', reason='Recovery cooldown or repeated observation', **fields)
        state = service_state()
        if state not in {'inactive', 'failed'}:
            return audit('unchanged', state=state, reason='Service is no longer stopped', **fields)
        save_attempt(directory, fields['observation_id'], now)
        try:
            subprocess.run(['/usr/bin/systemctl', 'start', SERVICE], check=True,
                           capture_output=True, timeout=30)
            for _ in range(3):
                if service_state() == 'active' and scanner_ready():
                    return audit('recovered', state='active', scanner_ready=True, **fields)
                time.sleep(1)
            return audit('recovery_failed', reason='Service did not pass the local scanner check', **fields)
        except (OSError, ValueError, subprocess.SubprocessError):
            return audit('recovery_failed', reason='Service start or health verification failed', **fields)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--check', action='store_true', help='Observe service state; never start the service')
    group.add_argument('--status', action='store_true', help='Read service, scanner and recovery cooldown state')
    args = parser.parse_args()
    if args.check:
        result = observe()
    elif args.status:
        previous = read_state(STATE)
        state = service_state()
        result = {'service': SERVICE, 'state': state, 'scanner_ready': state == 'active' and scanner_ready(),
                  'retry_after_seconds': max(0, math.ceil(COOLDOWN - (time.time() - previous['last_attempt_at']))) if previous else 0}
    else:
        raw = sys.stdin.readline(65537)
        if len(raw) > 65536:
            raise ValueError('Oversized Active Response message')
        message = json.loads(raw)
        if not isinstance(message, dict) or message.get('command') != 'add':
            raise ValueError('Only a stateless add response is supported')
        parameters = message.get('parameters')
        if not isinstance(parameters, dict):
            raise ValueError('Invalid Active Response parameters')
        result = recover(parameters.get('alert'), socket.gethostname().split('.')[0])
    print(json.dumps(result, allow_nan=False), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('[ERROR] Mail service recovery: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
