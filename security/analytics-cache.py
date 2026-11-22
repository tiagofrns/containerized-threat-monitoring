#!/usr/bin/python3
"""A bounded, local Wazuh response. No network calls or arbitrary commands."""
from datetime import datetime, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import re
import select
import socket
import stat
import subprocess
import sys
import tempfile
import time

CONTROL_DIR = Path('/var/lib/analytics-protection/analytics')
LOG = Path('/var/ossec/logs/active-responses.log')
SECONDS = 60
KEY = 'analytics-cache'
BRIDGE_LOG = '/var/log/alert-bridge/events.jsonl'


def bridge_alert(alert, hostname):
    return (
        hostname == 'k3s-node1'
        and str(alert['agent'].get('id')) == '005'
        and alert['agent'].get('name') == 'prometheus-container'
        and alert.get('location') == BRIDGE_LOG
        and alert['data'].get('integration') == 'alert_bridge'
        and alert['data'].get('alert_name') == 'AnalyticsClientImpact'
        and alert['data'].get('scope') == 'analytics'
        and alert['data'].get('bridge_state') == 'firing'
        and re.fullmatch(r'[0-9a-f]{64}', str(alert['data'].get('episode', ''))) is not None
        and re.fullmatch(r'\d+\.\d+', str(alert.get('id', ''))) is not None
    )


def valid_alert(alert, hostname):
    if not isinstance(alert, dict):
        return False
    if any(not isinstance(alert.get(key), dict) for key in ('rule', 'agent', 'data')):
        return False
    if str(alert['rule'].get('id')) == '100150':
        return bridge_alert(alert, hostname)
    if not isinstance(alert['data'].get('http'), dict):
        return False
    return (
        isinstance(alert, dict)
        and str(alert.get('rule', {}).get('id')) == '100121'
        and alert.get('agent', {}).get('name') == hostname
        and hostname in ('k3s-master', 'k3s-node1')
        and re.fullmatch(r'\d+\.\d+', str(alert.get('id', ''))) is not None
        and re.fullmatch(r'/var/log/pods/ssle_analytics-[^/]+/analytics/\d+\.log',
                         str(alert.get('location', ''))) is not None
        and alert.get('data', {}).get('http', {}).get('method') == 'GET'
        and str(alert.get('data', {}).get('http', {}).get('status_code')) == '429'
        and re.fullmatch(r'/average(?:\?[^\r\n]*)?', str(alert.get('data', {}).get('url', ''))) is not None
    )


def apply(command, alert, directory=CONTROL_DIR, now=None):
    now = time.time() if now is None else now
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Control directory must be root-owned and not writable by other users')
    path = directory/'cache.json'
    current = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Unsafe control file')
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ValueError('Oversized lease')
        current = json.loads(raw)
        if not isinstance(current, dict):
            current = None
    except FileNotFoundError:
        pass
    except json.JSONDecodeError:
        current = None

    if command == 'delete':
        if current and current.get('event_id') == alert['id']:
            path.unlink()
            return {'result': 'disabled'}
        return {'result': 'unchanged', 'reason': 'No matching lease to remove'}
    if command != 'add':
        raise ValueError('Unsupported command')
    expiry = current.get('expires_at') if current else None
    if type(expiry) in (int, float) and math.isfinite(expiry) and now < expiry <= now + SECONDS:
        return {'result': 'unchanged', 'reason': 'Existing active lease was not extended'}
    lease = {'version': 1, 'mode': 'cache', 'event_id': alert['id'],
             'issued_at': now, 'expires_at': now + SECONDS}
    fd, temporary = tempfile.mkstemp(prefix='.lease-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(lease, stream)
            stream.write('\n')
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {'result': 'enabled', 'expires_at': lease['expires_at']}


def log_result(action, alert, result):
    event = {'timestamp': datetime.now(timezone.utc).isoformat(), 'integration': KEY,
             'action': action, 'event_id': str(alert.get('id', '')),
             'rule_id': str(alert.get('rule', {}).get('id', '')),
             'node': socket.gethostname(), **result}
    if event['rule_id'] == '100150':
        event['bridge_episode'] = alert.get('data', {}).get('episode')
    with LOG.open('a') as stream:
        stream.write(json.dumps(event, ensure_ascii=True)+'\n')


def bridge_target_ready():
    result = subprocess.run(
        ['/usr/local/bin/k3s', 'crictl', 'ps', '--label', 'io.kubernetes.container.name=analytics',
         '--name', '^analytics$', '--state', 'Running', '-o', 'json'],
        capture_output=True, timeout=4, check=True)
    matching = [c for c in json.loads(result.stdout)['containers']
                if c.get('labels', {}).get('io.kubernetes.pod.namespace') == 'ssle'
                and c.get('labels', {}).get('io.kubernetes.pod.name', '').startswith('analytics-')]
    return len(matching) == 1


def locked_apply(action, alert):
    info = CONTROL_DIR.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Unsafe control directory')
    fd = os.open(CONTROL_DIR / '.response.lock',
                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe response lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'add' and str(alert['rule']['id']) == '100150':
            last = lock.read(64).strip()
            if last and time.time() - float(last) < 120:
                return {'result': 'unchanged', 'reason': 'Recent cache activation'}
            observed = datetime.fromisoformat(alert['data']['observed_at'])
            if not -5 <= (datetime.now(timezone.utc) - observed).total_seconds() <= 60:
                raise ValueError('Expired bridge event')
            if not bridge_target_ready():
                return {'result': 'unchanged', 'reason': 'Expected local analytics workload not confirmed'}
        result = apply(action, alert)
        if result['result'] == 'enabled':
            lock.seek(0)
            lock.write(str(time.time()))
            lock.truncate()
            lock.flush()
        return result


def main():
    alert, action = {}, 'invalid'
    try:
        if not select.select([sys.stdin], [], [], 5)[0]:
            raise ValueError('Timed out waiting for response input')
        message = json.loads(sys.stdin.readline(65537))
        if not isinstance(message, dict) or message.get('version') != 1:
            raise ValueError('Invalid response envelope')
        action = message.get('command')
        alert = message.get('parameters', {}).get('alert', {})
        if action not in ('add', 'delete') or not valid_alert(alert, socket.gethostname()):
            raise ValueError('Unexpected rule, node, service, event or request fields')
        if action == 'add':
            # Wazuh serializes repeated activation of this response key.
            print(json.dumps({'version': 1, 'origin': {'name': KEY, 'module': 'active-response'},
                              'command': 'check_keys', 'parameters': {'keys': [KEY]}}), flush=True)
            if not select.select([sys.stdin], [], [], 5)[0]:
                raise ValueError('Timed out waiting for Wazuh duplicate check')
            reply = json.loads(sys.stdin.readline(65537))
            if reply.get('command') != 'continue':
                log_result(action, alert, {'result': 'unchanged', 'reason': 'Wazuh duplicate check aborted'})
                return 0
        result = locked_apply(action, alert)
        log_result(action, alert, result)
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        try:
            log_result(action, alert if isinstance(alert, dict) else {},
                       {'result': 'rejected', 'reason': str(error)[:200]})
        except (OSError, TypeError, AttributeError):
            pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
