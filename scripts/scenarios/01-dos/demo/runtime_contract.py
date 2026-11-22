"""Read the deployed Analytics/Wazuh contract without changing runtime state."""
import ast
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import xml.etree.ElementTree as ET


def incus(host, *args):
    return subprocess.check_output(['incus', 'exec', host, '--', *args], text=True,
                                   stdin=subprocess.DEVNULL, timeout=20)


def read_metrics(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        sample, value = line.rsplit(None, 1)
        canonical = sample.removeprefix('ssle_')
        if canonical in values:
            raise ValueError('Ambiguous metric aliases: ' + canonical)
        values[canonical] = float(value)
    return values


def pod_stability_report(before, after):
    """Explain the original all-Pod UID/restart invariant without relaxing it."""
    def snapshot(cluster):
        result = {}
        for pod in cluster['items']:
            if pod['kind'] != 'Pod':
                continue
            metadata = pod['metadata']
            statuses = pod.get('status', {}).get('containerStatuses', [])
            result[metadata['uid']] = {
                'name': metadata['name'], 'uid': metadata['uid'],
                'app': metadata.get('labels', {}).get('app'),
                'node': pod.get('spec', {}).get('nodeName'),
                'phase': pod.get('status', {}).get('phase'),
                'container_names': [status.get('name') for status in statuses],
                'restart_counts': [status.get('restartCount', 0) for status in statuses],
            }
        return result
    first, last = snapshot(before), snapshot(after)
    changes = []
    for uid in sorted(first.keys() | last.keys()):
        previous, current = first.get(uid), last.get(uid)
        if previous is None or current is None or previous['restart_counts'] != current['restart_counts']:
            changes.append({'before': previous, 'after': current})
    return {'unchanged': not changes, 'changes': changes}


def compare_analytics_source(runtime_source, repository_source):
    """Allow only the known naming migration when comparing executable ASTs."""
    def canonical(source):
        tree = ast.parse(source)
        metrics = {'analytics_requests_total', 'analytics_storage_requests_total',
                   'analytics_cache_responses_total', 'analytics_protection_active'}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if (isinstance(node.func, ast.Name) and node.func.id in ('Counter', 'Gauge')
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and node.args[0].value.removeprefix('ssle_') in metrics):
                node.args[0].value = node.args[0].value.removeprefix('ssle_')
            if (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == 'os' and node.func.attr == 'getenv'
                    and len(node.args) == 2 and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == 'ANALYTICS_PROTECTION_FILE'
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == '/run/ssle-protection/cache.json'):
                node.args[1].value = '/run/analytics-protection/cache.json'
        return ast.dump(tree, include_attributes=False)
    if canonical(runtime_source) != canonical(repository_source):
        raise ValueError('Analytics source differs beyond the supported legacy naming migration')
    return {'runtime_sha256': hashlib.sha256(runtime_source.encode()).hexdigest(),
            'repository_sha256': hashlib.sha256(repository_source.encode()).hexdigest(),
            'exact_source_match': runtime_source == repository_source,
            'ast_match_after_legacy_name_normalization': True}


def discover():
    data = json.loads(incus('k3s-master', 'k3s', 'kubectl', '-n', 'ssle', 'get', 'pods', '-l', 'app=analytics', '-o', 'json'))
    pods = [pod for pod in data['items'] if not pod['metadata'].get('deletionTimestamp')]
    if len(pods) != 1 or len(pods[0]['spec']['containers']) != 1:
        raise ValueError('Expected one Analytics Pod with one application container')
    pod = pods[0]
    node = pod['spec']['nodeName']
    container = pod['spec']['containers'][0]
    environment = {var['name']: var.get('value') for var in container.get('env', [])}
    lease = PurePosixPath(environment['ANALYTICS_PROTECTION_FILE'])
    mounts = [mount for mount in container['volumeMounts']
              if lease.is_relative_to(PurePosixPath(mount['mountPath']))]
    if len(mounts) != 1:
        raise ValueError('Expected one mount containing the Analytics lease')
    mount = mounts[0]
    volume, = [volume for volume in pod['spec']['volumes'] if volume['name'] == mount['name']]
    host_lease = PurePosixPath(volume['hostPath']['path']) / lease.relative_to(mount['mountPath'])
    configuration = ET.fromstring('<root>' + incus('wazuh-container', 'cat', '/var/ossec/etc/ossec.conf') + '</root>')
    responses = [entry for entry in configuration.findall('.//active-response')
                 if entry.findtext('disabled') == 'no' and entry.findtext('location') == 'local'
                 and '100121' in (entry.findtext('rules_id') or '').replace(' ', '').split(',')]
    if len(responses) != 1:
        raise ValueError('Expected one enabled local response for rule 100121')
    command = responses[0].findtext('command')
    executable, = [entry.findtext('executable') for entry in configuration.findall('.//command')
                   if entry.findtext('name') == command]
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', executable or ''):
        raise ValueError('Unsupported Wazuh executable name')
    path = '/var/ossec/active-response/bin/' + executable
    incus(node, 'test', '-x', path)
    incus(node, 'systemctl', 'is-active', 'wazuh-agent')
    source = ast.parse(incus(node, 'cat', path))
    directories = [entry.value for entry in source.body if isinstance(entry, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'CONTROL_DIR' for target in entry.targets)]
    directory, = directories
    if not (isinstance(directory, ast.Call) and isinstance(directory.func, ast.Name)
            and directory.func.id == 'Path' and len(directory.args) == 1 and not directory.keywords):
        raise ValueError('Unsupported Active Response control-directory declaration')
    if PurePosixPath(ast.literal_eval(directory.args[0])) / 'cache.json' != host_lease:
        raise ValueError('Wazuh control directory does not match the Analytics lease mount')
    key, = [ast.literal_eval(entry.value) for entry in source.body if isinstance(entry, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'KEY' for target in entry.targets)]
    return {'node': node, 'pod': pod['metadata']['name'], 'response_command': command,
            'response_script': path, 'lease_file': str(host_lease), 'audit_integration': key}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, help='Also verify the deployed Analytics source')
    arguments = parser.parse_args()
    contract = discover()
    if arguments.source_root:
        runtime_source = incus('k3s-master', 'k3s', 'kubectl', '-n', 'ssle', 'exec',
                               contract['pod'], '--', 'cat', '/app/app.py')
        contract['analytics_source'] = compare_analytics_source(
            runtime_source, (arguments.source_root / 'apps/analytics.py').read_text())
    print(json.dumps(contract, indent=2))
