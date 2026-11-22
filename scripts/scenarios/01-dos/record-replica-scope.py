"""Bounded read-only replica/state evaluation in temporary K3s Pods.

The real analytics Deployment, database and Wazuh response configuration stay
unchanged. A labelled fixture lease is written only into a dedicated directory
for the temporary Deployment. It is not a Wazuh activation or capacity test.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]


def command(args, data=None, check=True):
    return subprocess.run(args, input=data, text=True, capture_output=True,
                          check=check, timeout=120)


def kube(*args, **kwargs):
    return command(['incus', 'exec', 'k3s-master', '--', 'k3s', 'kubectl',
                    '-n', 'ssle', *args], **kwargs)


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    name = 'analytics-scale-check-' + stamp.lower()
    out = ROOT / 'evidence/scenarios/01-dos' / ('replica-scope-' + stamp)
    out.mkdir(parents=True)
    directory = '/var/lib/analytics-protection/' + name
    nodes = ('k3s-master', 'k3s-node1')

    def save(filename, data):
        (out / filename).write_text(json.dumps(data, indent=2) + '\n')

    def pods():
        data = json.loads(kube('get', 'pods', '-l', 'app=' + name, '-o', 'json').stdout)
        return sorted([p for p in data['items'] if not p['metadata'].get('deletionTimestamp')],
                      key=lambda p: p['spec']['nodeName'])

    def read_phase(phase, count):
        phase_rows = []
        # Each Pod gets the same finite ordinary-read sequence, one per second.
        for pod in pods():
            code = '''import json,time,requests
rows=[]
for i in range(COUNT):
 started=time.monotonic()
 response=requests.get('http://127.0.0.1:5003/average',timeout=(1,5))
 rows.append({'ordinal':i+1,'status':response.status_code,'duration_ms':1000*(time.monotonic()-started),'body':response.json()})
 time.sleep(1)
print(json.dumps({'reads':rows,'metrics':requests.get('http://127.0.0.1:5003/metrics',timeout=(1,5)).text}))
'''.replace('COUNT', str(count))
            result = json.loads(kube('exec', pod['metadata']['name'], '--', 'python', '-c', code).stdout)
            result.update(pod=pod['metadata']['name'], node=pod['spec']['nodeName'])
            phase_rows.append(result)
            assert all(row['status'] == 200 for row in result['reads'])
        save(phase + '.json', phase_rows)
        return phase_rows

    original = json.loads(kube('get', 'deployment', 'analytics', '-o', 'json').stdout)
    save('production-deployment-before.json', original)
    spec = json.loads(json.dumps(original['spec']))
    spec['replicas'] = 1
    spec['selector'] = {'matchLabels': {'app': name}}
    spec['template']['metadata'] = {'labels': {'app': name}}
    podspec = spec['template']['spec']
    podspec['affinity'] = {'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [
        {'labelSelector': {'matchLabels': {'app': name}}, 'topologyKey': 'kubernetes.io/hostname'}]}}
    for volume in podspec['volumes']:
        if volume['name'] == 'protection':
            volume['hostPath']['path'] = directory
    manifest = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
                'metadata': {'name': name, 'namespace': 'ssle'}, 'spec': spec}
    save('temporary-deployment.json', manifest)
    save('conditions.json', {'scope': __doc__, 'manual_reads': 34,
                            'per_pod_cadence_seconds': 1,
                            'fixture_lease_seconds': 60,
                            'original_deployment_not_scaled': True})
    created = False
    created_nodes = []
    try:
        for node in nodes:
            command(['incus', 'exec', node, '--', 'mkdir', '-m', '755', directory])
            created_nodes.append(node)
        created = True
        kube('apply', '-f', '-', data=json.dumps(manifest))
        kube('rollout', 'status', 'deployment/' + name, '--timeout=90s')
        one = read_phase('one-replica-normal', 12)
        kube('scale', 'deployment/' + name, '--replicas=2')
        kube('rollout', 'status', 'deployment/' + name, '--timeout=90s')
        save('two-replica-pods.json', pods())
        assert {p['spec']['nodeName'] for p in pods()} == set(nodes)
        two = read_phase('two-replicas-normal', 4)
        issued = time.time()
        lease = {'version': 1, 'mode': 'cache', 'event_id': str(int(issued)) + '.999999',
                 'issued_at': issued, 'expires_at': issued + 60}
        # This authorization is a fixture on one temporary node directory only.
        writer = "import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o644)"
        command(['incus', 'exec', 'k3s-master', '--', 'python3', '-c', writer,
                 directory + '/cache.json', json.dumps(lease)])
        save('manual-fixture-lease.json', {'node': 'k3s-master', 'lease': lease,
                                         'origin': 'operator fixture; not Wazuh dispatch'})
        mixed = read_phase('one-node-fixture-authorization', 6)
        for result in mixed:
            expected = 'cache' if result['node'] == 'k3s-master' else 'normal'
            assert all(row['body']['protection_mode'] == expected for row in result['reads'])
        command(['incus', 'exec', 'k3s-master', '--', 'rm', '--', directory + '/cache.json'])
        recovery = read_phase('after-fixture-removal', 1)
        assert all(not row['body']['cached'] and row['body']['protection_mode'] == 'normal'
                   for result in recovery for row in result['reads'])
        summary = {'scope': 'Ordinary-read/state-scope evaluation in temporary replicas, not throughput or DoS capacity.',
                   'one_replica_successes': sum(len(p['reads']) for p in one),
                   'two_replica_normal_successes': sum(len(p['reads']) for p in two),
                   'fixture_phase': [{'node': p['node'], 'reads': len(p['reads']),
                                      'cached': sum(r['body']['cached'] for r in p['reads']),
                                      'modes': sorted({r['body']['protection_mode'] for r in p['reads']})}
                                     for p in mixed],
                   'recovery_successes': sum(len(p['reads']) for p in recovery),
                   'global_policy_not_demonstrated': True}
        save('summary.json', summary)
    finally:
        cleanup = []
        if created:
            p = kube('delete', 'deployment', name, '--ignore-not-found=true', '--wait=true', '--timeout=90s', check=False)
            cleanup.append({'deployment_deleted': p.returncode == 0, 'detail': p.stdout + p.stderr})
        for node in created_nodes:
            # Only the dedicated fixture filename and empty directory are removed.
            command(['incus', 'exec', node, '--', 'rm', '-f', '--', directory + '/cache.json'], check=False)
            p = command(['incus', 'exec', node, '--', 'rmdir', '--', directory], check=False)
            cleanup.append({'node': node, 'temporary_directory_removed': p.returncode == 0})
        after = json.loads(kube('get', 'deployment', 'analytics', '-o', 'json').stdout)
        save('production-deployment-after.json', after)
        save('cleanup.json', {'steps': cleanup, 'production_spec_unchanged': original['spec'] == after['spec']})
        assert original['spec'] == after['spec']
        assert all(step.get('deployment_deleted', step.get('temporary_directory_removed')) for step in cleanup)
    save('SHA256SUMS.json', {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in out.iterdir() if p.is_file()})
    print(json.dumps(summary, indent=2), flush=True)
    print('Evidence:', out, flush=True)


if __name__ == '__main__':
    main()
