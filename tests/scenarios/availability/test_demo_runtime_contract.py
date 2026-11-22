"""Regression checks for the scenario demo against deployed legacy names."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

DEMO = Path(__file__).resolve().parents[3] / 'scripts/scenarios/01-dos/demo'
spec = importlib.util.spec_from_file_location('runtime_contract', DEMO / 'runtime_contract.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def embedded_reader():
    shell = (DEMO / 'show-dos-flow.sh').read_text()
    code = shell.split("<<'PYREMOTE'\n", 1)[1].split('\nPYREMOTE', 1)[0]
    function, = [item for item in ast.parse(code).body
                 if isinstance(item, ast.FunctionDef) and item.name == 'metric']
    namespace = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<demo-reader>', 'exec'), namespace)
    return namespace['metric']


class MetricTests(unittest.TestCase):
    def test_actual_demo_reader_accepts_both_families_and_labels(self):
        reader = embedded_reader()
        for prefix in ('', 'ssle_'):
            with self.subTest(prefix=prefix):
                name = prefix + 'analytics_storage_requests_total'
                self.assertEqual(reader(f'{name}{{result="ok"}} 12\n{name}{{result="error"}} 3\n',
                                        'analytics_storage_requests_total'), 15)

    def test_missing_metric_remains_unverified(self):
        self.assertIsNone(embedded_reader()('other_total 15\n', 'analytics_storage_requests_total'))

    def test_alias_collision_is_rejected_instead_of_double_counted(self):
        text = 'analytics_storage_requests_total 15\nssle_analytics_storage_requests_total 15\n'
        with self.assertRaises(ValueError):
            embedded_reader()(text, 'analytics_storage_requests_total')
        with self.assertRaises(ValueError):
            runtime.read_metrics(text)

    def test_recorder_normalizes_analytics_and_client_samples(self):
        for prefix in ('', 'ssle_'):
            with self.subTest(prefix=prefix):
                values = runtime.read_metrics(f'# TYPE ignored counter\n{prefix}analytics_storage_requests_total 16\n'
                                              f'{prefix}client_requests_total{{outcome="success"}} 30\n')
                self.assertEqual(values['analytics_storage_requests_total'], 16)
                self.assertEqual(values['client_requests_total{outcome="success"}'], 30)


class DiscoveryTests(unittest.TestCase):
    def discover(self, prefix='', response_directory=None, executable_present=True):
        directory = '/var/lib/' + prefix + 'analytics-protection'
        executable = prefix + 'analytics-cache.py'
        pod = {'metadata': {'name': 'analytics-test'}, 'spec': {'nodeName': 'k3s-node1',
               'containers': [{'env': [{'name': 'ANALYTICS_PROTECTION_FILE', 'value': '/run/protection/cache.json'}],
                               'volumeMounts': [{'name': 'protection', 'mountPath': '/run/protection'}]}],
               'volumes': [{'name': 'protection', 'hostPath': {'path': directory}}]}}
        config = ('<ossec_config><command><name>configured-cache</name><executable>' + executable + '</executable></command>'
                  '<active-response><disabled>no</disabled><command>configured-cache</command>'
                  '<location>local</location><rules_id>100121</rules_id></active-response></ossec_config>')
        source = f'CONTROL_DIR = Path({(response_directory or directory)!r})\nKEY = {(prefix + "analytics-cache")!r}\n'
        def incus(host, *args):
            if args[-2:] == ('-o', 'json'):
                return json.dumps({'items': [pod]})
            if args == ('cat', '/var/ossec/etc/ossec.conf'):
                return config
            if args == ('cat', '/var/ossec/active-response/bin/' + executable):
                return source
            if args == ('test', '-x', '/var/ossec/active-response/bin/' + executable):
                if not executable_present:
                    raise FileNotFoundError(executable)
                return ''
            if args == ('systemctl', 'is-active', 'wazuh-agent'):
                return 'active\n'
            self.fail(f'Unexpected command: {host} {args}')
        with patch.object(runtime, 'incus', side_effect=incus):
            return runtime.discover()

    def test_uses_configured_executable_and_mounted_lease_for_both_names(self):
        for prefix in ('', 'ssle-'):
            with self.subTest(prefix=prefix):
                result = self.discover(prefix)
                self.assertEqual(result['response_script'], '/var/ossec/active-response/bin/' + prefix + 'analytics-cache.py')
                self.assertEqual(result['lease_file'], '/var/lib/' + prefix + 'analytics-protection/cache.json')
                self.assertEqual(result['audit_integration'], prefix + 'analytics-cache')

    def test_missing_configured_executable_still_fails(self):
        with self.assertRaises(FileNotFoundError):
            self.discover(executable_present=False)

    def test_wazuh_directory_must_match_analytics_mount(self):
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.discover(response_directory='/wrong/path')


class SourceComparisonTests(unittest.TestCase):
    def test_only_known_legacy_names_are_accepted_and_raw_hashes_differ(self):
        repository = "HTTP = Counter('analytics_requests_total', 'Requests')\nLEASE = os.getenv('ANALYTICS_PROTECTION_FILE', '/run/analytics-protection/cache.json')\n"
        deployed = repository.replace("'analytics_requests_total'", "'ssle_analytics_requests_total'").replace('/run/analytics-protection/', '/run/ssle-protection/')
        result = runtime.compare_analytics_source(deployed, repository)
        self.assertFalse(result['exact_source_match'])
        self.assertNotEqual(result['runtime_sha256'], result['repository_sha256'])

    def test_behavior_changes_are_rejected(self):
        with self.assertRaises(ValueError):
            runtime.compare_analytics_source('LIMIT = 10\n', 'LIMIT = 5\n')


class PodStabilityTests(unittest.TestCase):
    def snapshot(self):
        return {'items': [{'kind': 'Pod', 'metadata': {'uid': 'pod-uid', 'name': 'analytics-test',
                'labels': {'app': 'analytics'}}, 'spec': {'nodeName': 'k3s-node1'},
                'status': {'containerStatuses': [{'name': 'analytics', 'restartCount': 2}]}}]}

    def test_restart_still_fails_and_identifies_the_pod(self):
        before = self.snapshot()
        after = copy.deepcopy(before)
        after['items'][0]['status']['containerStatuses'][0]['restartCount'] = 3
        report = runtime.pod_stability_report(before, after)
        self.assertFalse(report['unchanged'])
        self.assertEqual(report['changes'][0]['before']['name'], 'analytics-test')
        self.assertEqual(report['changes'][0]['before']['restart_counts'], [2])
        self.assertEqual(report['changes'][0]['after']['restart_counts'], [3])

    def test_replacement_is_not_treated_as_unchanged(self):
        before = self.snapshot()
        after = copy.deepcopy(before)
        after['items'][0]['metadata']['uid'] = 'replacement-uid'
        report = runtime.pod_stability_report(before, after)
        self.assertFalse(report['unchanged'])
        self.assertEqual(len(report['changes']), 2)

    def test_an_unrelated_changed_pod_is_still_reported(self):
        before = self.snapshot()
        before['items'][0]['metadata']['labels']['app'] = 'other-service'
        report = runtime.pod_stability_report(before, {'items': []})
        self.assertFalse(report['unchanged'])
        self.assertEqual(report['changes'][0]['before']['app'], 'other-service')
        self.assertIsNone(report['changes'][0]['after'])

    def test_unchanged_snapshot_passes(self):
        before = self.snapshot()
        self.assertEqual(runtime.pod_stability_report(before, copy.deepcopy(before)),
                         {'unchanged': True, 'changes': []})


if __name__ == '__main__':
    unittest.main()
