"""The real demo comparison must allow scheduled cache refreshes."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
FLOW=ROOT/'scripts/scenarios/01-dos/demo/show-dos-flow.sh'


def compare(summary):
    shell=FLOW.read_text()
    prefix='python3 - "$OUT/unprotected-reads.jsonl" "$EVIDENCE/summary.json" <<\'PY\'\n'
    code=shell.split(prefix,1)[1].split('\nPY',1)[0]
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        (root/'reads.jsonl').write_text(json.dumps({'event':'summary','count':15,'http_statuses':{'200':15},'mean_latency_ms':10,'storage_calls_delta':15,'storage_metric_available':True})+'\n')
        (root/'summary.json').write_text(json.dumps(summary))
        return subprocess.run(['python3','-c',code,str(root/'reads.jsonl'),str(root/'summary.json')],text=True,capture_output=True)


class DemoComparisonTests(unittest.TestCase):
    def summary(self):
        phase={'manual_requests':30,'manual_http_statuses':{'200':30},'manual_cached':0,'manual_mean_ms':9,'storage_attempts_all_clients':48,'analytics_200_all_clients':48}
        result={'normal':copy.deepcopy(phase),'protected':copy.deepcopy(phase),'recovery':copy.deepcopy(phase),'admission_statuses':{'200':5,'429':10}}
        result['protected'].update(manual_cached=24,manual_mean_ms=5,storage_attempts_all_clients=6,analytics_200_all_clients=49)
        return result

    def test_periodic_refresh_is_valid_when_cache_reduces_dependency_work(self):
        result=compare(self.summary())
        self.assertEqual(result.returncode,0,result.stderr)

    def test_no_cache_hits_are_not_reported_as_success(self):
        summary=self.summary();summary['protected']['manual_cached']=0
        self.assertNotEqual(compare(summary).returncode,0)

    def test_cache_must_reduce_storage_work_per_admitted_request(self):
        summary=self.summary();summary['protected']['storage_attempts_all_clients']=49
        self.assertNotEqual(compare(summary).returncode,0)
