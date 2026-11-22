"""Run the actual comparison phase with delayed/missing Wazuh acknowledgements."""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[3]
FLOW=ROOT/'scripts/scenarios/03-spam/demo/show-mail-flow.sh'


def comparison_phase(fail_ack=False):
    source=FLOW.read_text()
    phase=source[source.index("step 4 'Resend"):source.index("\npress_enter\n\nstep 5")]
    stubs='''set -euo pipefail
token=fixture; evidence=/unused; script_dir=/unused; smtp_client_ip=192.0.2.20
step() { :; }
say() { :; }
send_message() { printf 'SEND %s\n' "$2"; }
verify_folder() { printf 'STORED %s\n' "$1"; }
python3() { printf 'VERIFY-FIREWALL\n'; }
fail() { printf 'FAIL %s\n' "$*"; exit 1; }
await_quarantine() { printf 'ACK %s\n' "$1"; ACK_RETURN; }
'''.replace('ACK_RETURN','return 1' if fail_ack else 'return 0')
    return subprocess.run(['bash','-c',stubs+phase],capture_output=True,text=True)


class FlowSynchronizationTests(unittest.TestCase):
    def test_each_quarantine_is_acknowledged_before_the_next_submission(self):
        result=comparison_phase()
        self.assertEqual(result.returncode,0,result.stderr)
        lines=result.stdout.splitlines()
        for number in (1,2,3):
            mid=f'<ssle-fixture-spam{number}@mail.lab.test>'
            self.assertIn('ACK '+mid,lines,'No Wazuh acknowledgement for a submitted GTUBE')
            self.assertLess(lines.index('STORED '+mid),lines.index('ACK '+mid))
            if number<3:
                following=f'<ssle-fixture-spam{number+1}@mail.lab.test>'
                self.assertLess(lines.index('ACK '+mid),lines.index('SEND '+following))
        self.assertLess(lines.index('ACK <ssle-fixture-spam3@mail.lab.test>'),lines.index('VERIFY-FIREWALL'))

    def test_missing_acknowledgement_stops_the_flow_without_extra_gtube(self):
        result=comparison_phase(fail_ack=True)
        self.assertNotEqual(result.returncode,0,'Flow continued without Wazuh evidence')
        self.assertNotIn('SEND <ssle-fixture-spam2@mail.lab.test>',result.stdout)
        self.assertNotIn('VERIFY-FIREWALL',result.stdout)


class ContainmentReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec=importlib.util.spec_from_file_location('smtp_containment',ROOT/'scripts/scenarios/03-spam/demo/record-smtp-containment.py')
        cls.helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.helper)

    def event(self,address='192.0.2.20'):
        return {'id':'fixture-event','agent':{'name':'mail-container'},'rule':{'id':'100607'},
                'data':{'message_id':'<fixture-token@mail.lab.test>','srcip':address,
                        'source_verified':'yes','source_blockable':'yes'}}

    def test_partial_log_line_does_not_discard_complete_alerts(self):
        import json
        from unittest.mock import patch
        row=self.event()
        with patch.object(self.helper,'remote',return_value=json.dumps(row)+'\n{"data":"fixture-token'):
            self.assertEqual(self.helper.manager_events('fixture-token'),[row])

    def test_acknowledgement_waits_for_this_message_and_source(self):
        import tempfile,json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            with patch.object(self.helper,'manager_events',side_effect=[[self.event('192.0.2.99')],[self.event()]]),patch.object(self.helper.time,'sleep') as sleep:
                self.helper.acknowledge(out,'fixture-token','192.0.2.20','<fixture-token@mail.lab.test>')
            self.assertEqual(sleep.call_count,1)
            retained=json.loads((out/'quarantine-acknowledgements.jsonl').read_text())
            self.assertEqual(retained['data']['srcip'],'192.0.2.20')

    def test_no_trigger_is_reported_as_detection_failure_with_raw_evidence(self):
        import tempfile,json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            with patch.object(self.helper,'manager_events',return_value=[self.event()]*3),patch.object(self.helper,'rules',return_value='*filter\nCOMMIT\n'),patch.object(self.helper,'remote',return_value=''):
                message=self.helper.missing_block_diagnostics(out,'fixture-token','192.0.2.20')
            report=json.loads((out/'failure-summary.json').read_text())
            self.assertEqual(report['stage'],'detection')
            self.assertEqual(report['eligible_quarantine_alerts'],3)
            self.assertEqual(report['containment_alerts'],0)
            self.assertIn('100607=3, 100620=0',message)
            self.assertEqual(len((out/'wazuh-missing-block-events.jsonl').read_text().splitlines()),3)
