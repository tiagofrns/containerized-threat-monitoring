"""Offline checks for the measurements used by the bounded live study."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('analytics_scaling',Path(__file__).with_name('run-analytics-scaling.py'))
scaling=importlib.util.module_from_spec(spec);spec.loader.exec_module(scaling)


class MeasurementTests(unittest.TestCase):
    def test_metrics_keep_admitted_requests_distinct_from_rejections(self):
        for prefix in ('','ssle_'):
            text=(f'{prefix}analytics_requests_total{{status="200"}} 20\n'
                  f'{prefix}analytics_requests_total{{status="429"}} 7\n'
                  f'{prefix}analytics_storage_requests_total 5\n'
                  f'{prefix}analytics_cache_responses_total{{reason="fresh"}} 13\n'
                  f'{prefix}analytics_cache_responses_total{{reason="fallback"}} 2\n')
            self.assertEqual(scaling.counters(text),{'requests':20,'storage':5,'cached':15})

    def test_missing_or_ambiguous_storage_counter_is_not_silently_zero(self):
        with self.assertRaises(AssertionError):scaling.counters('unrelated 10\n')
        with self.assertRaises(ValueError):scaling.counters('analytics_storage_requests_total 1\nssle_analytics_storage_requests_total 1\n')

    def test_cpu_uses_the_actual_kubelet_sample_window(self):
        def sample(stamp,first,second,memory):
            return {'pods':[{'uid':'a','cpu':{'time':stamp,'usageCoreNanoSeconds':first},'memory':{'workingSetBytes':memory}},
                            {'uid':'b','cpu':{'time':stamp,'usageCoreNanoSeconds':second},'memory':{'workingSetBytes':memory}}]}
        summary=scaling.cpu_summary([sample('2026-11-22T12:00:00Z',0,0,100),sample('2026-11-22T12:00:20Z',1_000_000_000,2_000_000_000,200)])
        self.assertAlmostEqual(summary['mean_cpu_cores'],.15)
        self.assertEqual(summary['cpu_sample_windows_seconds'],[20,20])
        self.assertEqual(summary['peak_sampled_memory_working_set_bytes'],400)

    def test_percentile_is_calculated_from_observations(self):
        self.assertAlmostEqual(scaling.percentile(list(range(1,21)),.95),19.05)

    def test_plan_has_a_fixed_request_budget_without_mutating_production(self):
        plan=scaling.plan()
        self.assertEqual(plan['maximum_measured_reads'],1080)
        self.assertEqual(plan['global_dispatch_interval_seconds'],.5)
        self.assertFalse(plan['production_deployment_scaled'])
