"""Cache policy controls, with fake clocks and no network requests."""
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from .test_analytics_rate_limit import load_application


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.m = load_application()
        self.now = 100.0
        self.lease = Mock()
        self.lease.active.return_value = True
        self.cache = self.m.ProtectiveCache(self.lease, clock=lambda: self.now)
        self.fetch = Mock(return_value={'average_temperature': 25.0})

    def test_normal_mode_fetches_every_time(self):
        self.lease.active.return_value = False
        for _ in range(3):
            self.assertFalse(self.cache.query(self.fetch)['cached'])
        self.assertEqual(self.fetch.call_count, 3)

    def test_protected_mode_reuses_then_refreshes(self):
        self.assertFalse(self.cache.query(self.fetch)['cached'])
        self.now += 4
        self.assertTrue(self.cache.query(self.fetch)['cached'])
        self.now += 1
        self.assertFalse(self.cache.query(self.fetch)['cached'])
        self.assertEqual(self.fetch.call_count, 2)

    def test_failure_fallback_is_bounded_and_refreshes_are_spaced(self):
        self.cache.query(self.fetch)
        self.fetch.side_effect = self.m.StorageUnavailable()
        self.now = 106
        result = self.cache.query(self.fetch)
        self.assertTrue(result['cache_fallback'])
        self.assertEqual(result['stats_age_seconds'], 6)
        self.now = 109
        self.cache.query(self.fetch)
        self.assertEqual(self.fetch.call_count, 2)
        self.now = 110.01
        with self.assertRaises(self.m.StorageUnavailable):
            self.cache.query(self.fetch)
        self.assertEqual(self.fetch.call_count, 2)
        self.now = 111
        with self.assertRaises(self.m.StorageUnavailable):
            self.cache.query(self.fetch)
        self.assertEqual(self.fetch.call_count, 3)

    def test_cold_failure_does_not_invent_a_value(self):
        self.fetch.side_effect = self.m.StorageUnavailable()
        with self.assertRaises(self.m.StorageUnavailable):
            self.cache.query(self.fetch)

    def test_expiry_returns_to_fresh_normal_queries(self):
        self.cache.query(self.fetch)
        self.lease.active.return_value = False
        result = self.cache.query(self.fetch)
        self.assertEqual(result['protection_mode'], 'normal')
        self.assertFalse(result['cached'])
        self.assertEqual(self.fetch.call_count, 2)

    def test_concurrent_refresh_has_only_one_storage_call(self):
        self.cache.query(self.fetch)
        self.now = 106
        entered, release = threading.Event(), threading.Event()
        results, errors = [], []
        def refresh():
            entered.set()
            if not release.wait(2):
                raise AssertionError('Test synchronization timed out')
            return {'average_temperature': 26}
        self.fetch.side_effect = refresh
        def run():
            try:
                results.append(self.cache.query(self.fetch))
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            others = [self.cache.query(self.fetch) for _ in range(5)]
            self.assertTrue(all(r['cache_fallback'] for r in others))
            self.assertEqual(self.fetch.call_count, 2)
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results[0]['average_temperature'], 26)

    def test_cache_does_not_bypass_admission_limit(self):
        self.m.CACHE = self.cache
        client = self.m.app.test_client()
        with patch.object(self.m, 'fetch_average', self.fetch):
            replies = [client.get('/average') for _ in range(6)]
        self.assertEqual([r.status_code for r in replies], [200]*5+[429])
        self.assertEqual(self.fetch.call_count, 1)
        self.assertEqual(replies[0].headers['Cache-Control'], 'no-store')

    def test_invalid_statistics_are_not_cached_and_zero_is_valid(self):
        response = Mock()
        with patch.object(self.m.requests, 'get', return_value=response):
            for data in ({}, [], {'measurements': -1, 'sum_temperature': 1},
                         {'measurements': 1, 'sum_temperature': float('nan')}):
                response.json.return_value = data
                with self.assertRaises(self.m.StorageUnavailable):
                    self.m.fetch_average()
            response.json.return_value = {'measurements': 1, 'sum_temperature': 0}
            self.assertEqual(self.m.fetch_average(), {'average_temperature': 0})
            response.json.return_value = {'measurements': 0, 'sum_temperature': 0}
            self.assertEqual(self.m.fetch_average(), {'average_temperature': None})


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.m = load_application()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'lease.json'
        self.wall, self.tick = 100.0, 100.0
        self.lease = self.m.ProtectionLease(self.path, owner_uid=os.getuid(),
                                           wall=lambda: self.wall, clock=lambda: self.tick)
        self.data = dict(version=1, mode='cache', event_id='123.4', issued_at=100, expires_at=160)
        self.write()

    def write(self):
        self.path.write_text(json.dumps(self.data))
        self.path.chmod(0o644)

    def test_expiry_without_wazuh_delete(self):
        self.assertTrue(self.lease.active())
        self.wall = self.tick = 160
        self.assertFalse(self.lease.active())
        self.assertTrue(self.path.exists())

    def test_wall_clock_rollback_cannot_extend_observed_lease(self):
        self.assertTrue(self.lease.active())
        self.wall, self.tick = 110, 161
        self.assertFalse(self.lease.active())

    def test_malformed_missing_and_oversized_leases_fail_closed(self):
        for text in ('{', 'null', '[]', 'x'*4097):
            self.path.write_text(text)
            self.assertFalse(self.lease.active())
        self.path.unlink()
        self.assertFalse(self.lease.active())

    def test_invalid_timestamps_and_wrong_mode_fail_closed(self):
        for key, value in [('expires_at', 161), ('issued_at', 120), ('expires_at', 100),
                           ('expires_at', float('nan')), ('issued_at', True),
                           ('mode', 'normal'), ('event_id', '../invalid')]:
            with self.subTest(key=key, value=value):
                original = self.data[key]
                self.data[key] = value
                self.write()
                self.assertFalse(self.lease.active())
                self.data[key] = original

    def test_wrong_owner_writable_file_and_symlink_fail_closed(self):
        other = self.m.ProtectionLease(self.path, owner_uid=os.getuid()+1,
                                       wall=lambda: self.wall, clock=lambda: self.tick)
        self.assertFalse(other.active())
        self.path.chmod(0o666)
        self.assertFalse(self.lease.active())
        self.path.unlink()
        target = Path(self.temp.name)/'target'
        target.write_text(json.dumps(self.data))
        self.path.symlink_to(target)
        self.assertFalse(self.lease.active())


if __name__ == '__main__':
    unittest.main()
