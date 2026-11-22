"""Real HTTP/SQLite fixtures on container loopback. No deployed service is used.

Only the protection authorization is a test switch. The actual storage service,
analytics handler, Requests timeouts, cache clock and database operations run.
"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

import requests
from werkzeug.serving import make_server, WSGIRequestHandler

from .test_analytics_rate_limit import load_application, SOURCE
import client as legitimate_client


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


class HTTPIntegrationTests(unittest.TestCase):
    records = []

    @classmethod
    def tearDownClass(cls):
        destination = os.getenv('HTTP_EVIDENCE')
        if destination:
            Path(destination).write_text(json.dumps(cls.records, indent=2) + '\n')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        spec = importlib.util.spec_from_file_location('storage_http_fixture', SOURCE.parent / 'storage.py')
        self.storage = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {'DB_PATH': str(Path(self.temp.name) / 'fixture.db')}):
            spec.loader.exec_module(self.storage)
        self.storage.init_db()
        self.delay = 0
        self.storage_requests = 0

        def delayed_storage(environ, start_response):
            if environ['PATH_INFO'] == '/stats':
                self.storage_requests += 1
                time.sleep(self.delay)
            return self.storage.app(environ, start_response)

        self.backend = self.serve(delayed_storage)
        self.module = load_application()
        self.module.STORAGE_URL = self.backend
        self.protected = False
        self.addCleanup(patch.stopall)
        patch.object(self.module.LEASE, 'active', side_effect=lambda: self.protected).start()
        self.frontend = self.serve(self.module.app)
        self.post_value(20)

    def serve(self, app):
        server = make_server('127.0.0.1', 0, app, threaded=True, request_handler=QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return 'http://127.0.0.1:' + str(server.server_port)

    def post_value(self, value):
        reply = requests.post(self.backend + '/store', json={'device_id': 'isolated-fixture', 'temperature': value}, timeout=(1, 5))
        reply.raise_for_status()

    def get_average(self, label):
        tick = time.monotonic()
        reply = requests.get(self.frontend + '/average', timeout=legitimate_client.HTTP_TIMEOUT)
        row = {'test': self._testMethodName, 'step': label, 'status': reply.status_code,
               'elapsed_ms': 1000 * (time.monotonic() - tick), 'body': reply.json(),
               'storage_attempts': self.storage_requests}
        self.records.append(row)
        return row

    def test_slow_storage_returns_application_error_before_client_read_timeout(self):
        self.delay = 2.4
        real_get = requests.get
        replies = []

        def record_get(url, **kwargs):
            reply = real_get(url, **kwargs)
            if url == self.frontend + '/average':
                replies.append({'status': reply.status_code, 'body': reply.json(), 'timeout': kwargs['timeout']})
            return reply

        # Run exactly one iteration of the real continuous client's main loop.
        clock = types.SimpleNamespace(monotonic=time.monotonic, sleep=Mock(side_effect=StopIteration))
        tick = time.monotonic()
        with patch.dict(os.environ, {'ANALYTICS_URL': self.frontend + '/average'}), \
                patch.object(legitimate_client, 'start_http_server'), \
                patch.object(legitimate_client, 'time', clock), \
                patch.object(legitimate_client.requests, 'get', side_effect=record_get):
            with self.assertRaises(StopIteration):
                legitimate_client.main()
        elapsed = time.monotonic() - tick
        self.assertEqual(self.module.STORAGE_TIMEOUT, (1, 2))
        self.assertEqual(legitimate_client.HTTP_TIMEOUT, (1, 5))
        self.assertEqual(replies[0]['status'], 502)
        self.assertEqual(replies[0]['timeout'], (1, 5))
        self.assertLess(elapsed, 5)
        self.records.append({'test': self._testMethodName, 'step': 'real_client_iteration',
                             'elapsed_ms': elapsed * 1000, 'reply': replies[0],
                             'meaning': 'Client received HTTP 502 rather than a client read-timeout.'})

    def test_warm_cache_fallback_is_served_then_expires_with_real_waits(self):
        warm = self.get_average('warm')
        self.assertEqual(warm['status'], 200)
        self.protected = True
        self.delay = 2.4
        time.sleep(5.1)
        fallback = self.get_average('slow_refresh_fallback')
        self.assertEqual(fallback['status'], 200)
        self.assertTrue(fallback['body']['cached'])
        self.assertTrue(fallback['body']['cache_fallback'])
        self.assertLessEqual(fallback['body']['stats_age_seconds'], 10)
        time.sleep(3.1)
        expired = self.get_average('fallback_too_old')
        self.assertEqual(expired['status'], 502)

    def test_changed_sqlite_data_becomes_visible_after_refresh_and_recovery(self):
        original = self.get_average('initial_twenty')
        self.assertEqual(original['body']['average_temperature'], 20)
        self.protected = True
        self.post_value(40)
        reused = self.get_average('eligible_old_aggregate')
        self.assertEqual(reused['body']['average_temperature'], 20)
        self.assertTrue(reused['body']['cached'])
        time.sleep(5.1)
        refreshed = self.get_average('refreshed_thirty')
        self.assertEqual(refreshed['body']['average_temperature'], 30)
        self.assertFalse(refreshed['body']['cached'])
        self.protected = False
        self.post_value(60)
        recovered = self.get_average('normal_forty')
        self.assertEqual(recovered['body']['average_temperature'], 40)
        self.assertEqual(recovered['body']['protection_mode'], 'normal')
        self.assertFalse(recovered['body']['cached'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
