import json
import math
import os
import re
import stat
import threading
import time

import requests
from flask import Flask, Response, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_client import CollectorRegistry, Counter, Gauge, CONTENT_TYPE_LATEST, generate_latest

STORAGE_TIMEOUT = (1, 2)  # Leave response-processing margin within the client read timeout.
CACHE_TTL = 5
MAX_STALE_AGE = 10
PROTECTION_SECONDS = 60


class StorageUnavailable(Exception):
    pass


class ProtectionLease:
    """Read a root-owned, bounded lease. The application cannot create it."""

    def __init__(self, path, owner_uid=0, wall=time.time, clock=time.monotonic):
        self.path = path
        self.owner_uid = owner_uid
        self.wall = wall
        self.clock = clock
        self.lock = threading.Lock()
        self.key = None
        self.deadline = 0

    def active(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd) as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o022:
                    return False
                raw = stream.read(4097)
            if len(raw) > 4096:
                return False
            lease = json.loads(raw)
            issued, expires = lease['issued_at'], lease['expires_at']
            if any(type(v) not in (int, float) or not math.isfinite(v) for v in (issued, expires)):
                return False
            now, tick = self.wall(), self.clock()
            if (lease.get('version') != 1 or lease.get('mode') != 'cache'
                    or not re.fullmatch(r'\d+\.\d+', str(lease.get('event_id', '')))
                    or not 0 < expires - issued <= PROTECTION_SECONDS
                    or not issued - 1 <= now < expires):
                return False
            key = (lease['event_id'], issued, expires)
            with self.lock:
                if key != self.key:
                    self.key, self.deadline = key, tick + min(expires - now, PROTECTION_SECONDS)
                else:
                    # A wall-clock correction cannot extend an already observed lease.
                    self.deadline = min(self.deadline, tick + expires - now)
                return tick < self.deadline
        except (OSError, ValueError, KeyError, TypeError):
            return False


class ProtectiveCache:
    """One last-good aggregate and one in-flight refresh per application process."""

    def __init__(self, lease, clock=time.monotonic):
        self.lease = lease
        self.clock = clock
        self.lock = threading.Lock()
        self.value = None
        self.observed_at = 0
        self.refreshing = False
        self.next_refresh = 0

    def result(self, value, observed_at, protected, cached, fallback=False):
        return dict(value, cached=cached, protection_mode='cache' if protected else 'normal',
                    stats_age_seconds=round(max(0, self.clock() - observed_at), 3),
                    cache_fallback=fallback)

    def remember(self, value, started):
        with self.lock:
            if self.value is None or started >= self.observed_at:
                self.value, self.observed_at = dict(value), started

    def query(self, fetch):
        protected = self.lease.active()
        if not protected:
            started = self.clock()
            value = fetch()
            self.remember(value, started)
            return self.result(value, started, False, False)

        with self.lock:
            now = self.clock()
            age = now - self.observed_at
            if self.value is not None and age < CACHE_TTL:
                return self.result(self.value, self.observed_at, True, True)
            if self.refreshing or now < self.next_refresh:
                if self.value is not None and age <= MAX_STALE_AGE:
                    return self.result(self.value, self.observed_at, True, True, True)
                raise StorageUnavailable('No eligible cache result while refresh is pending')
            self.refreshing, self.next_refresh = True, now + CACHE_TTL

        try:
            value = fetch()
            # The request start gives a conservative age for the fetched aggregate.
            if self.clock() - now > MAX_STALE_AGE:
                raise StorageUnavailable('Statistics response exceeded the freshness bound')
            self.remember(value, now)
            return self.result(value, now, True, False)
        except StorageUnavailable:
            with self.lock:
                if self.value is not None and self.clock() - self.observed_at <= MAX_STALE_AGE:
                    return self.result(self.value, self.observed_at, True, True, True)
            raise
        finally:
            with self.lock:
                self.refreshing = False


app = Flask(__name__)

# One process/replica in this lab. Neither budgets nor cached values are shared.
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[],
                  storage_uri='memory://', strategy='moving-window', headers_enabled=True,
                  enabled=os.getenv('ANALYTICS_RATE_LIMIT_ENABLED', 'true').lower() == 'true')

METRICS = CollectorRegistry()
HTTP_REQUESTS = Counter('ssle_analytics_requests_total', 'Completed average requests by HTTP response status',
                        ['status'], registry=METRICS)
STORAGE_REQUESTS = Counter('ssle_analytics_storage_requests_total',
                          'HTTP requests attempted from analytics to storage', registry=METRICS)
CACHE_RESPONSES = Counter('ssle_analytics_cache_responses_total', 'Responses served from the protective cache',
                          ['reason'], registry=METRICS)
PROTECTION_ACTIVE = Gauge('ssle_analytics_protection_active', 'Whether the bounded protective-cache lease is active',
                          registry=METRICS)
for status in ('200', '429', '502', '500'):
    HTTP_REQUESTS.labels(status=status).inc(0)
for reason in ('fresh', 'fallback'):
    CACHE_RESPONSES.labels(reason=reason).inc(0)

STORAGE_URL = os.getenv('STORAGE_URL', 'http://127.0.0.1:5002').rstrip('/')
LEASE = ProtectionLease(os.getenv('ANALYTICS_PROTECTION_FILE', '/run/ssle-protection/cache.json'))
CACHE = ProtectiveCache(LEASE)


def fetch_average():
    try:
        STORAGE_REQUESTS.inc()
        response = requests.get(f'{STORAGE_URL}/stats', timeout=STORAGE_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        count, total = data['measurements'], data['sum_temperature']
        if type(count) is not int or count < 0 or type(total) not in (int, float) or not math.isfinite(total):
            raise ValueError('Invalid statistics')
        average = round(total / count, 2) if count > 0 else None
        return {'average_temperature': average}
    except (requests.RequestException, ValueError, KeyError, TypeError, OverflowError) as error:
        raise StorageUnavailable('Storage unavailable or invalid response') from error


@app.after_request
def record_average_request(response):
    if request.endpoint == 'average_temp':
        HTTP_REQUESTS.labels(status=str(response.status_code)).inc()
        # Intermediaries must not extend our explicit freshness policy.
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/average', methods=['GET'])
@limiter.limit('5 per second')
def average_temp():
    try:
        result = CACHE.query(fetch_average)
    except StorageUnavailable:
        return jsonify({'error': 'Storage unavailable or invalid response'}), 502
    if result['cached']:
        CACHE_RESPONSES.labels(reason='fallback' if result['cache_fallback'] else 'fresh').inc()
    return jsonify(result)


@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'error': 'Too many requests'}), 429


@app.route('/metrics', methods=['GET'])
def metrics():
    PROTECTION_ACTIVE.set(LEASE.active())
    return Response(generate_latest(METRICS), content_type=CONTENT_TYPE_LATEST)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003)
