"""Accept local Alertmanager notifications and record verified firing episodes."""
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sqlite3
from urllib.request import urlopen

POLICIES = {"AnalyticsClientImpact": "analytics", "DNSPolicyRejections": "dns"}
STATE = Path("/var/lib/alert-bridge")
LOG = Path("/var/log/alert-bridge/events.jsonl")


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def events(payload, active, now):
    """Correlate webhook labels with live Prometheus state; retain fixed fields."""
    records = []
    for alert in payload["alerts"]:
        labels = alert["labels"]
        name = labels.get("alertname")
        scope = POLICIES.get(name)
        if alert["status"] != "firing" or scope is None or labels.get("bridge") != "wazuh":
            continue
        if labels.get("scope") != scope:
            continue
        # Alertmanager omits the real expiry from firing webhook notifications.
        # The Prometheus firing-state check is authoritative in that case.
        end = parse_time(alert["endsAt"])
        if end.year != 1 and end <= now:
            continue
        for local in active:
            if local["state"] != "firing" or local["labels"] != labels:
                continue
            started = parse_time(local["activeAt"])
            notified = parse_time(alert["startsAt"])
            if not -5 <= (now - started).total_seconds() <= 180:
                continue
            if not -1 <= (notified - started).total_seconds() <= 90:
                continue
            episode = sha256(f"{name}/{local['activeAt']}".encode()).hexdigest()
            records.append({"integration": "alert_bridge", "alert_name": name,
                            "scope": scope, "bridge_state": "firing", "episode": episode,
                            "observed_at": now.isoformat(), "active_at": local["activeAt"],
                            "validation": labels.get("mode") == "bridge-validation"})
            break
    return records


def record(records, database, log, now):
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS receipts (episode TEXT PRIMARY KEY, received REAL)")
        conn.execute("DELETE FROM receipts WHERE received < ?", (now.timestamp() - 86400,))
        count = 0
        for event in records:
            update = conn.execute("INSERT OR IGNORE INTO receipts VALUES (?, ?)",
                                  (event["episode"], now.timestamp()))
            if update.rowcount:
                with log.open("a") as stream:
                    stream.write(json.dumps(event, allow_nan=False) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                count += 1
        return count


def main():
    secret = Path("/etc/alert_bridge/webhook-secret").read_text().strip()
    auth = f"Bearer {secret}".encode()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            super().setup()

        def do_POST(self):
            if self.path != "/alerts":
                self.send_error(404)
                return
            if not compare_digest(self.headers.get("Authorization", "").encode(), auth):
                self.send_error(401)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 65536:
                    self.send_error(413)
                    return
                payload = json.loads(self.rfile.read(size))
                if not isinstance(payload["alerts"], list) or len(payload["alerts"]) > 20:
                    raise ValueError("Expected at most 20 alerts")
                with urlopen("http://127.0.0.1:9090/api/v1/alerts", timeout=3) as response:
                    current = json.load(response)
                now = datetime.now(timezone.utc)
                rows = events(payload, current["data"]["alerts"], now)
                count = record(rows, STATE / "receipts.db", LOG, now)
            except (ValueError, KeyError, AttributeError, TypeError, OverflowError):
                self.send_error(400)
                return
            except (OSError, sqlite3.Error):
                self.send_error(503)
                return
            body = json.dumps({"recorded": count}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    HTTPServer(("127.0.0.1", 9095), Handler).serve_forever()


if __name__ == "__main__":
    main()
