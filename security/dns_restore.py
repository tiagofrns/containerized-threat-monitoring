#!/usr/bin/python3
"""Check one lab DNS file at startup and restore it through Wazuh Active Response."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time

TARGET = Path("/etc/dnsmasq.d/dns_sec.conf")
STATE = Path("/var/lib/dns_sec")
APPROVED = b"local=/lab.test/\nhost-record=analytics.lab.test,10.255.255.74\n"
AUDIT = Path("/var/ossec/logs/dns_restore.jsonl")


def secure_read(path, uid=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise ValueError("Untrusted file ownership, type or permissions")
        data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError("File exceeds limit")
        return data


def secure_directory(path, uid=0):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise ValueError("Untrusted parent directory")


def execute(argv, timeout=10):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=True)


def approved_policy(target, state, uid):
    secure_directory(state, uid)
    secure_directory(target.parent, uid)
    baseline = secure_read(state / "approved.conf", uid)
    if baseline != APPROVED:
        raise ValueError("Baseline differs from the explicitly approved policy")
    return baseline


def read_configuration(target, uid):
    try:
        return secure_read(target, uid)
    except FileNotFoundError:
        return b""


def dns_agent(alert):
    return alert["agent"].get("id") == "004" and alert["agent"].get("name") == "dns-server-container"


def valid_startup(alert):
    data = alert.get("data", {})
    return (dns_agent(alert) and alert.get("location") == str(AUDIT)
            and data.get("integration") == "dns_integrity"
            and data.get("event") == "startup_mismatch" and data.get("file_path") == str(TARGET)
            and re.fullmatch(r"[0-9a-f]{32}", str(data.get("startup_id", ""))) is not None)


def valid_bridge(alert):
    data = alert.get("data", {})
    if (socket.gethostname() != "dns-server-container"
            or str(alert["agent"].get("id")) != "005"
            or alert["agent"].get("name") != "prometheus-container"
            or alert.get("location") != "/var/log/alert-bridge/events.jsonl"
            or data.get("integration") != "alert_bridge"
            or data.get("alert_name") != "DNSPolicyRejections"
            or data.get("scope") != "dns" or data.get("bridge_state") != "firing"
            or re.fullmatch(r"[0-9a-f]{64}", str(data.get("episode", ""))) is None):
        return False
    received = datetime.datetime.fromisoformat(data["observed_at"])
    age = (datetime.datetime.now(datetime.timezone.utc) - received).total_seconds()
    return -5 <= age <= 60


def restore(message, target=TARGET, state=STATE, uid=0, runner=execute):
    """Paths/runner can be replaced by isolated unit fixtures, not runtime CLI input."""
    result = {"integration": "dns_restore", "event": "response", "result": "rejected"}
    try:
        alert = message["parameters"]["alert"]
        rule = str(alert["rule"]["id"])
        fim = rule == "100141" and dns_agent(alert) and alert["syscheck"]["path"] == str(TARGET)
        bridge = rule == "100151" and valid_bridge(alert)
        startup = rule == "100145" and valid_startup(alert)
        if (message.get("command") != "add" or not (fim or bridge or startup)
                or not re.fullmatch(r"\d+\.\d+", str(alert.get("id", "")))):
            raise ValueError("Event is outside the approved response scope")
        result["alert_id"] = alert["id"]
        if bridge:
            result["bridge_episode"] = alert["data"]["episode"]
        if startup:
            result["startup_id"] = alert["data"]["startup_id"]
        baseline = approved_policy(target, state, uid)
        if not (state / "auto-restore.enabled").exists():
            return dict(result, result="maintenance")
        if secure_read(state / "auto-restore.enabled", uid) != b"enabled\n":
            raise ValueError("Invalid enable marker")
        lock_fd = os.open(state / "response.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock_fd, "a") as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
                raise ValueError("Untrusted lock")
            try:
                # A startup request must wait for any in-flight FIM repair to finish.
                fcntl.flock(lock, fcntl.LOCK_EX if startup else fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return dict(result, result="busy")
            current = read_configuration(target, uid)
            if current == baseline:
                return dict(result, result="already_approved")
            result["before_sha256"] = hashlib.sha256(current).hexdigest()
            temporary = None
            try:
                fd, temporary = tempfile.mkstemp(prefix=".dns-restore-", dir=target.parent)
                with os.fdopen(fd, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o644)
                    stream.write(baseline)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, target)
                temporary = None
            finally:
                if temporary is not None:
                    os.unlink(temporary)
            runner(["/usr/sbin/dnsmasq", "--test"])
            runner(["/usr/bin/systemctl", "restart", "dnsmasq"])
            # Verify DNS policy and an actual application read using the guarded client.
            check = runner(["/usr/bin/python3", "/opt/dns_sec/dns_client.py", "--once"], timeout=12)
            observation = json.loads(check.stdout)
            if (observation.get("outcome") != "success" or observation.get("peer_ip") != "10.255.255.74"
                    or observation.get("observed_addresses") != ["10.255.255.74"]):
                raise ValueError("Post-restoration application verification failed")
            result.update(result="restored", after_sha256=hashlib.sha256(baseline).hexdigest(),
                          verification=observation)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        result.update(result="failed", error=str(error)[:240])
    return result


def open_audit(path, mode, uid):
    flags = os.O_RDONLY if mode == "r" else os.O_WRONLY | os.O_APPEND | os.O_CREAT
    stream = os.fdopen(os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o640), mode, encoding="utf-8")
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        stream.close()
        raise ValueError("Untrusted audit file")
    return stream


def write_audit(record, path, uid):
    with open_audit(path, "a", uid) as stream:
        stream.write(json.dumps(record, allow_nan=False) + "\n")


def check_startup(target=TARGET, state=STATE, audit=AUDIT, uid=0, timeout=45):
    baseline = approved_policy(target, state, uid)
    current = read_configuration(target, uid)
    if current == baseline:
        return {"result": "already_approved"}

    event = {
        "integration": "dns_integrity", "event": "startup_mismatch", "file_path": str(TARGET),
        "startup_id": secrets.token_hex(16), "before_sha256": hashlib.sha256(current).hexdigest(),
        "approved_sha256": hashlib.sha256(baseline).hexdigest(),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    with open_audit(audit, "r", uid) as stream:
        stream.seek(0, os.SEEK_END)
        write_audit(event, audit, uid)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in stream:
                record = json.loads(line)
                if record.get("integration") != "dns_restore" or record.get("startup_id") != event["startup_id"]:
                    continue
                if record.get("result") not in ("restored", "already_approved"):
                    raise ValueError(f"Wazuh startup response: {record.get('result')}")
                if read_configuration(target, uid) != baseline:
                    raise ValueError("DNS file differs from the approved policy after the Wazuh response")
                return record
            time.sleep(0.25)
    raise TimeoutError(f"No Wazuh startup response for {event['startup_id']} within {timeout} seconds")


def main():
    if sys.argv[1:] == ["--check-startup"]:
        try:
            print(json.dumps(check_startup()))
        except (OSError, ValueError) as error:
            print(f"DNS configuration check failed: {error}", file=sys.stderr)
            return 1
        return 0

    started = time.monotonic()
    try:
        raw = sys.stdin.readline(65537)
        if len(raw) > 65536:
            raise ValueError("Input exceeds limit")
        result = restore(json.loads(raw))
    except (ValueError, TypeError) as error:
        result = {"integration": "dns_restore", "event": "response", "result": "failed", "error": str(error)[:240]}
    result.update(timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  duration_seconds=time.monotonic() - started)
    write_audit(result, AUDIT, 0)
    return int(result["result"] not in ("restored", "already_approved", "maintenance", "busy"))


if __name__ == "__main__":
    raise SystemExit(main())
