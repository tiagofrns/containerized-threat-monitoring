#!/usr/bin/python3
"""Remove sender-controlled classification headers before the local spam scan."""
from email import policy
from email.parser import BytesParser
import subprocess
import sys
from mail_origin import attach


def main():
    raw = sys.stdin.buffer.read(262145)
    if len(raw) > 262144:
        return 75
    message = BytesParser(policy=policy.SMTP).parsebytes(raw)
    for name in list(message.keys()):
        if name.lower().startswith(('x-spam-', 'x-mail-filter-')):
            del message[name]
    scan = subprocess.run(['/usr/bin/spamc', '-x', '-t', '30', '-d', '127.0.0.1'],
                          input=message.as_bytes(), capture_output=True, timeout=40)
    if scan.returncode or not scan.stdout:
        return 75
    scanned = BytesParser(policy=policy.SMTP).parsebytes(scan.stdout)
    if len(sys.argv) < 5:
        return 75
    attach(scanned, sys.argv[1], sys.argv[2])
    # Re-injection uses the Postfix envelope arguments, including a null sender.
    delivery = subprocess.run(['/usr/sbin/sendmail', '-G', '-i', '-f', sys.argv[3], '--', *sys.argv[4:]],
                              input=scanned.as_bytes(), timeout=30)
    return 0 if delivery.returncode == 0 else 75


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError):
        raise SystemExit(75)
