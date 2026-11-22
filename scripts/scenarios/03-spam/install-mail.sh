#!/usr/bin/env bash
# Run on the Debian VM. The guide stages use one dedicated Incus container.
set -euo pipefail

container=mail-container
stage=${1:-}
if [[ $# != 1 || ! $stage =~ ^(base|filter)$ ]]; then
    printf 'Usage: %s {base|filter}\n' "$0" >&2
    exit 2
fi

if ! incus info "$container" >/dev/null 2>&1; then
    if [[ $stage != base ]]; then
        printf 'Install the mail base first.\n' >&2
        exit 1
    fi
    incus launch "${MAIL_IMAGE:-images:ubuntu/22.04}" "$container" -c user.project.role=mail </dev/null
fi
if [[ $(incus config get "$container" user.project.role) != mail ]]; then
    printf 'The existing %s is outside this installer.\n' "$container" >&2
    exit 1
fi
if [[ $(incus list --format csv -c ns | awk -F, -v name="$container" '$1 == name {print $2}') == STOPPED ]]; then
    incus start "$container"
fi

incus exec "$container" -- bash -s -- "$stage" <<'CONTAINER'
set -euo pipefail
stage=$1
. /etc/os-release
if [[ $ID != ubuntu || $VERSION_ID != 22.04 ]]; then
    printf 'Expected the Ubuntu 22.04 container used in the guide.\n' >&2
    exit 1
fi

install_packages() {
    (
        # Apply the loopback settings before starting any newly installed daemon.
        policy=/usr/sbin/policy-rc.d
        if [[ ! -e $policy && ! -L $policy ]]; then
            (set -o noclobber; printf '#!/bin/sh\nexit 101\n' > "$policy")
            trap 'rm -f -- "$policy"' EXIT
            chmod 755 "$policy"
        fi
        export DEBIAN_FRONTEND=noninteractive
        apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=15 update
        apt-get -y --no-install-recommends -o Acquire::Retries=2 -o Acquire::http::Timeout=15 install "$@"
    )
}

if [[ $stage == base ]]; then
    printf '%s\n' 'postfix postfix/main_mailer_type select Local only' \
        'postfix postfix/mailname string mail.lab.test' | debconf-set-selections
    install_packages postfix dovecot-imapd dovecot-pop3d mailutils python3
    if ! id security-operations >/dev/null 2>&1; then
        adduser --disabled-password --gecos 'Security Operations operations mailbox' --shell /usr/sbin/nologin security-operations
    fi
    postconf -e 'myhostname = mail.lab.test' 'mydomain = lab.test' \
        'mydestination = $myhostname, localhost.localdomain, localhost' \
        'inet_interfaces = loopback-only' 'inet_protocols = ipv4' 'mynetworks = 127.0.0.0/8' \
        'smtpd_relay_restrictions = reject_unauth_destination' \
        'default_transport = error:5.7.1 External delivery disabled' \
        'relay_transport = error:5.7.1 External delivery disabled' 'message_size_limit = 262144'
    cat > /etc/dovecot/conf.d/99-mail-mail.conf <<'DOVECOT'
listen = 127.0.0.1
mail_location = mbox:~/mail:INBOX=/var/mail/%u
mail_privileged_group = mail
DOVECOT
    postfix check
    doveconf -n >/dev/null
    systemctl enable postfix dovecot
    systemctl restart postfix dovecot
    systemctl is-active postfix dovecot
    postconf myhostname inet_interfaces smtpd_relay_restrictions default_transport
else
    systemctl is-active --quiet postfix
    systemctl is-active --quiet dovecot
    install_packages spamassassin spamc
    if ! id spamd >/dev/null 2>&1; then
        adduser --system --group --home /var/lib/spamd --shell /usr/sbin/nologin spamd
    fi
    cat > /etc/spamassassin/99-mail-mail.cf <<'SPAMASSASSIN'
rewrite_header Subject *****SPAM*****
required_score 5.0
use_bayes 1
bayes_auto_learn 1
SPAMASSASSIN
    cat > /etc/default/spamassassin <<'SPAMD'
OPTIONS="--listen=127.0.0.1 --allowed-ips=127.0.0.1 --local --max-children=5 --username=spamd --nouser-config --helper-home-dir=/var/lib/spamd"
SPAMD
    spamassassin --lint --local
    systemctl enable --now spamassassin
    systemctl restart spamassassin
    if ! printf 'Subject: Security Operations spamd readiness\n\nService check.\n' | spamc -x -t 5 -d 127.0.0.1 | grep -F 'X-Spam-Status:'; then
        printf 'SpamAssassin is not ready for the Postfix filter.\n' >&2
        exit 1
    fi
    postconf -M 'spamassassin/unix=spamassassin unix - n n - 5 pipe flags=Rq user=spamd argv=/usr/bin/spamc -x -d 127.0.0.1 -e /usr/sbin/sendmail -G -i -f ${sender} -- ${recipient}'
    postconf -P 'smtp/inet/content_filter=spamassassin:filter'
    postfix check
    postfix reload
    systemctl is-active postfix dovecot spamassassin
    postconf -P smtp/inet/content_filter
fi
CONTAINER
