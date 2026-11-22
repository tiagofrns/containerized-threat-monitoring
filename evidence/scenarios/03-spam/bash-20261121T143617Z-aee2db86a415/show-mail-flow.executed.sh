#!/usr/bin/env bash
# SSLE / Cenário 03: demonstração de spam com provas de entrega, classificação, alertas e auditoria.
# Executar apenas no laboratório Incus mail-container / *.lab.test.
set -Eeuo pipefail

MAIL=mail-container
PROM=prometheus-container
WAZUH=wazuh-container
USER_MAIL=security-operations
DOMAIN=mail.lab.test
FROM_ADDR=validation@mail.lab.test
TO_ADDR=security-operations@mail.lab.test
MASTER_CF=/etc/postfix/master.cf
EVENTS=/var/log/mail-security/events.jsonl
GATEWAY=/opt/mail-security/mail_gateway.py
ALERT=MailQuarantineActivity
EXPECTED_FILTER=spamassassin:filter
PAUSE=0
PREFLIGHT=0
RELEASE=0

for arg in "$@"; do
  case "$arg" in
    --pause) PAUSE=1 ;;
    --preflight-only) PREFLIGHT=1 ;;
    --release) RELEASE=1 ;;
    -h|--help)
      cat <<'HELP'
Uso: bash show-mail-flow.sh [--pause] [--preflight-only] [--release]
  --pause           Pausa entre etapas, para apresentação ao vivo.
  --preflight-only  Verifica a configuração sem a modificar.
  --release         Demonstra a libertação autorizada de uma amostra GTUBE.
O filtro SMTP é automaticamente desativado durante o teste sem proteção e
reposto depois. Um trap tenta restaurar a configuração em caso de falha.
HELP
      exit 0 ;;
    *) printf 'Argumento desconhecido: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

for needed in incus python3 sha256sum awk grep mktemp; do
  command -v "$needed" >/dev/null 2>&1 || { echo "Falta o comando '$needed'" >&2; exit 1; }
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Colocar o script em scripts/scenarios/03-spam/demo/. Caso contrário, guardar ao lado do script.
if [[ "$script_dir" == */scripts/scenarios/03-spam/demo ]]; then
  project_root="$(cd "$script_dir/../../../.." && pwd)"
  evidence_root="$project_root/evidence/scenarios/03-spam"
else
  evidence_root="$script_dir/evidence"
fi
token="$(python3 -c 'import uuid;print(uuid.uuid4().hex[:12])')"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$evidence_root/bash-$stamp-$token"
mkdir -p -- "$evidence" "$evidence/messages"
if (( ! PREFLIGHT )); then
  exec > >(tee "$evidence/flow.log") 2>&1
fi

backup=""
original_sha=""
filter_changed=0
restored=0

say() { printf '%s\n' "$*"; }
step() { printf '\n========== [%s/7] %s ==========\n' "$1" "$2"; }
fail() { printf '[FALHA] %s\n' "$*" >&2; exit 1; }
press_enter() {
  if (( PAUSE )) && [[ -t 0 ]]; then
    read -r -p 'Carrega ENTER para continuar...' _
  fi
}
remote() { incus exec "$MAIL" -- "$@"; }
postfix_filter() {
  remote postconf -P | awk -F '=' '
    $1 ~ /^[[:space:]]*smtp\/inet\/content_filter[[:space:]]*$/ {
      sub(/^[[:space:]]*/, "", $2); sub(/[[:space:]]*$/, "", $2); print $2; found=1; exit
    }
    END { if (!found) exit 3 }
  '
}
restore() {
  local now
  [[ -n "$backup" ]] || return 0
  now="$(remote sha256sum "$MASTER_CF" | awk '{print $1}')" || return 1
  if [[ "$now" != "$original_sha" ]]; then
    remote cp -p -- "$backup" "$MASTER_CF" || return 1
  fi
  remote postfix check && remote postfix reload || return 1
  [[ "$(remote sha256sum "$MASTER_CF" | awk '{print $1}')" == "$original_sha" ]] || return 1
  [[ "$(postfix_filter)" == "$EXPECTED_FILTER" ]] || return 1
  restored=1
}
cleanup() {
  local status=$1
  trap - EXIT INT TERM
  set +e
  if [[ -n "$backup" ]]; then
    if restore; then
      printf '\n[SEGURANÇA] Filtro Postfix original confirmado.\n'
      remote rm -f -- "$backup"
    else
      printf '\n[CRÍTICO] Não consegui confirmar a reposição do Postfix. Backup preservado: %s\n' "$backup" >&2
      status=1
    fi
  fi
  if (( ! PREFLIGHT )); then
    printf '[EVIDÊNCIAS] %s\n' "$evidence"
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Envia RFC 5322 com Python apenas para formar corretamente o email.
# Toda a sequência e a verificação da demonstração são controladas por Bash.
send_message() {
  local kind=$1 mid=$2 flag=${3:-}
  remote python3 -c '
import sys,smtplib
from datetime import datetime,timezone
from email.message import EmailMessage
from email.utils import format_datetime
kind,mid,flag = sys.argv[1:]
gtube="XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
msg=EmailMessage()
msg["From"]="validation@mail.lab.test"
msg["To"]="security-operations@mail.lab.test"
msg["Subject"]="SSLE DEMO | "+kind
msg["Message-ID"]=mid
msg["Date"]=format_datetime(datetime.now(timezone.utc))
if flag: msg["X-Spam-Flag"]=flag
msg.set_content("A análise de temperatura terminou normalmente." if kind=="legitimo" else gtube)
with smtplib.SMTP("127.0.0.1",25,timeout=8) as smtp:
    refused=smtp.send_message(msg)
    if refused:
        raise RuntimeError(f"Destinatários recusados: {refused}")
' "$kind" "$mid" "$flag"
  say "[SMTP] Aceite pelo servidor: $kind | Message-ID: $mid"
}

mailbox_search() {
  local folder=$1 mid=$2
  remote doveadm search -u "$USER_MAIL" mailbox "$folder" header Message-ID "$mid"
}
observe() { remote python3 "$GATEWAY" observe >/dev/null; }

# Dovecot é a fonte primária para provar que a mensagem FOI GUARDADA numa pasta.
# Além de pesquisar o Message-ID, guardamos o resultado de doveadm fetch text
# e verificamos a assinatura GTUBE (ou o corpo legítimo) no conteúdo real.
prove_stored_message() {
  local mid=$1 expected=$2 kind=$3 actual=$4 other=$5 event=$6
  local key raw_file uid_file opposite_file event_file
  key="$(printf '%s' "$mid" | sha256sum | awk '{print substr($1,1,16)}')"
  raw_file="$evidence/messages/${key}-doveadm-fetch.txt"
  uid_file="$evidence/messages/${key}-uids-${expected}.txt"
  opposite_file="$evidence/messages/${key}-uids-OTHER.txt"
  event_file="$evidence/messages/${key}-audit.json"

  printf '%s\n' "$actual" > "$uid_file"
  printf '%s\n' "$other" > "$opposite_file"
  printf '%s\n' "$event" > "$event_file"
  remote doveadm fetch -u "$USER_MAIL" text mailbox "$expected" header Message-ID "$mid" > "$raw_file"
  # Comprovação do conteúdo devolvido pelo Dovecot, não pelo remetente.
  python3 - "$raw_file" "$mid" "$kind" "$expected" "$event_file" <<'PYMAIL'
from pathlib import Path
import json, sys, re
raw_path, mid, kind, folder, event_path = sys.argv[1:]
raw = Path(raw_path).read_text(encoding='utf-8', errors='replace')
event = json.loads(Path(event_path).read_text())
GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
if mid not in raw:
    sys.exit(f'[FALHA] O doveadm fetch não devolveu o Message-ID esperado: {mid}')
if kind == 'gtube' and GTUBE not in raw:
    sys.exit('[FALHA] O conteúdo GTUBE não está no email realmente guardado')
if kind == 'legitimo' and 'temperatura' not in raw.lower():
    sys.exit('[FALHA] Corpo legítimo não encontrado na mensagem armazenada')
if kind == 'notificacao' and ('[Security Operations]' not in raw or 'Dear Security Operations Team' not in raw):
    sys.exit('[FALHA] A notificação guardada não contém o texto operacional esperado')
if event.get('message_id') != mid or event.get('folder') != folder:
    sys.exit('[FALHA] Auditoria contradiz a pasta ou o Message-ID do Dovecot')
print(f'  [DOVECOT FETCH] Message-ID confirmado no conteúdo: {mid}')
for line in raw.splitlines():
    if re.match(r'(?i)^\s*(?:text:\s*)?(Subject|Message-ID|X-Spam-Flag|X-Spam-Status):', line):
        print('  [CABEÇALHO REAL] ' + line.strip()[:220])
if kind == 'gtube':
    print('  [CORPO REAL] Assinatura GTUBE presente no email armazenado')
elif kind == 'legitimo':
    print('  [CORPO REAL] Conteúdo legítimo confirmado')
else:
    print('  [CORPO REAL] Notificação de segurança confirmada')
print('  [AUDITORIA JSON] outcome={}, folder={}, spam_status={}'.format(
    event.get('outcome'), event.get('folder'), event.get('spam_status')))
PYMAIL
  printf '%s\t%s\t%s\t%s\n' "$mid" "$expected" "$key" "$kind" >> "$evidence/messages/indice.tsv"
  say "  [FICHEIROS PROVA] messages/${key}-doveadm-fetch.txt | ${key}-uids-${expected}.txt | ${key}-audit.json"
}

# Exige duas fontes INDEPENDENTES de prova:
# 1) Dovecot: exatamente 1 mensagem na pasta esperada e 0 na oposta;
# 2) Ledger do observer: mesmo Message-ID, outcome e folder.
verify_folder() {
  local mid=$1 expected=$2 max=${3:-60} kind=${4:-gtube}
  local other outcome actual wrong event i
  if [[ "$expected" == INBOX ]]; then
    other=Quarantine; outcome=delivered
  else
    other=INBOX; outcome=quarantined
  fi
  for ((i=0; i<max/2; i++)); do
    observe
    actual="$(mailbox_search "$expected" "$mid")"
    wrong="$(mailbox_search "$other" "$mid")"
    [[ -z "$wrong" ]] || fail "$mid foi encontrado em $other, mas esperava $expected"
    event="$(remote tail -n 2000 "$EVENTS" | json_select event "$mid" "$outcome")"
    if [[ -n "$actual" && -n "$event" ]]; then
      [[ "$(printf '%s\n' "$actual" | wc -l)" -eq 1 ]] || fail "Duplicados no $expected para $mid"
      say "  [DOVEADM SEARCH] mailbox=$expected | UID/GUID: $actual"
      say "  [DOVEADM SEARCH] mailbox=$other | nenhum resultado (0 mensagens)"
      printf '%s\n' "$event" >> "$evidence/delivery-events.jsonl"
      prove_stored_message "$mid" "$expected" "$kind" "$actual" "$wrong" "$event"
      say "  [PROVA CRUZADA] Dovecot + Maildir observer: $expected (1 cópia)"
      return 0
    fi
    sleep 2
  done
  fail "Não apareceu $mid em $expected dentro de $max segundos"
}

# Seletores JSON/JSONL com Python 3: sem dependência de jq.
# Lê da entrada padrão e imprime apenas os dados pedidos.
json_select() {
  python3 -c '
import json, sys

mode, *args = sys.argv[1:]

def json_lines():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue

def output(row):
    print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))

if mode == "event":
    message_id, outcome = args
    matches = [r for r in json_lines() if r.get("message_id") == message_id and r.get("outcome") == outcome]
    if matches:
        output(matches[-1])
elif mode == "spam_status":
    print(json.load(sys.stdin).get("spam_status") or "sem classificação")
elif mode == "alert_exists":
    name = args[0]
    rows = json.load(sys.stdin).get("data", {}).get("alerts", [])
    sys.exit(0 if any(a.get("labels", {}).get("alertname") == name for a in rows) else 1)
elif mode == "target_up":
    rows = json.load(sys.stdin).get("data", {}).get("activeTargets", [])
    sys.exit(0 if any(t.get("labels", {}).get("job") == "mail-security" and t.get("health") == "up" for t in rows) else 1)
elif mode == "alert":
    name = args[0]
    rows = json.load(sys.stdin).get("data", {}).get("alerts", [])
    for row in rows:
        if row.get("labels", {}).get("alertname") == name:
            output(row)
            break
elif mode == "state":
    print(json.load(sys.stdin).get("state", ""))
elif mode == "notification":
    episode = args[0]
    matches = [r for r in json_lines() if r.get("outcome") == "notification_submitted"
               and r.get("alert_title") == "Mail quarantine activity"
               and r.get("episode") == episode]
    if matches:
        print(matches[-1].get("message_id", ""))
elif mode == "wazuh":
    agent, *message_ids = args
    wanted = set(message_ids)
    for row in json_lines():
        if row.get("agent", {}).get("name") == agent and row.get("data", {}).get("message_id") in wanted:
            output(row)
elif mode == "rule_ids":
    for rid in sorted({str(r.get("rule", {}).get("id", "")) for r in json_lines()}):
        if rid:
            print(rid)
elif mode == "wazuh_summary":
    wanted = {"100601", "100602", "100605"}
    for row in json_lines():
        rid = str(row.get("rule", {}).get("id", ""))
        if rid in wanted:
            print("[WAZUH] regra {} | alerta {} | Message-ID {} | outcome {} | agent {}".format(
                rid, row.get("id", ""), row.get("data", {}).get("message_id", ""),
                row.get("data", {}).get("outcome", ""), row.get("agent", {}).get("name", "")))
elif mode == "notification_count":
    episode = args[0]
    rows = [r for r in json_lines() if r.get("outcome") == "notification_submitted" and r.get("episode") == episode]
    print(len(rows))
elif mode == "submitted":
    print(json.load(sys.stdin).get("submitted", ""))
elif mode == "wazuh_pairs":
    mid_off, mid_good, mid_spam1, mid_spam2, mid_spam3, notification = args
    seen = {(str(row.get("rule", {}).get("id", "")), row.get("data", {}).get("message_id"))
            for row in json_lines()}
    required = {( "100602", mid_off), ("100602", mid_good),
                ("100601", mid_spam1), ("100601", mid_spam2),
                ("100601", mid_spam3), ("100602", notification),
                ("100605", notification)}
    sys.exit(0 if required.issubset(seen) else 1)
elif mode == "only_rule":
    wanted=args[0]
    matches=[r for r in json_lines() if str(r.get("rule",{}).get("id", ""))==wanted]
    if matches:
        output(matches[-1])
elif mode == "digest":
    message_id = args[0]
    matches = [r for r in json_lines() if r.get("message_id") == message_id and r.get("digest")]
    if matches:
        print(matches[-1]["digest"])
else:
    sys.exit("JSON selector desconhecido: " + mode)
' "$@"
}

# Prometheus API é consultada de dentro do prometheus-container.
prom() { incus exec "$PROM" -- curl -fsS --max-time 5 "http://10.255.255.21:9090$1"; }
check_alert_clear() {
  local response i
  for ((i=0; i<72; i++)); do
    response="$(prom /api/v1/alerts)"
    if ! printf '%s' "$response" | json_select alert_exists "$ALERT"; then
      return 0
    fi
    if ((i % 5 == 0)); then say "A aguardar o episódio anterior de $ALERT terminar..."; fi
    sleep 5
  done
  fail "Já existe um alerta $ALERT; espera que termine antes de repetir a demo"
}

say 'SSLE | CENÁRIO 03: Spam antes/depois da proteção'
say 'Laboratório: mail-container | security-operations@mail.lab.test'
say 'O antispam será desativado AUTOMATICAMENTE na etapa 1.'
step 0 'Confirmar serviços, configuração e baseline do Prometheus'
for svc in postfix dovecot spamassassin mail_gateway wazuh-agent; do
  state="$(remote systemctl is-active "$svc")" || fail "$svc não está ativo"
  [[ "$state" == active ]] || fail "$svc não está ativo: $state"
  say "  [SYSTEMD] $svc: $state"
done
[[ "$(remote postconf -h inet_interfaces)" == loopback-only ]] || fail 'A demo só é permitida com Postfix em loopback-only'
[[ "$(remote postconf -h myhostname)" == "$DOMAIN" ]] || fail "O Postfix não usa $DOMAIN"
value="$(postfix_filter)" || fail 'Não encontrei smtp/inet/content_filter no master.cf'
[[ "$value" == "$EXPECTED_FILTER" ]] || fail "Filtro inesperado ($value). Nenhuma alteração efetuada."
say "  [POSTCONF] smtp/inet/content_filter = $value"
remote postconf -P smtp/inet/content_filter > "$evidence/postconf-original.txt"
remote sha256sum "$MASTER_CF" > "$evidence/mastercf-sha256-before.txt"
if (( PREFLIGHT )); then
  say '[OK] Preflight concluído. Não desativei nenhuma proteção.'
  exit 0
fi
check_alert_clear
prom /api/v1/targets | json_select target_up \
  || fail 'Exporter mail-security não está UP no Prometheus'
backup="$(remote mktemp /tmp/ssle-postfix.XXXXXXXX)"
remote cp -p -- "$MASTER_CF" "$backup"
original_sha="$(remote sha256sum "$MASTER_CF" | awk '{print $1}')"
press_enter

step 1 'SEM ANTISPAM: desativar temporariamente o filtro SMTP'
filter_changed=1
remote postconf -P 'smtp/inet/content_filter='
remote postfix check
remote postfix reload
[[ -z "$(postfix_filter)" ]] || fail 'content_filter continua ativo'
remote postconf -P smtp/inet/content_filter | tee "$evidence/postconf-sem-filtro.txt"
say '  [PROVA] content_filter vazio; Postfix e Dovecot continuam ativos.'
press_enter

step 2 'Enviar GTUBE sem filtro e mostrar chegada real à INBOX'
mid_off="<ssle-$token-sem-filtro@mail.lab.test>"
send_message gtube-sem-filtro "$mid_off"
verify_folder "$mid_off" INBOX 60 gtube
say '[PROVA] GTUBE chegou à INBOX porque a filtragem estava desligada.'
press_enter

step 3 'Reativar antispam e confirmar Postfix original'
restore || fail 'Não consegui reativar o filtro'
say "  [PROVA] Filtro restaurado: $(postfix_filter)"
remote postconf -P smtp/inet/content_filter | tee "$evidence/postconf-com-filtro.txt"
say '  A permitir que Prometheus recolha o histórico do contador (35 s)...'
sleep 35
press_enter

step 4 'Reenviar GTUBE com filtro; comparar pastas'
mid_good="<ssle-$token-legitimo@mail.lab.test>"
mid_spam1="<ssle-$token-spam1@mail.lab.test>"
mid_spam2="<ssle-$token-spam2@mail.lab.test>"
mid_spam3="<ssle-$token-spam3@mail.lab.test>"
send_message legitimo "$mid_good"
verify_folder "$mid_good" INBOX 60 legitimo
send_message gtube-protegido "$mid_spam1"
verify_folder "$mid_spam1" Quarantine
send_message gtube-falso-limpo "$mid_spam2" NO
verify_folder "$mid_spam2" Quarantine
send_message gtube-repetido "$mid_spam3"
verify_folder "$mid_spam3" Quarantine
say 'COMPARAÇÃO: GTUBE sem filtro -> INBOX | GTUBE com filtro -> Quarantine'
press_enter

step 5 'Esperar alerta real MailQuarantineActivity no Prometheus'
alert_json=""
previous_state=""
for ((i=0; i<90; i++)); do
  alert_json="$(prom /api/v1/alerts | json_select alert "$ALERT")"
  if [[ -n "$alert_json" ]]; then
    state="$(printf '%s' "$alert_json" | json_select state)"
    if [[ "$state" != "$previous_state" ]]; then
      say "  $ALERT: $state"
      previous_state=$state
    fi
    [[ "$state" != firing ]] || break
  fi
  sleep 3
done
[[ -n "$alert_json" && "$(printf '%s' "$alert_json" | json_select state)" == firing ]] \
  || fail "O alerta $ALERT não chegou a FIRING"
printf '%s\n' "$alert_json" > "$evidence/prometheus-firing.json"
python3 - "$evidence/prometheus-firing.json" <<'PYPROM'
import json,sys
row=json.load(open(sys.argv[1]))
print('[PROMETHEUS API] alertname =', row['labels'].get('alertname'))
print('[PROMETHEUS API] state =', row['state'])
print('[PROMETHEUS API] activeAt =', row.get('activeAt'))
print('[PROMETHEUS API] labels =', json.dumps(row['labels'],sort_keys=True))
PYPROM
say "[PROVA] Alerta $ALERT em FIRING confirmado pela API, JSON integral guardado."
press_enter

step 6 'Alertmanager, notificação operacional e Wazuh'
# A identificação do episódio deve coincidir exatamente com o cálculo do gateway.
episode="$(printf '%s' "$alert_json" | python3 -c '
import hashlib,json,sys
row=json.load(sys.stdin)
print(hashlib.sha256(json.dumps([row["labels"],row["activeAt"]],sort_keys=True).encode()).hexdigest())
')"
notification=""
for ((i=0; i<75; i++)); do
  notification="$(remote tail -n 3000 "$EVENTS" | json_select notification "$episode")"
  [[ -z "$notification" ]] || break
  sleep 2
done
[[ -n "$notification" ]] || fail 'Não foi encontrada notificação deste episódio no Alertmanager/Mail gateway'
say "[MAIL GATEWAY] Evento notification_submitted do episódio: $episode"
say "[MAIL GATEWAY] Message-ID da notificação: $notification"
remote tail -n 3000 "$EVENTS" | json_select event "$notification" notification_submitted > "$evidence/notification-submitted-event.json"
# O evento acima tem origem no mail_gateway. A prova de receção vem do doveadm fetch.

verify_folder "$notification" INBOX 90 notificacao
remote doveadm fetch -u "$USER_MAIL" text mailbox INBOX header Message-ID "$notification" \
  > "$evidence/notification.txt"
grep -qF '[Security Operations]' "$evidence/notification.txt" \
  || fail 'O email operacional foi entregue sem o conteúdo esperado'
say '[PROVA] Notificação recebida: UID/GUID no Dovecot + texto do email + evento de entrega.'

# Verifica o controlo de acesso ao webhook e a prevenção de duplicados,
# reutilizando o episódio real que foi detetado nesta demonstração.
say '[WEBHOOK] Testar autenticação e supressão de notificações duplicadas'
unauth_status="$(remote curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
  -X POST http://127.0.0.1:9096/alerts)"
printf '%s\n' "$unauth_status" > "$evidence/webhook-sem-auth-http-status.txt"
[[ "$unauth_status" == 401 ]] || fail "Webhook sem autenticação devolveu HTTP $unauth_status (esperado 401)"
say "  [PROVA] POST sem credenciais -> HTTP $unauth_status"

before_notifications="$(remote tail -n 3000 "$EVENTS" | json_select notification_count "$episode")"
[[ "$before_notifications" -eq 1 ]] || fail "Episódio deve ter uma única submissão, encontrei $before_notifications"
replay_result="$(remote python3 -c '
import json,sys,urllib.request
from pathlib import Path
row=json.loads(sys.argv[1])
replay={"status":"firing","alerts":[{"status":"firing","labels":row["labels"],"startsAt":row["activeAt"]}]}
request=urllib.request.Request("http://127.0.0.1:9096/alerts",
  data=json.dumps(replay).encode(),
  headers={"Authorization":"Bearer "+Path("/etc/mail-security/webhook-secret").read_text().strip(),
           "Content-Type":"application/json"})
with urllib.request.urlopen(request, timeout=10) as response:
    print(response.read().decode())
' "$alert_json")"
printf '%s\n' "$replay_result" > "$evidence/webhook-repetido.json"
[[ "$(printf '%s' "$replay_result" | json_select submitted)" == 0 ]] \
  || fail 'A repetição do mesmo alerta causou uma nova submissão SMTP'
after_notifications="$(remote tail -n 3000 "$EVENTS" | json_select notification_count "$episode")"
[[ "$after_notifications" -eq 1 ]] \
  || fail "Foram registadas novas notificações no episódio (total=$after_notifications)"
say "  [PROVA] Repetição autenticada -> submitted=0; ledger mantém $after_notifications notificação."

wazuh_events=""
for ((i=0; i<60; i++)); do
  wazuh_events="$(incus exec "$WAZUH" -- tail -n 6000 /var/ossec/logs/alerts/alerts.json \
      | json_select wazuh "$MAIL" "$mid_off" "$mid_good" "$mid_spam1" "$mid_spam2" "$mid_spam3" "$notification")"
  ids="$(printf '%s\n' "$wazuh_events" | json_select rule_ids)"
  if printf '%s\n' "$wazuh_events" | json_select wazuh_pairs "$mid_off" "$mid_good" "$mid_spam1" "$mid_spam2" "$mid_spam3" "$notification"; then
    break
  fi
  sleep 2
done
if ! printf '%s\n' "$wazuh_events" | json_select wazuh_pairs "$mid_off" "$mid_good" "$mid_spam1" "$mid_spam2" "$mid_spam3" "$notification"; then
  fail 'Wazuh: faltam eventos de auditoria específicos para um ou mais Message-IDs desta execução'
fi
printf '%s\n' "$wazuh_events" > "$evidence/wazuh-events.jsonl"
printf '%s\n' "$wazuh_events" | json_select wazuh_summary
say '[PROVA] Wazuh Manager: alertas reais com IDs, regras, agent e Message-IDs guardados em wazuh-events.jsonl'
press_enter

step 7 'Resumo final e configuração original'
if (( RELEASE )); then
  digest="$(json_select digest "$mid_spam1" < "$evidence/delivery-events.jsonl")"
  [[ -n "$digest" ]] || fail 'Digest da mensagem em quarentena não encontrado'
  say 'Operador: a libertar uma única mensagem GTUBE de teste...'
  remote python3 "$GATEWAY" release "$digest"
  remote python3 "$GATEWAY" release "$digest"
  observe
  [[ "$(mailbox_search INBOX "$mid_spam1" | wc -l)" -eq 1 ]] \
    || fail 'A libertação não resultou numa única mensagem em INBOX'
  [[ -z "$(mailbox_search Quarantine "$mid_spam1")" ]] \
    || fail 'A mensagem ainda está em Quarantine depois da libertação'
  say '[PROVA] Libertação: exatamente uma cópia na INBOX, nenhuma em Quarantine.'
  # Regra 100603: evidência do evento de libertação após observação do Maildir.
  release_alert=''
  for ((j=0; j<60; j++)); do
    release_alert="$(incus exec "$WAZUH" -- tail -n 6000 /var/ossec/logs/alerts/alerts.json \
      | json_select wazuh "$MAIL" "$mid_spam1" | json_select only_rule 100603)"
    [[ -z "$release_alert" ]] || break
    sleep 2
  done
  [[ -n "$release_alert" ]] || fail 'Libertação sem evidência da regra Wazuh 100603'
  printf '%s\n' "$release_alert" > "$evidence/wazuh-release-100603.json"
  say "[WAZUH] regra 100603 confirmada para $mid_spam1"
fi
restore || fail 'Configuração original Postfix não confirmada'
say '  [OK] GTUBE sem filtro -> INBOX'
say '  [OK] GTUBE com filtro -> Quarantine'
say '  [OK] Email legítimo -> INBOX'
say '  [OK] Prometheus MailQuarantineActivity -> FIRING'
say '  [OK] Alerta operacional -> INBOX'
say '  [OK] Webhook sem autenticação -> 401; replay -> 0 notificações novas'
say '  [OK] Wazuh 100601 / 100602 / 100605'
remote postconf -P smtp/inet/content_filter > "$evidence/postconf-final.txt"
remote sha256sum "$MASTER_CF" > "$evidence/mastercf-sha256-final.txt"
say "  [POSTFIX FINAL] $(cat "$evidence/postconf-final.txt")"
say "  [SHA-256 ANTES] $(cat "$evidence/mastercf-sha256-before.txt")"
say "  [SHA-256 DEPOIS] $(cat "$evidence/mastercf-sha256-final.txt")"
[[ "$(awk '{print $1}' "$evidence/mastercf-sha256-before.txt")" == \
   "$(awk '{print $1}' "$evidence/mastercf-sha256-final.txt")" ]] \
  || fail 'Hash final do master.cf difere do original'
say '  [OK] Configuração Postfix restaurada e hash SHA-256 idêntico' 
say "[EVIDÊNCIAS CONCRETAS] $evidence"
say '  flow.log                         - stdout completo da execução'
say '  messages/indice.tsv              - Message-ID -> pasta -> prova doveadm'
say '  messages/*-doveadm-fetch.txt     - conteúdo efetivo lido do Maildir'
say '  messages/*-uids-*                - pesquisas real/oposta do Dovecot'
say '  messages/*-audit.json            - evento real do observador'
say '  prometheus-firing.json           - alerta FIRING da API'
say '  notification.txt                 - email operacional real'
say '  wazuh-events.jsonl              - alertas reais do manager'
say '  webhook-sem-auth-http-status.txt - prova de HTTP 401'
say '  webhook-repetido.json           - replay com submitted=0'
say '  mastercf-sha256-{before,final}.txt - integridade do Postfix'
say '[DONE] Demonstração concluída com provas cruzadas.' 
