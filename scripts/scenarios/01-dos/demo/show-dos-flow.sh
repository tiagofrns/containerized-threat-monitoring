#!/usr/bin/env bash
# Scenario 1: controlled availability demonstration.
# Disable rate limiting only on a disposable replica; production keeps its controls.
# The protected phase uses the current demo evaluator.
set -Eeuo pipefail

usage() {
  cat <<'HELP'
Usage: bash show-dos-flow.sh [--pause] [--preflight-only] [--replicas]

  --pause           Pause between phases for a live presentation
  --preflight-only  Check prerequisites without creating Pods or generating requests
  --replicas        Also run the isolated replica test at the end

Requirements: project Incus/k3s, Python 3 on the host and in Analytics.
Production Deployment protection remains enabled.
HELP
}
PAUSE=0; PREFLIGHT=0; REPLICAS=0
for arg in "$@"; do
  case "$arg" in
    --pause) PAUSE=1 ;;
    --preflight-only) PREFLIGHT=1 ;;
    --replicas) REPLICAS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

DEMO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Place in scripts/scenarios/01-dos/demo/ or set SSLE_ROOT.
ROOT="${SSLE_ROOT:-$(cd -- "$DEMO_DIR/../../../.." && pwd)}"
# Use the demo evaluator: check Active Response prerequisites only on the Pod node.
# The original evaluator remains unchanged.
RECORD_SCRIPT="${CASE1_CACHE_SCRIPT:-$DEMO_DIR/record-cache-response-demo.py}"
# Optional bounded replica check; evidence is retained under evidence/.
REPLICA_SCRIPT="${CASE1_REPLICA_SCRIPT:-$DEMO_DIR/../record-replica-scope.py}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEMO_NAME="analytics-no-limit-$(date -u +%y%m%dt%H%M%S)-$$"
DIR="/var/lib/analytics-protection/$DEMO_NAME"
OUT="$DEMO_DIR/results/demo-flow-$STAMP-$$"
MASTER=k3s-master
NODES=(k3s-master k3s-node1)
NAMESPACE=ssle
CLONE_CREATED=0
DIR_NODES=()
PROD_BEFORE_SAVED=0
SUCCESS=0

say() {
  printf '\n'
  printf '%s\n' '=================================================================='
  printf '  %s\n' "$*"
  printf '%s\n' '=================================================================='
}
info() { printf '  %-24s %s\n' "$1" "$2"; }

pause() { if (( PAUSE )); then read -r -p 'Press ENTER to continue...' _ || :; fi; }
kube() { incus exec "$MASTER" -- k3s kubectl -n "$NAMESPACE" "$@"; }
err() { printf '\n[ERROR] %s\n' "$*" >&2; }

cleanup_clone() {
  local bad=0
  if (( CLONE_CREATED )); then
    echo '[CLEANUP] Removing the temporary Deployment...'
    kube delete deployment "$DEMO_NAME" --ignore-not-found=true --wait=true --timeout=90s >"$OUT/delete-deployment.log" 2>&1 || { cat "$OUT/delete-deployment.log" >&2; bad=1; }
    # Deployment deletion does not guarantee that its terminating Pods are gone.
    # Remove/wait for this uniquely labelled temporary Pod before snapshots.
    kube delete pods -l "app=$DEMO_NAME" --ignore-not-found=true --wait=true --timeout=90s >>"$OUT/delete-deployment.log" 2>&1 || { cat "$OUT/delete-deployment.log" >&2; bad=1; }
    # On failure, the exit trap retries cleanup and preserves the logs.
    (( bad == 0 )) && CLONE_CREATED=0
  fi
  local node
  local remaining=()
  for node in "${DIR_NODES[@]}"; do
    incus exec "$node" -- rm -f -- "$DIR/cache.json" >>"$OUT/delete-directories.log" 2>&1 || bad=1
    if ! incus exec "$node" -- rmdir -- "$DIR" >>"$OUT/delete-directories.log" 2>&1; then
      remaining+=("$node")
      bad=1
    fi
  done
  DIR_NODES=("${remaining[@]}")
  return "$bad"
}
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -d "$OUT" ]]; then
    cleanup_clone || { err 'Could not fully clean up the temporary environment. Check the logs.'; rc=1; }
    if (( PROD_BEFORE_SAVED )); then
      if kube get deployment analytics -o json >"$OUT/production-after.json" 2>"$OUT/postflight-error.log"; then
        if python3 - "$OUT/production-before.json" "$OUT/production-after.json" <<'PY'
import json,sys
before,after=(json.load(open(p)) for p in sys.argv[1:])
assert before['spec']==after['spec'], 'The production Deployment spec changed!'
print('[EVIDENCE] Deployment analytics: spec unchanged before and after.')
PY
        then :; else err 'The production Deployment changed or verification failed.'; rc=1; fi
      else
        err 'Could not read the production Deployment after the run.'; rc=1
      fi
    fi
    python3 - "$OUT" <<'PY' || true
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1])
manifest={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(root.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.json'}
(root/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
    printf '\n[RESULTS AND EVIDENCE] %s\n' "$OUT"
    if (( rc == 0 )); then printf '[RESULT] Demonstration completed.\n'; else printf '[RESULT] Demonstration incomplete (exit code %s).\n' "$rc"; fi
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for bin in incus python3; do command -v "$bin" >/dev/null || { err "Required host command is missing: $bin."; exit 1; }; done
[[ -f "$RECORD_SCRIPT" ]] || { err "Cannot find $RECORD_SCRIPT. Set CASE1_CACHE_SCRIPT or SSLE_ROOT."; exit 1; }
[[ -f "$ROOT/apps/analytics.py" ]] || { err "Cannot find apps/analytics.py in $ROOT. Set SSLE_ROOT."; exit 1; }
mkdir -p -- "$OUT"
: >"$OUT/delete-directories.log"

say '[0/8] PREREQUISITES: K3s, live Analytics and active protection'
kube get deployment analytics -o json >"$OUT/production-before.json"
PROD_BEFORE_SAVED=1
python3 - "$OUT/production-before.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); s=p['spec']
cs=s['template']['spec']['containers']
assert len(cs)==1, 'Expected one Analytics container in the manifest'
env={e['name']:e.get('value') for e in cs[0].get('env',[])}
assert env.get('ANALYTICS_RATE_LIMIT_ENABLED')=='true', 'Production Analytics rate limiting is not enabled'
assert s.get('replicas',1)==1, 'The protected evaluator requires one production replica'
vol=next((v for v in s['template']['spec'].get('volumes',[]) if v['name']=='protection'),None)
assert vol and 'hostPath' in vol, 'Cannot find the protection hostPath volume'
print('Deployment:',p['metadata']['name'])
print('Image:',cs[0]['image'])
print('ANALYTICS_RATE_LIMIT_ENABLED:',env['ANALYTICS_RATE_LIMIT_ENABLED'])
print('Production replicas:',s['replicas'])
print('Protection hostPath:',vol['hostPath']['path'])
print('[EVIDENCE] Production protection is enabled and remains active throughout the demonstration.')
PY
kube get pods -l app=analytics -o wide | tee "$OUT/production-pods.txt"
printf '[POLICY] 5 requests/s per observed source; 10 rejections/60 s trigger Wazuh rule 100121.\n' 
printf '[CONTROL] Unrestricted clone: 15 serial reads + 1 warm-up; protected service: at most 77 reads.\n'
python3 "$DEMO_DIR/runtime_contract.py" --source-root "$ROOT" > "$OUT/runtime-contract.json"
cat "$OUT/runtime-contract.json"
if (( PREFLIGHT )); then
  echo '[OK] Preflight completed. No runtime changes or /average requests were made.'
  exit 0
fi
pause

say '[1/8] WITHOUT PROTECTION: create a TEMPORARY Pod without rate limiting'
python3 - "$OUT/production-before.json" "$OUT/temporary-manifest.json" "$DEMO_NAME" "$DIR" <<'PY'
import copy,json,sys
src,dest,name,directory=sys.argv[1:]
original=json.load(open(src))
spec=copy.deepcopy(original['spec'])
spec['replicas']=1
spec['selector']={'matchLabels':{'app':name}}
spec['template']['metadata']={'labels':{'app':name}}
container=spec['template']['spec']['containers'][0]
found=0
for var in container['env']:
    if var['name']=='ANALYTICS_RATE_LIMIT_ENABLED':
        assert var.get('value')=='true'
        var['value']='false'
        found+=1
assert found==1, 'Expected one ANALYTICS_RATE_LIMIT_ENABLED variable'
for volume in spec['template']['spec']['volumes']:
    if volume['name']=='protection':
        assert volume.get('hostPath',{}).get('path')
        volume['hostPath']['path']=directory
        break
else:
    raise SystemExit('Protection volume not found')
manifest={'apiVersion':'apps/v1','kind':'Deployment',
          'metadata':{'name':name,'namespace':'ssle','labels':{'ssle-demo':'unprotected-clone'}},
          'spec':spec}
with open(dest,'w') as f:json.dump(manifest,f,indent=2)
print('Isolated manifest:',name)
print('Clone environment: ANALYTICS_RATE_LIMIT_ENABLED=false')
print('Dedicated volume:',directory)
print('The clone has no Service or NodePort.')
PY
for node in "${NODES[@]}"; do
  # Create the parent directory first to avoid ambiguity between -m and -p.
  incus exec "$node" -- mkdir --parents -- "$DIR"
  DIR_NODES+=("$node")
  incus exec "$node" -- chmod 0755 -- "$DIR"
done
CLONE_CREATED=1
kube apply -f - <"$OUT/temporary-manifest.json"
kube rollout status "deployment/$DEMO_NAME" --timeout=90s
kube get pods -l "app=$DEMO_NAME" -o json >"$OUT/temporary-pods.json"
POD="$(python3 - "$OUT/temporary-pods.json" <<'PY'
import json,sys
pods=json.load(open(sys.argv[1]))['items']
assert len(pods)==1, f'Expected one temporary Pod, found {len(pods)}'
p=pods[0]; c=p['spec']['containers'][0]
env={v['name']:v.get('value') for v in c.get('env',[])}
assert env['ANALYTICS_RATE_LIMIT_ENABLED']=='false'
assert p['metadata']['labels']['app'].startswith('analytics-no-limit-')
print(p['metadata']['name'])
PY
)"
printf '[EVIDENCE] Temporary Pod: %s\n' "$POD"
printf '[EVIDENCE] Production is unchanged. Rate limiting is disabled only on the temporary clone.\n'
pause

say '[2/8] WITHOUT PROTECTION: 15 HTTP responses and the Storage request counter'
# Prometheus counters may be absent before the first request.
# One warm-up request initializes lazily created metrics.
remote_code="$(cat <<'PYREMOTE'
import json,time,requests,collections,statistics
url='http://127.0.0.1:5003'
metric_name='analytics_storage_requests_total'

def fetch_metrics():
    response=requests.get(url+'/metrics',timeout=(1,5))
    response.raise_for_status()
    return response.text

def metric(raw, name):
    # Aggregate all exposed series in the counter family, with or without labels.
    values=[]
    for line in raw.splitlines():
        line=line.strip()
        if not line or line.startswith('#'):
            continue
        pieces=line.rsplit(None,1)
        if len(pieces)!=2:
            continue
        sample_name=pieces[0].split('{',1)[0]
        if sample_name in (name, 'ssle_' + name):
            values.append((sample_name, float(pieces[1])))
    families = {sample for sample, value in values}
    if len(families) > 1:
        raise ValueError('Ambiguous metric aliases: ' + ', '.join(sorted(families)))
    return sum(value for sample, value in values) if values else None

def available(raw):
    return sorted({line.split(None,1)[0].split('{',1)[0] for line in raw.splitlines()
                   if line and not line.startswith('#') and not line.isspace()})

# Prepare the fixture outside the measured 15-request sample.
t=time.monotonic()
warm=requests.get(url+'/average',timeout=(1,5))
warm.raise_for_status()
warm_body=warm.json()
assert warm_body.get('protection_mode')=='normal' and not warm_body.get('cached'), warm_body
print(json.dumps({'event':'warmup','http_status':warm.status_code,
                  'duration_ms':round((time.monotonic()-t)*1000,3),
                  'body':warm_body},ensure_ascii=False),flush=True)
before_text=fetch_metrics()
before=metric(before_text,metric_name)
rows=[]
for i in range(1,16):
    t=time.monotonic()
    r=requests.get(url+'/average',timeout=(1,5))
    try: body=r.json()
    except ValueError: body={'raw':r.text[:200]}
    row={'event':'request','ordinal':i,'http_status':r.status_code,
         'duration_ms':round((time.monotonic()-t)*1000,3),'body':body}
    rows.append(row)
    print(json.dumps(row,ensure_ascii=False),flush=True)
after_text=fetch_metrics()
after=metric(after_text,metric_name)
if before is None or after is None:
    print(json.dumps({'event':'metric_diagnostic',
                      'metric':metric_name,
                      'before_present':before is not None,
                      'after_present':after is not None,
                      'available_before':available(before_text),
                      'available_after':available(after_text),
                      'reason':'Cannot verify the number of Storage calls without this counter'},ensure_ascii=False),flush=True)
summary={'event':'summary','count':len(rows),'warmup_requests':1,
         'http_statuses':dict(collections.Counter(str(r['http_status']) for r in rows)),
         'modes':sorted(set(str(r['body'].get('protection_mode')) for r in rows)),
         'cached':sum(bool(r['body'].get('cached')) for r in rows),
         'storage_metric_available':before is not None and after is not None,
         'storage_calls_before':before,'storage_calls_after':after,
         'storage_calls_delta':(after-before) if before is not None and after is not None else None,
         'mean_latency_ms':round(statistics.mean(r['duration_ms'] for r in rows),3)}
print(json.dumps(summary,ensure_ascii=False),flush=True)
PYREMOTE
)"
kube exec "$POD" -- python -c "$remote_code" > "$OUT/unprotected-reads.jsonl"
printf '\n  Requests to the instance WITHOUT rate limiting (live data):\n'
python3 - "$OUT/unprotected-reads.jsonl" <<'PY_TABLE'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
for r in rows:
    if r.get('event')=='request':
        b=r.get('body',{})
        print(f"    #{r['ordinal']:02d}  HTTP {r['http_status']}   {r['duration_ms']:7.2f} ms   cache={'YES' if b.get('cached') else 'NO'}")
PY_TABLE
python3 - "$OUT/unprotected-reads.jsonl" <<'PY'
import json,sys
rows=[json.loads(x) for x in open(sys.argv[1])]
warm=next((r for r in rows if r['event']=='warmup'),None)
reads=[r for r in rows if r['event']=='request']
s=next((r for r in rows if r['event']=='summary'),None)
assert warm and warm['http_status']==200 and s and len(reads)==15
assert all(r['http_status']==200 for r in reads), 'Some requests were rejected or failed'
assert all(r['body'].get('protection_mode')=='normal' and not r['body'].get('cached') for r in reads)
print('\n[EVIDENCE] 1 warm-up request + 15 measured requests: HTTP 200; cached=false; protection_mode=normal.')
if s['storage_metric_available']:
    delta=s['storage_calls_delta']
    print('[EVIDENCE] %s: %s -> %s (delta %s)' %
          ('analytics_storage_requests_total',s['storage_calls_before'],s['storage_calls_after'],delta))
    assert delta>0, 'The counter exists but recorded no Storage calls'
else:
    print('  [UNVERIFIED] The expected Analytics Storage request metric was not found in /metrics.')
    print('  [LIMITATION] HTTP requests are real, but the Storage HTTP attempt counter could not be identified.')
    for row in rows:
        if row['event']=='metric_diagnostic':
            print('  [DIAGNOSTIC] Available metrics: '+', '.join(row['available_after']))
            break
print('  [SCOPE] Functional demonstration only; saturation and DoS capacity are not measured.')
from collections import Counter
counts=Counter(str(r['http_status']) for r in reads)
print('\n  HTTP RESPONSES (test Pod without rate limiting)')
for code in sorted(counts):
    n=counts[code]
    print(f'    HTTP {code} |{"█"*n}{"░"*(15-n)}| {n}')

PY
pause

say '[3/8] CLEANUP: remove the temporary Pod and verify production is unchanged'
cleanup_clone
kube get deployment analytics -o json >"$OUT/production-after-clone.json"
python3 - "$OUT/production-before.json" "$OUT/production-after-clone.json" <<'PY'
import json,sys
a,b=(json.load(open(x)) for x in sys.argv[1:])
assert a['spec']==b['spec'], 'The production Analytics Deployment was modified'
print('[EVIDENCE] Analytics spec unchanged before and after the clone.')
PY
pause

say '[4/8] WITH PROTECTION: live Analytics, HTTP rate limiting, Wazuh and cache' 
echo 'Live Analytics keeps its protection and receives at most 77 controlled reads:'
echo '  30 normal -> 15 admission -> 30 cached -> 2 recovery reads.'
echo 'Evidence files retain HTTP status, response body, mode, cache state and latency.'
printf '\n  [PREFLIGHT] Locate the protected Pod and the Wazuh response executable...\n'
kube get pods -l app=analytics -o json >"$OUT/protected-pods.json"
PROTECTED_NODE="$(python3 - "$OUT/protected-pods.json" <<'PY_NODE'
import json,sys
items=[p for p in json.load(open(sys.argv[1]))['items'] if not p['metadata'].get('deletionTimestamp')]
assert len(items)==1, f'Expected exactly one production Analytics Pod, found {len(items)}'
print(items[0]['spec']['nodeName'])
PY_NODE
)"
info 'Analytics node:' "$PROTECTED_NODE"
python3 "$DEMO_DIR/runtime_contract.py" --source-root "$ROOT" > "$OUT/runtime-contract.json"
python3 - "$OUT/runtime-contract.json" <<'PY_CONTRACT'
import json,sys
contract=json.load(open(sys.argv[1]))
print('  Configured Active Response:', contract['response_script'])
print('  Lease file on the node:', contract['lease_file'])
print('  Audit integration identifier:', contract['audit_integration'])
PY_CONTRACT
# The evaluator still requires actual event, activation and recovery evidence.
python3 -u "$RECORD_SCRIPT" >"$OUT/protected-run.log" 2>&1 || {
  printf '\n  [FAIL] Protected evaluation failed; last log lines:\n' >&2
  tail -n 24 "$OUT/protected-run.log" >&2
  exit 1
}
printf '  [EVIDENCE] Protected evaluation completed; full log: protected-run.log\n'

EVIDENCE="$(python3 - "$OUT/protected-run.log" <<'PY'
import re,sys
s=open(sys.argv[1]).read()
m=re.findall(r'^Evidence:\s*(/[^\n]+)$',s,re.M)
assert m, 'The evaluator did not return an evidence directory'
print(m[-1].strip())
PY
)"
[[ -f "$EVIDENCE/summary.json" ]] || { err "The evaluator did not create $EVIDENCE/summary.json"; exit 1; }
printf '[EVIDENCE] Evidence produced by the evaluator: %s\n' "$EVIDENCE"
printf '%s\n' "$EVIDENCE" >"$OUT/protected-evidence-path.txt"
pause

say '[5/8] COMPARISON: accepted/rejected requests, cache and latency'
python3 - "$OUT/unprotected-reads.jsonl" "$EVIDENCE/summary.json" <<'PY'
import json,sys
unprot=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
u=next(r for r in unprot if r['event']=='summary')
s=json.load(open(sys.argv[2]))
print('\n  WITHOUT RATE LIMITING | isolated Pod')
print('    Requests:',u['count'],'| HTTP:',u['http_statuses'],'| Mean:',u['mean_latency_ms'],'ms')
print('    Storage counter:',u['storage_calls_delta'] if u['storage_metric_available'] else 'UNAVAILABLE')
print('\n  WITH RATE LIMITING | production Analytics (bounded trial)')
print('    HTTP responses:',s['admission_statuses'])
assert int(s['admission_statuses'].get('429',0))>=1, 'No HTTP 429 response was recorded'
for phase in ('normal','protected','recovery'):
    p=s[phase]
    print(f'  PHASE {phase}:')
    for name in ('manual_requests','manual_http_statuses','manual_cached',
                 'manual_mean_ms','storage_attempts_all_clients',
                 'analytics_200_all_clients'):
        print(f'    {name}: {p.get(name)}')
assert s['normal']['manual_cached']==0
assert 0 < s['protected']['manual_cached'] <= s['protected']['manual_requests'], 'No protected cache hits were observed'
normal=s['normal']; protected=s['protected']
assert normal['analytics_200_all_clients'] > 0 and protected['analytics_200_all_clients'] > 0
normal_cost=normal['storage_attempts_all_clients']/normal['analytics_200_all_clients']
protected_cost=protected['storage_attempts_all_clients']/protected['analytics_200_all_clients']
assert 0 <= protected_cost < normal_cost, 'Cache did not reduce Storage attempts per admitted request'
print('[EVIDENCE] Protected cache hits: {}/{}; other protected reads can perform scheduled refreshes.'.format(protected['manual_cached'],protected['manual_requests']))
print('[EVIDENCE] Storage attempts per admitted request: normal={:.3f}; cache={:.3f}'.format(normal_cost,protected_cost))
assert s['recovery']['manual_cached']==0
print('[EVIDENCE] Rate limiting rejected requests; cache served reads; lease expiry restored normal mode.')
print('[SCOPE] Clone and production latency measurements are not directly comparable.')

def bar(v, mx, width=26):
    n=max(0,round(width*v/mx)) if mx else 0
    return '█'*n+'░'*(width-n)

ad=s['admission_statuses']
print('\n  RESPONSE DISTRIBUTION (bounded admission check)')
max_count=max((int(x) for x in ad.values()),default=1)
for status in ('200','429'):
    count=int(ad.get(status,0))
    print(f'    HTTP {status} |{bar(count,max_count)}| {count}')
print('\n  OBSERVED MEAN LATENCY (normal, cache and recovery requests)')
means=[(lab, float(s[key]['manual_mean_ms'])) for lab,key in
       [('Normal','normal'),('Cache active','protected'),('Recovery','recovery')]]
maximum=max((v for _,v in means),default=1)
for lab,value in means:
    print(f'    {lab:<12s}|{bar(value,maximum)}| {value:.3f} ms')
print('  [NOTE] Bars represent only observations from this trial.')
PY
pause

say '[6/8] WAZUH: event 100121, response 100130 and lease expiry'
python3 - "$EVIDENCE" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); s=json.loads((p/'summary.json').read_text())
lease=json.loads((p/'active-lease.json').read_text())
responses=json.loads((p/'response-events.json').read_text())
alerts=json.loads((p/'manager-alerts.json').read_text())
print('Correlated event ID:',s['event_id'])
print('Temporary lease: mode=%s | issued=%s | expires=%s' % (lease.get('mode'),lease.get('issued_at'),lease.get('expires_at')))
for a in alerts:
    print('MANAGER id=%s rule=%s timestamp=%s' %
          (a.get('id'),a.get('rule',{}).get('id'),a.get('timestamp')))
for e in responses:
    print('ACTIVE RESPONSE:',json.dumps({k:e.get(k) for k in ('integration','event_id','result','timestamp')},ensure_ascii=False))
assert any(a.get('id')==s['event_id'] and a.get('rule',{}).get('id')=='100121' for a in alerts)
assert {'enabled','disabled'}<=set(e.get('result') for e in responses)
assert s['indexed_hits']>=3
print('[EVIDENCE] 100121 -> cache enabled -> cache disabled | indexed events: %s' % s['indexed_hits'])
PY
pause

say '[7/8] PROMETHEUS: metrics and recorded alert history'
python3 - "$EVIDENCE" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); f=p/'prometheus-full-history.json'; c=p/'prometheus-cache-history.json'
for path in (c,f):
    if not path.exists():
        print('Not found:',path.name);continue
    doc=json.loads(path.read_text())
    assert doc.get('status')=='success'
    samples=doc.get('data',{}).get('result',[])
    print('File:',path.name,'series:',len(samples))
    seen=0
    for series in samples:
        m=series.get('metric',{})
        name=m.get('__name__','').removeprefix('ssle_')
        if name not in ('analytics_protection_active','analytics_cache_responses_total','analytics_storage_requests_total','ALERTS'):
            continue
        if seen>=12:break
        values=series.get('values',[])
        labels={k:v for k,v in m.items() if k!='__name__'}
        print('    %s %s | samples=%d | first=%s | last=%s' %
              (name,labels,len(values),values[0] if values else None,values[-1] if values else None))
        seen+=1
print('[EVIDENCE] API history saved. Alert evaluations use their own time windows.')
PY
pause

say '[8/8] RECOVERY: verify normal mode, removed lease and unchanged production'
python3 - "$EVIDENCE" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); s=json.loads((p/'summary.json').read_text())
assert json.loads((p/'lease-after.json').read_text()) is None
assert s['pod_identities_and_restarts_unchanged']
assert s['recovery']['manual_http_statuses']=={'200':2}
print('[EVIDENCE] Cache lease removed (lease-after.json = null).')
print('[EVIDENCE] 2/2 HTTP 200, protection_mode normal, cached=false.')
print('[EVIDENCE] Pod identities and restart counts are unchanged.')
print('[LIMITATION] Capacity, saturation and DDoS resilience are outside the scope of this trial.')
PY
if (( REPLICAS )); then
  [[ -f "$REPLICA_SCRIPT" ]] || { err "Cannot find $REPLICA_SCRIPT"; exit 1; }
  say '[EXTRA] 1 -> 2 replicas: verify cache activates only on the authorized node'
  if SSLE_REPLICA_RESULTS="$OUT" python3 -u "$REPLICA_SCRIPT" >"$OUT/replica-run.log" 2>&1; then
    python3 - "$OUT/replica-run.log" <<'PY_REPLICAS'
import json,re,sys
s=open(sys.argv[1]).read()
m=re.search(r'^Evidence:\s*(.+)$',s,re.M)
if m: print('  [EVIDENCE] Replica trial results:',m.group(1).strip())
else: print('  [EVIDENCE] See replica-run.log for the complete result')
PY_REPLICAS
  else
    tail -n 25 "$OUT/replica-run.log" >&2
    err 'The optional replica trial failed. See replica-run.log.'
    exit 1
  fi
  echo '[NOTE] This trial uses a test lease, not a second Wazuh activation.' 
fi
SUCCESS=1
printf '\n[COMPLETE] Original results from each check have been saved.\n'
