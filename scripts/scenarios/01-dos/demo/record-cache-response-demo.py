"""Fixed-cap functional validation of the cache response, not a load test.

Run on the lab VM. Controls stay enabled. No writes, concurrency or escalation.
The admission check has a hard cap of fifteen serial requests, once only.
"""
from collections import Counter
from datetime import datetime, timezone
import csv
import math
import statistics
import hashlib
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from runtime_contract import compare_analytics_source, discover, pod_stability_report, read_metrics

# This demo evaluator lives in scripts/scenarios/01-dos/demo/.
ROOT = Path(__file__).resolve().parents[4]
ANALYTICS = 'http://10.255.255.254:30503'
PROM = 'http://10.255.255.21:9090'
CLIENT = 'http://10.255.255.74:30802/metrics'
NORMAL_READS = 30
PROTECTED_READS = 30
RECOVERY_READS = 2
assert NORMAL_READS + PROTECTED_READS + RECOVERY_READS + 15 <= 80

def command(args, data=None, check=True):
    return subprocess.run(args, input=data, text=True, capture_output=True, check=check, timeout=90)

def incus(node, *args, **kwargs):
    return command(['incus','exec',node,'--',*args], **kwargs)

def get(url):
    with urllib.request.urlopen(url, timeout=5) as reply:
        return reply.read().decode()

def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    marker = 'case1-cache-'+stamp
    out = Path(__file__).resolve().parent / 'results' / marker
    out.mkdir(parents=True)
    def save(name, data):
        path = out/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, allow_nan=False)+'\n')
    def now():
        return datetime.now(timezone.utc).isoformat()
    def query(expression, endpoint='query', **kwargs):
        return json.loads(get(PROM+'/api/v1/'+endpoint+'?'+urllib.parse.urlencode(dict(query=expression,**kwargs))))
    def snapshot(label):
        data = {'utc':now(), 'time':time.time(), 'analytics_metrics':get(ANALYTICS+'/metrics'),
                'client_metrics':get(CLIENT), 'monitoring':query(
                    '{__name__=~"(ssle_)?(service_up|storage_measurements|container_cpu_usage_cores|container_memory_working_set_bytes)"}')}
        save(label+'.json',data)
        return data
    contract = discover()
    def lease():
        process = incus(node,'cat',contract['lease_file'],check=False)
        return json.loads(process.stdout) if process.returncode==0 else None
    rows=[]
    def request(label, ordinal):
        tick=time.monotonic()
        started=now()
        try:
            with urllib.request.urlopen(ANALYTICS+'/average?'+urllib.parse.urlencode({'source':marker}),timeout=5) as reply:
                status, data = reply.status, json.load(reply)
        except urllib.error.HTTPError as error:
            status, data = error.code, json.loads(error.read())
        row={'phase':label,'ordinal':ordinal,'utc':started,'status':status,
             'duration_ms':1000*(time.monotonic()-tick),'body':data}
        rows.append(row)
        save('responses/'+label+'-'+str(ordinal)+'.json',row)
        return row
    for test_node in ('k3s-master', 'k3s-node1'):
        incus(test_node, 'test', '-x', '/usr/bin/python3')
    pre = json.loads(incus('k3s-master','k3s','kubectl','-n','ssle','get','deployments,pods','-o','json').stdout)
    save('cluster-before.json',pre)
    deployments = {v['metadata']['name']:v for v in pre['items'] if v['kind']=='Deployment'}
    assert deployments['sensor']['spec']['replicas']==0
    assert deployments['analytics']['spec']['replicas']==1
    assert deployments['analytics']['spec']['template']['spec']['containers'][0]['image'].endswith(':case1-final-v1')
    pods = [v for v in pre['items'] if v['kind']=='Pod' and v['metadata']['labels'].get('app')=='analytics']
    assert len(pods)==1
    node=pods[0]['spec']['nodeName']
    assert node in ('k3s-master','k3s-node1')
    # Wazuh needs the Active Response executable on the node running Analytics.
    # If it is missing on that node, stop with an explicit cause; do not skip validation.
    assert contract['node'] == node
    save('runtime-contract.json', contract)
    print('[PREREQUISITE] Configured Active Response: ' + contract['response_script'], flush=True)
    assert lease() is None, 'A lease from another run already exists; check it before continuing'
    save('conditions.json', {'normal_reads': NORMAL_READS, 'protected_reads': PROTECTED_READS, 'recovery_reads': RECOVERY_READS, 'single_admission_check_cap': 15, 'cadence_seconds': 1, 'node': node, 'total_manual_cap': 77, 'scope': 'Fixed ordinary-read comparison and functional response; no workload escalation or saturation test'})
    runtime_source = incus('k3s-master','k3s','kubectl','-n','ssle','exec',pods[0]['metadata']['name'],
                            '--','cat','/app/app.py').stdout
    repository_source = (ROOT/'apps/analytics.py').read_text()
    save('source-comparison.json', compare_analytics_source(runtime_source, repository_source))
    (out/'analytics-runtime.py').write_text(runtime_source)
    (out/'analytics-repository.py').write_text(repository_source)
    start=time.time()
    before=snapshot('normal-before')
    for i in range(NORMAL_READS):
        row=request('normal',i+1)
        assert row['status']==200 and row['body']['protection_mode']=='normal' and not row['body']['cached']
        time.sleep(1)
    normal_after=snapshot('normal-after')
    time.sleep(2)
    for i in range(15):
        request('admission',i+1)
    print('[ADMISSION] Responses from the controlled 15-request admission check:',dict(Counter(r['status'] for r in rows if r['phase']=='admission')),flush=True)
    for _ in range(20):
        active=lease()
        if active and active['expires_at']>time.time():
            break
        time.sleep(1)
    else:
        save('partial-results.json',rows)
        raise RuntimeError('Wazuh did not activate the cache; stopping without increasing the request count.')
    save('active-lease.json',active)
    print('[WAZUH] Temporary lease observed: mode=%s; expires=%s' % (active.get('mode'),active.get('expires_at')),flush=True)
    protected_before=snapshot('protected-before')
    for i in range(PROTECTED_READS):
        row=request('protected',i+1)
        assert row['status']==200 and row['body']['protection_mode']=='cache'
        assert row['body']['stats_age_seconds']<=10
        time.sleep(1)
    protected_after=snapshot('protected-after')
    samples=[]
    # Observe expiration. No application requests are generated in this wait.
    while time.time()<active['expires_at']+3:
        samples.append({'time':time.time(),'utc':now(),'metrics':get(ANALYTICS+'/metrics')})
        time.sleep(min(5,max(0.1,active['expires_at']+3-time.time())))
    save('lease-expiry-observations.json',samples)
    recovery_before=snapshot('recovery-before')
    for i in range(RECOVERY_READS):
        row=request('recovery',i+1)
        assert row['status']==200 and row['body']['protection_mode']=='normal' and not row['body']['cached']
        time.sleep(1)
    recovery_after=snapshot('recovery-after')
    final_lease=lease()
    save('lease-after.json',final_lease)
    assert final_lease is None, 'Application recovered but Wazuh delete has not been observed'
    logs=incus(node,'tail','-n','150','/var/ossec/logs/active-responses.log').stdout
    (out/'active-responses.log').write_text(logs)
    response_events=[]
    for line in logs.splitlines():
        try:
            item=json.loads(line)
        except ValueError:
            continue
        if item.get('integration')==contract['audit_integration'] and item.get('event_id')==active['event_id']:
            response_events.append(item)
    save('response-events.json',response_events)
    assert {v['result'] for v in response_events}>={'enabled','disabled'}
    manager=incus('wazuh-container','tail','-n','5000','/var/ossec/logs/alerts/alerts.json').stdout
    alerts=[]
    for line in manager.splitlines():
        item=json.loads(line)
        if item.get('id')==active['event_id'] or (
                item.get('rule',{}).get('id')=='100130' and active['event_id'] in item.get('full_log','')):
            alerts.append(item)
    save('manager-alerts.json',alerts)
    assert any(v.get('id')==active['event_id'] and v['rule']['id']=='100121' for v in alerts)
    assert sum(v['rule']['id']=='100130' for v in alerts)>=2
    finalize(out)


def finalize(out):
    """Finish retained observations. This function generates no /average requests."""
    out = out.resolve()
    if out.parent != (Path(__file__).resolve().parent / 'results').resolve():
        raise ValueError('Expected a scenario 1 result directory under demo/results')
    if (out/'summary.json').exists():
        raise ValueError('This run is already finalized; do not overwrite it')
    def load(name):
        return json.loads((out/name).read_text())
    def save(name, data):
        (out/name).write_text(json.dumps(data, indent=2, allow_nan=False)+'\n')
    def now():
        return datetime.now(timezone.utc).isoformat()
    def query(expression, endpoint='query', **kwargs):
        return json.loads(get(PROM+'/api/v1/'+endpoint+'?'+urllib.parse.urlencode(dict(query=expression,**kwargs))))
    marker=out.name
    rows=[json.loads(path.read_text()) for path in (out/'responses').glob('*.json')]
    rows.sort(key=lambda r: (['normal','admission','protected','recovery'].index(r['phase']),r['ordinal']))
    active=load('active-lease.json')
    pre=load('cluster-before.json')
    before,normal_after=load('normal-before.json'),load('normal-after.json')
    protected_before,protected_after=load('protected-before.json'),load('protected-after.json')
    recovery_before,recovery_after=load('recovery-before.json'),load('recovery-after.json')
    response_events=load('response-events.json')
    start,end=before['time'],recovery_after['time']
    search={'size':20,'query':{'bool':{'filter':[
        {'terms':{'rule.id':['100121','100130']}},
        {'range':{'timestamp':{'gte':datetime.fromtimestamp(start,timezone.utc).isoformat()}}}],
        'should':[{'match_phrase':{'full_log':marker}},
                  {'match_phrase':{'full_log':active['event_id']}}], 'minimum_should_match':1}}}
    args=['curl','--silent','--show-error','--fail','--max-time','15',
          '--cacert','/etc/wazuh-indexer/certs/root-ca.pem','--cert','/etc/wazuh-indexer/certs/admin.pem',
          '--key','/etc/wazuh-indexer/certs/admin-key.pem','-H','Content-Type: application/json',
          '-X','POST','https://127.0.0.1:9200/wazuh-alerts-*/_search','--data-binary','@-']
    # Indexing is asynchronous. Preserve each bounded read, including a partial result.
    for attempt in range(1,21):
        index=json.loads(incus('wazuh-container',*args,data=json.dumps(search)).stdout)
        save('indexer-attempt-'+datetime.now(timezone.utc).strftime('%H%M%S')+'-'+str(attempt)+'.json',index)
        hits=index['hits']['hits']
        detected=any(h['_source'].get('id')==active['event_id'] for h in hits)
        outcomes={h['_source'].get('data',{}).get('result') for h in hits
                  if h['_source'].get('rule',{}).get('id')=='100130'
                  and h['_source'].get('data',{}).get('event_id')==active['event_id']}
        if detected and outcomes >= {'enabled','disabled'}:
            break
        time.sleep(1)
    else:
        raise RuntimeError('Indexing incomplete; retain evidence and retry --finalize-existing, without new traffic')
    save('indexed-alerts-final.json',index)
    save('prometheus-cache-history.json',query('{__name__=~"(ssle_)?(analytics_protection_active|analytics_cache_responses_total|analytics_storage_requests_total)"}',
        endpoint='query_range',start=start,end=end,step=5))
    save('prometheus-full-history.json', query('{__name__=~"(ssle_)?(service_up|resource_collection_up|container_cpu_usage_cores|container_memory_working_set_bytes|storage_measurements|client_requests_total|client_request_duration_seconds_bucket|analytics_requests_total|ALERTS)"}', endpoint='query_range', start=start, end=end, step=15))
    # Re-finalization must retain the snapshot captured at the end of the trial.
    # A new snapshot would measure later changes and overwrite the original proof.
    if (out/'cluster-after.json').exists():
        post = load('cluster-after.json')
    else:
        post=json.loads(incus('k3s-master','k3s','kubectl','-n','ssle','get','deployments,pods','-o','json').stdout)
        save('cluster-after.json',post)
    stability = pod_stability_report(pre, post)
    save('pod-stability.json', stability)
    if not stability['unchanged']:
        for change in stability['changes']:
            print('[CLUSTER CHANGE] ' + json.dumps(change, sort_keys=True), flush=True)
        raise RuntimeError('Pod identity or restart count changed during trial; see ' + str(out/'pod-stability.json'))
    metrics = read_metrics
    def percentile(data, p):
        values=sorted(data)
        position=(len(values)-1)*p
        lower=math.floor(position)
        upper=math.ceil(position)
        return values[lower]+(values[upper]-values[lower])*(position-lower)
    def phase(name,first,last):
        replies=[r for r in rows if r['phase']==name]
        a,b=metrics(first['analytics_metrics']),metrics(last['analytics_metrics'])
        c,d=metrics(first['client_metrics']),metrics(last['client_metrics'])
        n=d['client_request_duration_seconds_count']-c['client_request_duration_seconds_count']
        successes=d['client_requests_total{outcome="success"}']-c['client_requests_total{outcome="success"}']
        return {'manual_mean_ms':statistics.mean(r['duration_ms'] for r in replies),
                'manual_p50_ms':percentile([r['duration_ms'] for r in replies],0.5),
                'manual_p95_ms':percentile([r['duration_ms'] for r in replies],0.95),
                'manual_requests':len(replies),'manual_http_statuses':dict(Counter(r['status'] for r in replies)),
                'manual_cached':sum(r['body'].get('cached',False) for r in replies),
                'manual_fresh':sum(r['status']==200 and not r['body'].get('cached',False) for r in replies),
                'manual_max_snapshot_age_seconds':max(r['body'].get('stats_age_seconds',0) for r in replies),
                'storage_attempts_all_clients':b['analytics_storage_requests_total']-a['analytics_storage_requests_total'],
                'analytics_200_all_clients':b['analytics_requests_total{status="200"}']-a['analytics_requests_total{status="200"}'],
                'background_client_requests':n,'background_client_errors':n-successes,
                'background_client_mean_latency_ms':1000*(d['client_request_duration_seconds_sum']-c['client_request_duration_seconds_sum'])/n if n else None}
    result={'run_marker':marker,'scope':'Bounded equal-cadence cache comparison and functional response; not a saturation/capacity trial',
            'event_id':active['event_id'],'lease':active,'normal':phase('normal',before,normal_after),
            'protected':phase('protected',protected_before,protected_after),
            'recovery':phase('recovery',recovery_before,recovery_after),
            'admission_statuses':dict(Counter(r['status'] for r in rows if r['phase']=='admission')),
            'response_events':response_events,'indexed_hits':len(index['hits']['hits']),
            'pod_identities_and_restarts_unchanged':True,'completed_at_utc':now()}
    save('summary.json',result)
    with (out/'requests.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=['phase','ordinal','utc','status','duration_ms','cached','protection_mode','stats_age_seconds','cache_fallback','average_temperature'])
        writer.writeheader()
        for r in rows:
            writer.writerow({**{k:v for k,v in r.items() if k!='body'},
                             **{k:v for k,v in r['body'].items() if k!='error'}})
    save('SHA256SUMS.json',{str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(out.rglob('*')) if p.is_file()})
    print(json.dumps(result,indent=2),flush=True)
    print('Evidence:',out,flush=True)
    print('[EVIDENCE] Results saved to:',out,flush=True)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--finalize-existing',type=Path,help='Finish retained evidence without new application requests')
    arguments=parser.parse_args()
    if arguments.finalize_existing:
        finalize(arguments.finalize_existing)
    else:
        main()
