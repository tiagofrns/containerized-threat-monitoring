#!/usr/bin/env python3
"""Compare temporary Analytics replicas using fixed ordinary-read workloads.

Run on the existing lab VM. Default: print the plan only. No saturation search,
production scaling, database writes or Wazuh activation is performed.
"""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
NODES=('k3s-master','k3s-node1')
REPLICAS=(1,2,4)
REPEATS=3
READS=60
INTERVAL=.5
NAMESPACE='ssle'

DRIVER=r'''
import json,sys,time
import requests
url,count,interval=sys.argv[1],int(sys.argv[2]),float(sys.argv[3])
start=time.monotonic();rows=[];next_allowed=start
for i in range(count):
    scheduled=start+i*interval
    time.sleep(max(0,max(scheduled,next_allowed)-time.monotonic()))
    tick=time.monotonic();next_allowed=tick+interval
    try:
        response=requests.get(url+'/average',timeout=(1,2),headers={'Connection':'close'})
        row={'ordinal':i+1,'status':response.status_code,'body':response.json()}
    except (requests.RequestException,ValueError) as error:
        row={'ordinal':i+1,'status':0,'error':type(error).__name__}
    row.update(duration_ms=1000*(time.monotonic()-tick),dispatch_delay_seconds=max(0,tick-scheduled))
    rows.append(row)
time.sleep(max(0,start+count*interval-time.monotonic()))
print(json.dumps({'reads':rows,'duration_seconds':time.monotonic()-start}))
'''


def command(args,check=True,data=None,timeout=90):
    return subprocess.run(args,input=data,text=True,capture_output=True,check=check,timeout=timeout)


def kube(*args,**kwargs):
    return command(['incus','exec','k3s-master','--','k3s','kubectl','-n',NAMESPACE,*args],**kwargs)


def percentile(values,q):
    values=sorted(values);position=(len(values)-1)*q
    low=int(position);high=min(low+1,len(values)-1)
    return values[low]+(values[high]-values[low])*(position-low)


def counters(text):
    values={'requests':0.,'storage':0.,'cached':0.};seen=set()
    pattern=r'^(?:ssle_)?analytics_(requests_total|storage_requests_total|cache_responses_total)(\{[^}]*\})?\s+([0-9.eE+-]+)$'
    for line in text.splitlines():
        match=re.match(pattern,line)
        if not match:continue
        family,labels,value=match.groups();key=(family,labels or '')
        if key in seen:raise ValueError('Ambiguous metric aliases')
        seen.add(key)
        if family=='requests_total' and 'status="200"' in (labels or ''):values['requests']+=float(value)
        elif family=='storage_requests_total':values['storage']+=float(value)
        elif family=='cache_responses_total':values['cached']+=float(value)
    assert any(x[0]=='storage_requests_total' for x in seen),'Storage-attempt counter is absent'
    return values


def cpu_summary(samples):
    grouped={}
    for sample in samples:
        for pod in sample['pods']:
            grouped.setdefault(pod['uid'],[]).append(pod)
    cores=[];windows=[]
    for rows in grouped.values():
        valid=[r for r in rows if r.get('cpu',{}).get('usageCoreNanoSeconds') is not None]
        first,last=valid[0]['cpu'],valid[-1]['cpu']
        a=datetime.fromisoformat(first['time'].replace('Z','+00:00'))
        b=datetime.fromisoformat(last['time'].replace('Z','+00:00'))
        seconds=(b-a).total_seconds()
        assert seconds>0,'Kubelet did not provide two distinct CPU samples'
        delta=last['usageCoreNanoSeconds']-first['usageCoreNanoSeconds']
        assert delta>=0,'CPU counter reset during a trial'
        cores.append(delta/1e9/seconds);windows.append(seconds)
    memory=[sum(p['memory']['workingSetBytes'] for p in s['pods']) for s in samples]
    return {'mean_cpu_cores':sum(cores),'cpu_sample_windows_seconds':windows,
            'mean_memory_working_set_bytes':statistics.mean(memory),
            'peak_sampled_memory_working_set_bytes':max(memory)}


def plan():
    return {'scope':'Fixed ordinary-read comparison; not a maximum-throughput, saturation or multi-host resilience test',
            'replicas':REPLICAS,'modes':['normal','operator-fixture-cache'],
            'repeats_per_combination':REPEATS,'measured_reads_per_trial':READS,
            'global_dispatch_interval_seconds':INTERVAL,'nominal_duration_seconds':READS*INTERVAL,
            'maximum_measured_reads':len(REPLICAS)*2*REPEATS*READS,
            'cache_activation':'Operator fixture on dedicated temporary node paths, not Wazuh dispatch',
            'production_deployment_scaled':False,'rate_limiting_kept_enabled':True,
            'additional_reads':'One warm-up per candidate Pod per trial, four state-scope reads, two Storage dataset snapshots'}


class Study:
    def __init__(self,out):
        self.out=out;out.mkdir(parents=True,exist_ok=False)
        self.name='analytics-scaling-'+datetime.now(timezone.utc).strftime('%y%m%dt%H%M%S')+'-'+str(os.getpid())
        self.path='/var/lib/analytics-protection/'+self.name
        self.client=self.name+'-client';self.created=False;self.paths=[];self.trials=[]
        self.original=json.loads(kube('get','deployments,pods','-o','json').stdout)
        self.production={x['metadata']['name']:x for x in self.original['items'] if x['kind']=='Deployment'}
        self.save('cluster-before.json',self.original);self.save('conditions.json',plan())
        self.save('host.json',{'cpu_count':os.cpu_count(),'node_names':NODES,'shared_vm':True})

    def save(self,name,value):
        p=self.out/name;p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')

    def pods(self):
        rows=json.loads(kube('get','pods','-l','app='+self.name,'-o','json').stdout)['items']
        return sorted([p for p in rows if not p['metadata'].get('deletionTimestamp')],key=lambda p:p['metadata']['name'])

    def client_python(self,code,*args):
        return kube('exec',self.client,'--','python','-c',code,*args).stdout

    def get_json(self,url):
        return json.loads(self.client_python('import requests,json,sys; r=requests.get(sys.argv[1],timeout=(1,3));r.raise_for_status();print(json.dumps(r.json()))',url))

    def metric_snapshot(self,pods):
        data={}
        for p in pods:
            text=self.client_python('import requests,sys; r=requests.get(sys.argv[1],timeout=(1,3));r.raise_for_status();print(r.text)', 'http://'+p['status']['podIP']+':5003/metrics')
            data[p['metadata']['uid']]={'name':p['metadata']['name'],'node':p['spec']['nodeName'],'text':text,'counters':counters(text)}
        return data

    def resource_snapshot(self,pods):
        wanted={p['metadata']['uid'] for p in pods};selected=[]
        for node in sorted({p['spec']['nodeName'] for p in pods}):
            data=json.loads(kube('get','--raw','/api/v1/nodes/'+node+'/proxy/stats/summary','--request-timeout=10s',timeout=15).stdout)
            for p in data.get('pods',[]):
                if p.get('podRef',{}).get('uid') in wanted:
                    selected.append({'uid':p['podRef']['uid'],'name':p['podRef']['name'],'node':node,'cpu':p.get('cpu',{}),'memory':p.get('memory',{})})
        assert {p['uid'] for p in selected}==wanted,'Resource metrics are missing for a candidate Pod'
        return {'observed_at':datetime.now(timezone.utc).isoformat(),'pods':selected}

    def lease(self,mode,node_only=None):
        issued=time.time()
        value={'version':1,'mode':'cache','event_id':str(int(issued))+'.990001','issued_at':issued,'expires_at':issued+60}
        for node in NODES:
            if mode=='cache' and (node_only is None or node_only==node):
                code="from pathlib import Path;import sys;p=Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o644)"
                command(['incus','exec',node,'--','python3','-c',code,self.path+'/cache.json',json.dumps(value)])
            else:command(['incus','exec',node,'--','rm','-f','--',self.path+'/cache.json'])
        return {'origin':'operator fixture only','nodes':[node_only] if node_only else list(NODES),'lease':value} if mode=='cache' else None

    def setup(self):
        original=self.production['analytics']
        container=original['spec']['template']['spec']['containers'][0]
        env={x['name']:x.get('value') for x in container.get('env',[])}
        assert env.get('ANALYTICS_RATE_LIMIT_ENABLED')=='true'
        assert self.production['sensor']['spec']['replicas']==0,'Sensor writes must be stopped for a fixed dataset'
        assert original['spec']['replicas']==1
        assert not json.loads(kube('get','hpa','-o','json').stdout)['items'],'Review autoscalers before an isolated study'
        self.created=True
        spec=json.loads(json.dumps(original['spec']));spec['replicas']=1
        spec['selector']={'matchLabels':{'app':self.name}}
        template=spec['template'];template['metadata']={'labels':{'app':self.name}}
        template['spec'].pop('affinity',None)
        template['spec']['topologySpreadConstraints']=[{'maxSkew':1,'topologyKey':'kubernetes.io/hostname','whenUnsatisfiable':'DoNotSchedule','labelSelector':{'matchLabels':{'app':self.name}}}]
        for volume in template['spec'].get('volumes',[]):
            if volume['name']=='protection':volume['hostPath']['path']=self.path
        for node in NODES:
            command(['incus','exec',node,'--','mkdir','-p','/var/lib/analytics-protection'])
            command(['incus','exec',node,'--','mkdir','-m','755',self.path]);self.paths.append(node)
        deployment={'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':self.name,'namespace':NAMESPACE},'spec':spec}
        service={'apiVersion':'v1','kind':'Service','metadata':{'name':self.name,'namespace':NAMESPACE},'spec':{'selector':{'app':self.name},'ports':[{'port':5003,'targetPort':5003}]}}
        client={'apiVersion':'v1','kind':'Pod','metadata':{'name':self.client,'namespace':NAMESPACE,'labels':{'scaling-study':self.name}},'spec':{'automountServiceAccountToken':False,'restartPolicy':'Never','securityContext':{'runAsNonRoot':True,'runAsUser':10001,'runAsGroup':10001},'containers':[{'name':'client','image':container['image'],'imagePullPolicy':'Never','command':['python','-c','import time;time.sleep(3600)'],'resources':{'requests':{'cpu':'25m','memory':'32Mi'},'limits':{'cpu':'250m','memory':'96Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}}}]}}
        self.save('temporary-resources.json',{'apiVersion':'v1','kind':'List','items':[deployment,service,client]})
        kube('apply','-f','-',data=json.dumps({'apiVersion':'v1','kind':'List','items':[deployment,service,client]}))
        kube('rollout','status','deployment/'+self.name,'--timeout=90s',timeout=100)
        kube('wait','--for=condition=Ready','pod/'+self.client,'--timeout=90s',timeout=100)
        service=json.loads(kube('get','service',self.name,'-o','json').stdout)
        self.url='http://'+service['spec']['clusterIP']+':5003'
        self.dataset=self.get_json('http://storage:5002/stats');self.save('dataset-before.json',self.dataset)
        production_pod=next(p for p in self.original['items'] if p['kind']=='Pod' and p['metadata'].get('labels',{}).get('app')=='analytics')
        source=kube('exec',production_pod['metadata']['name'],'--','cat','/app/app.py').stdout
        (self.out/'analytics-runtime.py').write_text(source)
        self.runtime_hash=hashlib.sha256(source.encode()).hexdigest()
        (self.out/'driver.py').write_text(DRIVER)

    def trial(self,count,mode,repetition):
        label=f'replicas-{count}/{mode}/repeat-{repetition}'
        pods=self.pods();self.save(label+'/pods-before.json',pods)
        fixture=self.lease(mode);self.save(label+'/fixture-lease.json',fixture)
        for p in pods:
            body=self.get_json('http://'+p['status']['podIP']+':5003/average')
            assert body['protection_mode']==mode and body['stats_age_seconds']<=10
            time.sleep(INTERVAL)
        before=self.metric_snapshot(pods);self.save(label+'/metrics-before.json',before)
        resources=[]
        for _ in range(15):
            try:resources=[self.resource_snapshot(pods)];break
            except AssertionError:time.sleep(1)
        assert resources,'No initial kubelet resource samples'
        stdout=self.out/label/'client.json';stderr=self.out/label/'client-error.log'
        args=['incus','exec','k3s-master','--','k3s','kubectl','-n',NAMESPACE,'exec',self.client,'--','python','-c',DRIVER,self.url,str(READS),str(INTERVAL)]
        with stdout.open('w') as output,stderr.open('w') as errors:
            process=subprocess.Popen(args,stdout=output,stderr=errors,text=True)
            tick=time.monotonic();next_sample=tick+5
            while process.poll() is None:
                if time.monotonic()-tick>READS*INTERVAL+30:
                    process.terminate();raise RuntimeError('Client exceeded the fixed trial deadline')
                if time.monotonic()>=next_sample:
                    resources.append(self.resource_snapshot(pods));next_sample=time.monotonic()+5
                time.sleep(.2)
            assert process.returncode==0,'Read client failed; see retained stderr'
        resources.append(self.resource_snapshot(pods));self.save(label+'/resources.json',resources)
        result=json.loads(stdout.read_text());rows=result['reads']
        after=self.metric_snapshot(pods);self.save(label+'/metrics-after.json',after)
        now=self.pods();self.save(label+'/pods-after.json',now)
        def identity(items):return {(p['metadata']['uid'],tuple(s['restartCount'] for s in p['status']['containerStatuses'])) for p in items}
        assert identity(pods)==identity(now),'Candidate identity/restart changed during a trial'
        assert len(rows)==READS and all(r['status']==200 for r in rows),'The bounded load did not receive only HTTP 200'
        assert all(r['body']['protection_mode']==mode and r['body']['stats_age_seconds']<=10 for r in rows)
        if mode=='normal':assert all(not r['body']['cached'] for r in rows)
        else:assert any(r['body']['cached'] for r in rows)
        assert max(r['dispatch_delay_seconds'] for r in rows)<.5,'Offered load was not maintained; trial is not comparable'
        deltas={}
        for uid,item in after.items():
            deltas[item['name']]={k:item['counters'][k]-before[uid]['counters'][k] for k in ('requests','storage','cached')}
            assert all(v>=0 for v in deltas[item['name']].values()),'A counter reset during the trial'
        assert sum(p['requests'] for p in deltas.values())==READS,'Service request attribution failed'
        summary={'replicas':count,'mode':mode,'repetition':repetition,'measured_reads':READS,'duration_seconds':result['duration_seconds'],
                 'achieved_requests_per_second':READS/result['duration_seconds'],'http_statuses':dict(Counter(r['status'] for r in rows)),
                 'mean_latency_ms':statistics.mean(r['duration_ms'] for r in rows),'p95_latency_ms':percentile([r['duration_ms'] for r in rows],.95),
                 'cache_hits':sum(r['body']['cached'] for r in rows),'max_data_age_seconds':max(r['body']['stats_age_seconds'] for r in rows),
                 'storage_attempts':sum(p['storage'] for p in deltas.values()),'per_pod_deltas':deltas,**cpu_summary(resources)}
        self.save(label+'/summary.json',summary);self.trials.append(summary)
        print('[TRIAL] replicas={} mode={} repeat={} p95={:.3f}ms storage={} cache_hits={}/{}'.format(count,mode,repetition,summary['p95_latency_ms'],summary['storage_attempts'],summary['cache_hits'],READS),flush=True)

    def run(self):
        self.setup()
        for count in REPLICAS:
            kube('scale','deployment/'+self.name,'--replicas='+str(count))
            kube('rollout','status','deployment/'+self.name,'--timeout=90s',timeout=100)
            pods=self.pods();assert len(pods)==count
            if count>1:assert {p['spec']['nodeName'] for p in pods}==set(NODES)
            for pod in pods:
                source=kube('exec',pod['metadata']['name'],'--','cat','/app/app.py').stdout
                assert hashlib.sha256(source.encode()).hexdigest()==self.runtime_hash,'Candidate source differs from production'
            for repetition in range(1,REPEATS+1):
                modes=('normal','cache') if repetition%2 else ('cache','normal')
                for mode in modes:self.trial(count,mode,repetition)
        self.lease('cache',node_only='k3s-master');scope=[]
        for pod in self.pods():
            body=self.get_json('http://'+pod['status']['podIP']+':5003/average')
            expected='cache' if pod['spec']['nodeName']=='k3s-master' else 'normal'
            assert body['protection_mode']==expected
            scope.append({'pod':pod['metadata']['name'],'node':pod['spec']['nodeName'],'body':body});time.sleep(INTERVAL)
        self.save('node-local-state-scope.json',{'origin':'operator fixture on one node; not Wazuh dispatch','observations':scope})
        final=self.get_json('http://storage:5002/stats');self.save('dataset-after.json',final);assert final==self.dataset,'Dataset changed during the comparison'
        self.save('summary.json',{'scope':plan()['scope'],'trials':self.trials,'dataset_unchanged':True,'all_replicas_share_one_vm':True})

    def report(self):
        grouped=[]
        for count in REPLICAS:
            for mode in ('normal','cache'):
                trials=[x for x in self.trials if x['replicas']==count and x['mode']==mode]
                rows=[]
                for repetition in range(1,REPEATS+1):
                    rows.extend(json.loads((self.out/f'replicas-{count}/{mode}/repeat-{repetition}/client.json').read_text())['reads'])
                grouped.append({'replicas':count,'mode':mode,'repetitions':len(trials),'http_200':len(rows),
                    'achieved_requests_per_second':len(rows)/sum(x['duration_seconds'] for x in trials),
                    'mean_latency_ms':statistics.mean(r['duration_ms'] for r in rows),
                    'pooled_p95_latency_ms':percentile([r['duration_ms'] for r in rows],.95),
                    'cache_hits':sum(r['body']['cached'] for r in rows),
                    'storage_attempts':sum(x['storage_attempts'] for x in trials),
                    'mean_cpu_cores':statistics.mean(x['mean_cpu_cores'] for x in trials),
                    'mean_memory_mib':statistics.mean(x['mean_memory_working_set_bytes'] for x in trials)/(1024**2)})
        summary=json.loads((self.out/'summary.json').read_text());summary['aggregate']=grouped;self.save('summary.json',summary)
        with (self.out/'summary.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(grouped[0]));writer.writeheader();writer.writerows(grouped)
        lines=['# Analytics replica comparison','','Fixed workload: 60 ordinary reads at two requests/s, 30 seconds per trial, three repetitions per configuration.',
               'Rate limiting remains enabled. Cache mode uses operator fixtures on temporary node paths, not Wazuh activation.','',
               '| Replicas | Mode | HTTP 200 | Mean ms | Pooled p95 ms | Storage attempts | Cache hits | Mean CPU cores | Mean working set MiB |',
               '|---:|---|---:|---:|---:|---:|---:|---:|---:|']
        for r in grouped:
            lines.append('| {replicas} | {mode} | {http_200} | {mean_latency_ms:.3f} | {pooled_p95_latency_ms:.3f} | {storage_attempts:.0f} | {cache_hits} | {mean_cpu_cores:.5f} | {mean_memory_mib:.2f} |'.format(**r))
        lines.extend(['','All node containers share one VM and one Storage/SQLite dependency. These results measure bounded low-rate behavior; they do not establish maximum throughput, linear speedup, saturation resistance or multi-host fault tolerance.',
                      'CPU windows use the kubelet sample timestamps and can differ from the HTTP window. Resource samples are coarse.',
                      'Per-trial and per-Pod records, fixture provenance, dataset equality and production/cleanup verification are retained alongside this summary.'])
        (self.out/'SUMMARY.md').write_text('\n'.join(lines)+'\n')

    def cleanup(self):
        steps=[]
        if self.created:
            for args in [('delete','deployment',self.name,'--ignore-not-found=true','--wait=true','--timeout=90s'),('delete','pods','-l','app='+self.name,'--ignore-not-found=true','--wait=true','--timeout=90s'),('delete','service',self.name,'--ignore-not-found=true'),('delete','pod',self.client,'--ignore-not-found=true','--wait=true','--timeout=90s')]:
                result=kube(*args,check=False,timeout=100);steps.append({'args':args,'exit_code':result.returncode,'output':result.stdout+result.stderr})
        for node in self.paths:
            command(['incus','exec',node,'--','rm','-f','--',self.path+'/cache.json'],check=False)
            result=command(['incus','exec',node,'--','rmdir','--',self.path],check=False)
            steps.append({'node':node,'directory':self.path,'exit_code':result.returncode})
        after=json.loads(kube('get','deployments,pods','-o','json').stdout);self.save('cluster-after.json',after)
        deployments={p['metadata']['name']:p for p in after['items'] if p['kind']=='Deployment'}
        unchanged=all(name in deployments and p['spec']==deployments[name]['spec'] for name,p in self.production.items())
        def pod_state(cluster):return {p['metadata']['uid']:tuple(x['restartCount'] for x in p['status'].get('containerStatuses',[])) for p in cluster['items'] if p['kind']=='Pod'}
        stable=pod_state(self.original)==pod_state(after)
        self.save('cleanup.json',{'steps':steps,'production_specs_unchanged':unchanged,'production_pods_unchanged':stable})
        assert unchanged and stable and all(p['exit_code']==0 for p in steps),'Cleanup or production invariants failed'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true',help='Run the bounded study on the project VM')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if not args.run:print(json.dumps(plan(),indent=2));return
    out=args.output or ROOT/'evidence/scalability'/('analytics-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    with open('/tmp/analytics-scaling-study-'+str(os.getuid())+'.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        study=Study(out)
        try:study.run()
        except Exception as error:
            study.save('failure.json',{'type':type(error).__name__,'message':str(error),'completed_trials':study.trials});raise
        finally:
            try:study.cleanup()
            finally:study.save('SHA256SUMS.json',{str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in out.rglob('*') if p.is_file() and p.name!='SHA256SUMS.json'})
        study.report()
        study.save('SHA256SUMS.json',{str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in out.rglob('*') if p.is_file() and p.name!='SHA256SUMS.json'})
    print('[PASS] Study completed; production unchanged and temporary resources removed.',flush=True)
    print('Evidence:',out,flush=True)


if __name__=='__main__':main()
