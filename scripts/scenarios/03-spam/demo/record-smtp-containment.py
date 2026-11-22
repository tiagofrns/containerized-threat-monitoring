"""Observe native Wazuh firewall-drop, failed SMTP and automatic recovery."""
import argparse
import json
from pathlib import Path
import subprocess
import time
import sys

MAIL='10.171.72.142'


def remote(host,*args):
    return subprocess.check_output(['incus','exec',host,'--',*args],text=True,timeout=12)


def rules():
    return remote('mail-container','iptables-save')


def blocked(text, client):
    return any(line.startswith('-A INPUT ') and '-s '+client+'/32 ' in line and '-j DROP' in line
               for line in text.splitlines())


def probe():
    code='''import json,socket,time
start=time.time()
try:
 with socket.create_connection(("10.171.72.142",25),timeout=2) as sock:
  local=sock.getsockname()[0]; banner=sock.recv(512).decode(errors="replace")
 print(json.dumps({"connected":True,"source_ip":local,"banner":banner,"at":start}))
except OSError as error:print(json.dumps({"connected":False,"error":type(error).__name__,"at":start}))
'''
    return json.loads(remote('smtp-client','python3','-c',code))


def manager_events(token):
    raw=remote('wazuh-container','tail','-n','6000','/var/ossec/logs/alerts/alerts.json')
    result=[]
    for line in raw.splitlines():
        if token not in line:continue
        try:row=json.loads(line)
        except ValueError:continue
        if row.get('agent',{}).get('name')=='mail-container':result.append(row)
    return result


def acknowledge(out, token, client, message_id, timeout=20):
    events=[]
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        events=manager_events(token)
        for row in events:
            data=row.get('data',{})
            if (row.get('rule',{}).get('id') in {'100607','100620'}
                    and data.get('message_id')==message_id and data.get('srcip')==client
                    and data.get('source_verified')=='yes' and data.get('source_blockable')=='yes'):
                with (out/'quarantine-acknowledgements.jsonl').open('a') as stream:
                    stream.write(json.dumps(row)+'\n')
                print('[WAZUH] Quarantine acknowledged: rule {} | alert {} | {}'.format(
                    row['rule']['id'],row['id'],message_id),flush=True)
                return
        time.sleep(.3)
    (out/'wazuh-acknowledgement-timeout.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in events))
    raise RuntimeError('Wazuh did not acknowledge an eligible quarantine for '+message_id)


def missing_block_diagnostics(out, token, client):
    events=manager_events(token)
    (out/'wazuh-missing-block-events.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in events))
    (out/'iptables-not-observed.txt').write_text(rules())
    native=remote('mail-container','cat','/var/ossec/logs/active-responses.log')
    (out/'native-missing-block-actions.log').write_text('\n'.join(x for x in native.splitlines() if token in x)+'\n')
    detections=[row for row in events if row.get('rule',{}).get('id')=='100620']
    eligible=[row for row in events if row.get('rule',{}).get('id')=='100607']
    result={'source_ip':client,'eligible_quarantine_alerts':len(eligible),
            'containment_alerts':len(detections),'drop_rule_observed':False,
            'stage':'detection' if not detections else 'response_or_observation'}
    (out/'failure-summary.json').write_text(json.dumps(result,indent=2)+'\n')
    return ('No native firewall-drop INPUT rule observed: 100607={}, 100620={}; '
            'inspect failure-summary.json and the retained manager/native logs').format(len(eligible),len(detections))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('token')
    parser.add_argument('--source-ip', required=True, help='Source observed by the initial SMTP connection')
    parser.add_argument('--acknowledge', metavar='MESSAGE_ID', help='Wait for this quarantine to be analysed before the next submission')
    args=parser.parse_args();client=args.source_ip;out=args.output;out.mkdir(parents=True,exist_ok=True)
    if args.acknowledge:
        acknowledge(out,args.token,client,args.acknowledge)
        return
    policy_code="""from pathlib import Path
import json,xml.etree.ElementTree as ET
r=ET.fromstring('<root>'+Path('/var/ossec/etc/ossec.conf').read_text()+'</root>')
rows=[{x.tag:x.text for x in entry} for entry in r.findall('.//active-response') if entry.findtext('rules_id')=='100620']
assert len(rows)==1 and rows[0].get('command')=='firewall-drop' and rows[0].get('location')=='local' and rows[0].get('disabled')=='no' and rows[0].get('timeout')=='20'
print(json.dumps(rows[0]))
"""
    effective=json.loads(remote('wazuh-container','python3','-c',policy_code))
    (out/'effective-response-before.json').write_text(json.dumps(effective,indent=2)+'\n')
    deadline=time.monotonic()+35
    first=None
    while time.monotonic()<deadline:
        snapshot=rules()
        if blocked(snapshot, client):
            first=time.time();(out/'iptables-blocked.txt').write_text(snapshot);break
        time.sleep(.3)
    if first is None:raise RuntimeError(missing_block_diagnostics(out,args.token,client))
    print('[FIREWALL] Native DROP rule observed for '+client,flush=True)
    failed=probe();(out/'smtp-blocked.json').write_text(json.dumps(failed,indent=2)+'\n')
    assert failed['connected'] is False,'SMTP unexpectedly remained reachable during the block'
    attempts=[{'at':first,'blocked':True}]
    deadline=time.monotonic()+35
    while time.monotonic()<deadline:
        snapshot=rules();active=blocked(snapshot, client);attempts.append({'at':time.time(),'blocked':active})
        if not active:break
        time.sleep(.5)
    else:raise RuntimeError('Wazuh did not remove the firewall rule automatically')
    assert not any('-s '+client+'/32 ' in line and '-j DROP' in line for line in snapshot.splitlines()),'A native DROP rule remains after timeout'
    (out/'iptables-recovered.txt').write_text(snapshot)
    recovered=probe();(out/'smtp-recovered.json').write_text(json.dumps(recovered,indent=2)+'\n')
    assert recovered['connected'] and recovered['source_ip']==client and recovered['banner'].startswith('220')
    raw=remote('mail-container','cat','/var/ossec/logs/active-responses.log')
    actions=[]
    for line in raw.splitlines():
        if 'firewall-drop' not in line or '{' not in line:continue
        try:row=json.loads(line[line.index('{'):])
        except ValueError:continue
        alert=row.get('parameters',{}).get('alert',{})
        if (alert.get('rule',{}).get('id')=='100620' and args.token in json.dumps(alert)
                and alert.get('data',{}).get('srcip')==client):
            actions.append({'log':line,'command':row.get('command'),'alert_id':alert.get('id')})
    (out/'native-firewall-actions.json').write_text(json.dumps(actions,indent=2)+'\n')
    assert {x['command'] for x in actions}>={'add','delete'},'Native add/delete audit missing'
    assert len({x['alert_id'] for x in actions})==1,'Response actions are not correlated'
    selected=[row for row in manager_events(args.token) if row.get('rule',{}).get('id') in {'100607','100620'}]
    (out/'wazuh-containment-events.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in selected))
    assert any(x['rule']['id']=='100620' for x in selected)
    summary={'command':'firewall-drop','trigger_rule':'100620','source_ip':client,
             'configured_timeout_seconds':int(effective['timeout']),'observed_remaining_block_seconds':round(attempts[-1]['at']-first,3),
             'scope':'Native IP-wide INPUT/FORWARD block on mail-container; not SMTP-only',
             'trigger_event_id':actions[0]['alert_id'],'smtp_failed_during_block':True,
             'smtp_recovered_automatically':True,'polls':attempts}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print('[EVIDENCE] Native firewall-drop add/delete share event '+actions[0]['alert_id'],flush=True)
    print('[EVIDENCE] SMTP failed during the block and recovered automatically; timeout=20 seconds.',flush=True)


if __name__=='__main__':
    try:main()
    except RuntimeError as error:
        print('[FAIL] '+str(error),file=sys.stderr)
        raise SystemExit(1)
