
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
