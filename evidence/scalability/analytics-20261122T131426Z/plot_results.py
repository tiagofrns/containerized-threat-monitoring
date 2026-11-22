"""Render measured replica-study aggregates; no synthetic observations."""
import json
from pathlib import Path
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
root=Path(sys.argv[1])
data=json.loads((root/'summary.json').read_text())
rows=data['aggregate']
fig,axes=plt.subplots(1,3,figsize=(13.2,4.3),layout='constrained')
colors={'normal':'#4263a6','cache':'#13806f'}
for mode,label in [('normal','Normal'),('cache','Protective cache')]:
 r=sorted((x for x in rows if x['mode']==mode),key=lambda x:x['replicas'])
 for ax,key in [(axes[0],'pooled_p95_latency_ms'),(axes[1],'storage_attempts'),(axes[2],'mean_memory_mib')]:
  ax.plot([x['replicas'] for x in r],[x[key] for x in r],marker='o',linewidth=2,color=colors[mode],label=label)
for ax,title,ylabel in zip(axes,['Measured latency','Dependency work','Replica memory'],['Pooled HTTP p95 (ms)','Storage HTTP attempts / 180 reads','Mean total working set (MiB)']):
 ax.set(title=title,xlabel='Analytics replicas',ylabel=ylabel,xticks=[1,2,4]);ax.grid(alpha=.2);ax.set_ylim(bottom=0)
axes[0].legend(frameon=False)
fig.suptitle('Fixed load: 2 reads/s, 3 × 60 reads per configuration\nTwo K3s nodes in one VM; cache uses labelled operator fixtures',fontsize=12)
fig.savefig(root/'replica-comparison.png',dpi=180)
fig.savefig(root/'replica-comparison.pdf')
