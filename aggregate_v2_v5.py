#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,json,math,statistics
from pathlib import Path

def read_csvs(root:Path,name:str):
 out=[]
 for p in sorted(root.rglob(name)):
  if p.stat().st_size:
   with p.open(newline='',encoding='utf-8') as f: out.extend(csv.DictReader(f))
 return out

def b(x): return str(x).strip().lower() in {'true','1','yes'}
def f(x):
 try:return float(x)
 except:return float('nan')
def wilson(k,n,z=1.959963984540054):
 if not n:return (float('nan'),float('nan'))
 p=k/n; den=1+z*z/n; c=(p+z*z/(2*n))/den; h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
 return max(0,c-h),min(1,c+h)
def pct(k,n):return 100*k/n if n else float('nan')
def write(path,rows):
 path.parent.mkdir(parents=True,exist_ok=True)
 if not rows: path.write_text('',encoding='utf-8'); return
 with path.open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

def summarize(rows):
 groups={}
 for r in rows: groups.setdefault((r['vector'],r['mode']),[]).append(r)
 out=[]
 for (v,m),rs in sorted(groups.items()):
  valid=[r for r in rs if not r.get('api_error')]
  n=len(valid); k=sum(b(r['malicious_allowed']) for r in valid); lo,hi=wilson(k,n)
  mc=[r for r in valid if b(r['model_called'])]
  out.append({'vector':v,'mode':m,'n':n,'api_errors':len(rs)-n,
   'attack_induction_pct':pct(sum(b(r['malicious_proposed']) for r in valid),n),
   'asr_pct':pct(k,n),'asr_wilson_lo_pct':100*lo if n else float('nan'),'asr_wilson_hi_pct':100*hi if n else float('nan'),
   'safe_authorized_proposed_pct':pct(sum(b(r['safe_authorized_proposed']) for r in valid),n),
   'safe_authorized_allowed_pct':pct(sum(b(r['safe_authorized_allowed']) for r in valid),n),
   'pre_model_block_pct':pct(sum(b(r['blocked_before_model']) for r in valid),n),
   'mean_latency_s_model_called':statistics.mean([f(r['latency_s']) for r in mc]) if mc else float('nan')})
 for m in sorted(set(r['mode'] for r in rows)):
  rs=[r for r in rows if r['mode']==m]; valid=[r for r in rs if not r.get('api_error')]; n=len(valid); k=sum(b(r['malicious_allowed']) for r in valid); lo,hi=wilson(k,n); mc=[r for r in valid if b(r['model_called'])]
  out.append({'vector':'V2-V5_pooled','mode':m,'n':n,'api_errors':len(rs)-n,
   'attack_induction_pct':pct(sum(b(r['malicious_proposed']) for r in valid),n),'asr_pct':pct(k,n),
   'asr_wilson_lo_pct':100*lo if n else float('nan'),'asr_wilson_hi_pct':100*hi if n else float('nan'),
   'safe_authorized_proposed_pct':pct(sum(b(r['safe_authorized_proposed']) for r in valid),n),
   'safe_authorized_allowed_pct':pct(sum(b(r['safe_authorized_allowed']) for r in valid),n),
   'pre_model_block_pct':pct(sum(b(r['blocked_before_model']) for r in valid),n),
   'mean_latency_s_model_called':statistics.mean([f(r['latency_s']) for r in mc]) if mc else float('nan')})
 return out

def main():
 p=argparse.ArgumentParser(); p.add_argument('--input-root',type=Path,required=True); p.add_argument('--out-dir',type=Path,required=True); a=p.parse_args()
 rows=read_csvs(a.input_root,'details.csv'); a.out_dir.mkdir(parents=True,exist_ok=True)
 write(a.out_dir/'details_combined.csv',rows); s=summarize(rows); write(a.out_dir/'summary_v2_v5.csv',s)
 (a.out_dir/'aggregate_metadata.json').write_text(json.dumps({'detail_rows':len(rows),'expected_rows':136*5*5,'complete':len(rows)==136*5*5},indent=2),encoding='utf-8')
 print(json.dumps({'detail_rows':len(rows),'summary_rows':len(s)},indent=2))
if __name__=='__main__': main()
