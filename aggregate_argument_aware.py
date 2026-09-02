#!/usr/bin/env python3
import argparse, csv, json, sys, importlib.util
from pathlib import Path
BOOL_FIELDS={'l1','l2','blocked_before_model','model_called','malicious_proposed','malicious_allowed','authorized_proposed','authorized_allowed'}
INT_FIELDS={'repeat'}
FLOAT_FIELDS={'latency_s'}
def load_exp(path: Path):
    spec=importlib.util.spec_from_file_location('argaware_exp',path)
    mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod); return mod
def parse_row(exp,d):
    vals={}
    for f in exp.Row.__dataclass_fields__:
        v=d.get(f,'')
        if f in BOOL_FIELDS: vals[f]=str(v).lower() in {'true','1','yes'}
        elif f in INT_FIELDS: vals[f]=int(v or 0)
        elif f in FLOAT_FIELDS: vals[f]=float(v or 0)
        else: vals[f]=v
    return exp.Row(**vals)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input-root',type=Path,required=True); ap.add_argument('--out-dir',type=Path,required=True); ap.add_argument('--exp-script',type=Path,default=Path('argument_aware_llama_eval.py')); args=ap.parse_args()
    exp=load_exp(args.exp_script); files=sorted(args.input_root.rglob('details.csv'))
    if not files: raise SystemExit('No shard details.csv files found')
    rows=[]
    for p in files:
        with p.open(newline='',encoding='utf-8') as f: rows += [parse_row(exp,r) for r in csv.DictReader(f)]
    args.out_dir.mkdir(parents=True,exist_ok=True)
    exp.write_csv(args.out_dir/'details_combined.csv',[exp.asdict(r) for r in rows]); exp.write_csv(args.out_dir/'summary.csv',exp.summarize(rows))
    expected=124*6*5
    manifest={'shard_files':len(files),'combined_rows':len(rows),'expected_rows':expected,'unique_cells':len({(r.scenario_id,r.mode,r.repeat) for r in rows}),'api_errors':sum(bool(r.api_error) for r in rows),'complete':len(rows)==expected and len({(r.scenario_id,r.mode,r.repeat) for r in rows})==expected and not any(r.api_error for r in rows),'modes':['M0','M1','M2','M3lex','M3cap','M3arg'],'repeats':5,'scenario_count':124,'scoring':'tool + exact destination/resource target'}
    (args.out_dir/'aggregate_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8'); print(json.dumps(manifest,indent=2))
    if not manifest['complete']: raise SystemExit('Aggregate incomplete or contains API errors')
if __name__=='__main__': main()
