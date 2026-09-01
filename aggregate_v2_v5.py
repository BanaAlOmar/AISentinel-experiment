#!/usr/bin/env python3
import argparse, csv, json
from pathlib import Path
import v2_v5_capability_rerun as exp

BOOL_FIELDS = {
    'l1','l2','blocked_before_model','model_called','malicious_marker_proposed',
    'malicious_marker_allowed','same_capability_proposed','same_capability_allowed',
    'final_text_present'
}
FLOAT_FIELDS = {'latency_s'}
INT_FIELDS = {'repeat'}

def parse_row(d):
    vals = {}
    for f in exp.CapRow.__dataclass_fields__:
        v = d.get(f, '')
        if f in BOOL_FIELDS:
            vals[f] = str(v).lower() in {'true','1','yes'}
        elif f in FLOAT_FIELDS:
            vals[f] = float(v or 0)
        elif f in INT_FIELDS:
            vals[f] = int(v or 0)
        else:
            vals[f] = v
    return exp.CapRow(**vals)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input-root', type=Path, required=True)
    ap.add_argument('--out-dir', type=Path, required=True)
    args = ap.parse_args()
    files = sorted(args.input_root.rglob('details.csv'))
    if not files:
        raise SystemExit('No shard details.csv files found')
    rows=[]
    for p in files:
        with p.open(newline='', encoding='utf-8') as f:
            rows.extend(parse_row(r) for r in csv.DictReader(f))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    exp.write_csv(args.out_dir/'details_combined.csv', [exp.asdict(r) for r in rows])
    summary = exp.summaries(rows)
    exp.write_csv(args.out_dir/'summary_by_vector.csv', summary)
    manifest={
        'shard_files': len(files),
        'combined_rows': len(rows),
        'expected_rows': 136*5*5,
        'unique_cells': len({(r.scenario_id,r.mode,r.repeat) for r in rows}),
        'api_errors': sum(bool(r.api_error) for r in rows),
    }
    (args.out_dir/'aggregate_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps(manifest,indent=2))
if __name__=='__main__':
    main()
