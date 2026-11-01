#!/usr/bin/env python3
"""Read-only analyzer for SAC exported JSON telemetry. Never infer independent trials from repeated snapshots."""
import json
import sys
import statistics
from datetime import datetime, timezone
from pathlib import Path

def iso(t):
    return datetime.fromisoformat(t.replace('Z','+00:00')).astimezone(timezone.utc)

def analyze(rows):
    if not isinstance(rows,list):raise ValueError('Expected JSON list')
    timestamps=sorted(iso(r['sampled_at']) for r in rows)
    gaps=[(b-a).total_seconds() for a,b in zip(timestamps,timestamps[1:])]
    metrics=[r['metrics'] for r in rows]
    states=lambda p:sorted({str(m.get(p[0],{}).get(p[1],None)) for m in metrics})
    result={
       'record_count':len(rows),
       'earliest_utc':timestamps[0].isoformat() if timestamps else None,
       'latest_utc':timestamps[-1].isoformat() if timestamps else None,
       'gaps_over_1h':sum(g>3600 for g in gaps),
       'max_gap_s':max(gaps) if gaps else None,
       'median_interval_s':statistics.median(gaps) if gaps else None,
       'federation_states':len({json.dumps(m.get('federation'),sort_keys=True) for m in metrics}),
       'workload_states':len({json.dumps(m.get('workloads'),sort_keys=True) for m in metrics}),
       'runner_tick_states':states(('runtime','runner_latest_tick_state')),
       'queue_paused_states':states(('runtime','queue_paused')),
       'node_count_states':states(('federation','owner_enrolled_nodes')),
       'a2a_task_count_states':states(('workloads','a2a_task_contracts')),
       'proof_of_independent_consensus':False,
       'assessment':'monitoring_statistics_only'
    }
    return result

def main():
    if len(sys.argv)!=2:raise ValueError('Usage: analyze_telemetry.py export.json')
    rows=json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps(analyze(rows),indent=2))
if __name__=='__main__':main()