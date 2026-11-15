"""Strict v0.4 process contract around the unchanged advisory v0.3 scanner."""
import importlib.util
import json
import os
import sys


def main():
    if len(sys.argv) != 2:
        return 2
    scanner = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'triage_worker.py')
    spec = importlib.util.spec_from_file_location('sac_triage_worker', scanner)
    if spec is None or spec.loader is None:
        return 2
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        report = module.triage(sys.argv[1])
    except (OSError, ValueError):
        report = {'status':'REJECT', 'reason':'FILE_READ_OR_PARSE_ERROR'}
    if not isinstance(report, dict) or report.get('status') not in ('REJECT','ADVISORY_ONLY'):
        print(json.dumps({'status':'REJECT', 'reason':'INVALID_SCANNER_REPORT'},sort_keys=True))
        return 2
    print(json.dumps(report,sort_keys=True))
    return 1 if report['status']=='REJECT' else 0


if __name__ == '__main__':
    sys.exit(main())
