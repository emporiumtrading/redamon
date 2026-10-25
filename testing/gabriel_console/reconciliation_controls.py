"""Alter generated browser copies; no rejected copy may acquire a success receipt."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    lab,original=map(Path,sys.argv[1:])
    browser=json.loads(original.read_text())
    with tempfile.TemporaryDirectory(prefix='gabriel-negative-') as directory:
        for name in ('changed_id','changed_time','changed_log','missing_event','duplicate_event'):
            root=Path(directory)/name;root.mkdir()
            copy=deepcopy(browser);events=copy['replay_event_query']['native_details']
            if name=='changed_id': events[0]['event_id']='0.0'
            elif name=='changed_time': events[0]['event_time']='2000-01-01T00:00:00Z'
            elif name=='changed_log': events[0]['full_log']+=' altered'
            elif name=='missing_event': events.pop()
            else: events[-1]=deepcopy(events[0])
            report=root/'browser.json';report.write_text(json.dumps(copy))
            outcome=subprocess.run([sys.executable,'tooling/scripts/gabriel_console_lab.py',
                'reconcile','wazuh',str(lab),'--browser-report',str(report)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
            assert outcome.returncode!=0 and not (root/'native-reconciliation.json').exists(),name
    print('PASS: changed native ID/time/log, missing record and duplicate record all rejected')


if __name__=='__main__': main()
