"""Candidate reports must bind one successful, nonempty strict run to the source."""
import importlib.util
import json
from pathlib import Path

import pytest

spec=importlib.util.spec_from_file_location('candidate_export',Path('/repo/tooling/scripts/gabriel_candidate_export.py'))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def report(tmp_path,**updates):
    directory=tmp_path/'run.generated';directory.mkdir()
    (directory/'source-sha.txt').write_text('a'*40+'\n')
    value=dict(status='PASS',strict=True,counts=dict(collected=2,passed=2,failed=0,errors=0,skipped=0))
    value.update(updates)
    (directory/'identity-tests.json').write_text(json.dumps(value))
    return directory


def test_fresh_nonempty_strict_source_bound_report(tmp_path):
    path=report(tmp_path)
    original,receipt=module.checked_report(tmp_path,'identity-tests.json','a'*40)
    assert original==path/'identity-tests.json' and receipt['counts']['passed']==2 and len(receipt['sha256'])==64


@pytest.mark.parametrize('mode',['missing','multiple','source','empty','skip','failure','not_strict'])
def test_unaccepted_reports_fail_closed(tmp_path,mode):
    if mode!='missing':
        directory=report(tmp_path)
        value=json.loads((directory/'identity-tests.json').read_text())
        if mode=='multiple':
            another=tmp_path/'run.old';another.mkdir()
            (another/'identity-tests.json').write_text(json.dumps(value))
        elif mode=='source': (directory/'source-sha.txt').write_text('b'*40)
        elif mode=='empty': value['counts'].update(collected=0,passed=0)
        elif mode=='skip': value['counts'].update(passed=1,skipped=1)
        elif mode=='failure': value['status']='FAIL'
        elif mode=='not_strict': value['strict']=False
        (directory/'identity-tests.json').write_text(json.dumps(value))
    with pytest.raises(ValueError): module.checked_report(tmp_path,'identity-tests.json','a'*40)
