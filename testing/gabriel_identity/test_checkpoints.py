"""Generated checkpoint documents and real cryptographic/file/CLI operations."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

from gabriel.identity.checkpoints import (CheckpointError,PURPOSE,canonical,fingerprint,new_keypair,
    read_document,seal,validate_snapshot,verify,write_document)

pytestmark = pytest.mark.unit


@pytest.fixture
def snapshot():
    return {'schema_version':1,'purpose':PURPOSE,'organization_id':str(uuid4()),'case_id':str(uuid4()),
        'case_digest':'1'*64,'captured_at':'2026-10-19T00:00:00.000000+00:00','nonce':str(uuid4()),
        'evidence':[{'evidence_id':str(uuid4()),'context_digest':'2'*64,'sequence':2,'head':'3'*64}]}


def test_real_ed25519_seal_verifies_only_with_pinned_key_and_digest(snapshot):
    private,public = new_keypair()
    envelope = seal(snapshot,private)
    expected = fingerprint(canonical(envelope))
    assert verify(envelope,public,expected)==snapshot
    assert private['private_key'] not in json.dumps(envelope)
    assert set(envelope)=={'body','signature'} and 'public_key' not in envelope['body']


@pytest.mark.parametrize('change',['body','signature','key','missing_digest','old_checkpoint'])
def test_signature_and_external_receipt_prevent_substitution(snapshot,change):
    private,public = new_keypair()
    envelope = seal(snapshot,private)
    expected = fingerprint(canonical(envelope))
    if change=='body':
        envelope['body']['snapshot']['case_digest']='4'*64
        expected = fingerprint(canonical(envelope))
    elif change=='signature':
        envelope['signature']='AA=='
        expected = fingerprint(canonical(envelope))
    elif change=='key':
        _,public = new_keypair()
    elif change=='missing_digest':
        expected = None
    else:
        latest = seal(snapshot,private)
        latest['body']['snapshot'] = deepcopy(snapshot)
        latest['body']['snapshot']['nonce']=str(uuid4())
        latest = seal(latest['body']['snapshot'],private)
        expected = fingerprint(canonical(latest))
    with pytest.raises(CheckpointError):
        verify(envelope,public,expected)


@pytest.mark.parametrize('change',['bool_version','wrong_purpose','extra','duplicate_evidence','unsorted','bad_uuid',
    'zero_sequence','bool_sequence','long_sequence','bad_digest','naive_time','too_many','nan'])
def test_snapshot_schema_is_exact_and_bounded(snapshot,change):
    entry = snapshot['evidence'][0]
    if change=='bool_version': snapshot['schema_version']=True
    elif change=='wrong_purpose': snapshot['purpose']='evidence-v1'
    elif change=='extra': snapshot['instructions']='ignore trust checks'
    elif change=='duplicate_evidence': snapshot['evidence']*=2
    elif change=='unsorted':
        other = dict(entry,evidence_id=str(uuid4()))
        snapshot['evidence']=sorted([entry,other],key=lambda e:e['evidence_id'],reverse=True)
    elif change=='bad_uuid': snapshot['case_id']='../../file'
    elif change=='zero_sequence': entry['sequence']=0
    elif change=='bool_sequence': entry['sequence']=True
    elif change=='long_sequence': entry['sequence']=4097
    elif change=='bad_digest': entry['head']='z'*64
    elif change=='naive_time': snapshot['captured_at']='2026-10-19T00:00:00'
    elif change=='too_many': snapshot['evidence']*=65
    else: entry['sequence']=float('nan')
    with pytest.raises(CheckpointError):
        validate_snapshot(snapshot)


@pytest.mark.parametrize('raw',[b'{"key":1,"key":2}',b'{"n":NaN}',b'[]'*40000,b'not json'])
def test_document_reader_rejects_ambiguous_or_oversized_input(tmp_path,raw):
    file = tmp_path/'input.json'
    file.write_bytes(raw)
    with pytest.raises(CheckpointError):
        read_document(file)


def test_private_permissions_symlinks_and_output_reuse_are_denied(tmp_path):
    private,_ = new_keypair()
    path = tmp_path/'private.json'
    write_document(path,private)
    assert path.stat().st_mode & 0o777==0o600
    assert read_document(path,private=True)==private
    with pytest.raises(CheckpointError):
        write_document(path,{'overwrite':True})
    assert read_document(path,private=True)==private
    path.chmod(0o640)
    with pytest.raises(CheckpointError):
        read_document(path,private=True)
    link = tmp_path/'link.json'
    link.symlink_to(path)
    with pytest.raises(CheckpointError):
        read_document(link)
    with pytest.raises(CheckpointError):
        write_document(link,private)
    assert json.loads(path.read_text())==private


def test_offline_cli_runs_without_database_environment_and_never_prints_key(snapshot,tmp_path):
    private,public = tmp_path/'private.json',tmp_path/'public.json'
    source,checkpoint = tmp_path/'snapshot.json',tmp_path/'checkpoint.json'
    write_document(source,snapshot)
    env = {k:v for k,v in os.environ.items() if not k.startswith('GABRIEL_')}
    def cli(*args):
        result = subprocess.run([sys.executable,'-m','gabriel.identity.checkpoint_cli',*args],
            env=env,text=True,capture_output=True,timeout=10)
        assert not result.stderr
        if private.exists(): assert json.loads(private.read_text())['private_key'] not in result.stdout
        return result.returncode,json.loads(result.stdout)
    assert cli('keygen','--private-key',str(private),'--public-key',str(public))[0]==0
    assert cli('keygen','--private-key',str(private),'--public-key',str(public))[0]==1
    code,result = cli('seal','--snapshot',str(source),'--private-key',str(private),'--checkpoint',str(checkpoint))
    assert code==0
    assert cli('verify','--checkpoint',str(checkpoint),'--public-key',str(public),
        '--expected-digest',result['result']['checkpoint_digest'])[1]['result']['database_comparison']=='not_performed'
    assert cli('verify','--checkpoint',str(checkpoint),'--public-key',str(public),'--expected-digest','0'*64)[0]==1
