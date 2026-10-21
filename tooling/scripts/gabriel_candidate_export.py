"""Export existing checked images without rebuilding or copying runtime state."""
import argparse
from hashlib import sha256
import gzip
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile


def checked_report(root,name,source):
    paths=list(Path(root).glob('run.*/'+name))
    if len(paths)!=1: raise ValueError('candidate_requires_one_fresh_report')
    path=paths[0]
    if (path.parent/'source-sha.txt').read_text().strip()!=source: raise ValueError('candidate_source_mismatch')
    value=json.loads(path.read_text())
    counts=value['counts']
    if (value['status']!='PASS' or value['strict'] is not True or type(counts['collected']) is not int
            or any(type(counts[key]) is not int or counts[key]<0 for key in ('collected','passed','failed','errors','skipped'))
            or counts['collected']<=0 or counts['passed']!=counts['collected']
            or any(counts[key]!=0 for key in ('failed','errors','skipped'))):
        raise ValueError('candidate_report_not_accepted')
    return path,dict(name=name,sha256=sha256(path.read_bytes()).hexdigest(),counts=counts)


def docker(*args):
    return subprocess.check_output(['docker',*args],text=True).strip()


def export(output,identity,runtime,foundation):
    source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    if re.fullmatch('[a-f0-9]{40}',source) is None: raise ValueError('candidate_source_required')
    selected=[checked_report(root,name,source) for root,name in (
        (identity,'identity-tests.json'),(identity,'focused-identity-tests.json'),
        (runtime,'runtime-tests.json'),(foundation,'foundation.json'))]
    identity_dir=selected[0][0].parent;runtime_dir=selected[2][0].parent
    specs=(('core',identity_dir/'identity-image-id.txt'),
        ('defender',runtime_dir/'runtime-image-id.txt'),('checkpoint-signer',identity_dir/'checkpoint-signer-image-id.txt'))
    images=[];tags=[];architecture=None
    for role,path in specs:
        expected=path.read_text().strip()
        if re.fullmatch('sha256:[a-f0-9]{64}',expected) is None: raise ValueError('candidate_image_id_required')
        value=json.loads(docker('image','inspect',expected))[0]
        if value['Id']!=expected or value['Os']!='linux' or value['Architecture'] not in {'amd64','arm64'}:
            raise ValueError('candidate_image_identity_mismatch')
        if architecture and architecture!=value['Architecture']: raise ValueError('candidate_mixed_architectures')
        architecture=value['Architecture']
        if value['Config']['User']!='10001:10001': raise ValueError('candidate_nonroot_required')
        if any(re.search('(API_KEY|TOKEN|PASSWORD|DSN|KEYRING)=',item) for item in value['Config'].get('Env',[])):
            raise ValueError('candidate_image_contains_secret_configuration')
        tag='gabriel-'+role+':candidate-'+source+'-'+architecture
        docker('image','tag',expected,tag);tags.append(tag)
        images.append(dict(role=role,image_id=expected,tag=tag,os='linux',architecture=architecture))
    if docker('image','inspect','gabriel-identity:dev','--format','{{.Id}}')!=images[0]['image_id']:
        raise ValueError('candidate_core_tag_changed')
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory() as temporary:
        archive=Path(temporary)/'images.tar'
        docker('image','save','--output',str(archive),*tags)
        with tarfile.open(archive) as tar:
            entries=json.load(tar.extractfile('manifest.json'))
            if len(entries)!=len(images): raise ValueError('candidate_archive_image_count')
            for entry,image in zip(sorted(entries,key=lambda row:row['RepoTags'][0]),sorted(images,key=lambda row:row['tag'])):
                if entry['RepoTags']!=[image['tag']]: raise ValueError('candidate_archive_tag_mismatch')
                config=tar.extractfile(entry['Config']).read()
                if 'sha256:'+sha256(config).hexdigest()!=image['image_id']: raise ValueError('candidate_archive_config_mismatch')
        target=output/'images.tar.gz'
        with archive.open('rb') as incoming,target.open('wb') as raw:
            with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as outgoing: shutil.copyfileobj(incoming,outgoing)
    checksum=sha256()
    with target.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): checksum.update(chunk)
    docker('image','load','--input',str(target))
    for image in images:
        if docker('image','inspect',image['tag'],'--format','{{.Id}}')!=image['image_id']:
            raise ValueError('candidate_loaded_image_mismatch')
    subprocess.run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--memory','512m','--cpus','1','--entrypoint','python',
        images[0]['image_id'],'-c',
        "import importlib.util; from gabriel.identity.cases import CaseService; from gabriel.identity.browser_navigation import CONTRACTS; assert not CONTRACTS; assert importlib.util.find_spec('pytest') is None"],check=True)
    manifest=dict(schema_version=1,purpose='gabriel-core-test-candidate',source_sha=source,architecture=architecture,
        images=images,archive=dict(name=target.name,sha256=checksum.hexdigest(),bytes=target.stat().st_size),
        component_reports=[report for _,report in selected],production_admitted=False,
        external_actions_enabled=False,model_routes_admitted=False,
        remaining_gates=['browser artifact at matching source','dependency/license/container scans and SBOM',
            'real-console and native OS UAT','model quality qualification','release authorization','post-release observation'])
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    for path,_ in selected: shutil.copyfile(path,output/path.name)
    print('PASS: exported checked '+architecture+' core images without rebuild; production admission remains false')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    parser.add_argument('--identity-evidence',required=True)
    parser.add_argument('--runtime-evidence',required=True)
    parser.add_argument('--foundation-evidence',required=True)
    args=parser.parse_args()
    export(args.output,args.identity_evidence,args.runtime_evidence,args.foundation_evidence)
