#!/usr/bin/env python3
"""Collect bounded runtime evidence; native browser and release approval stay pending."""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import ssl
import sys

SERVICES={'identity-db','workbench','hermes','investigation-tools','local-entry'}
APP=SERVICES-{'identity-db'}
NETWORKS={'identity-db':{'private'},'workbench':{'private','toolbus'},'hermes':{'toolbus'},
    'investigation-tools':{'toolbus'},'local-entry':{'private','entry'}}
MOUNTS={'identity-db':{'/var/lib/postgresql/data':('volume',True),'/run/secrets/db_password':('bind',False),
    '/docker-entrypoint-initdb.d/01-gabriel-role.sql':('bind',False)},
    'workbench':{'/var/lib/gabriel-evidence':('volume',True),'/var/lib/gabriel-workbench':('volume',True),
        **{'/run/secrets/'+n:('bind',False) for n in ('app_dsn','provider_keyring','evidence_keyring','tls_certificate','tls_key','tls_ca')}}}



def require(condition,code):
    if not condition:raise ValueError(code)


def assess(config,containers,networks,*,provider_egress=False):
    require(type(provider_egress) is bool,'invalid_egress_policy')
    require(re.fullmatch('sha256:[a-f0-9]{64}',config['image']) is not None,'invalid_image_identity')
    by_service={}
    for row in containers:
        labels=row['Config'].get('Labels') or {}
        require(labels.get('com.docker.compose.project')==config['project'],'foreign_project')
        service=labels.get('com.docker.compose.service')
        require(service in SERVICES and service not in by_service,'unexpected_or_duplicate_service')
        by_service[service]=row
    require(set(by_service)==SERVICES,'required_services_missing')
    result=[]
    for service,row in sorted(by_service.items()):
        host=row['HostConfig'];state=row['State'];cfg=row['Config']
        require(state.get('Running') is True and state.get('Health',{}).get('Status')=='healthy','service_not_healthy')
        require(not host.get('Privileged') and host.get('NetworkMode')!='host' and host.get('PidMode')!='host','host_privilege_denied')
        bindings=host.get('PortBindings') or {}
        if service=='local-entry':
            require(bindings=={'8444/tcp':[{'HostIp':'127.0.0.1','HostPort':str(config['port'])}]},'entry_listener_not_loopback')
        else:require(not bindings,'private_service_published')
        if service in APP:
            require(row['Image']==config['hermes_image' if service=='hermes' else 'image'],'image_identity_changed')
            require(host.get('ReadonlyRootfs') is True and cfg.get('User')=='10001:10001','application_hardening_missing')
            require('ALL' in [v.upper() for v in host.get('CapDrop',[])] and not host.get('CapAdd'),'capability_policy_changed')
            require(any(v in {'no-new-privileges','no-new-privileges:true'} for v in host.get('SecurityOpt',[])),'privilege_policy_missing')
            temporary=host.get('Tmpfs') or {}
            require(set(temporary)=={'/tmp'} and {'noexec','nosuid'}<=set(temporary['/tmp'].split(',')),'temporary_mount_hardening_missing')
            require(type(host.get('Memory')) is int and host['Memory']>0 and host.get('PidsLimit',0)>0,'resource_limits_missing')
        mounts=row.get('Mounts',[])
        targets=[m.get('Destination') for m in mounts]
        require(len(set(targets))==len(targets) and set(MOUNTS.get(service,{}))<=set(targets),'required_mounts_missing')
        for mount in mounts:
            target=mount.get('Destination')
            if mount.get('Type')=='tmpfs' and target=='/tmp':continue
            expected=MOUNTS.get(service,{}).get(target)
            require(expected is not None and (mount.get('Type'),mount.get('RW'))==expected,'unexpected_mount')
        attached=row['NetworkSettings']['Networks']
        expected=set(NETWORKS[service])|({'ai_egress'} if service=='workbench' and provider_egress else set())
        require(set(attached)=={config['project']+'_'+n for n in expected},'network_membership_changed')
        for name in attached:
            require(name in networks,'network_evidence_missing')
            network=networks[name]
            labels=network.get('Labels') or {}
            require(labels.get('com.docker.compose.project')==config['project'],'foreign_network')
            require(type(network.get('Internal')) is bool,'network_policy_missing')
            require(network['Internal']==(name not in {config['project']+'_entry',config['project']+'_ai_egress'}),'network_privacy_changed')
        result.append(dict(service=service,image=row['Image'],healthy=True,memory_limit_bytes=host.get('Memory',0)))
    return dict(runtime_checks_passed=True,services=result,provider_egress_explicit=provider_egress,
        production_admitted=False,native_browser_acceptance='pending',operational_acceptance='pending',
        limitations=['Docker health is not analyst session freshness or detection effectiveness.',
            'Private CA TLS verification is not native browser certificate trust.',
            'Local evidence hashes are not independent review or authenticated release approval.'])


def collect(root,*,provider_egress=False):
    from gabriel_install import Installation,run
    app=Installation(root)
    source=run(['git','rev-parse','HEAD']).decode().strip()
    require(source==app.config['source'],'installation_source_differs_from_checkout')
    ids=app.compose('ps','--all','--quiet').decode().split()
    require(ids and all(re.fullmatch('[a-f0-9]{12,64}',v) for v in ids),'invalid_container_inventory')
    containers=json.loads(run(['docker','inspect',*ids]))
    names=sorted({name for row in containers for name in row['NetworkSettings']['Networks']})
    network_rows=json.loads(run(['docker','network','inspect',*names]))
    networks={row['Name']:row for row in network_rows}
    hermes_image=json.loads(run(['docker','image','inspect',app.config['project']+'-hermes:local']))[0]['Id']
    report=assess(dict(app.config,hermes_image=hermes_image),containers,networks,provider_egress=provider_egress)
    supervisor=json.loads(app.compose('exec','-T','workbench','python','-c',
        'import json; from gabriel.identity.hermes_bridge import health; print(json.dumps(health()))'))
    require(supervisor.get('status')=='ready' and re.fullmatch('[a-f0-9]{64}',supervisor.get('runtime_digest','')),'hermes_source_binding_failed')
    report['hermes_runtime']=supervisor
    client=http.client.HTTPSConnection('localhost',app.config['port'],timeout=10,
        context=ssl.create_default_context(cafile=str(root/'tls/ca.pem')))
    try:
        client.request('GET','/cases');response=client.getresponse()
        require(response.status==403,'unauthenticated_cases_not_denied')
        response.read(4096)
        report['trusted_private_ca_https_denies_unauthenticated_cases']=True
    finally:client.close()
    engine=json.loads(run(['docker','info','--format','{{json .}}']))
    report.update(version='gabriel-native-runtime-evidence-v1',source=source,image=app.config['image'],
        collected_at=datetime.now(timezone.utc).isoformat(),
        collector_host=dict(system=platform.system(),architecture=platform.machine(),release=platform.release()),
        docker_engine={k:engine.get(k) for k in ('OSType','Architecture','NCPU','MemTotal','ServerVersion')})
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installation',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--allow-provider-egress',action='store_true')
    args=parser.parse_args(argv)
    require(args.output.is_absolute(),'absolute_output_required')
    parent=args.output.parent
    info=parent.stat()
    require(info.st_uid==os.getuid() and not info.st_mode&0o077,'operator_owned_private_output_required')
    require(parent.resolve()==parent and not args.output.exists(),'new_private_output_required')
    report=collect(args.installation,provider_egress=args.allow_provider_egress)
    raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    print(json.dumps(dict(runtime_checks_passed=True,evidence_sha256=hashlib.sha256(raw).hexdigest(),production_admitted=False)))


if __name__=='__main__':
    try:main()
    except Exception:
        print('Runtime acceptance collection failed; inspect the local installation. No release approval was granted.',file=sys.stderr)
        raise SystemExit(2)
