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
RUNTIME_FILES=('service.py','schema.sql','schema_v31.sql','installation.py','workbench.py',
    'model_worker.py','model_budget.py','model_routes.py','model_transport.py','personal_providers.py',
    'specialist_agents.py','specialist_qualification.py','hermes_supervisor.py','hermes_bridge.py',
    'hermes_qualification.py','browser_hermes.py','release_qualification.py','reviewed_memory.py',
    'memory.py','coordinator.py','browser_sessions.py','browser_observations.py','browser_events.py','browser_specialists.py')

NETWORKS={'identity-db':{'private'},'workbench':{'private','toolbus'},'hermes':{'toolbus'},
    'investigation-tools':{'toolbus'},'local-entry':{'private','entry'}}
BIND_FILES={'/run/secrets/db_password':'database/db_password',
    '/docker-entrypoint-initdb.d/01-gabriel-role.sql':'database/role_init.sql',
    '/run/secrets/app_dsn':'database/app_dsn','/run/secrets/provider_keyring':'provider/keyring.json',
    '/run/secrets/evidence_keyring':'evidence/keyring.json','/run/secrets/tls_certificate':'tls/server.pem',
    '/run/secrets/tls_key':'tls/server.key','/run/secrets/tls_ca':'tls/ca.pem'}
VOLUME_NAMES={'/var/lib/postgresql/data':'database','/var/lib/gabriel-evidence':'evidence',
    '/var/lib/gabriel-workbench':'workbench'}
MOUNTS={'identity-db':{'/var/lib/postgresql/data':('volume',True),'/run/secrets/db_password':('bind',False),
    '/docker-entrypoint-initdb.d/01-gabriel-role.sql':('bind',False)},
    'workbench':{'/var/lib/gabriel-evidence':('volume',True),'/var/lib/gabriel-workbench':('volume',True),
        **{'/run/secrets/'+n:('bind',False) for n in ('app_dsn','provider_keyring','evidence_keyring','tls_certificate','tls_key','tls_ca')}}}



def require(condition,code):
    if not condition:raise ValueError(code)


def committed_runtime_sources(source,run_command):
    require(type(source) is str and re.fullmatch('[a-f0-9]{40}',source),'invalid_source_identity')
    return {name:hashlib.sha256(run_command(['git','show',source+':gabriel/identity/'+name])).hexdigest()
        for name in RUNTIME_FILES}


def validate_runtime_sources(expected,actual):
    for value in (expected,actual):
        require(type(value) is dict and set(value)==set(RUNTIME_FILES),'runtime_source_manifest_invalid')
        require(all(type(v) is str and re.fullmatch('[a-f0-9]{64}',v) for v in value.values()),'runtime_source_manifest_invalid')
    require(actual==expected,'running_runtime_source_mismatch')
    return dict(critical_file_sha256=actual,manifest_sha256=hashlib.sha256(
        json.dumps(actual,sort_keys=True,separators=(',',':')).encode()).hexdigest())


NATIVE_MOUNTS='native-exact-v1'
DESKTOP_MOUNTS='darwin-docker-desktop-host-mnt-v1'


def mount_source_profile(host_system,engine):
    require(type(host_system) is str and type(engine) is dict,'invalid_mount_platform_evidence')
    return DESKTOP_MOUNTS if (host_system=='Darwin' and engine.get('OSType')=='linux'
        and engine.get('OperatingSystem')=='Docker Desktop') else NATIVE_MOUNTS


def assess(config,containers,networks,*,provider_egress=False,mount_profile=NATIVE_MOUNTS):
    require(type(provider_egress) is bool,'invalid_egress_policy')
    require(mount_profile in {NATIVE_MOUNTS,DESKTOP_MOUNTS},'invalid_mount_source_profile')
    require(re.fullmatch('sha256:[a-f0-9]{64}',config['image']) is not None,'invalid_image_identity')
    root=Path(config['installation_root'])
    require(root.is_absolute() and str(root)==config['installation_root'] and '..' not in root.parts,'invalid_installation_root')
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
            if service=='local-entry':require(not temporary,'relay_temporary_mount_denied')
            else:require(set(temporary)=={'/tmp'} and {'noexec','nosuid'}<=set(temporary['/tmp'].split(',')),'temporary_mount_hardening_missing')
            require(type(host.get('Memory')) is int and host['Memory']>0 and host.get('PidsLimit',0)>0,'resource_limits_missing')
        mounts=row.get('Mounts',[])
        targets=[m.get('Destination') for m in mounts]
        require(len(set(targets))==len(targets) and set(MOUNTS.get(service,{}))<=set(targets),'required_mounts_missing')
        for mount in mounts:
            target=mount.get('Destination')
            if mount.get('Type')=='tmpfs' and target=='/tmp':continue
            expected=MOUNTS.get(service,{}).get(target)
            require(expected is not None and (mount.get('Type'),mount.get('RW'))==expected,'unexpected_mount')
            if expected[0]=='bind':
                sources={str(root/BIND_FILES[target])}
                if mount_profile==DESKTOP_MOUNTS:
                    sources.add('/host_mnt'+str(root/BIND_FILES[target]))
                require(mount.get('Source') in sources,'secret_mount_source_changed')
            else:
                require(mount.get('Name')==config['project']+'_'+VOLUME_NAMES[target],'persistent_volume_changed')
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
        mount_source_profile=mount_profile,
        production_admitted=False,native_browser_acceptance='pending',operational_acceptance='pending',
        limitations=['Docker health is not analyst session freshness or detection effectiveness.',
            'Private CA TLS verification is not native browser certificate trust.',
            'Local evidence hashes are not independent review or authenticated release approval.'])


def collect(root,*,provider_egress=False):
    from gabriel_install import Installation,run
    app=Installation(root)
    engine=json.loads(run(['docker','info','--format','{{json .}}']))
    host_system=platform.system()
    mount_profile=mount_source_profile(host_system,engine)
    source=run(['git','rev-parse','HEAD']).decode().strip()
    require(source==app.config['source'],'installation_source_differs_from_checkout')
    ids=app.compose('ps','--all','--quiet').decode().split()
    require(ids and all(re.fullmatch('[a-f0-9]{12,64}',v) for v in ids),'invalid_container_inventory')
    containers=json.loads(run(['docker','inspect',*ids]))
    names=sorted({name for row in containers for name in row['NetworkSettings']['Networks']})
    network_rows=json.loads(run(['docker','network','inspect',*names]))
    networks={row['Name']:row for row in network_rows}
    hermes_image=json.loads(run(['docker','image','inspect',app.config['project']+'-hermes:local']))[0]['Id']
    report=assess(dict(app.config,installation_root=str(root.resolve()),hermes_image=hermes_image),containers,networks,provider_egress=provider_egress,mount_profile=mount_profile)
    supervisor=json.loads(app.compose('exec','-T','workbench','python','-c',
        'import json; from gabriel.identity.hermes_bridge import health; print(json.dumps(health()))'))
    require(supervisor.get('status')=='ready' and re.fullmatch('[a-f0-9]{64}',supervisor.get('runtime_digest','')),'hermes_source_binding_failed')
    report['hermes_runtime']=supervisor
    expected=committed_runtime_sources(source,run)
    program=('import hashlib,json; from pathlib import Path; names='+repr(RUNTIME_FILES)+
        '; print(json.dumps({n:hashlib.sha256((Path("/app/gabriel/identity")/n).read_bytes()).hexdigest() for n in names}))')
    actual=json.loads(app.compose('exec','-T','workbench','python','-c',program))
    report['runtime_source_binding']=validate_runtime_sources(expected,actual)
    client=http.client.HTTPSConnection('localhost',app.config['port'],timeout=10,
        context=ssl.create_default_context(cafile=str(root/'tls/ca.pem')))
    try:
        client.request('GET','/cases');response=client.getresponse()
        require(response.status==403,'unauthenticated_cases_not_denied')
        response.read(4096)
        report['trusted_private_ca_https_denies_unauthenticated_cases']=True
    finally:client.close()
    report.update(version='gabriel-native-runtime-evidence-v1',source=source,image=app.config['image'],
        collected_at=datetime.now(timezone.utc).isoformat(),
        collector_host=dict(system=host_system,architecture=platform.machine(),release=platform.release()),
        docker_engine={k:engine.get(k) for k in ('OSType','OperatingSystem','Architecture','NCPU','MemTotal','ServerVersion')})
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
