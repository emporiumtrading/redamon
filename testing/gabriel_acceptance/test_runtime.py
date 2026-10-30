"""Run in the installation image; generated Docker inspect fault injection only."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import json
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tooling/scripts'))
from gabriel_acceptance import assess,SERVICES,NETWORKS,MOUNTS,RUNTIME_FILES,validate_runtime_sources,committed_runtime_sources,BIND_FILES,VOLUME_NAMES,mount_source_profile,NATIVE_MOUNTS,DESKTOP_MOUNTS


class RuntimeAcceptance(unittest.TestCase):
    def setUp(self):
        self.config=dict(project='generated-project',image='sha256:'+'a'*64,hermes_image='sha256:'+'a'*64,port=18444,installation_root='/generated-install')
        self.rows=[]
        for service in SERVICES:
            self.rows.append(dict(Image=self.config['image'],Config=dict(User='10001:10001',Labels={
                'com.docker.compose.project':self.config['project'],'com.docker.compose.service':service}),
                State=dict(Running=True,Health=dict(Status='healthy')),Mounts=[dict(Destination=k,Type=v[0],RW=v[1],**(dict(Source='/generated-install/'+BIND_FILES[k]) if v[0]=='bind' else dict(Name='generated-project_'+VOLUME_NAMES[k]))) for k,v in MOUNTS.get(service,{}).items()],
                HostConfig=dict(Tmpfs={} if service=='local-entry' else {'/tmp':'rw,noexec,nosuid,size=8m'},Privileged=False,ReadonlyRootfs=True,CapDrop=['ALL'],SecurityOpt=['no-new-privileges:true'],Memory=1024,PidsLimit=32,
                    PortBindings={'8444/tcp':[dict(HostIp='127.0.0.1',HostPort='18444')]} if service=='local-entry' else {}),
                NetworkSettings=dict(Networks={'generated-project_'+n:{} for n in NETWORKS[service]})))
        self.networks={'generated-project_'+n:dict(Internal=n!='entry',Labels={'com.docker.compose.project':'generated-project'}) for n in ('private','toolbus','entry')}
    def browser_fixture(self):
        config=dict(self.config,browser_port=18443,browser_expires_at=(datetime.now(timezone.utc)+timedelta(seconds=120)).isoformat(),
            browser_image_environment=['PATH=/usr/local/bin:/usr/bin','PYTHONUNBUFFERED=1'])
        rows=deepcopy(self.rows)
        for service in ('browser-gateway','browser-entry'):
            row=deepcopy(next(r for r in rows if r['Config']['Labels']['com.docker.compose.service']==('workbench' if service=='browser-gateway' else 'local-entry')))
            row['Config']['Labels']['com.docker.compose.service']=service
            row['Config']['Entrypoint']=['python','-m','gabriel.identity.installation','browser-serve' if service=='browser-gateway' else 'browser-relay']
            row['Config']['Cmd']=None
            env=({'GABRIEL_IDENTITY_DSN_FILE':'/run/secrets/app_dsn','GABRIEL_EVIDENCE_KEYRING_FILE':'/run/secrets/evidence_keyring',
                'GABRIEL_EVIDENCE_ROOT':'/var/lib/gabriel-evidence'} if service=='browser-gateway' else {'GABRIEL_BROWSER_EXPIRES_AT':config['browser_expires_at']})
            row['Config']['Env']=config['browser_image_environment']+[k+'='+v for k,v in env.items()]
            row['Mounts']=[dict(Destination=k,Type=v[0],RW=v[1],**(dict(Source='/generated-install/'+BIND_FILES[k]) if v[0]=='bind' else dict(Name='generated-project_'+VOLUME_NAMES[k]))) for k,v in MOUNTS.get(service,{}).items()]
            row['HostConfig']['PortBindings']={'8443/tcp':[dict(HostIp='127.0.0.1',HostPort='18443')]} if service=='browser-entry' else {}
            row['NetworkSettings']['Networks']={'generated-project_'+n:{} for n in NETWORKS[service]}
            rows.append(row)
        return config,rows

    def test_optional_browser_pair_is_strictly_attested_and_never_silently_ignored(self):
        config,rows=self.browser_fixture()
        self.assertEqual(len(assess(config,rows,self.networks)['services']),7)
        for invalid in (rows[:-1],rows[:-2],rows+[deepcopy(rows[-1])]):
            with self.assertRaises(ValueError):assess(config,invalid,self.networks)
        with self.assertRaises(ValueError):assess(self.config,rows,self.networks)

    def test_browser_environment_execution_overrides_duplicates_and_topology_fail_closed(self):
        config,fixture=self.browser_fixture()
        for change in ('public','provider-secret','workbench-volume','egress','entrypoint','command','restart','expired',
                'PYTHONPATH','PYTHONHOME','LD_PRELOAD','PATH','duplicate','lease-expiry'):
            rows=deepcopy(fixture);cfg=dict(config)
            gateway=rows[-2];relay=rows[-1]
            if change=='public':relay['HostConfig']['PortBindings']['8443/tcp'][0]['HostIp']='0.0.0.0'
            if change=='provider-secret':gateway['Mounts'].append(dict(Destination='/run/secrets/provider_keyring',Type='bind',RW=False,Source='/generated-install/provider/keyring.json'))
            if change=='workbench-volume':gateway['Mounts'].append(dict(Destination='/var/lib/gabriel-workbench',Type='volume',RW=True,Name='generated-project_workbench'))
            if change=='egress':gateway['NetworkSettings']['Networks']['generated-project_entry']={}
            if change=='entrypoint':gateway['Config']['Entrypoint']=['sh','-c','unreviewed']
            if change=='command':relay['Config']['Cmd']=['unreviewed']
            if change=='restart':gateway['HostConfig']['RestartPolicy']={'Name':'always'}
            if change=='expired':cfg['browser_expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
            if change in {'PYTHONPATH','PYTHONHOME','LD_PRELOAD','PATH'}:gateway['Config']['Env'].append(change+'=/generated/unreviewed')
            if change=='duplicate':gateway['Config']['Env'].append('PYTHONUNBUFFERED=1')
            if change=='lease-expiry':relay['Config']['Env'][-1]='GABRIEL_BROWSER_EXPIRES_AT=2099-01-01T00:00:00+00:00'
            with self.subTest(change=change),self.assertRaises(ValueError):assess(cfg,rows,self.networks)
    def test_runtime_evidence_never_admits_browser_or_release(self):
        result=assess(self.config,self.rows,self.networks)
        self.assertTrue(result['runtime_checks_passed'])
        self.assertEqual(len(result['services']),5)
        self.assertFalse(result['production_admitted'])
        self.assertEqual(result['native_browser_acceptance'],'pending')
        self.assertEqual(result['operational_acceptance'],'pending')
        self.assertNotIn('Config',json.dumps(result))
    def test_actual_runtime_source_map_must_match_checkout_exactly(self):
        expected={n:'a'*64 for n in RUNTIME_FILES}
        self.assertEqual(validate_runtime_sources(expected,dict(expected))['critical_file_sha256'],expected)
        for bad in (dict(expected,**{'model_worker.py':'b'*64}),dict(expected,unexpected='a'*64),
                    {n:v for n,v in expected.items() if n!='browser_hermes.py'},dict(expected,**{'service.py':None})):
            with self.assertRaises(ValueError):validate_runtime_sources(expected,bad)
    def test_runtime_source_hashes_come_from_named_commit_not_working_tree(self):
        source='a'*40
        calls=[]
        def git_blob(command):
            calls.append(command)
            return ('committed:'+command[-1]).encode()
        expected=committed_runtime_sources(source,git_blob)
        self.assertEqual(calls,[['git','show',source+':gabriel/identity/'+name] for name in RUNTIME_FILES])
        self.assertEqual(expected['service.py'],hashlib.sha256(('committed:'+source+':gabriel/identity/service.py').encode()).hexdigest())
        dirty=dict(expected,**{'service.py':hashlib.sha256(b'generated dirty runtime and checkout bytes').hexdigest()})
        with self.assertRaisesRegex(ValueError,'running_runtime_source_mismatch'):validate_runtime_sources(expected,dirty)
        with self.assertRaisesRegex(ValueError,'invalid_source_identity'):committed_runtime_sources('HEAD',git_blob)
    def test_wrong_secret_files_and_persistent_volume_names_are_rejected(self):
        for service in SERVICES:
            for target,expected in MOUNTS.get(service,{}).items():
                rows=deepcopy(self.rows)
                row=next(r for r in rows if r['Config']['Labels']['com.docker.compose.service']==service)
                mount=next(m for m in row['Mounts'] if m['Destination']==target)
                field='Source' if expected[0]=='bind' else 'Name'
                mount[field]='/generated-other/wrong-file' if field=='Source' else 'generated-other-volume'
                with self.subTest(service=service,target=target),self.assertRaisesRegex(ValueError,'secret_mount_source_changed|persistent_volume_changed'):
                    assess(self.config,rows,self.networks)
                del mount[field]
                with self.subTest(service=service,target=target,missing=True),self.assertRaises(ValueError):
                    assess(self.config,rows,self.networks)
        self.assertNotIn('/generated-install',json.dumps(assess(self.config,self.rows,self.networks)))
    def test_desktop_source_mapping_requires_darwin_and_linux_desktop_engine(self):
        rows=deepcopy(self.rows)
        config=dict(self.config,installation_root='/Users/generated/gabriel')
        for row in rows:
            for mount in row['Mounts']:
                if mount['Type']=='bind':mount['Source']='/host_mnt'+config['installation_root']+'/'+BIND_FILES[mount['Destination']]
        metadata=dict(OSType='linux',OperatingSystem='Docker Desktop')
        profile=mount_source_profile('Darwin',metadata)
        self.assertEqual(profile,DESKTOP_MOUNTS)
        result=assess(config,rows,self.networks,mount_profile=profile)
        self.assertEqual(result['mount_source_profile'],DESKTOP_MOUNTS)
        self.assertEqual(result['native_browser_acceptance'],'pending')
        self.assertNotIn('/Users/',json.dumps(result))
        native=deepcopy(rows)
        for row in native:
            for mount in row['Mounts']:
                if mount['Type']=='bind':mount['Source']=config['installation_root']+'/'+BIND_FILES[mount['Destination']]
        self.assertTrue(assess(config,native,self.networks,mount_profile=profile)['runtime_checks_passed'])
        for host,engine in [('Linux',metadata),('Windows',metadata),('Darwin',dict(metadata,OSType='windows')),
                ('Darwin',dict(metadata,OperatingSystem='Ubuntu')),('Darwin',dict(OSType='linux'))]:
            profile=mount_source_profile(host,engine)
            self.assertEqual(profile,NATIVE_MOUNTS)
            with self.subTest(host=host,engine=engine),self.assertRaisesRegex(ValueError,'secret_mount_source_changed'):
                assess(config,rows,self.networks,mount_profile=profile)
        with self.assertRaisesRegex(ValueError,'secret_mount_source_changed'):assess(config,rows,self.networks)
        with self.assertRaisesRegex(ValueError,'invalid_mount_source_profile'):
            assess(config,rows,self.networks,mount_profile='generic-prefix-strip')
    def test_desktop_mapping_rejects_wrong_file_prefix_and_traversal(self):
        for source in ('/host_mnt/generated-other/database/app_dsn','/host_mnt/generated-install/database/other',
                '/host_mnt/host_mnt/generated-install/database/app_dsn','/run/desktop/mnt/host/generated-install/database/app_dsn',
                '/host_mnt/generated-install/database/../database/app_dsn'):
            rows=deepcopy(self.rows)
            row=next(r for r in rows if r['Config']['Labels']['com.docker.compose.service']=='workbench')
            next(m for m in row['Mounts'] if m['Destination']=='/run/secrets/app_dsn')['Source']=source
            with self.subTest(source=source),self.assertRaisesRegex(ValueError,'secret_mount_source_changed'):
                assess(self.config,rows,self.networks,mount_profile=DESKTOP_MOUNTS)
        with self.assertRaisesRegex(ValueError,'invalid_installation_root'):
            assess(dict(self.config,installation_root='/generated-install/../other'),self.rows,self.networks,mount_profile=DESKTOP_MOUNTS)
    def test_every_service_required_healthy_and_unique(self):
        for change in ('missing','duplicate','unhealthy','foreign'):
            rows=deepcopy(self.rows)
            if change=='missing':rows.pop()
            if change=='duplicate':rows.append(deepcopy(rows[0]))
            if change=='unhealthy':rows[0]['State']['Health']['Status']='starting'
            if change=='foreign':rows[0]['Config']['Labels']['com.docker.compose.project']='other'
            with self.subTest(change=change),self.assertRaises(ValueError):assess(self.config,rows,self.networks)
    def test_real_security_regressions_fail_closed(self):
        for field,value in [('Privileged',True),('ReadonlyRootfs',False),('CapAdd',['SYS_ADMIN']),('CapDrop',[]),('SecurityOpt',[]),('Memory',0),('PidsLimit',0),('NetworkMode','host'),('PidMode','host'),('Tmpfs',{'/tmp':'rw,exec,nosuid'})]:
            rows=deepcopy(self.rows);next(r for r in rows if r['Config']['Labels']['com.docker.compose.service']=='workbench')['HostConfig'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):assess(self.config,rows,self.networks)
    def test_listener_image_mount_and_network_drift_rejected(self):
        for change in ('public','database-port','image','owner-secret','docker-socket','tool-volume','egress','network-missing','host-root','secret-writable','required-mount-missing','network-role','relay-tmpfs'):
            rows=deepcopy(self.rows);by={r['Config']['Labels']['com.docker.compose.service']:r for r in rows};networks=deepcopy(self.networks)
            if change=='public':by['local-entry']['HostConfig']['PortBindings']['8444/tcp'][0]['HostIp']='0.0.0.0'
            if change=='database-port':by['identity-db']['HostConfig']['PortBindings']={'5432/tcp':[]}
            if change=='image':by['workbench']['Image']='sha256:'+'b'*64
            if change in {'owner-secret','docker-socket'}:by['workbench']['Mounts']=[dict(Type='bind',Destination='/run/secrets/owner_dsn' if change=='owner-secret' else '/var/run/docker.sock')]
            if change=='tool-volume':by['hermes']['Mounts']=[dict(Type='volume',Destination='/data')]
            if change=='relay-tmpfs':by['local-entry']['HostConfig']['Tmpfs']={'/tmp':'rw,noexec,nosuid,size=8m'}
            if change=='host-root':by['workbench']['Mounts'].append(dict(Type='bind',Destination='/host',RW=True))
            if change=='secret-writable':next(m for m in by['workbench']['Mounts'] if m['Destination']=='/run/secrets/app_dsn')['RW']=True
            if change=='required-mount-missing':by['workbench']['Mounts'].pop()
            if change=='network-role':by['workbench']['NetworkSettings']['Networks']={'generated-project_toolbus':{}}
            if change=='egress':networks['generated-project_private']['Internal']=False
            if change=='network-missing':networks.pop('generated-project_private')
            with self.subTest(change=change),self.assertRaises(ValueError):assess(self.config,rows,networks)
    def test_workbench_egress_requires_explicit_policy_and_cannot_relax_toolbus(self):
        rows=deepcopy(self.rows);by={r['Config']['Labels']['com.docker.compose.service']:r for r in rows}
        by['workbench']['NetworkSettings']['Networks']['generated-project_ai_egress']={};networks=dict(self.networks,**{'generated-project_ai_egress':dict(Internal=False,Labels={'com.docker.compose.project':'generated-project'})})
        with self.assertRaises(ValueError):assess(self.config,rows,networks)
        self.assertTrue(assess(self.config,rows,networks,provider_egress=True)['provider_egress_explicit'])
        by['hermes']['NetworkSettings']['Networks']['generated-project_ai_egress']={}
        with self.assertRaises(ValueError):assess(self.config,rows,networks,provider_egress=True)


if __name__=='__main__':unittest.main()
