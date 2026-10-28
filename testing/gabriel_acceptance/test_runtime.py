"""Run in the installation image; generated Docker inspect fault injection only."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tooling/scripts'))
from gabriel_acceptance import assess,SERVICES,NETWORKS,MOUNTS


class RuntimeAcceptance(unittest.TestCase):
    def setUp(self):
        self.config=dict(project='generated-project',image='sha256:'+'a'*64,hermes_image='sha256:'+'a'*64,port=18444)
        self.rows=[]
        for service in SERVICES:
            self.rows.append(dict(Image=self.config['image'],Config=dict(User='10001:10001',Labels={
                'com.docker.compose.project':self.config['project'],'com.docker.compose.service':service}),
                State=dict(Running=True,Health=dict(Status='healthy')),Mounts=[dict(Destination=k,Type=v[0],RW=v[1]) for k,v in MOUNTS.get(service,{}).items()],
                HostConfig=dict(Tmpfs={'/tmp':'rw,noexec,nosuid,size=8m'},Privileged=False,ReadonlyRootfs=True,CapDrop=['ALL'],SecurityOpt=['no-new-privileges:true'],Memory=1024,PidsLimit=32,
                    PortBindings={'8444/tcp':[dict(HostIp='127.0.0.1',HostPort='18444')]} if service=='local-entry' else {}),
                NetworkSettings=dict(Networks={'generated-project_'+n:{} for n in NETWORKS[service]})))
        self.networks={'generated-project_'+n:dict(Internal=n!='entry',Labels={'com.docker.compose.project':'generated-project'}) for n in ('private','toolbus','entry')}
    def test_runtime_evidence_never_admits_browser_or_release(self):
        result=assess(self.config,self.rows,self.networks)
        self.assertTrue(result['runtime_checks_passed'])
        self.assertEqual(len(result['services']),5)
        self.assertFalse(result['production_admitted'])
        self.assertEqual(result['native_browser_acceptance'],'pending')
        self.assertEqual(result['operational_acceptance'],'pending')
        self.assertNotIn('Config',json.dumps(result))
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
        for change in ('public','database-port','image','owner-secret','docker-socket','tool-volume','egress','network-missing','host-root','secret-writable','required-mount-missing','network-role'):
            rows=deepcopy(self.rows);by={r['Config']['Labels']['com.docker.compose.service']:r for r in rows};networks=deepcopy(self.networks)
            if change=='public':by['local-entry']['HostConfig']['PortBindings']['8444/tcp'][0]['HostIp']='0.0.0.0'
            if change=='database-port':by['identity-db']['HostConfig']['PortBindings']={'5432/tcp':[]}
            if change=='image':by['workbench']['Image']='sha256:'+'b'*64
            if change in {'owner-secret','docker-socket'}:by['workbench']['Mounts']=[dict(Type='bind',Destination='/run/secrets/owner_dsn' if change=='owner-secret' else '/var/run/docker.sock')]
            if change=='tool-volume':by['hermes']['Mounts']=[dict(Type='volume',Destination='/data')]
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
