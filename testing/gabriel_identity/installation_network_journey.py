"""Reproduce a healthy DB with deliberately blocked private peer connections."""
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tooling/scripts'))
from gabriel_install import Installation,InstallationNetworkError,prepare


def main():
    root=Path(sys.argv[1]);image=sys.argv[2]
    prepare(root,18446,image)
    app=Installation(root)
    override=root/'blocked-private-network.json'
    override.write_text(json.dumps({'networks':{'private':{'driver_opts':{
        'com.docker.network.bridge.enable_icc':'false'}}}}))
    app.command.extend(['--file',str(override)])
    try:
        config=json.loads(app.compose('--profile','operator','config','--format','json'))
        network=config['networks']['private']
        assert network['internal'] and network['driver_opts']['com.docker.network.bridge.enable_icc']=='false'
        probe=config['services']['network-check']
        assert set(probe['networks'])=={'private'}
        assert probe['user']=='10001:10001' and probe['read_only'] and probe['cap_drop']==['ALL']
        assert not any(probe.get(key) for key in ('secrets','volumes','ports','environment','cap_add'))
        app.start_db()
        ready=app.compose('exec','-T','identity-db','pg_isready','-h','127.0.0.1','-U','postgres','-d','gabriel')
        assert b'accepting connections' in ready
        try: app.check_network()
        except InstallationNetworkError as error: assert error.phase=='database_tcp'
        else: raise AssertionError('blocked inter-container network was accepted')
        untouched=app.compose('exec','-T','identity-db','psql','-U','postgres','-d','gabriel','-Atc',
            "SELECT to_regnamespace('gabriel_identity') IS NULL")
        assert untouched.strip()==b't'
        rows=app.compose('ps','--all','--quiet').decode().split()
        assert len(rows)==1
        result=dict(version='gabriel-blocked-private-network-test-v1',database_self_healthy=True,
            dns_resolves=True,tcp_reachable=False,denial_phase='database_tcp',schema_not_created=True,
            probe_has_no_credentials_or_volumes=True,production_admitted=False)
        (root/'network-failure-result.json').write_text(json.dumps(result,indent=2)+'\n')
        print('PASS: healthy database with blocked private peer TCP is denied before migration')
    finally:
        app.compose('--profile','operator','down','--volumes','--remove-orphans')


if __name__=='__main__': main()
