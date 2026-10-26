"""Trusted operator-only enrollment and native-TLS server launcher."""
import argparse
import json
import os

from gabriel.identity.browser_gateway import prepare,serve
from gabriel.identity.browser_navigation import BrowserNavigationService
from gabriel.identity.checkpoints import read_document
from gabriel.identity.cli import read_secret
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.service import IdentityError


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=('prepare','serve','serve-group','navigation-grant','ai-readiness'))
    for option in ('token-file','task-id','case-id','context-file','endpoint','extension-origin','directory','configuration','certificate','key','navigation-file'):
        parser.add_argument('--'+option)
    parser.add_argument('--bind',default='127.0.0.1:8443')
    parser.add_argument('--approve-observation-sharing',action='store_true')
    parser.add_argument('--monitor-seconds',type=int,help='Explicit scheduled-sharing lifetime, 60–3600 seconds; requires approved observation sharing')
    parser.add_argument('--auto-discover-pages',action='store_true',help='Approve bounded read-only same-origin link discovery for the scheduled lease')
    parser.add_argument('--ai-model',help='Approve minimized browser-signal AI triage using an exact production-admitted model configuration')
    args=parser.parse_args()
    try:
        if args.command=='ai-readiness':
            from gabriel.identity.browser_ai import configuration,VERSION
            from gabriel.identity.model_routes import ROUTES,PRODUCTION_CONFIGURATIONS
            from gabriel.identity.model_evaluation import digest
            if args.ai_model not in ROUTES:raise ValueError('supported_ai_model_required')
            configured=configuration(args.ai_model);fingerprint=digest(configured)
            print(json.dumps(dict(status='ok',projection_version=VERSION,model=args.ai_model,
                configuration_digest=fingerprint,production_admitted=fingerprint in PRODUCTION_CONFIGURATIONS,
                raw_page_text_export=False,reviewed_memory_export=False,external_actions_enabled=False)))
            return 0
        if args.command in {'serve','serve-group'}:
            serve(args.configuration,args.certificate,args.key,args.bind,group=args.command=='serve-group')
            return 0
        store=LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],EvidenceKeys.from_file(os.environ['GABRIEL_EVIDENCE_KEYRING_FILE']))
        service=BrowserNavigationService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']),store)
        if args.command=='navigation-grant':
            from pathlib import Path
            configuration=Path(args.configuration)
            if not configuration.is_absolute() or '..' in configuration.parts: raise ValueError('private_configuration_required')
            configured=read_document(configuration,private=True)
            human=read_document(configuration.parent/'human.json',private=True)['token']
            credential=read_document(configuration.parent/'peer.json',private=True)
            if (configured.get('schema_version')!=1 or configured.get('purpose')!='gabriel-browser-gateway-v1'
                    or credential['lease_id']!=configured['lease_id']): raise ValueError('gateway_lease_mismatch')
            peer=credential['token']
            plan=read_document(args.navigation_file)
            if not isinstance(plan,dict) or set(plan)!={'request_id','contract_version','destinations','max_moves'}:
                raise ValueError('invalid_navigation_grant')
            result=service.grant_navigation(human,peer,plan['request_id'],plan['contract_version'],plan['destinations'],max_moves=plan['max_moves'])
        else:
            result=prepare(service,read_secret(args.token_file,128),args.task_id,args.case_id,read_document(args.context_file),
                args.endpoint,args.extension_origin,args.directory,share_observations=args.approve_observation_sharing,monitor_seconds=args.monitor_seconds,auto_discover=args.auto_discover_pages,ai_model=args.ai_model)
        print(json.dumps({'status':'ok','result':result}))
        return 0
    except (IdentityError,OSError,ValueError,TypeError,KeyError):
        print(json.dumps({'status':'denied','code':'gateway_operation_denied'}))
        return 1


if __name__=='__main__': raise SystemExit(main())
