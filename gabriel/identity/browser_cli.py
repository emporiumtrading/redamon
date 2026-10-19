"""Explicit browser-pairing operator and peer contract; no external browser login or page reads."""
import argparse
import json
import os

from gabriel.identity.browser_sessions import BrowserSessionService,approved_context
from gabriel.identity.checkpoints import read_document,write_document
from gabriel.identity.cli import read_secret
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.service import IdentityError


def main():
    parser = argparse.ArgumentParser(description='Gabriel scoped browser pairing contract')
    parser.add_argument('command',choices=('task-create','lease-issue','lease-get','lease-revoke','connect','heartbeat','disconnect'))
    parser.add_argument('--token-file')
    parser.add_argument('--credential-file')
    parser.add_argument('--context-file')
    parser.add_argument('--output')
    parser.add_argument('--lease-id')
    parser.add_argument('--case-id')
    parser.add_argument('--task-id')
    parser.add_argument('--name')
    parser.add_argument('--ttl',type=int,default=300)
    parser.add_argument('--max-steps',type=int,default=20)
    args = parser.parse_args()
    try:
        store = LocalEvidenceStore(os.environ.get('GABRIEL_EVIDENCE_ROOT'),EvidenceKeys.from_file(os.environ.get('GABRIEL_EVIDENCE_KEYRING_FILE')))
        service = BrowserSessionService(read_secret(os.environ.get('GABRIEL_IDENTITY_DSN_FILE')),store)
        if args.command in {'connect','heartbeat','disconnect'}:
            document = read_document(args.credential_file,private=True)
            if (not isinstance(document,dict) or set(document)!={'schema_version','purpose','lease_id','token','expires_at'}
                    or type(document['schema_version']) is not int or document['schema_version']!=1
                    or document['purpose']!='gabriel-browser-pair-v1'):
                raise ValueError
            token = document['token']
            if args.command=='disconnect':
                service.disconnect_browser(token)
                result = {'disconnected':True}
            else:
                context = approved_context(read_document(args.context_file))
                result = service.connect_browser(token,context) if args.command=='connect' else service.heartbeat_browser(token,context)
        else:
            token = read_secret(args.token_file,128)
            if args.command=='task-create':
                result = service.create_browser_task(token,args.name,args.ttl,args.max_steps)
            elif args.command=='lease-issue':
                context = approved_context(read_document(args.context_file))
                grant = service.issue_browser_lease(token,args.task_id,args.case_id,context,args.ttl)
                try:
                    write_document(args.output,{'schema_version':1,'purpose':'gabriel-browser-pair-v1',
                        'lease_id':str(grant.id),'token':grant.token,'expires_at':str(grant.expires_at)})
                except ValueError:
                    service.revoke_browser_lease(token,grant.id)
                    raise
                result = {'lease_id':str(grant.id),'expires_at':grant.expires_at,'credential_written':True}
            elif args.command=='lease-get':
                result = service.get_browser_lease(token,args.lease_id)
            else:
                service.revoke_browser_lease(token,args.lease_id)
                result = {'revoked':True}
        print(json.dumps({'status':'ok','result':result},default=str))
        return 0
    except (IdentityError,OSError,ValueError,TypeError,UnicodeError,RecursionError):
        print(json.dumps({'status':'denied','code':'browser_pairing_denied'}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
