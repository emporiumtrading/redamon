"""Trusted operator-only enrollment and native-TLS server launcher."""
import argparse
import json
import os

from gabriel.identity.browser_gateway import prepare,serve
from gabriel.identity.browser_observations import BrowserObservationService
from gabriel.identity.checkpoints import read_document
from gabriel.identity.cli import read_secret
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.service import IdentityError


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=('prepare','serve'))
    for option in ('token-file','task-id','case-id','context-file','endpoint','extension-origin','directory','configuration','certificate','key'):
        parser.add_argument('--'+option)
    parser.add_argument('--bind',default='127.0.0.1:8443')
    parser.add_argument('--approve-observation-sharing',action='store_true')
    args=parser.parse_args()
    try:
        if args.command=='serve':
            serve(args.configuration,args.certificate,args.key,args.bind)
            return 0
        store=LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],EvidenceKeys.from_file(os.environ['GABRIEL_EVIDENCE_KEYRING_FILE']))
        service=BrowserObservationService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']),store)
        result=prepare(service,read_secret(args.token_file,128),args.task_id,args.case_id,read_document(args.context_file),
            args.endpoint,args.extension_origin,args.directory,share_observations=args.approve_observation_sharing)
        print(json.dumps({'status':'ok','result':result}))
        return 0
    except (IdentityError,OSError,ValueError,TypeError,KeyError):
        print(json.dumps({'status':'denied','code':'gateway_operation_denied'}))
        return 1


if __name__=='__main__': raise SystemExit(main())
