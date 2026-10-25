"""Private operator enrollment and HTTPS analyst workbench launcher."""
import argparse
import json
import os
from gabriel.identity.cases import CaseService
from gabriel.identity.cli import read_secret
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.service import IdentityError
from gabriel.identity.workbench import prepare_workbench,serve_workbench


def main():
    parser=argparse.ArgumentParser(description='Gabriel analyst workbench')
    parser.add_argument('command',choices=('prepare','serve'))
    for name in ('token-file','endpoint','directory','configuration','certificate','key'):
        parser.add_argument('--'+name)
    parser.add_argument('--bind',default='127.0.0.1:8444')
    args=parser.parse_args()
    try:
        if args.command=='serve':
            serve_workbench(args.configuration,args.certificate,args.key,args.bind)
            return 0
        store=LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],EvidenceKeys.from_file(os.environ['GABRIEL_EVIDENCE_KEYRING_FILE']))
        service=CaseService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']),store)
        result=prepare_workbench(service,read_secret(args.token_file,128),args.endpoint,args.directory)
        print(json.dumps(dict(status='ok',result=result)))
        return 0
    except (IdentityError,OSError,ValueError,TypeError,KeyError):
        print(json.dumps(dict(status='denied',code='workbench_operation_denied')))
        return 1


if __name__=='__main__': raise SystemExit(main())
