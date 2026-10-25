"""Offline custodian CLI; no database credentials or evidence decryption keys are used."""
import argparse
import json

from gabriel.identity.checkpoints import (CheckpointError,canonical,fingerprint,new_keypair,read_document,
    seal,verify,write_document)


def main():
    parser = argparse.ArgumentParser(description='Offline Gabriel custody checkpoint custodian')
    parser.add_argument('command',choices=('keygen','seal','verify'))
    parser.add_argument('--private-key')
    parser.add_argument('--public-key')
    parser.add_argument('--snapshot')
    parser.add_argument('--checkpoint')
    parser.add_argument('--expected-digest')
    args = parser.parse_args()
    try:
        if args.command=='keygen':
            private,public = new_keypair()
            write_document(args.private_key,private)
            write_document(args.public_key,public)
            result = {'created':True}
        elif args.command=='seal':
            envelope = seal(read_document(args.snapshot),read_document(args.private_key,private=True))
            write_document(args.checkpoint,envelope)
            result = {'checkpoint_digest':fingerprint(canonical(envelope))}
        else:
            snapshot = verify(read_document(args.checkpoint),read_document(args.public_key),args.expected_digest)
            result = {'signature_verified':True,'organization_id':snapshot['organization_id'],'case_id':snapshot['case_id'],
                'source_authenticity':'unverified','database_comparison':'not_performed'}
        print(json.dumps({'status':'ok','result':result}))
        return 0
    except (CheckpointError,OSError,ValueError,TypeError):
        print(json.dumps({'status':'denied','code':'checkpoint_operation_failed'}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
