"""Case metadata and explicit encrypted intake/export; no evidence body on stdout."""
import argparse
import getpass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

from gabriel.identity.cli import read_secret
from gabriel.identity.service import IdentityError,InvalidIdentityInput
from gabriel.identity.cases import CaseService
from gabriel.identity.actions import ActionService
from gabriel.identity.retention import RetentionService
from gabriel.identity.checkpoint_service import CheckpointService
from gabriel.identity.checkpoint_policy import CheckpointPolicyService
from gabriel.identity.checkpoints import read_document,write_document,canonical,fingerprint
from gabriel.identity.evidence_store import EvidenceError,EvidenceKeys,LocalEvidenceStore,MAX_BYTES


class ExportError(EvidenceError):
    def __init__(self,code,export_id):
        super().__init__(code)
        self.export_id = str(export_id)


def approved_file(path,root):
    try:
        path,root = Path(path),Path(root).resolve()
        if not path.is_absolute() or root==Path('/') or '..' in path.parts:
            raise ValueError
        relative = path.relative_to(root)
        if not relative.parts:
            raise ValueError
        parent = os.open(root,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in relative.parts[:-1]:
                child = os.open(part,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(relative.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
        finally:
            os.close(parent)
        with os.fdopen(fd,'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError
            value = stream.read(MAX_BYTES+1)
        if not 1<=len(value)<=MAX_BYTES:
            raise ValueError
        return value.decode('utf-8')
    except (OSError,TypeError,ValueError,UnicodeError):
        raise InvalidIdentityInput('approved_content_file_unavailable') from None


def export_file(service,token,evidence_id,path):
    output = Path(path)
    if not output.is_absolute() or output.resolve()==service.store.root.resolve() or service.store.root.resolve() in output.resolve().parents:
        raise InvalidIdentityInput('external_absolute_export_path_required')
    bundle = service.prepare_export(token,evidence_id)
    try:
        fd = os.open(output,os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w+b') as stream:
            stream.write(bundle.reveal())
            stream.flush()
            os.fsync(stream.fileno())
            stream.seek(0)
            digest = sha256(stream.read(MAX_BYTES+1)).hexdigest()
        parent = os.open(output.parent,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        if digest!=bundle.metadata['digest']:
            raise EvidenceError('export_digest_mismatch')
    except (OSError,EvidenceError):
        try:
            service.finish_export(token,bundle.export_id,completed=False)
        except IdentityError:
            raise ExportError('export_status_unresolved',bundle.export_id) from None
        raise ExportError('export_file_write_failed',bundle.export_id) from None
    try:
        service.finish_export(token,bundle.export_id,completed=True,written_digest=digest)
    except IdentityError:
        raise ExportError('export_completion_unrecorded',bundle.export_id) from None
    return {'export_id':str(bundle.export_id),'digest':digest,'byte_length':bundle.metadata['byte_length']}


def main():
    parser = argparse.ArgumentParser(description='Gabriel case and evidence operator')
    parser.add_argument('command',choices=('create','list','get','link-task','acquire','custody','verify','close','export','exports',
        'policy-set','policy-get','propose-close','action-get','action-submit','action-approve','action-reject','action-cancel','action-execute',
        'retention-set','retention-get','hold-place','hold-release','governance','purge-propose','purge-get','purge-approve',
        'purge-prepare','purge-execute','purge-reconcile','purge-abort','purge-cancel','checkpoint-capture','checkpoint-verify',
        'checkpoint-key-trust','checkpoint-key-revoke','checkpoint-policy-set','checkpoint-policy-get','checkpoint-accept','checkpoint-check'))
    parser.add_argument('--token-file')
    parser.add_argument('--title')
    parser.add_argument('--case-id')
    parser.add_argument('--task-id')
    parser.add_argument('--evidence-id')
    parser.add_argument('--ingestion-id')
    parser.add_argument('--content-file')
    parser.add_argument('--source-label')
    parser.add_argument('--source-event-time')
    parser.add_argument('--redaction-state',choices=('not_redacted','user_declared_redacted'),default='not_redacted')
    parser.add_argument('--parent-id')
    parser.add_argument('--approved-content',action='store_true')
    parser.add_argument('--output')
    parser.add_argument('--approval-id')
    parser.add_argument('--request-id')
    parser.add_argument('--rationale')
    parser.add_argument('--expected-digest')
    parser.add_argument('--ttl',type=int,default=900)
    parser.add_argument('--approval-ttl',type=int,default=300)
    parser.add_argument('--distinct-approver',choices=('yes','no'),default='yes')
    parser.add_argument('--days',type=int)
    parser.add_argument('--hold-id')
    parser.add_argument('--attempt-id')
    parser.add_argument('--checkpoint-file')
    parser.add_argument('--trusted-public-key')
    parser.add_argument('--key-fingerprint')
    parser.add_argument('--max-age-seconds',type=int)
    parser.add_argument('--checkpoint-digest')
    args = parser.parse_args()
    try:
        keys = EvidenceKeys.from_file(os.environ.get('GABRIEL_EVIDENCE_KEYRING_FILE'))
        store = LocalEvidenceStore(os.environ.get('GABRIEL_EVIDENCE_ROOT'),keys)
        service = CheckpointPolicyService(read_secret(os.environ.get('GABRIEL_IDENTITY_DSN_FILE')),store)
        token = read_secret(args.token_file,128) if args.token_file else getpass.getpass('Gabriel session: ')
        if args.command=='checkpoint-key-trust':
            result = service.trust_checkpoint_key(token,read_document(args.trusted_public_key),args.key_fingerprint)
        elif args.command=='checkpoint-key-revoke':
            service.revoke_checkpoint_key(token,args.key_fingerprint,args.rationale)
            result = {'revoked':True}
        elif args.command=='checkpoint-policy-set':
            result = service.set_checkpoint_policy(token,args.key_fingerprint,args.max_age_seconds)
        elif args.command=='checkpoint-policy-get':
            result = service.get_checkpoint_policy(token)
        elif args.command=='checkpoint-accept':
            result = service.accept_checkpoint(token,args.case_id,read_document(args.checkpoint_file),args.expected_digest)
        elif args.command=='checkpoint-check':
            result = service.check_checkpoint_policy(token,args.case_id,args.expected_digest)
        elif args.command=='checkpoint-capture':
            snapshot = service.capture_checkpoint(token,args.case_id)
            write_document(args.output,snapshot)
            result = {'snapshot_digest':fingerprint(canonical(snapshot)),'case_id':str(args.case_id),'sealed':False}
        elif args.command=='checkpoint-verify':
            result = service.verify_checkpoint(token,args.case_id,read_document(args.checkpoint_file),
                read_document(args.trusted_public_key),args.expected_digest)
        elif args.command=='retention-set':
            result = service.set_retention(token,args.days)
        elif args.command=='retention-get':
            result = service.get_retention(token)
        elif args.command=='hold-place':
            result = service.place_hold(token,args.case_id,args.rationale)
        elif args.command=='hold-release':
            service.release_hold(token,args.hold_id,args.expected_digest,args.rationale)
            result = {'released':True}
        elif args.command=='governance':
            result = service.governance(token,args.case_id)
        elif args.command=='purge-propose':
            result = service.propose_purge(token,args.evidence_id,args.request_id,args.rationale)
        elif args.command=='purge-get':
            result = service.get_purge(token,args.approval_id)
        elif args.command=='purge-approve':
            service.approve_purge(token,args.approval_id,args.expected_digest)
            result = {'approved':True}
        elif args.command=='purge-prepare':
            result = service.prepare_purge(token,args.approval_id)
        elif args.command=='purge-execute':
            result = service.execute_purge(token,args.attempt_id)
        elif args.command in {'purge-reconcile','purge-abort'}:
            result = service.reconcile_purge(token,args.attempt_id,abort=args.command=='purge-abort')
        elif args.command=='purge-cancel':
            service.cancel_purge(token,args.approval_id)
            result = {'cancelled':True}
        elif args.command=='policy-set':
            result = service.set_policy(token,distinct_approver=args.distinct_approver=='yes',approval_ttl=args.approval_ttl)
        elif args.command=='policy-get':
            result = service.get_policy(token)
        elif args.command=='propose-close':
            result = service.propose_close(token,args.case_id,args.request_id,args.rationale,ttl=args.ttl)
        elif args.command=='action-get':
            result = service.get_action(token,args.approval_id)
        elif args.command=='action-submit':
            service.submit(token,args.approval_id)
            result = {'submitted':True}
        elif args.command=='action-approve':
            service.approve(token,args.approval_id,args.expected_digest)
            result = {'approved':True}
        elif args.command in {'action-reject','action-cancel'}:
            service.end(token,args.approval_id,'rejected' if args.command=='action-reject' else 'cancelled')
            result = {'ended':True}
        elif args.command=='action-execute':
            result = service.execute(token,args.approval_id,checkpoint_digest=args.checkpoint_digest)
        elif args.command=='create':
            result = service.create_case(token,args.title)
        elif args.command=='list':
            result = service.list_cases(token)
        elif args.command=='get':
            result = service.get_case(token,args.case_id)
        elif args.command=='link-task':
            service.link_task(token,args.case_id,args.task_id)
            result = {'linked':True}
        elif args.command=='acquire':
            if not args.content_file:
                raise InvalidIdentityInput('approved_content_file_required')
            content = approved_file(args.content_file,os.environ.get('GABRIEL_CASE_INTAKE_ROOT','/intake'))
            result = service.acquire(token,args.case_id,args.ingestion_id,content,args.source_label,
                approved=args.approved_content,event_time=args.source_event_time,redaction_state=args.redaction_state,parent_id=args.parent_id)
        elif args.command=='custody':
            result = service.custody(token,args.evidence_id)
        elif args.command=='verify':
            result = service.verify_case(token,args.case_id)
        elif args.command=='close':
            result = service.close_case(token,args.case_id,approval_id=args.approval_id,checkpoint_digest=args.checkpoint_digest)
        elif args.command=='exports':
            result = service.list_exports(token)
        else:
            if not args.output:
                raise InvalidIdentityInput('external_absolute_export_path_required')
            result = export_file(service,token,args.evidence_id,args.output)
        print(json.dumps({'status':'ok','result':result},default=str,allow_nan=False))
        return 0
    except IdentityError as exc:
        result = {'status':'denied','code':str(exc)}
        if isinstance(exc,ExportError):
            result['export_id'] = exc.export_id
        print(json.dumps(result))
        return 1
    except (OSError,UnicodeError,ValueError,TypeError,RecursionError):
        print(json.dumps({'status':'denied','code':'case_input_or_file_unavailable'}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
