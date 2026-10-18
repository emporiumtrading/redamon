# Gabriel retention, legal holds and primary-content disposition — increment 9

Migration 8 adds immutable retention policies, case-scoped holds and releases, hold generations, exact purge proposals/approvals, durable attempts and append-only disposition events. It preserves earlier migration checksums. This component deletes only the selected encrypted file in the configured primary evidence store. It retains evidence metadata, hashes, custody, approvals, receipts and audit. It does not erase exports, backups, snapshots, disk remnants, model memory or remote copies; it does not assert cryptographic erasure or legal compliance.

## Policy and holds

Owners/admins explicitly configure 1–3,650 days. No legal duration or default deletion authority is invented. Eligibility uses the server-recorded observation time plus the longest duration in the tenant's policy history, and requires a closed case. Shortening a later policy never shortens that floor; extension or any new policy revision invalidates older purge consent. Policy revisions are bounded at 1,024 per tenant. Automatic exception/shortening workflows are unavailable.

Owners/admins/analysts may place a case hold; viewers may inspect metadata. Holds cover current and later artifacts in that case. Reads and local case closure remain permitted; content deletion is denied while any hold is active. A different current owner/admin must release a hold with its exact reviewed digest and a reason. The placer cannot release it. Immutable hold/release records and incremented hold generations prevent releasing a hold from reviving old purge consent. Up to 64 active holds per case are admitted.

Hold placement records observed coverage, including corrupt/missing/pending/previously purged artifacts. An active hold protects remaining content; it does not restore missing data or certify complete preservation. Inspect coverage gaps and reconcile interrupted disposition. A hold arriving before unlink wins under the tenant lock. If unlink already committed or an earlier crash removed bytes, the later hold records that limitation. Trusted server credentials/filesystem administration remain outside the client/tenant boundary; this is not independently enforced WORM storage.

## Exact destructive consent and durable intent

Purge proposals bind the exact evidence/context hash, case closure time, retention revision/floor, hold generation, custody prefix, reason and enrolled store identity. Requests expire after 15 minutes; approval lasts at most five minutes and cannot outlive the request. A different current owner/admin must approve the reviewed digest. The local case-closure self-approval setting cannot relax this rule. Workers cannot propose, approve or delete. At most 100 unexpired active purge requests per tenant are admitted.

A prepared attempt commits before file removal. It blocks ordinary content reads, exports and intake replay while preserving metadata/custody. Preparation retries use one attempt per request; conflicting/other dispositions deny. Execution rechecks closed case, retention, holds, generation/policy drift, unresolved exports, current requester/approver/executor sessions/roles and expiry. The final admission callback runs after the last ciphertext verification immediately before unlink. The attempt/request/evidence relationship has a composite foreign key. No caller-supplied path determines a deletion target.

The first valid proposal enrolls a random `store-id` after verifying the actual object. Subsequent operations require that identity; an unmounted/wrong empty directory cannot certify absence. Back up and restore the marker with the encrypted objects. It identifies the configured storage lineage, not a global inventory of all clones/copies. There is no deletion claim for another store or backup.

Removal verifies a present regular encrypted file and its authenticated context/hash, unlinks only its server-generated filename and syncs the directory. A missing, tampered or symbolic-link object is not blindly deleted. The outcome `removed` means this attempt removed the primary pathname and verified its absence. If receipt/audit persistence fails after unlink, the separately committed attempt remains `prepared`; success is not returned. **Do not blindly retry deletion.**

Reconciliation is non-destructive: it confirms and syncs absence in the bound store, recording `absence_confirmed` without claiming who removed the bytes. It can run under a newly active hold or expired original consent because it performs no deletion. Aborting a prepared attempt instead requires authenticated content still present; it cancels that request and restores ordinary access. A missing object cannot be declared safely aborted. A completed disposition denies normal access even if old bytes reappear; absence recheck reports that discrepancy. Metadata/custody and separate retention/disposition events remain available.

## Operator commands

Follow [case/evidence setup](README.GABRIEL_CASE_EVIDENCE.md) and [case-approval setup](README.GABRIEL_APPROVALS.md), rebuild, then migrate through version 8. Human tokens are internal Gabriel sessions. No command logs into an external console. Commands prompt for a session or accept an explicitly mounted `--token-file`.

```bash
bash gabriel.sh identity-build
bash gabriel.sh identity-migrate
bash gabriel.sh case-data retention-set --days ORGANIZATION_SELECTED_DAYS
bash gabriel.sh case-data retention-get
bash gabriel.sh case-data hold-place --case-id CASE_UUID --rationale 'Authorized preservation reason'
bash gabriel.sh case-data governance --case-id CASE_UUID
# A different owner/admin reviews the hold and its coverage before release:
bash gabriel.sh case-data hold-release --hold-id HOLD_UUID --expected-digest REVIEWED_HOLD_SHA256 \
  --rationale 'Authorized release reason'
```

For eligible primary content, the requesting owner/admin creates a local proposal; a different owner/admin reviews the full payload and explicitly approves:

```bash
bash gabriel.sh case-data purge-propose --evidence-id EVIDENCE_UUID --request-id RETRY_UUID \
  --rationale 'Reviewed primary-store disposition reason'
bash gabriel.sh case-data purge-get --approval-id PURGE_REQUEST_UUID
bash gabriel.sh case-data purge-approve --approval-id PURGE_REQUEST_UUID --expected-digest REVIEWED_REQUEST_SHA256
bash gabriel.sh case-data purge-prepare --approval-id PURGE_REQUEST_UUID
bash gabriel.sh case-data purge-execute --attempt-id PREPARED_ATTEMPT_UUID
```

Preparation and execution use the same preparing current owner/admin. `purge-cancel --approval-id ...` cancels a proposal/approval before preparation. For a prepared attempt use `purge-abort --attempt-id ...` only when authentic content is still present, or `purge-reconcile --attempt-id ...` to record confirmed absence. These reconciliation operations require a current owner/admin but do not recreate the original deletion authority. Changes in holds/policy require a fresh proposal and a fresh distinct approval before deletion. `governance` returns all current holds/dispositions within the 64-artifact/hold bounds plus bounded recent history, with total counts and truncation flags.

There is no automatic destructive scheduler, bulk purge, metadata-erasure command, backup/export deletion or cloud-object enforcement. No inert schedule configuration or simulated deletion integration is exposed. Those remain explicit acceptance work in CV-05; external custody checkpoints remain CV-04.

## Verification and rollback

Run `bash gabriel.sh identity-test /absolute/private/report-directory` in Docker. The matching-image suite uses real disposable PostgreSQL and generated encrypted historical fixtures with recomputed GCM/custody hashes; it does not fabricate live telemetry or mock persistence. Tests cover exact distinct consent, retention floor, holds/releases/races, actor/policy expiry, ciphertext/path safety, wrong stores, failed audit admission, receipt failure after actual unlink, non-destructive reconciliation, abort, tenant/role/worker denials, immutable grants, concurrent retry and actual CLI flows. Historical migrations and interrupted DDL preserve existing evidence.

The checkpoint uses a real active hold, completed purge, and a controlled receipt failure after unlink. Restart and coherent database/object restore must retain hold state, reject purged reads and reconcile the unresolved absence without another deletion. Store markers, dumps, plaintext fixtures, keys and credential checkpoints stay outside retained evidence artifacts.

Rollback disables new disposition entry points and retains schema 8, holds, requests, tombstones, encrypted objects and referenced keys. Never downgrade the migrator or drop governance records to regain access. Restoring older object snapshots can reintroduce purged content; reconcile tombstones before enabling reads or deletion. Use coherent quiesced snapshots and retain independently controlled backups subject to their separately approved policy. Component checks do not accept full disaster recovery, independent security review or integrated human UAT.
