# Gabriel local action policy and approvals — increment 8

Migration 6 adds immutable policy revisions, canonical requests, human approvals, append-only decisions and transactional execution receipts. Migration 7 adds a database compatibility guard without changing migration 6's checksum. The only admitted operation is **Gabriel-local case closure**. There is no external response executor, browser control, external login or generated query program. Unsupported future operations have no placeholder implementations.

## Authority and exact consent

Existing valid cases now require an approved request to close. The previous direct operator/service closure path denies without that approval. A database trigger additionally rejects older runtime closure SQL lacking the new transaction-local request context, matching dispatch state, current policy and unexpired approval. Application credentials cannot remove that trigger. This protects the version boundary; it does not make the shared server database credential a client/tenant authorization boundary. Cases with missing/invalid evidence still report integrity failure and retain a blocked-closure audit event. Closure remains a record-management operation, never proof of attacker containment.

Owners/admins configure policy, approve and execute. Analysts may propose, submit and cancel their own requests. Viewers inspect scoped metadata. Workers cannot manage actions. The default policy requires a different approver. An administrator may explicitly configure self-approval for this low-impact local operation; changing policy invalidates earlier proposals/approvals. This setting cannot enable external or high-impact operations.

Requests bind the exact case, resource creation version, rationale, evidence set, authenticated provenance digests, custody-prefix sequence/hash, policy revision/content digest and lifetime. Evidence bodies and raw session tokens are not persisted in requests. Approvers must supply the exact reviewed request digest. A matching request key replays its original proposal; changed caller, target, rationale or lifetime conflicts. Replay never silently refreshes the original snapshot or consent. Use a new key after reviewing a changed case.

Submit, approve and execute recheck current policy, target/evidence and requester session/membership. Execution additionally requires the original approver's live privileged session/membership and an unexpired approval. Logout, password reset, membership changes and session expiry revoke this authority. A fresh login cannot revive a request bound to a revoked requester/approver session. Prepare a fresh request and obtain fresh consent. Evidence added or changed since proposal invalidates it. Valid access events may append to the approved custody prefix without invalidating consent. The prefix check is an approval drift control, not an external custody anchor.

Requests last 60–3,600 seconds; approval lifetime is policy-bounded to 60–900 seconds and cannot exceed the request deadline. At most 100 unexpired active requests and 1,024 policy revisions per tenant are admitted. Metadata preserves recorded decision state and reports effective expiry/requester-policy invalidation separately. Metadata alone is not execution permission: dispatch always performs live checks, including approver authority and evidence integrity.

## Operator flow

Follow [case/evidence setup](README.GABRIEL_CASE_EVIDENCE.md), rebuild the image and apply migrations through version 7. Existing cases, evidence and earlier schema checksums remain intact. Migration creates no policy, approval or retroactive consent. Every command prompts for the current internal Gabriel session, or accepts an explicitly mounted token file.

```bash
bash gabriel.sh identity-build
bash gabriel.sh identity-migrate
bash gabriel.sh case-data policy-set --approval-ttl 300 --distinct-approver yes
bash gabriel.sh case-data policy-get
bash gabriel.sh case-data propose-close --case-id CASE_UUID --request-id RETRY_UUID \
  --rationale 'Evidence reviewed; close the local investigation record' --ttl 900
bash gabriel.sh case-data action-get --approval-id ACTION_UUID
bash gabriel.sh case-data action-submit --approval-id ACTION_UUID
```

The separate owner/admin reviews the payload, snapshot and digest before consenting:

```bash
bash gabriel.sh case-data action-approve --approval-id ACTION_UUID --expected-digest REVIEWED_SHA256
bash gabriel.sh case-data action-execute --approval-id ACTION_UUID
bash gabriel.sh case-data action-get --approval-id ACTION_UUID
```

`case-data close --case-id CASE_UUID --approval-id ACTION_UUID` uses the same mandatory execution gate. `action-reject` and `action-cancel` record explicit terminal decisions. Submitted/approved/terminal records cannot be edited back into drafts. Cancellation concurrent with execution serializes under the tenant lock: committed cancellation prevents later admission; a completed closure is not undone by cancellation.

## Transaction, recovery and SSDLC

For this local PostgreSQL operation, dispatch admission, case update, receipt, successful state and audit commit in one transaction. A failed receipt/audit insert rolls back the actual case update. Concurrent duplicate executions return one stored receipt without another closure effect, while live authorization remains required. This atomicity does not extend to external systems. No provider timeout/unknown-outcome reconciliation is claimed; future external effects must implement that before admission.

The strict matching-image test suite uses real disposable PostgreSQL. It covers default self-approval denial, exact digest checks, policy/evidence/resource/custody drift, role/session revocation, expiry, rejection/cancellation, concurrent propose/approve/execute/cancel, audit failures and an actual receipt-permission failure after the case update. Restricted SQL grants prevent rewriting/deleting policy, requests, approvals, decisions and receipts. Historical upgrade tests preserve evidence and reject invented authority; interrupted DDL rolls back.

The recovery checkpoint retains both a pending approved closure and a completed closure receipt. Real database restart and fresh dump/object restore must preserve exact authority, execute the pending local operation, replay the original receipt and enforce later revocations. These are component regression/recovery checks, not human product UAT.

Source `3c9d16704e833e9fa18d67fac2b0af095c5cdc2b` passed [hosted VM verification](https://github.com/emporiumtrading/redamon/actions/runs/39134498090): 316 cases (246 identity/evidence/approval, 49 runtime/inventory, 21 foundation), zero failures/errors/skips, including real restart/restore and the approver-session expiry regression. See the implementation ledger for source, artifact digest and review/repair record.

Rollback: disable action/case closure entry points, retain schema 7 and all cases/evidence/keys. Older closure images intentionally fail at the database guard; do not remove it for compatibility. Do not downgrade the migrator, drop tables or delete volumes. Restore only a coherent reviewed quiesced database/object snapshot with retained keys into fresh locations, reconcile counts/relationships and verify integrity before resuming. Do not restore old approval authority into a live external system; this component has no such executor.

Remaining caveats are tracked in [the caveat register](GABRIEL_CAVEAT_REGISTER.md). Independent review, full C00–C04 acceptance, retention/legal holds/deletion, external tamper anchoring, browser/source authenticity and human pre/post-release UAT remain open. Test success cannot accept these gates or establish perfect security confidence.
