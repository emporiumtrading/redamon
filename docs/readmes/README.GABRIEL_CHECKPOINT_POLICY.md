# Checkpoint trust, freshness and local closure admission

Schema 9 adds immutable signer enrollments, irreversible revocation records, policy revisions, capture registrations and accepted receipts. A configured tenant requires a current accepted checkpoint and an independently retained digest before a new local case closure. This gate supplements the exact existing action approval; it does not authorize any new effect. The [checkpoint guide](README.GABRIEL_CHECKPOINTS.md) covers independent signing and the narrower historical-prefix comparison.

## Configure and accept

Owner/admin controls configure trust. Owner/admin/analyst may capture; only owner/admin may accept a signed checkpoint. Viewers may check existing receipts, and worker tokens cannot use these human operations. Durable acceptance records historical acceptance: acceptor logout does not erase it. Current callers still require live sessions/roles; explicit signer revocation invalidates that trust key.

Existing tenants receive no invented trust roots or policy on upgrade. Enable strict local closure by enrolling an independently verified public key and setting a maximum capture age of 60–86400 seconds. Fingerprints are SHA-256 of raw 32-byte Ed25519 public keys, not hashes of JSON files. `public_fingerprint(document)` implements that format. Obtain the expected fingerprint through trusted custodian records rather than accepting a value from an untrusted enrollment request.

These are case CLI arguments, using the private Compose project/session/operator mounts described in the case/evidence and checkpoint guides. Never mount a signer private key into case-data:

```bash
checkpoint-key-trust --trusted-public-key /operator/trusted-public.json --key-fingerprint TRUSTED_FINGERPRINT --token-file /operator/human-session
checkpoint-policy-set --key-fingerprint TRUSTED_FINGERPRINT --max-age-seconds 3600 --token-file /operator/human-session
checkpoint-policy-get --token-file /operator/human-session
```

Capture a new snapshot and independently seal it using the existing offline image. Capture now transactionally records its exact nonce, snapshot digest and database timestamp with audit admission. Snapshots captured before schema 9 require recapture; migration creates no retrospective authority. Limits are 4096 captures and receipts per case, 128 enrolled keys per tenant and 1024 policy revisions. There is no automatic deletion or quota reset.

Accept the signed snapshot with the independently retained envelope digest. The public key comes from the current tenant policy, with no caller-supplied key override:

```bash
checkpoint-accept --case-id CASE_UUID --checkpoint-file /operator/checkpoint-001.json --expected-digest ACCEPTED_DIGEST --token-file /operator/human-session
checkpoint-check --case-id CASE_UUID --expected-digest ACCEPTED_DIGEST --token-file /operator/human-session
```

Acceptance checks signature, active configured key, scope, exact capture registration, metadata/custody prefixes and coverage of every current evidence row. Freshness starts at the database capture time, not signing or acceptance time. Future or expired captures deny. Repeating the latest accepted digest returns the original receipt without refreshing age. New receipts require a strictly newer capture; older signed files cannot replace the latest receipt. A policy revision invalidates previous receipts and requires a new capture/acceptance. Additional evidence requires recapture; valid later custody events retain prefix coverage. These checks do not certify source authenticity or evidence content.

## Closure and revocation

For a configured tenant, execute an already approved local closure using the accepted external digest:

```bash
action-execute --approval-id ACTION_UUID --checkpoint-digest ACCEPTED_DIGEST --token-file /operator/human-session
```

The current receipt, nonrevoked configured key, policy revision, full evidence coverage, signature, metadata and custody prefixes are checked before dispatch. Existing exact action consent and live requester/approver/executor checks remain required. A database trigger checks transaction-local checkpoint context, current receipt/policy, key revocation, age and coverage/prefix references at the actual case update. Older runtime SQL without that context is denied; expiry between application validation and update rolls back closure and its receipt. The trigger supplements application cryptographic checks: it is not an Ed25519 implementation or protection against a compromised database owner/runtime credential. Replaying a previously completed action returns its original receipt without a new effect.

Explicit key revocation cannot be undone or bypassed by re-enrolling the same key:

```bash
checkpoint-key-revoke --key-fingerprint RETIRED_FINGERPRINT --rationale 'Retire reviewed signer' --token-file /operator/human-session
```

To replace a signer, enroll a different independently trusted key, append a policy selecting it, and recapture/seal/accept under that key. Offline private-key custody remains separate. There is no policy-disable or revocation-delete operation. Administrative configuration is a trusted internal operation; application append-only grants do not prevent database-owner rewriting. Keep latest accepted digests and trusted key identity independently retained.

The legacy `checkpoint-verify` command remains a caller-pinned historical-prefix check. It cannot replace the accepted receipt or strict policy gate for closure. This increment adds no checkpoint gate to purge, automatic scheduler, trusted-clock monitoring, governance/policy anchoring or external custody provider. Such requirements and independent operational acceptance remain open.

## Verification and recovery

Run `bash tooling/scripts/gabriel_identity_check.sh /absolute/private/report-directory` with Docker. New real PostgreSQL/signature/CLI tests exercise trust enrollment/revocation, stale/future/older receipts, replay, policy revision, full coverage, tenant/role/worker denials, concurrency, audit failure, actual closure, expired dispatch, old-runtime guard, migration preservation and interrupted DDL. Historical-age fixtures explicitly reconstruct signed capture/receipt bindings with actual SQL; no persistence or clock is mocked. All prior component regressions remain required.

Recovery probes retain policy, accepted receipts, capture registrations, trusted keys and revocation through real PostgreSQL restart and fresh dump/object restore. The pending closure requires its independently retained digest after recovery. Private signer keys and checkpoint material stay outside retained CI artifacts. Source `fed9906c4d974677e11aecb61afcc0e2f0638848` passed [hosted VM verification](https://github.com/emporiumtrading/redamon/actions/runs/39181405206): **430 cases passed, zero failures/errors/skips**, including 32 new real SQL/signature/CLI cases and actual recovery/closure checks. Exact artifact/digest, commands and remaining gates are recorded in [the implementation ledger](GABRIEL_IMPLEMENTATION_STATUS.md). Independent review, operational custody acceptance and integrated human UAT remain open; no production readiness is claimed.

Rollback disables new dispatch while preserving schema 9, its guard, trust/revocation/receipt records and external checkpoints. Do not drop the migration or restore a pre-policy database and treat it as an authorized policy disable. Older runtimes can read compatible records but cannot close a policy-protected case without new admission context. Restore a coherent current database/object snapshot with separately retained keys/public trust/accepted digests, reconcile and then resume. Trusted clock operations, independently operated custody, governance anchoring, broader destructive-action admission, independent review and human UAT remain required before production acceptance.
