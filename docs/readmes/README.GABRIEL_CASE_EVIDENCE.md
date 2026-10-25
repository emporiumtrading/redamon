# Gabriel cases and evidence — increment 7

Migration 8 adds [retention, legal holds and approved primary-content disposition](README.GABRIEL_RETENTION.md). Prepared/purged content has explicit storage state; original metadata/custody remain available. Follow that guide for reconciliation rather than treating intentional absence as an ordinary intake retry.

Migration 6 now requires an exact human-approved request for valid-case closure. Follow the [policy/approval operator flow](README.GABRIEL_APPROVALS.md); `close` without `--approval-id` is denied. Earlier integrity, export and storage controls remain in force.

This C04 component persists tenant cases, real task links and approved UTF-8 artifacts. It does not collect from browsers, authenticate to consoles, run queries or execute responses. Vendor-neutral labels identify engineer-supplied artifacts; they do not prove source authenticity or a live attack. A matching hash verifies stored bytes against acquisition metadata, not the truth of the evidence.

## Storage and authority

Migration 5 adds cases, evidence metadata, immutable key fingerprints, append-only custody and export receipts. Originals and user-declared redacted artifacts remain separate objects with same-case parent links. Metadata records claimed event time, server observation time, supplying user, parser/schema version, redaction declaration, length and SHA-256. Normalization/source truth remain explicitly unverified.

AES-256-GCM encrypted files live in a separate evidence volume. Authenticated context binds tenant, case, object, provenance, content hash and acquisition custody hash. Purpose-marked evidence keys are mounted separately from PostgreSQL and model-provider keys. Random object IDs determine filenames. Files are created exclusively and synced; existing files are verified, never overwritten. Symbolic links, nonregular files and oversized objects deny.

Live human sessions and membership govern every operation. Owners/admins/analysts may create cases, link tasks, acquire, read and export artifacts. Viewers see metadata, custody and integrity findings. Worker credentials have no case/content authority. Tenant predicates and composite database relationships enforce scope. The shared database application credential remains trusted server infrastructure; it is not a client credential or per-tenant RLS boundary.

Acquisition commits its intent and custody genesis before writing encrypted bytes. A second tenant-locked transaction serializes writes/retries, verifies integrity and records completion. Failed completion leaves a visible pending intent and possibly an encrypted file; storage failure attempts quarantine. Retry the exact ingestion ID and payload to reconcile. Conflicting retries deny. Damaged files are never overwritten: preserve the failure and restore a genuine backup. Audit unavailability never returns success. Session expiry between phases may require a fresh authorized session for reconciliation.

Custody is hash-linked and verified on access/export/closure. Application credentials cannot update/delete custody or immutable evidence fields. These controls detect tested corruption and missing acquisition history. They are not an externally anchored or privileged-administrator-proof ledger: a privileged administrator can rewrite the database, and deletion of a valid suffix is not generally detectable without an independent anchor. Preserve independently controlled backups. Limits are 128 KiB per artifact, 64 records per case, 100 open cases per tenant and 4,096 custody events per artifact. This is not a bulk forensic collection system.

## Operator flow

Complete [identity setup](README.GABRIEL_IDENTITY.md), rebuild the image and apply migration 5 with migration-only credentials. Earlier schema checksums remain unchanged. Commands prompt for an internal Gabriel session; `--token-file` accepts an explicitly mounted session file. No evidence body is printed.

```bash
export GABRIEL_EVIDENCE_KEY_DIR=/absolute/private/gabriel-evidence-keys
bash gabriel.sh evidence-keys-prepare "$GABRIEL_EVIDENCE_KEY_DIR"
bash gabriel.sh identity-build
bash gabriel.sh identity-migrate
bash gabriel.sh case-data create --title 'Approved investigation'
bash gabriel.sh case-data list
bash gabriel.sh case-data get --case-id CASE_UUID
bash gabriel.sh case-data link-task --case-id CASE_UUID --task-id REAL_TASK_UUID
bash gabriel.sh case-data verify --case-id CASE_UUID
```

Prepare reviewed text outside Git in a private parent directory; make only the selected file container-readable (for example mode 0444 within a host directory of mode 0700). Admission requires an ingestion UUID for retries and refuses paths outside `/intake`. Mount only the selected artifact read-only:

```bash
docker compose --project-name gabriel-identity -f compose.gabriel-identity.yml run --rm --no-deps \
  -v /absolute/private/reviewed.txt:/intake/source.txt:ro case-data acquire \
  --case-id CASE_UUID --ingestion-id INGESTION_UUID \
  --content-file /intake/source.txt --source-label 'Approved console artifact' \
  --source-event-time '2026-01-01T00:00:00+00:00' --approved-content
```

For a redacted derivative use `--redaction-state user_declared_redacted --parent-id ORIGINAL_EVIDENCE_UUID`. This declaration is not a guarantee of successful redaction. Never admit provider keys, backend credentials or unrelated browser secrets as artifacts.

Exports commit a prepared receipt before releasing plaintext to a new absolute file; they never overwrite files. Explicitly mount the operator's private output directory. Using the operator UID owns the mode-0600 result. Protect the plaintext after export.

```bash
docker compose --project-name gabriel-identity -f compose.gabriel-identity.yml run --rm --no-deps \
  --user "$(id -u):$(id -g)" -v /absolute/private/exports:/exports \
  case-data export --evidence-id EVIDENCE_UUID --output /exports/artifact.txt
bash gabriel.sh case-data exports
bash gabriel.sh case-data custody --evidence-id EVIDENCE_UUID
bash gabriel.sh case-data close --case-id CASE_UUID
```

Success requires file fsync, read-back digest verification and committed completion. A filesystem failure records failure when possible. Later audit failure returns an unresolved/completion-unrecorded error with export ID; plaintext may already exist. Inspect it and the receipt before retrying. The backend reconciliation interface `finish_export` requires the same currently authorized preparing user and expected written digest. It does not prove downstream delivery. Closure requires a nonempty case with every artifact ready and integrity/custody verified; closure is not proof of attacker containment.

## Recovery and tests

Back up PostgreSQL, encrypted objects and keys as separate protected assets. Use a coherent database/object snapshot under maintenance quiescence; a database dump alone cannot recover bytes. Retain every referenced key. The preparer can generate new keys while retaining old keys, but no evidence rewrap/retirement or generation downgrade prevention is implemented; never remove/reuse key IDs. Provider rotation does not rotate evidence keys.

`bash gabriel.sh identity-test /absolute/private/report-directory` runs strict per-file matching-image tests with real disposable PostgreSQL. Cases cover tenant/role/worker denials, concurrent retries, ciphertext/custody/provenance damage, missing/wrong keys, real audit privilege failures, export failure/reconciliation, intake confinement, quotas, CLI, upgrade preservation and DDL rollback. A separate checkpoint database is restarted, then its real dump and encrypted objects are restored into fresh locations. Counts, decryption, custody, task linkage, closure and revocations are checked. Keys, plaintext, private dumps and credential checkpoints stay outside retained artifacts. Prior runtime/foundation regressions remain mandatory.

Full C04 remains open: retention/legal holds/purge, external tamper anchors, remote storage, binary/large artifacts, browser provenance/collection, normalization/deduplication, assignments/timelines/reports, scoped memory, response/approval state and UI. These deferred features have no placeholder implementations. Component tests do not constitute human UAT, production shipment or autonomous attack detection. Independent review and pre/post-release UAT remain release gates.
