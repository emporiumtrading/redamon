# Independently retained custody checkpoints

This component captures a tenant case's immutable metadata and all current evidence custody heads, seals the snapshot with an independently held Ed25519 key, and checks those historical prefixes against the current database. It detects valid-looking history rewriting, removed anchored evidence and deletion of an anchored custody tail. It works after approved primary-content deletion because original metadata and custody are retained.

The trusted custodian retains the signed file, public-key identity and **latest accepted checkpoint digest outside the application/database administrator's control**. Verification requires both a supplied trusted public key and that external digest. Replacing a file or presenting an older valid signature fails against the latest trusted digest. Computing a fresh expected digest from the untrusted candidate file defeats rollback detection: never use that as the trust source. There is no automatic discovery of the latest checkpoint, external provider integration, WORM claim or enforcement of periodic checkpointing in this increment.

## Scope and authority

`CheckpointService.capture_checkpoint` requires a current owner/admin/analyst session, acquires the existing tenant/case lock, checks every custody chain and captures at most 64 evidence objects. It binds organization/case IDs, immutable case metadata, a fresh nonce, database capture time, evidence context hashes and each complete custody prefix's sequence/head. Schema and duplicate IDs/fields are strictly validated. Capture returns only metadata hashes and IDs; it never exports evidence bodies or signing keys. Successful capture and verification require transactional audit admission and a current human session at completion. Viewers may compare existing checkpoints but cannot capture; worker credentials cannot do either.

The offline `checkpoint-signer` image contains cryptographic/file code and the custodian CLI only. It has no database driver, application services, session access, provider credentials or evidence decryption keys. The runtime/test image does not gain a signing key or a signer volume. Deployment must preserve this authority separation: host both roles under one compromised administrator and they are not independent.

The signer attests to the supplied snapshot bytes. It does not independently inspect the database or prove that capture was honest. A trusted custodian must accept the intended tenant/case snapshot and retain the corresponding digest. Compromise before the first trusted capture, collusion with the signer, deletion of all external trust material or rollback of the custodian's accepted digest remain outside this protection.

## Operator workflow

Build images in Docker:

```bash
docker build -f gabriel/identity/Dockerfile --target production -t gabriel-identity:dev .
docker build -f gabriel/identity/Dockerfile --target checkpoint-signer -t gabriel-checkpoint-signer:dev .
```

Use the existing private identity Compose project and case-data profile for the following **case CLI arguments**. Supply the current Gabriel session using `--token-file /operator/human-session`, and explicitly mount the operator directory as shown in the case/evidence guide. Paths are inside the container; never mount the independent signing-key directory into case-data.

```bash
checkpoint-capture --case-id CASE_UUID --output /operator/snapshot.json --token-file /operator/human-session
```

Transfer the snapshot to the separately administered custodian directory. The examples below assume its absolute host path is `/srv/gabriel-custodian`; it must be private, owned by the selected container user, and have trusted parent directories. Run key generation once, retain the public-key identity independently, then seal each newly accepted snapshot into a new file:

```bash
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" -v /srv/gabriel-custodian:/custodian \
  gabriel-checkpoint-signer:dev keygen \
  --private-key /custodian/signing-key.json --public-key /custodian/trusted-public.json

docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" -v /srv/gabriel-custodian:/custodian \
  gabriel-checkpoint-signer:dev seal --snapshot /custodian/snapshot.json \
  --private-key /custodian/signing-key.json --checkpoint /custodian/checkpoint-001.json
```

The seal command returns `checkpoint_digest`, the SHA-256 of canonical signed-envelope JSON (excluding the output file's trailing newline). Retain that digest as the accepted receipt in the independent custody record. File writes are exclusive, mode 0600, fsynced and never overwrite existing outputs. On an unconfirmed write, inspect the partial output before using a new filename; key generation can leave one file if its second output fails. Reads reject symlinks, nonregular files, group/world-writable inputs, ambiguous JSON and oversized documents; private-key reads additionally deny any group/world permissions. Trusted parent directories and filesystem administration remain operator responsibilities.

Transfer only the signed checkpoint and trusted public file back to an approved read-only operator mount. Supply the independently accepted digest to the case CLI:

```bash
checkpoint-verify --case-id CASE_UUID --checkpoint-file /operator/checkpoint-001.json \
  --trusted-public-key /operator/trusted-public.json --expected-digest ACCEPTED_DIGEST \
  --token-file /operator/human-session
```

For signature/file verification without database access, the offline image also supports `verify --checkpoint ... --public-key ... --expected-digest ...`. Its result explicitly says `database_comparison: not_performed`.

## Meaning of a pass

A successful database comparison confirms only that the anchored case metadata, evidence contexts and historical custody prefixes still match the signed checkpoint. Valid later events and new evidence are permitted; new evidence is explicitly not covered until a new checkpoint is accepted. Case closure and primary-content disposition do not invalidate historical prefixes. Missing/tampered evidence bytes are not checked by this command; use the separate evidence integrity workflow for active content. Source authenticity, governance/hold/disposition/audit history, deleted unanchored later events, whole-organization completeness and trusted wall-clock timestamping are not established. The signer time is not a timestamp authority. A compromised database or application can lie before capture or comparison; independent comparison/monitoring against independently acquired snapshots is still an operational prerequisite.

This is a case-scoped operator mechanism. Automatic admission policies for closure/purge, periodic freshness checks, signer rotation/revocation and externally managed storage require further implementation and independent acceptance. A pass is not production approval, security/compliance equivalence, or evidence of live attack detection.

## Verification and recovery

Run `bash tooling/scripts/gabriel_identity_check.sh /absolute/private/report-directory` with Docker. The workflow builds the separate signer image, proves it excludes database drivers/application services, and executes strict per-file tests in the identity test image against disposable PostgreSQL. Tests use generated fixtures, actual signatures, real CLI/file operations and privileged SQL changes that remain internally valid but disagree with trusted checkpoints. Earlier retention, approval, case, identity, runtime and foundation regressions remain required.

Recovery retains signed checkpoints/public trust/digests separately from pg_dump, encrypted objects and decryption keys. The probe compares active and purged case checkpoints after restart and fresh database/object restore, then demonstrates detection of privileged valid rehash in the restored database. Private signer keys never enter the dump, app volume or retained CI artifacts. Source `92920453f2a5df637a2fc7a9602c3185b77313de` passed [hosted VM verification](https://github.com/emporiumtrading/redamon/actions/runs/39179949944): **398 passed, zero failures/errors/skips**, including 38 new checkpoint cases and the actual restart/restore/tampering probes. Exact evidence digest, commands and remaining gates are recorded in [the implementation ledger](GABRIEL_IMPLEMENTATION_STATUS.md). These component checks do not establish independent operational custody, human UAT or production readiness.

Rollback disables the new operator commands while retaining external checkpoints, trust receipts and existing data/keys. No schema migration or database rollback is required; existing schema 8 remains unchanged. Investigate any mismatch against preserved independent records rather than silently accepting a new baseline.
