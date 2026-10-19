# Evidence encryption rollover and live-key retirement checks

Schema 10 adds immutable tenant encryption epochs, prepared rewrap attempts and append-only result receipts. An original evidence record, content hash, AAD, acquisition hash and custody chain remain unchanged. Completed encryption bindings select the actual ciphertext key separately from the original historical key ID. Existing signed custody checkpoints therefore remain usable after rollover. Evidence is re-encrypted with authenticated AES-GCM under the new key; this is not merely relabeling metadata.

Use a new purpose-marked evidence keyring generated outside Git, retaining old keys during transition:

```bash
python3 tooling/scripts/gabriel_evidence_keys.py /private/new-evidence-keys --from-file /private/previous-evidence-keys/keyring.json
```

Mount that new configuration through the existing case-data evidence secret. Stop older binaries before rollover. Current code with a stale generation fails content verification/writes; database insert/update guards reject older SQL lacking the current generation context. Already re-encrypted ciphertext also fails decryption under an old runtime's original key. These boundaries do not revoke ciphertext already read/cached, protect against compromised filesystem/database administration, or prevent an older binary from reading a still-unrotated file during transition.

The following are case CLI arguments with the private Compose project, operator session mount and evidence volume described in the case/evidence guide. No external-system login or vendor API is involved:

```bash
evidence-key-activate --token-file /operator/human-session
evidence-rewrap-prepare --evidence-id EVIDENCE_UUID --token-file /operator/human-session
evidence-rewrap-execute --attempt-id ATTEMPT_UUID --token-file /operator/human-session
evidence-rewrap-get --attempt-id ATTEMPT_UUID --token-file /operator/human-session
```

Activation is owner/admin only and tenant-scoped. It checks required existing keys, fingerprints, custody and readable live objects before advancing exactly one generation. It denies pending/quarantined/disposition-unresolved evidence and prepared rewraps; completed primary-content purges need no missing bytes. Existing key IDs cannot acquire different fingerprints or be reactivated in that tenant's epoch history. At most 4096 evidence objects are examined per activation. The first current-code acquisition records its initial epoch; migration creates no invented epoch for older records. Activation does not mean that every object has been re-encrypted.

Preparation commits a durable intent before replacing any bytes. It verifies the source, records exact immutable AAD context and source/target keys and admits one unresolved attempt per artifact. At most 64 rewrap attempts are retained per artifact. Ordinary reads/exports and purge validation block while a rewrap is prepared. Hold placement reports that verification gap truthfully; holds remain active and encryption changes preserve original bytes/hashes. No retained original metadata or custody event is edited.

Execution authenticates the source, writes/fsyncs a new encrypted temporary file, reads it back, revalidates the source and live caller/epoch/audit admission, atomically replaces the original ciphertext and fsyncs the directory. Completion requires authenticated target read-back and a transactional result receipt/audit. Temporary names are server-generated, symlinks/corrupt sources deny, and no plaintext is written to a temporary file. The file replacement cannot roll back with a failed database transaction: the previously committed prepared intent remains and the caller receives failure.

## Interruption and recovery

```bash
evidence-rewrap-reconcile --attempt-id ATTEMPT_UUID --token-file /operator/human-session
```

Reconciliation never encrypts or replaces a file. A verified target ciphertext completes the original intent; a verified original ciphertext aborts it and restores ordinary source reads. Corrupt, missing or ambiguous/unavailable-key content remains unresolved. Repeating a completed reconciliation verifies the current actual binding and original result. Preserve temporary encrypted files and both required keys after an unclean process/filesystem interruption until the original attempt is reconciled. Do not delete a prepared row or invent a success receipt.

Keep coherent database/object backups and independently retained old and current key files. A historical pre-rollover ciphertext snapshot still requires its old decryption key, even if current live references are clear. The hosted recovery probe preserves completed and interrupted replacements through actual database restart and fresh dump/object restore; it checks target-only live decryption, old-runtime denial and unchanged custody/checkpoint validation. Keys and private checkpoint material remain outside retained CI artifacts.

## Retirement checks and limits

```bash
evidence-key-retirement-check --key-id OLD_KEY_ID --token-file /operator/human-session
```

This is a bounded tenant-live report, considering current encryption bindings, completed purges, active epoch and unresolved attempts. `tenant_live_ready` does not include other tenants or backups. For a separate read-only global live-database report, run the migration-operator image with only its existing owner DSN secret and override its entry point to:

```bash
python -m gabriel.identity.key_retirement --key-id OLD_KEY_ID
```

The global report requires schema-owner/migration authority and uses a repeatable-read, read-only database snapshot. It reports live references, active tenants and prepared attempts without evidence bodies, tenant listings or key bytes. Both reports explicitly return `physical_key_deletion_authorized: false`. Neither command deletes a key, automatically retires backups, inventories external exports, or certifies an independent backup retention decision. A clear live report can support reducing a tenant's current ring after all applicable tenants are reconciled, while historical keys remain separately retained for old backups. Plan changes can occur after a read-only report: stop conflicting operations and recheck the full operational inventory before changing mounts.

Rollback keeps schema 10, encryption manifests, guards, receipts, original metadata, ciphertext snapshots and all required key versions. Older applications cannot interpret new encryption bindings; disable dispatch and restore a coherent compatible application/database/object/key snapshot, then reconcile before resuming. Never drop manifests to force an older runtime to read new ciphertext or discard an old key because the live report is clear.

Verification uses strict matching-image PostgreSQL/filesystem/cryptographic/CLI regressions and restart/restore probes. Hosted counts/source/artifact evidence are pending in the implementation ledger. Independent security review, operational backup/key custody acceptance and full product UAT remain open.
