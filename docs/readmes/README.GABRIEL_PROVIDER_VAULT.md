# Gabriel model-provider vault — increment 5

The vault stores model-provider credentials as AES-256-GCM ciphertext in PostgreSQL. A separate mounted key file supplies encryption keys; PostgreSQL, the identity process and the migration process do not receive that file. This implements part of C03 / GAB-004 / T05. No external-console credentials, browser login, model request or legacy plaintext import is added. The engineer continues to authenticate to security consoles manually.

## Authority and storage

Only a current Gabriel owner/admin session can store, list metadata, resolve for trusted backend code, revoke or rotate tenant credentials. Local worker tokens remain restricted to their existing operations and cannot access this vault. Every value resolution or change requires a committed audit event. No plaintext read/export command exists in the CLI. `ProviderVault.resolve_for_backend` returns a redacted `ProviderCredential`; trusted in-process consumers explicitly call `reveal()`. This interface is not exposed to browser pages, HTTP callers, tools or models. Python process memory is not a protected enclave and cannot be guaranteed zeroized.

Each ciphertext authenticates its purpose, organization, record ID, provider name, revision and key ID. Every encryption uses a fresh random 96-bit nonce. The database also rejects nonce reuse among current rows under one key ID. This prevents cross-record substitution without the encryption key; it does not independently detect a privileged administrator restoring an entire old database snapshot. Ciphertext hashes are not evidence of provider credential validity.

Metadata includes provider slug, record ID, revision, timestamps, revocation and key ID. There is a fixed `model-provider-v1` purpose and at most 64 provider records per tenant, including revoked tombstones. Values are 1–8192 UTF-8 bytes without control characters. A provider slug is a label, not a configured network destination or proof that a provider integration works.

Keys are 256 random bits with immutable IDs. The database stores SHA-256 fingerprints to reject changed bytes under an existing ID and an active key/generation per organization. It stores no encryption key. The runtime role cannot update/delete/truncate key-registry or audit rows. SQL credentials are trusted backend credentials; tenant policy is enforced in the service and this is not database RLS against a compromised backend credential. An attacker with both application access and mounted keys can access values; encryption does not protect a compromised vault process.

## Setup and use

First complete the identity setup in [README.GABRIEL_IDENTITY.md](README.GABRIEL_IDENTITY.md). Upgrade the image and apply schema version 3 before using the vault. The original version-1/version-2 migrations remain unchanged.

```bash
key_parent="$(mktemp -d)"
export GABRIEL_PROVIDER_KEY_DIR="$key_parent/v1"
bash gabriel.sh provider-keys-prepare "$GABRIEL_PROVIDER_KEY_DIR"
bash gabriel.sh identity-build
bash gabriel.sh identity-migrate
bash gabriel.sh provider-secrets put --provider your_model_provider
# Prompts for Gabriel owner/admin session, then the model-provider credential.
bash gabriel.sh provider-secrets list
```

The preparation utility creates a new external directory only, with parent mode 0700 and a read-only key file. It refuses existing directories and paths within the repository. Files are 0444 for the non-root container's explicit read-only secret mount; keep the host parent private. Key files are not environment values, command-line values, Git content, container-image layers, database rows or evidence artifacts. `--token-file` and `--secret-file` accept operator-protected bounded files; secret values are never command-line arguments or printed by vault commands.

`GABRIEL_PROVIDER_KEY_DIR` is independent of the database secret directory. Ordinary identity/migration operations mount no encryption keys. `provider-secrets` mounts only the app DSN and keyring; its private network permits database access and has no public ports. The existing network-free local runtime has no key mount. This is a local container profile; a production secret manager/KMS, deployment permissions and remote TLS remain deployment work.

## Encryption-key rotation and retirement

```bash
bash gabriel.sh provider-keys-prepare "$key_parent/v2" \
  --from-file "$GABRIEL_PROVIDER_KEY_DIR/keyring.json"
export GABRIEL_PROVIDER_KEY_DIR="$key_parent/v2"
bash gabriel.sh provider-secrets rotate
bash gabriel.sh provider-secrets list
```

The replacement file retains old keys, adds a newly generated active key and increments its generation. Roll out that same reviewed key configuration to every vault process before resuming writers. `rotate` verifies and re-encrypts every active value for the authenticated tenant in a single transaction, then changes its active key/generation and records audit events. A missing old key, corrupted record, audit failure or storage failure rolls back the whole operation. The organization lock uses the same ordering as identity administration. A stale process cannot put/resolve under the old generation or rotate the tenant backwards. Repeating the same successful rotation verifies records and reports zero rewrapped values.

Rotation is tenant scoped. Repeat it with an authorized session for every tenant sharing that key file, verify each result, and restart/reconfigure consumers to use the accepted generation. Old-key removal is a separate operator change: keep only keys needed by all remaining database rows and all retained backups, retain the current generation/active ID, and validate the reduced file in a restricted scope before rollout. The preparation utility intentionally retains keys and stops at 16; it never silently discards a recovery key. Restoring a reduced key file after an error is different from rolling the database generation backwards.

Database backups contain ciphertext, account hashes and session digests. Back up keys separately under access control and test their recovery; losing the required key prevents recovery of its values. Old backups may require retired keys even after current rows have been re-encrypted. Keep those keys in restricted recovery storage for the backup retention period. Do not delete a working database or overwrite original keys to fix a configuration error.

Encryption-key rotation does **not** rotate/revoke the provider's own credential. To replace that credential, obtain a new value through the provider's human-controlled process, `put` it, validate the real provider integration when implemented, then revoke the old value at the provider. `revoke --provider name` blocks local resolution and clears current-row ciphertext/nonce/key references; prior backups and provider-side validity are unaffected.

There is no automatic migration of RedAmon's plaintext provider settings. Do not connect the legacy application to the vault or assume those old values are secured by this increment. A later migration needs an inventory, controlled import, verification and reviewed removal from legacy stores, logs and backups.

## Verification and remaining gates

Run `bash gabriel.sh identity-test /absolute/path/to/evidence` on a Docker-capable host. Matching-image tests exercise real PostgreSQL and cryptography, tenant/role denials, modified ciphertext/context, key substitution, rotation/downgrade/concurrency, missing old keys, audit-failure rollback, private file preparation and CLI redaction. Migration regressions preserve prior identity/service behavior. No real provider keys or external targets are used: all credentials are generated disposable fixtures.

The VM gate additionally saves a private `pg_dump` outside the artifact directory, restarts PostgreSQL, verifies decrypted persistence and revocation, restores the dump to a fresh database in the same disposable cluster, compares row counts and verifies recovered values using the separately mounted keys. Dump/checkpoint/key files are excluded from published evidence. This is a component backup/restore rehearsal; full-system disaster recovery, evidence-store reconciliation, production KMS and human UAT remain open. The gate repeats the runtime/inventory and foundation regressions. Test counts and source/image evidence belong in [the implementation ledger](GABRIEL_IMPLEMENTATION_STATUS.md).

Dependency references checked for this implementation: [cryptography 50.0.2](https://pypi.org/project/cryptography/50.0.2/) and its [AESGCM authenticated-encryption API](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/). The PostgreSQL review informed restricted grants, indexes and transaction/lock ordering. Dependency choice and automated tests alone do not certify production security.
