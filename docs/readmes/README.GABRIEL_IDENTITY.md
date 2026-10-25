# Gabriel identity foundation — increment 3

The [case/evidence operator guide](README.GABRIEL_CASE_EVIDENCE.md) describes migration 5, encrypted artifact storage, custody, exports and recovery limits.

## Delivered scope

The `gabriel.identity` package provides PostgreSQL-backed organization accounts, memberships, password verification, opaque sessions, administrative role/password changes and a session-authenticated wrapper around the two existing local capabilities. It has an operator CLI and no listening HTTP/browser endpoint. This is part of C03 and GAB-003/GAB-004/GAB-005/P-T01; it does not complete every C03 or product release gate.

Passwords use salted Argon2id hashes. Usernames are normalized within an organization; the same username in another organization has separate credentials. Sessions contain 32 random bytes and a fixed version prefix. Only token digests, subject/organization identifiers, fixed audience, expiry and revocation state are stored. Sessions last one hour. Membership, user activity, role, expiry and revocation are read from the database on each authorized operation. Request-body fields cannot grant an organization, role or approval.

Owners can manage members in their organization. Admins can manage analysts/viewers, but cannot create/edit/reset owners or other admins. Analysts/viewers cannot administer identity. Membership changes and password reset revoke the target's existing sessions. A transaction-scoped organization lock serializes administration and protects the last active owner from concurrent demotion. Composite foreign keys bind users, memberships and sessions to the same organization.

Login admission is stored in PostgreSQL: five attempts per organization/normalized login in a fifteen-minute window, shared by service instances. Successful login and authorized password reset clear the counter. Invalid credentials and throttled attempts produce the same public denial. This is an account-level guard; a future internet-facing endpoint also needs origin/IP limits, MFA/SSO design, request quotas and transport/session protections before exposure.

## Database authority and audit

Migration/provisioning uses a separate owner connection available only to the operator service. The runtime database role cannot own the schema, act as superuser, create roles/databases, bypass RLS, replicate, or rewrite/delete/truncate the audit table. Runtime startup/operations reject these elevated configurations. Queries use bound parameters, fully qualified tables, and statement/lock/connect timeouts.

Identity mutations and successful session creation commit with their audit record in the same transaction; an unavailable audit insert blocks the operation. Failed login admission counters are separately committed before account locking to prevent concurrent attempts from bypassing the shared budget. Audit rows contain fixed event names and identifiers, not passwords, raw session tokens, DSNs or arbitrary request bodies.

These grants protect audit records from the runtime role. Database owners, infrastructure administrators and backups remain privileged; this is not tamper-proof storage against those actors. External anchoring, retention, key management and immutable evidence storage remain C04/operations work. Provider/connector secret encryption and rotation are also not implemented here.

Tenant enforcement is at the identity-service boundary with composite relational constraints. Runtime SQL credentials are private trusted-service credentials, never browser/user credentials. This increment does not claim database RLS protection against a compromised identity-service credential or provide general SQL access to callers. Future case/graph/export/job surfaces need their own enforced scope and negative tests.

## Local operator setup

Run on a Docker-capable host. Keep this composition separate from both the legacy stack and the network-free local-inspection profile.

```bash
export GABRIEL_IDENTITY_SECRET_DIR="$(mktemp -d)"
bash gabriel.sh identity-prepare "$GABRIEL_IDENTITY_SECRET_DIR"
bash gabriel.sh identity-build
bash gabriel.sh identity-up
bash gabriel.sh identity-migrate
bash gabriel.sh identity-admin provision --organization-name 'Your organization' --username owner
# Provision reports organization/user IDs; password entry is hidden and confirmed.
bash gabriel.sh identity login --organization YOUR_ORGANIZATION_UUID --username owner
bash gabriel.sh identity whoami
```

Login returns a new raw session token once to the caller's stdout. Treat that output as a credential: do not paste it into source, GitHub, shared logs or reports. Other commands prompt for a session token, or accept `--token-file` pointing to an operator-protected file. Password-bearing commands prompt by default; `--password-file` supports bounded private-file automation. Password/token values are not command-line flags or built-in defaults. `identity members`, `create-member`, `set-membership`, `reset-password`, `logout` and `execute` have CLI help.

The preparation utility refuses repository paths and nonempty directories; it never replaces existing deployment credentials. It creates a host directory with mode 0700. Files are read-only 0444 so each non-root container can read its explicitly mounted secret; the private parent directory restricts host traversal. Preserve that parent permission and keep backup handling private. The runtime service mounts only its app DSN; the operator service mounts only the owner DSN. The test service deliberately receives both for isolated fault/privilege verification.

PostgreSQL has no published host port and sits on an internal Docker network with the identity containers. Credentials in these local DSNs use that isolated network. The composition is a local development/verification profile; remote database access requires separately reviewed TLS verification and deployment secret management. No public login API is exposed.

The named volume persists database state. Secret preparation and PostgreSQL initialization are first-install steps, not a password-rotation mechanism. Replacing secret files does not rotate an existing database role. Do not discard the volume or owner credentials to repair an authentication problem; an upgrade/rotation/recovery procedure is required.

## Migrations and verification

Schema migration is transactionally locked, versioned and checksum-checked. Reapplying the same version is idempotent; changed migration content is refused. Subsequent schema changes need a new reviewed migration, backup and recovery strategy. No destructive automatic migration/reset is provided.

`bash gabriel.sh identity-test /absolute/path/to/evidence` creates fresh secrets and a unique disposable project, starts a real PostgreSQL server, migrates, runs the matching image's unit/integration cases, restarts PostgreSQL and checks persisted account/membership/session state and revocation. It then removes only its own disposable database project/volume. Checkpoint tokens and secret files are outside the evidence directory. Reports contain counts, sanitized rendered deployment and source/image/version identifiers. Missing Docker/required tests block verification; no host pytest fallback is used.

The VM workflow also repeats the runtime/inventory and foundation regressions. Automated operator/contract tests are not human UAT or production verification. MFA/SSO, browser pairing, REST/stream/job scopes, encryption/rotation of provider secrets, disaster restore, durable cases and response authority remain separate requirements.

## Service identity — increment 4

These are **internal Gabriel worker credentials only**. They do not log into security consoles or external systems. Engineers authenticate to those systems manually; the future extension uses only approved authenticated browser tabs, pauses at authentication walls and never extracts/replays vendor sessions. Named security vendors are examples, not dependencies. Gabriel user sign-in/pairing/internal authorization must not be confused with external-system login.

Schema version 2 adds service grants without rewriting version 1. Run `identity-migrate` before using the upgraded runtime. Migration verifies every applied checksum, rejects unknown/gapped histories and applies outstanding versions in one transaction. The tests exercise actual v1-to-v2 upgrade and failed-migration rollback; this is not a backup/restore procedure or a rolling-upgrade compatibility guarantee.

An owner/admin can issue a service credential for one task UUID and an explicit subset of `capabilities.list` and `evidence.hash`. Its issuer, audience and resource are server constants: `gabriel-identity-service-v1`, `gabriel-local-worker-v2`, and `local-inspection-v1`. Current `gbs2_` tokens are 32 random bytes with only SHA-256 digests stored; they cannot serve as human sessions or create other grants. Version-1 tokens were retired by schema version 4. Lifetime defaults to 900 seconds, bounded to 60–3600 seconds. There are at most 100 active grants per tenant. Service listing returns the latest 100 rows without raw credentials or digests.

Schema version 4 now requires a persisted active task, caps grant expiry to that task and revokes old unbound grants. Follow [the task and migration guide](README.GABRIEL_TASKS.md). Worker execution also requires a stable request UUID for receipt-based retries.

```bash
bash gabriel.sh identity task-create --name 'Local review' --operation evidence.hash
# Use the returned task UUID below.
bash gabriel.sh identity issue-service --name 'Local evidence worker' \
  --task-id YOUR_TASK_UUID --operation evidence.hash --ttl-seconds 900
# Prompts for an owner/admin session. New service token is printed ONCE to stdout.
# Securely hand it to the intended worker; never record it in Git or shared logs.
bash gabriel.sh identity services
bash gabriel.sh identity service-execute --token-file /private/worker-token \
  --task-id YOUR_TASK_UUID --request-id YOUR_REQUEST_UUID
# Supply the existing versioned capability request on stdin.
bash gabriel.sh identity revoke-service --grant-id YOUR_GRANT_UUID
```

Service execution reads tenant/task/scope/expiry/revocation and current issuer activity/privileged membership from storage, not request claims. Issuer membership changes and password reset revoke their outstanding service credentials; explicit revocation is tenant-admin scoped. Human logout ends that session, not separately issued delegations: revoke those explicitly or let their short lifetime expire. All tenant admins can revoke/list tenant grants. This is deliberate tenant administration, not one-admin/one-service ownership isolation.

Issuance, revocation and successful local execution require a committed audit event. Audit failure withholds execution results or rolls back the mutation. Organization locks use the same ordering as human operations. A local computation already admitted may finish before a concurrent revocation commits; all later admissions deny. No externally mutating work is performed. No model decision can widen scope.

Task UUIDs now identify server-created persisted local task records with deadlines, operation scope and step budgets. This supersedes increment 4's correlation-only binding. There is no external response, connector, browser, network endpoint, workload attestation or general-purpose service identity platform here. Token rotation means issue a replacement then revoke the old grant; request receipts remain bound to their original grant. Safe distribution and transport belong to later deployment work. Service SQL credentials remain trusted backend credentials, never credentials given to workers.

## Model-provider secrets — increment 5

The optional vault profile adds separately mounted encryption keys, authenticated ciphertext, tenant-scoped resolution, transactional key rotation and a component backup/restore rehearsal. Follow [the vault operator and recovery guide](README.GABRIEL_PROVIDER_VAULT.md). Schema version 3 is required; no existing plaintext legacy settings are imported automatically. Earlier descriptions of missing provider encryption describe the previous increment; the new vault still has no deployed model route or external login capability.

Dependency/API references verified for this increment: [Psycopg 3.3.6](https://pypi.org/project/psycopg/3.3.6/), [argon2-cffi 25.1.0](https://pypi.org/project/argon2-cffi/25.1.0/), and [password verification/rehashing](https://argon2-cffi.readthedocs.io/en/stable/howto.html). The PostgreSQL review applied least privilege, composite key/index coverage, consistent lock ordering and short bounded transactions from the Postgres best-practices skill. Dependency choice alone is not security certification.
