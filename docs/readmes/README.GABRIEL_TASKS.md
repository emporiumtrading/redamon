# Gabriel durable investigation tasks — increment 6

This increment connects worker authorization to real PostgreSQL task records. It implements part of C03's verified job/resource scope and C04's durable task/idempotency foundation (GAB-003/GAB-005/GAB-006/GAB-028/GAB-037). Each task is tenant scoped, identifies its authenticated creator, permits an explicit subset of the two existing local capabilities, and has a deadline and committed-step limit. There is no background scheduler, browser operation, case store or external response here.

## Operator flow

Apply schema version 4 with the upgraded identity image. Earlier migration files remain unchanged. **The migration revokes existing unbound service grants**, records their revocation in audit, and does not invent task records for their old correlation IDs. Human sessions, identity records and encrypted provider values remain intact. Create new tasks and issue new grants after migration; old code that cannot enforce task binding must not run against this schema. This is a reviewed migration boundary, not rolling-upgrade compatibility.

New grants use `gbs2_` tokens and the fixed `gabriel-local-worker-v2` audience. Previous worker code accepts only the version-1 prefix/audience, so it cannot consume a new grant while ignoring task limits. Version-1 rows are retained only in revoked state. Worker issuance/execution must be upgraded together.

```bash
bash gabriel.sh identity-build
bash gabriel.sh identity-migrate
bash gabriel.sh identity task-create --name 'Local evidence review' \
  --operation evidence.hash --ttl-seconds 900 --max-steps 20
# Record the returned server-generated task ID.
bash gabriel.sh identity issue-service --name 'Local worker' \
  --task-id YOUR_RETURNED_TASK_UUID --operation evidence.hash --ttl-seconds 900
# Securely supply the returned service token to the intended local worker.
bash gabriel.sh identity service-execute --token-file /private/worker-token \
  --task-id YOUR_RETURNED_TASK_UUID --request-id YOUR_REQUEST_UUID
# Supply a normal versioned capability request on stdin.
bash gabriel.sh identity task-get --task-id YOUR_RETURNED_TASK_UUID
bash gabriel.sh identity tasks
bash gabriel.sh identity task-cancel --task-id YOUR_RETURNED_TASK_UUID
```

Human commands prompt for the Gabriel session unless an operator-protected `--token-file` is provided. Secret values are not command-line arguments. The existing issuance command prints the new raw service token once to its authorized caller; keep it out of Git, shared logs and artifacts. Task commands return metadata only. `task-complete` records an explicit completion decision; it is not proof of a detected threat, verified defense or completed incident response.

## Authorization, limits and states

Owners/admins/analysts can create tasks. Viewers can inspect tenant task metadata but cannot create or end tasks. Analysts can end only tasks they created; owners/admins can end any tenant task. Only owners/admins issue worker grants, including grants for analyst-created tasks. Worker tokens cannot create, list, inspect or end tasks through human management commands.

Task scope is fixed to `local-inspection-v1`, with `capabilities.list` and/or `evidence.hash`. Grant operations must be a subset of the task's stored operations. Grant expiry is capped at the task deadline. Requested task/grant lifetimes are 60–3600 seconds; a newly issued grant may have less remaining time because the task is already running. Successful committed steps are bounded to 1–1000 (default 20). At most 100 active, unexpired tasks per tenant may exist. Task listing returns the latest 100 records; data retention and pagination remain later operations work.

Stored states are active, cancelled, completed and exhausted. Deadline expiry is enforced at every worker admission and reported as expired for otherwise-active tasks; it does not require a background timer to update rows. Used steps and exhaustion persist. Creator activity/membership is rechecked as well as the issuing administrator's current authority. A creator demoted below analyst or disabled cannot continue delegating work through the task, even when another active admin issued its grant. Metadata exposes `creator_authorized` so that condition is visible.

Cancellation/completion revokes all bound grants in the same audited transaction. Terminal tasks cannot be reopened; create a new task after review. The common organization lock serializes admission with cancellation, membership changes and revocation. A local computation admitted before cancellation may finish first; subsequent admissions deny. Direct human CLI inspection/hashing remains available outside worker tasks and grants no external authority.

## Request receipts and retry behavior

Every worker execution requires a UUID request ID. Persist one ID per logical request and reuse it on a retry. The service hashes canonical JSON (including all request fields/arguments) and stores a small response receipt keyed by organization/task/request. It stores no request content or token in the receipt. Response, used-step increment, exhaustion transition and audit admission commit together. Storage/audit failure withholds the result and rolls back those writes.

The same authorized grant and request ID with the same payload returns the recorded response, including after step exhaustion, without spending another step. Changed payloads or a different grant under that ID are conflicts. Concurrent duplicate requests commit one receipt and one step. Every replay still rechecks token, current issuer/creator authority, task cancellation/completion/deadline and operation scope, and requires an audit event. Revocation or expiry blocks cached replay too.

Receipt rows are append-only for the application role; privileged database owners remain trusted. These guarantees cover the current local computations. A computation interrupted before commit can be recomputed after retry; no external effect exists to reconcile. This does not promise exactly-once external actions or implement a response queue, approval service, dispatch/unknown-effect reconciliation or model-cost budget. Failed/denied requests are not successful committed steps; future autonomous loops also need bounded attempts, elapsed time and cost under C07.

Task IDs and request IDs confer no authority by themselves. They do not authorize console login, new tabs, browser permissions, external network destinations, model-provider secret access or offensive tools. Chrome/Brave selected-tab binding, human-only external login, cases/evidence and the remaining specialist workflows retain their own acceptance gates.

## Verification and recovery

`bash gabriel.sh identity-test /absolute/path/to/evidence` uses real PostgreSQL and matching per-file Docker tests. Coverage includes unknown/foreign tasks, overbroad grants, role changes, deadline/budget limits, concurrent duplicates and overspend, request conflicts, cancellation races, audit rollback, CLI flow, receipt privileges and interrupted schema-v4 migration. Earlier migration tests now explicitly account for revocation of old unbound grants.

The existing restart/backup/restore probe now creates a task and receipt before the checkpoint, replays the receipt after database restart and after restore, confirms the used-step count stays at one, and verifies cancellation prevents further use. Task/receipt tables enter backup row-count reconciliation. Credentials and checkpoint files remain outside artifacts. Full-system recovery, accepted browser workflows, human UAT and production deployment remain open. See [the implementation ledger](GABRIEL_IMPLEMENTATION_STATUS.md) for executed counts and evidence.
