# Durable local coordinator

Partial C07, GAB-006/022/025/033/037/038/039/044/045. This component advances the fixed local plan; it does not implement the model/network worker, autonomous browser navigation, full incident investigation or response. Its `local_plan_complete` state refers only to its admitted local steps. No model call, credential retrieval, command execution or arbitrary tool dispatch occurs.

## Acceptance and rollback before release

Accept this component only after its real-PostgreSQL tests and existing image/recovery/browser regressions pass at a recorded source. Required behaviors: idempotent creation; two-step maximum and fifteen-minute maximum; exact case/evidence binding; current creator/caller authority before and after execution; Stop/expiry; concurrent claims; audit rollback; interrupted specialist completion with no duplicate specialist record; tenant/case isolation; and actual restart and fresh dump/restore retaining partial claims/results/Stop. Matching-image and native ARM64 automated acceptance passed at the source recorded below. Human UAT and independent review remain separate.

Schema 17 is additive and append-only for the application role. Rollback stops callers/workers, retains coordinator history and restores the prior image. Do not delete migration 17, rewrite previous migration checksums or claim that an older binary can perform automatic migration downgrade. No external effect or model charge needs reversal because this module cannot dispatch either.

## Bound plan and source set

The only plan is `local-coordinator-v1`: step 1 is an evidence metadata inventory; step 2 is the already-implemented local telemetry-health specialist. An engineer may set the maximum to one or two steps and a lifetime from 60 to 900 seconds. The case permits at most 128 retained plans. There is no model-selected operation, task, URL, query or script. Inventories disclose unverified source authenticity and unchecked content integrity. Telemetry results keep their existing partial/historical scope and do not decide attacker status.

Creation captures at most 64 ready, undisposed evidence records. Composite foreign keys bind each to the plan's organization/case, and a stable digest binds the complete selected set. Every advancement compares current IDs and digests with that set before executing and before recording completion. Added evidence, changed digests, unavailable objects or disposition activity stop continuation; the engineer must create a new scoped plan. This is not content decryption or proof of source truth. Browser health is sampled separately by the specialist and remains an individually timed partial observation.

## Durable claims and recovery

Plans, sources, steps, claims, receipts and Stops live in PostgreSQL. Each step has one stable request UUID. Only idempotent local operations are admitted: the existing specialist protocol reuses that UUID after interruption. Concurrent calls can repeat local sampling, but only one specialist record and one coordinator receipt are committed. This is not an exactly-once protocol for external effects and must never be reused for containment, browser actions or paid inference.

The creator must still be an active owner/admin/analyst. Advancement requires a current authenticated session belonging to the creating analyst or a current owner/admin. A demoted creator blocks continuation even by an administrator; an administrator can stop the old plan and create a new one. Stop persists and cannot be cleared. A revoked caller session cannot finalize a receipt; a new valid engineer session must explicitly resume allowed work. Expiry, case closure, source changes and authority loss discovered after local computation leave an unfinished claim, never a success receipt. Local work may have completed before an interrupted receipt: replay preserves that history honestly.

Status retrieval is historical and labels `current_source_authority_checked: false`; reading it grants no current permission. `model_enabled: false`, `external_actions_enabled: false` and `incident_assessment: not_performed` stay explicit. Source authority is checked during advancement, not inferred from a historical status response. Models are not required for these two deterministic operations. Existing model budget reservations remain a separate dependency for a future admitted network worker.

## Operator CLI

After standard identity/evidence-key initialization, use the existing private session prompt or protected `--token-file` option:

```
./gabriel.sh case-data coordinator-begin --case-id CASE_UUID --request-id REQUEST_UUID
./gabriel.sh case-data coordinator-get --run-id RUN_UUID
./gabriel.sh case-data coordinator-next --run-id RUN_UUID
./gabriel.sh case-data coordinator-stop --run-id RUN_UUID
```

`coordinator-next` runs at most one local step. There is no unattended background daemon in this increment. The workbench exposes case-scoped plan history, creation, one-step advancement, stored receipts, telemetry assessment links and Stop under the existing live session and same-origin form boundary. An API or CLI contract alone is not a complete engineer onboarding flow. Do not put a session token or provider key on a command line or in source control.

## Model qualification remains distinct

An unavailable route is not a poor-quality result. Gemini's required Vertex route was unavailable at the recorded checkpoint, so it could not complete the approved probe; its defensive quality is unmeasured. GPT-4.1 mini/Azure passed one real generated-data connection/contract probe, not a reviewed detection benchmark. Qwen3.5-35B-A3B and Mistral Small 3.2 are additional currently listed comparison candidates, not admitted models. Each exact route/model/prompt/redaction/compression configuration requires its own privacy checks, actual evaluation corpus, human claim/decision review, cost/latency assessment and release admission. Generic benchmark scores and presence in OpenRouter's catalog do not supply Gabriel acceptance evidence.

Model catalog references retrieved 20 October 2026: https://openrouter.ai/openai/gpt-4.1-mini , https://openrouter.ai/qwen/qwen3.5-35b-a3b , https://openrouter.ai/mistralai/mistral-small-3.2-24b-instruct . Route policies are endpoint-specific: https://openrouter.ai/docs/guides/features/zdr . No new paid calls or broader egress are authorized by this document or by the local coordinator.

## Recorded automated acceptance

Source `e47ef7c43acf12edd415a7b78501b0ff03af38f3`, tree `896ff49705dc99ff6ac5fd38ca679f68d6f096f2`, passed the PR checkout on 20 October 2026. Both native ARM64 [run 39467254107](https://github.com/emporiumtrading/redamon/actions/runs/39467254107) and x86 [run 39467253766](https://github.com/emporiumtrading/redamon/actions/runs/39467253766) executed **747 component + 49 runtime + 21 foundation = 817 tests per architecture**, with zero failures, errors or skips. Each also completed real PostgreSQL restart and fresh pg_dump/pg_restore checks: partial coordinator claims, source binding, receipt replay without duplicate specialist work, and Stop survived both recovery paths. Image checks denied all 80 discovered inherited executable names and excluded inherited scanner/test dependencies. Browser regression [run 39467253962](https://github.com/emporiumtrading/redamon/actions/runs/39467253962) passed separately.

CI reported ARM64 artifact `12286445755` ZIP SHA256 `1f7b5ea7a0dd4ee13192ba08df247b5c04c94545a225a9ccaf676395746ab251` and x86 artifact `12286970397` ZIP SHA256 `959f9f7f576716aec3854a697bed2f933d305cc6605b56114a460c20159611ef`. These are runner-reported upload digests, not independently downloaded hashes. Retention is fourteen days. The live provider job skipped intentionally on this branch; this result adds no model-quality evidence or production admission. Human UAT, independent review, a qualified model/network worker and workbench integration remain open.

## Workbench controls

Open a case, then **Local investigation plan**. **Create local plan** captures the current evidence set and creates the fixed two-step, fifteen-minute plan; it does not execute either step. **Run next local step** advances only the step displayed when the form was rendered. Replaying that same form cannot advance the next step. The screen shows completion receipts and an evidence inventory or link to the telemetry assessment, with historical/partial coverage clearly stated. The history lists up to 32 most recent plans and discloses omitted older plans. GET views do not dispatch work.

**Stop this plan** persists an irreversible stop for that plan. Local steps run synchronously; a running local computation may finish before the workbench processes a Stop request. Backend checks still prevent a receipt if another authorized caller stops the plan during computation. No external effects or paid calls are possible. Expired, stopped and authority-lost plans cannot advance. Closed cases cannot create or advance plans, but an authorized controller can still stop a retained plan.

Viewers may read historical metadata but have no mutation controls. Owners/admins control plans in their organization; an analyst controls only plans they created. Route case IDs must match the actual plan case before mutation. Cookie, current session, CSRF, exact origin and exact form fields are required; source/creator/caller authority is independently rechecked by the service. Adding evidence returns an actionable conflict instead of silently broadening the plan. A page view does not attest current source authority. No automatic polling, background investigation or AI worker is enabled.

This workbench increment adds no schema migration. Rollback uses the preceding image while retaining schema-17 history. Its new matching-image HTTPS, real PostgreSQL and native Chrome/Brave journeys passed at the source recorded below; historical coordinator results above remain separate. Independent review and human UAT remain open.

## Workbench automated acceptance

Corrected source `207954a297dcc8443088fd9ad8b677ac30b89275`, tree `2c8abd4f3fee3264e4839579778c173ff0be26a9`, passed [x86 39514615051](https://github.com/emporiumtrading/redamon/actions/runs/39514615051) and [native ARM64 39514615027](https://github.com/emporiumtrading/redamon/actions/runs/39514615027): **769 component + 49 runtime + 21 foundation = 839 tests per architecture**, zero failures/errors/skips. These are the same cases on two architectures. The component count includes 49 actual HTTPS workbench cases and 21 coordinator cases. Both jobs completed actual PostgreSQL restart and fresh dump/restore, preserving partial coordinator claims, source binding, receipt replay without duplicate specialist work, and Stop. Isolated software passed 43 (a subset, not an additional suitability evaluation); the live provider job intentionally skipped. Separate runtime 39514615070 passed.

[Browser run 39514615049](https://github.com/emporiumtrading/redamon/actions/runs/39514615049) passed **40 checks each in Chrome for Testing and Brave**, including plan creation, both local steps, receipt link and Stop retained after reload. Downloaded ZIPs independently matched SHA256:

| Artifact | ID | Independently checked ZIP SHA256 |
| --- | --- | --- |
| x86 component/recovery | 12307936609 | fa06fa911a20e8cacb5c4d186a82ed6c95834103a70f12a8bac2fcaaac755316 |
| ARM64 component/recovery | 12307373652 | 8ad65d61edce3febd89377c33f12674436bb410cc5b4ee5b14823fbc0e4fd746 |
| Browser | 12308115359 | bdd0c28ef0ede2d765096a516595dc36cd79144853179f996495c10e646f4dd3 |

All retained source records identify checkout `9067356e5d522c3233df58015aadb45cdc207827`, whose tree exactly matches the corrected candidate tree. Artifacts expire after fourteen days and contain generated-only lab evidence, source/configuration metadata and sanitized counts; no provider credentials, private evidence keys, raw database backups or browser profiles are included.

Initial source `d9865dda002e1731b3d9a39f168a63bd52aee0fb` failed x86 run 39513322185 and ARM64 run 39513322284: 768 of 769 component cases passed; the new closed-case test attempted direct SQL closure and the existing database approval trigger rejected its setup. It did not reach its denied-advance assertion. Repair 207954a2 uses the real approved closure workflow, asserts actual closed state, then retains the denied advancement/no-claim assertions. No product assertion, approval trigger or threshold was weakened. Initial source browser/runtime passes do not supersede this failure; corrected-source passes above do.

Status: automated component acceptance only. Independent review, human UAT, real console/OS compatibility, eleven specialist engines, qualified AI/network dispatch and full product/release acceptance remain open. No merge, deployment, model activation or production admission occurred.
