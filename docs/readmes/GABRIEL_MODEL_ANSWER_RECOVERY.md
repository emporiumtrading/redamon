# Encrypted model answer and lineage recovery

This increment adds durable unreviewed answers to the restricted worker. No model configuration is production-admitted, no workbench AI action/background service is enabled, and no private evidence has been submitted by these tests. The worker now uses the versioned v2 response prompt, which creates a new configuration hash. Actual generated model comparison results remain separate from fixture recovery tests.

## Persistence and authority

Schema 18 adds append-only model answer intents and completion receipts. Tenant/case/coordinator/input/reservation/dispatch-claim relationships are foreign-key bound; payload, configuration, input and provider-response hashes bind the envelope. Current owner/admin authority, source ciphertext, live coordinator/investigation and budget pause are checked around persistence/recovery. A maximum of 128 intents per case and the existing 64-object evidence quota bound storage. Metadata stores IDs/hashes only; result text and private lineage/identity maps use the existing authenticated encrypted evidence store, with its audited custody, epoch/rotation, disposition and key-retirement controls.

Generated outputs have distinct `model_generated_text` / `model-json-v1` provenance, require a backend staging intent, and remain unreviewed. They are not independent evidence or proof that a source/model claim is true. Automatic reuse as model source evidence is denied. They consume the existing evidence quota and change the case source set for later plans. Only the exact backend-owned staging ingestion ID can be omitted while completing that answer against its original source snapshot; other new/changed/unavailable sources still deny completion.

`get_answer(token,reservation_id)` verifies current owner/admin and case access, protected receipt/bindings, authenticated ciphertext and referenced source integrity. It returns a redacted EvidenceContent wrapper marked historical, partial and unreviewed. Reading a completed answer does not require current model admission, a provider credential or an active historical plan, and never calls the provider. It does not grant execution authority or a current incident verdict. Purged/unavailable/corrupt answer or referenced source material denies retrieval. Authorized general case evidence operations can inspect staged generated objects; an incomplete model receipt is never presented as a completed worker answer.

## Interruption and recovery

The one-time dispatch claim remains the no-resend boundary. A successful validated reply first commits its protected intent, then acquires encrypted evidence and commits an immutable completion receipt. Existing reservations stay held in full, even with a durable result; this does not automate provider billing settlement.

`recover_answer` returns an already completed historical receipt idempotently, or verifies and finishes an interrupted encrypted acquisition/receipt while the original coordinator/investigation/creator/source scope and budget permission remain live. It never resolves a provider credential or resubmits a call. Concurrent recovery produces one receipt. Stop, expiry, authority loss, budget pause and unrelated source changes prevent incomplete publication. Completed records remain historical evidence. If the process fails before recoverable ciphertext exists, the answer may be lost; retain the claim and possible cost, never resend to reconstruct it. The operator must reconcile held costs and incomplete artifacts. This is not exactly-once external execution or automatic cost reconciliation.

## Validation and deployment limits

Matching-image real-PostgreSQL tests cover encrypted/private durable replay, committed-ciphertext/database rollback, missing ciphertext/no resend, failed completion audit/receipt, concurrent recovery, Stop/source change/pause, historical read after Stop, default admission, original-source corruption, foreign tenant denial, append-only permissions, origin admission and interrupted schema-18 migration. The real restart/fresh dump-restore checkpoint adds both completed answers and an interrupted receipt using hermetic provider fixtures in a separate generated tenant; no provider key or checkpoint contents enter artifacts. Existing cases, authorization, browser, runtime and foundation gates remain required. Host pytest is never an acceptance substitute. Execution results are pending until their exact source and artifacts are recorded.

Migration retains prior checksums. Because older images reject unknown migration histories, do not promise rollback to a pre-schema-18 image against an upgraded database. Use a schema-18-compatible repaired image, or the reviewed database/evidence/key backup restore process. Full-system recovery/operational acceptance, retained-key custody, retention/erasure dependency review, independent model suitability, service grants, real console adapters and Mac UAT remain open. Human review must address derived answer retention alongside the case's source objects; there is no automatic source-erasure propagation claim.


Initial source 4153b0b62e6d4c996e6e69b591718bb521970f7e passed all 823 component checks in native ARM64 run 39525087825, zero failures/errors/skips, but its subsequent restart setup failed serializing a UUID in the newly generated normalized-input fixture. This is not a completed restart/restore acceptance. The integrated source explicitly serializes the fixture evidence/input IDs as strings, without changing recovery assertions. Full rerun results remain required; the earlier failure is retained in history.


Integrated source bc9ed3b559b9d60b2626103c7c4ec9b38298f07f passed its component/runtime/foundation and existing restart/restore gates, but artifact review showed its restart script had retained the older fixture without the new answer-receipt scenarios. That pass is not new-answer restart acceptance. The full fixture is restored from the original authored source, both UUIDs are explicitly serialized as strings, and its pending/completed answer checkpoints are verified present before publication. A fresh exact-source run is required. No assertion is removed or relaxed and no paid call is repeated.


## Verified combined recovery checkpoint

Corrected source `b76e329c5019c0b22129fd81b814cffb01d2d297`, tree `144c0437bcf218d68f0a992889b84a7ca39c5ff7`, passed all five workflows. Native ARM64 run 39527507120 and x86 run 39527507154 each passed **826 component + 49 runtime + 21 foundation = 896 tests**, zero failures/errors/skips. The restored full restart fixture (SHA256 `a1fabd915987566d29ff93c68b73d428f6ce1e6a36669c5bdc5a6bd864d92757`) was checked in the published source before execution. On both architectures the logs separately confirm completed encrypted answer/lineage replay and interrupted receipt recovery after actual database restart and after fresh pg_dump/pg_restore, with no provider access/resend and two claimed-cost slots retained. Fresh restore also reconciled both new tables' row counts. Fixture HTTP is not actual model quality evidence.

Browser run 39527507148 passed 40 generated-console checks each in Chrome and Brave; separate runtime 39527507113 and isolated 31-case comparison software run 39527507111 passed. Both paid jobs intentionally skipped on this follow-up. No paid model call was repeated by the repair or integration. Earlier source failures and the older-fixture verification gap remain recorded above and are not relabeled as successful new-answer recovery.

All three evidence ZIPs were independently downloaded and hash-verified:

| Evidence | Run / artifact | Verified ZIP SHA256 |
| --- | --- | --- |
| x86 | 39527507154 / 12314025999 | `336c2ea7a18f41f60289e02ce556328e697bd20f902670a93c68cc8e775841bf` |
| Native ARM64 | 39527507120 / 12314340759 | `5bcae648d697876126ad999be92d4f311b7a21a47acc0001add3cb69273d1088` |
| Chrome / Brave | 39527507148 / 12313919355 | `f6c3c4010d4f27fb33f4c46e1d708e6448406791566bf6f99a02327eba3aea1a` |

All report source files name checkout `ee916edc6681fc6de3c5e24be34cf6f20ba51cd2`; its tree was verified identical to `144c0437bcf218d68f0a992889b84a7ca39c5ff7`. Architecture totals cover the same scenarios, not 1,792 distinct cases. Application/runtime/test code is unchanged by subsequent evidence-only documentation/data commits. No schema-18 database was deployed to production and no model is admitted. The model review queue contains 24 actual answers with seven provisional AI screening flags and all human adjudication pending. Full product/specialist/adapter/retention/operational acceptance and Mac UAT remain open.
