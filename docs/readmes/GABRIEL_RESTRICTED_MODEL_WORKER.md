# Restricted model worker and budgeted comparison

This increment supplies a restricted dispatcher kernel and a separate generated-data comparison runner. It is not full production acceptance, a background AI service or an implementation of the eleven remaining specialist engines. The production admission set is deliberately empty. Adding an OpenRouter candidate to the registry, buying credits or creating a price quote cannot enable private-case inference.

## Dispatcher boundary

`ModelWorker(cases, vault)` requires the same backend database for the case service and encrypted provider vault. Initial access is owner/admin only; bounded analyst/service grants remain future work. `reserve(token, coordinator_run_id, normalized_evidence_id, request_id, model)` requires a completed, active local coordinator plan, current creator/caller access, ready case-bound sources and current evidence encryption epoch. The normalized JSON input is read through verified encrypted storage and audited. Every typed observation must reference an evidence ID and digest in that exact plan. Typed minimization removes local identities from the wire and retains the private lineage manifest locally.

Reservations bind coordinator/input identity, exact request body, model configuration/prompt/projection versions and fixed token/price ceilings. At the current ceiling a call reserves 6,304 micro-USD ($0.006304). The existing $18 monthly dispatch, $0.50 daily, $0.05 investigation, two unresolved slots and six-attempt limits remain. Expensive or unknown routes are not automatically substituted. A replay reuses the original reservation.

`dispatch(token, coordinator_run_id, normalized_evidence_id, reservation_id)` checks the binding, reads the credential from the backend vault, preflights current catalog ZDR/parameter/price classification and account limits, then claims once under the database transaction with a fresh source/authority guard. The transport has one fixed HTTPS host, three permitted paths, TLS validation, response/request bounds and no redirects, retries, tools, plugins or fallback. Current authority, case, Stop, expiry, source set and encryption epoch are checked again before returning an answer. Stop cannot retract a request already sent. Raw provider errors and credentials are never emitted.

Production admission remains blocked for every configuration. Hermetic tests temporarily admit one configuration only inside their isolated process and substitute a fixture transport; those answers are not actual model evidence. Shared decision parsing contains no executable live probe; the production image does not need the generated-lab CLI.

## Deliberate remaining limits

Results are returned as a redacted `EvidenceContent` wrapper in private memory, including a local lineage manifest. They are **not durably persisted**. Claimed reservations remain fully held until explicit operator reconciliation, even after a validated response. Crashes and repeated dispatch cannot resend; they may lose an answer. Reported costs are not independently authenticated billing. There is no automated settlement, workbench AI control or unattended daemon. The byte cap is not a certified tokenizer bound; provider-specific token admission, adapter semantic validation, encrypted answer/manifest lifecycle and recovery remain necessary before activation. No static admission digest should be populated until these gaps and exact model/configuration quality requirements are satisfied.

The existing local plan does not gain an AI step. Its inventory/telemetry completion is a prerequisite, not permission for production inference or evidence egress. The worker cannot execute model-requested actions. Output claims and incident decisions remain unreviewed and partial.

## Wider OpenRouter comparison

The candidate registry covers GPT-4.1 mini/Azure, Qwen3.5-35B-A3B/DeepInfra, Mistral Small 3.2/DeepInfra, Nemotron 3 Super/DeepInfra, GPT-OSS-120B/DeepInfra, Llama 3.3 70B/DeepInfra, DeepSeek V3.2/DeepInfra and Qwen3.5-122B-A10B/SiliconFlow. Model/provider slugs, parameters and configuration hashes are recorded. OpenRouter base slugs such as Azure can cover backend variants; catalog classification and returned provider name do not independently establish the exact execution backend or residency.

The runner uses only the original pinned generated development corpus, with fixed attack (`dev-auth-attack`), benign (`dev-backup`) and visibility (`dev-logout`) examples per candidate. No private case evidence, operator credentials, held-out cases, tools or external actions are accepted. Public ZDR endpoint metadata is screened before a paid call, and ZDR/data-collection/parameter/price restrictions are repeated in every request. Catalog presence is not an independent privacy attestation or qualification.

The batch reserves at most **$0.16**, at most 24 requests (three per model), and at most $0.018912 per model investigation at the stated ceilings. Requests are serial, under the existing shared-key CI concurrency lock. Actual costs may be much lower. Key preflight requires an inference-only key capped at $18/month, enough remaining credit, and daily/monthly headroom for the full batch allowance. Other applications sharing the account are outside this local batch accounting.

A dispatch-start journal record is flushed before each POST. Unknown usage, unexpected routing, transport errors or possible charges stop the entire batch with no retry. A complete response with known bounded reported cost but an invalid decision stops that model's remaining examples; later distinct candidates may still be compared. Known costs stay in the report. If a process is interrupted, a start record without a matching response remains unresolved; never infer zero charge. The journal and final result are generated-only CI artifacts with fourteen-day retention. Private keys and account metadata are not retained.

The paid CI job runs only on the initial opening of the designated same-repository branch after its isolated software gate. Subsequent code/documentation pushes do not automatically repeat paid comparisons. A failed/partial comparison is not retried automatically. Fixture tests, correct development answers and catalog listings never set `quality_qualified` or `production_admission` to true. Analyst-reviewed labels, independent holdout sealing, actual full evaluation and release review remain separate.

Official routing/privacy references: https://openrouter.ai/docs/guides/routing/provider-selection and https://openrouter.ai/docs/guides/features/zdr . Public endpoint classification: https://openrouter.ai/api/v1/endpoints/zdr .

## Acceptance and rollback

Run the isolated lab tests without network/credentials, the matching identity image against real PostgreSQL on x86/ARM64, existing restart/dump-restore and browser/runtime regressions. Test one-time claim recovery, source and reservation binding, Stop before/during a call, budget pause, audit failure, secret exclusion and default-denied production admission. No host pytest is an acceptance substitute. Actual live comparison evidence must be recorded separately from fixtures.

No database migration is added. Rollback stops callers and restores the preceding image; retained claims/reservations require the existing reconciliation process, never automatic release or resend. Full product acceptance, independent review and human Mac Docker UAT remain open.
