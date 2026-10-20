# Gabriel governed reference memory

This C07 slice implements explicitly reviewed, expiring reference records over the existing encrypted case-evidence store. It stores facts and preferences as data; no record can grant permissions, change a prompt/playbook, suppress alerts, normalize attacker behavior or train model weights. There is no model integration, retrieval cache, embedding index or hidden copy of source content. A reviewed record is labelled analyst-validated reference data, with source authenticity still unverified. Self-review is permitted for a solo engineer and explicitly identified; it is not independent corroboration.

## Lifecycle and persistence

Schema 15 adds append-only `memory_records`, `memory_reviews`, `memory_invalidations` and `memory_resets`, with tenant/case/evidence/member foreign keys and indexed retrieval. Runtime grants permit SELECT/INSERT only. Earlier migration files/checksums are unchanged. A proposal references an existing approved, ready, available UTF-8 evidence artifact of at most 4 KiB. Actual encrypted bytes/custody are verified on proposal and approval; content reads add custody/audit. Record metadata stores source digest, proposer/reviewer, kind, topic, scope, sensitivity, dates, expiry, epoch and correction lineage. Source content remains encrypted in the evidence store.

A proposal is excluded until an explicit approve decision acknowledges the source and matches its exact digest. Rejection, expiry, changed contributor/reviewer/source-actor membership, unavailable/purged/disposition-pending source, forgetting, supersession and reset exclude retrieval. Every retrieval rechecks live caller and record authority, verifies actual bytes and adds custody/audit. A corrupt source fails the retrieval explicitly; no partially assembled result is released. Backend content uses the existing redacted `EvidenceContent` wrapper. The CLI memory-check returns only eligible metadata; it never prints source bodies. Existing explicit evidence export/content-view paths remain available to authorized humans.

Case scope applies only to that case. Organization scope can be proposed, reviewed or forgotten only by an owner/admin; approved organization references may be retrieved from other cases in the same tenant. A topic requires an explicit correction rather than a second root record. Correction must name the current unsuperseded record, preserve scope/kind/topic and use the current epoch; case corrections also preserve case. A pending correction immediately suspends its predecessor. Review decisions and lineage are immutable. Re-proposal uses exact actor/payload/UUID replay, and concurrent retries converge. A reset requires an owner/admin and an exact expected epoch, preventing a stale reset from clearing newly created references.

Expiry is fixed at proposal, from 60 seconds through 30 days. The workbench initially proposes internal-classification records for 24 hours; the CLI exposes classification and TTL explicitly. Sensitivity is a handling label, not permission for model egress. Admission is bounded at 128 records per organization epoch and 4,096 retained records overall. Retrieval fails beyond its bound, rather than silently truncating eligible data. History shows up to 128 latest applicable records with an omission flag. Managed archival/capacity changes require a later accepted operational policy.

## Forgetting, retention and legal holds

Forget/reset removes reference retrieval immediately under the existing tenant lock. It **does not claim to erase source evidence, immutable review/audit history, exported files or backups**. Forget returns the linked evidence ID, current legal-hold presence, `source_erased=false` and the requirement to use the existing source-purge approval/policy workflow. Reset reports the new epoch and the number of retained source cases currently on hold. Existing case retention floors, closed-case requirements, legal holds, unresolved exports and exact purge approvals remain enforced by the evidence subsystem. Shared source evidence is not destroyed merely because one reference was forgotten. No derived index/cache exists to retain stale references. These exceptions must remain visible in product and UAT; this slice is not a claim of complete privacy erasure or compliance certification.

## Operator and browser paths

Apply schema 15 with the existing migration operator and rebuild the identity image. Use its normal restricted DSN, evidence keyring/volume and a private current human session file:

```bash
python -m gabriel.identity.cli migrate
python -m gabriel.identity.case_cli memory-propose --token-file /operator/human-session --case-id CASE_UUID --evidence-id EVIDENCE_UUID --request-id REQUEST_UUID --topic environment.mfa --ttl 86400
python -m gabriel.identity.case_cli memory-list --token-file /operator/human-session --case-id CASE_UUID
python -m gabriel.identity.case_cli memory-review --token-file /operator/human-session --memory-id MEMORY_UUID --decision approved --expected-digest SOURCE_SHA256 --acknowledged-source
python -m gabriel.identity.case_cli memory-check --token-file /operator/human-session --case-id CASE_UUID
python -m gabriel.identity.case_cli memory-forget --token-file /operator/human-session --memory-id MEMORY_UUID
python -m gabriel.identity.case_cli memory-reset --token-file /operator/human-session --epoch CURRENT_EPOCH
```

Use `--memory-kind preference`, `--memory-scope organization`, `--sensitivity confidential` or `restricted`, and `--supersedes MEMORY_UUID` only for the intended explicit scope/classification/correction. Topic identifiers are bounded lowercase metadata labels, not a place for secrets. Never place actual sensitive source content in command arguments, issues or PRs.

The workbench **Memory review** link displays history, expiry, scope and source-evidence links. Authorized users can propose a record, explicitly review its source/decision, forget it, or (owner/admin) reset organization retrieval. Every POST retains exact Host/Origin, CSRF, field-set and live service authorization checks. Viewers see metadata without mutation or content retrieval. Source bodies are opened through the existing explicit evidence-view control. Human-readable statuses explain exclusions. No automatic model memory use is enabled by this UI.

## Loop, UAT and rollback

Status: **IMPLEMENTED_UNVERIFIED** until exact-source hosted outcomes are recorded. Partial C07 and GAB-006/007/008/020/025/031/032/038/040. Tests use actual PostgreSQL and encrypted evidence for review/digest/role/scope/replay/concurrency, correction, expiry, reviewer revocation, source corruption, holds, forget/reset, audit rollback, immutable grants, TTL and interrupted migration. Actual CLI/TLS forms, generated-console Chrome/Brave proposal/review/forget, and real restart/dump-restore of reviewed memory plus forget/reset epochs are included. No host pytest or manufactured runtime pass.

Human UAT inventory includes proposed/reviewed/rejected/expired/forgotten/reset/superseded/authority-loss/source-loss/empty/error states; exact source review; solo self-review disclosure; role/scope controls; correction and expiry; reset scope/CAS; retained-source/hold exceptions; keyboard/accessibility; and pre/post-release regression. Human UAT/independent review remain NOT_RUN. Poisoning/prompt-injection effectiveness and expert detection quality are not proven by lifecycle tests. Actual AI/coordinator reuse, provider policy, held-out analyst evaluation, full deletion/backups/operations and complete PRD acceptance remain open.

Rollback stops new workbench processes and restores the prior image, keeping additive encrypted source/history intact. Do not drop tables, erase evidence or rewrite migration checksums to roll back. The prior runtime cannot perform memory retrieval; existing case/evidence governance remains available. No production deployment or model spend is performed by this increment.
