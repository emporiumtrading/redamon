# Gabriel specialist contracts and telemetry health

This C07 increment adds the first executable local specialist: a deterministic assessment of the case's recorded browser-session coverage. It uses real authoritative session/task/human checks, immutable PostgreSQL records and audited operator requests. It does not run a model, detect an attacker, browse a vendor console, execute a query or initiate response. The twelve PRD role identifiers are registered; eleven have contracts only and execution is explicitly denied. Registry presence is not an implemented AI capability.

## Operation and controls

Apply the additive schema 14 migration through the existing migration operator, rebuild the identity image, and use the existing restricted runtime DSN, evidence keyring/store and private human session. Earlier schema files/checksums are unchanged. Commands:

```bash
python -m gabriel.identity.cli migrate
python -m gabriel.identity.case_cli specialist-run --token-file /operator/human-session --case-id CASE_UUID --request-id REQUEST_UUID
python -m gabriel.identity.case_cli specialist-list --token-file /operator/human-session --case-id CASE_UUID
python -m gabriel.identity.case_cli specialist-get --token-file /operator/human-session --case-id CASE_UUID --run-id RUN_UUID
```

The workbench case detail links to **Telemetry assessments**. **Check telemetry coverage** uses a CSRF-protected POST, a random request UUID, the current content-writing role, an open case and mandatory audit. A repeated UUID from the same actor/role returns the original result; conflicting actors are denied. Concurrent retries converge to one record. Viewer access is historical metadata only. Logout/revocation denies subsequent reads and new runs. Sampling rechecks authority in separate transactions, then rechecks the caller/open case before committing. No nested tenant lock is held during source-service calls.

Input packets contain one scoped case reference, up to 64 evidence metadata references, and up to 32 most recent browser-lease samples from that case. Source sampling is partial and individual, not one atomic security-system snapshot; older-session omission is explicit. Every output claim cites one or more admitted typed references. Case-record absence observations are distinct from source evidence. Packets exclude evidence bodies, URLs/account labels, credentials, key IDs and executable content. A stored packet/result hash detects accidental record alteration; it does not protect against a database owner who can replace both data and hashes, and is not a source attestation.

The result reports the observed control states (pending, recent heartbeat, gap, lost authority or disconnected), a benign alternative explanation, uncertainty and a fixed review-step vocabulary. Attacker status remains **unknown**, incident assessment **not performed**, source verification false and page visibility unverified. The engine has no provider/model/prompt and records model cost zero and measured local elapsed time. This is not a fabricated AI assessment. Retained results remain historical after live authority changes and never become environment memory or permission. Re-run to obtain a new sample.

Schema 14 permits runtime SELECT/INSERT only, uses composite tenant/case/member foreign keys and indexed access, and stores bounded JSON with packet/result digests. Per-case admission stops at 128 runs; history returns the latest 50 with an omission flag. Unsupported role names, unknown references, unexpected fields/actions, changed scope, claimed source truth, invented model execution, missing uncertainty and non-admitted conclusions fail closed. Existing evidence metadata/custody validation still governs packet construction. No evidence body is read.

## Loop, verification and rollback

Owner: implementation agent. Status: **COMPONENT_VERIFIED at `470addfec33c450eeac5782d2d77bd91a476d54e`**: 675 component/regression cases, actual restart/dump-restore and 31 developer-journey checks per browser passed. Combined memory source `ac6513ba` passed 704 cases and 34 checks per browser. Partial GAB-003/005/006/008/020/023/025/027/028/040 only. Real PostgreSQL concurrency/replay, tenant/case/role/revocation, append-only grants, packet/result attacks, audit/session rollback, quota, migration, CLI/HTTPS forms and persisted result/hash reconstruction were exercised. Artifact hashes/source-tree equivalence are recorded in the ledger; no host pytest or invented pass substitutes for those gates.

Human UAT inventory: case-detail link; empty/history/omitted states; run button; recorded observation/reference; unknown attacker/source labels; alternative and uncertainty; history return; viewer read/no run; CSRF/replay/foreign/revoked/closed/error states; keyboard and accessibility. Independent review and human pre/post-release UAT remain NOT_RUN. Full role quality, first-five specialist activation, model routing/evaluation, proactive hunting, entity/event correlation and governed baseline/memory remain open.

Rollback stops new workbench processes and restores the prior runtime image while retaining additive table/history. Do not drop the table or edit migration checksums as rollback. Earlier CLI case/evidence paths remain available. The migration CLI reports the actual latest migration version rather than a stale literal. This component introduces no deployment, live model spending or external-console action.
