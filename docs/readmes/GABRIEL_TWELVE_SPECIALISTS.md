# Twelve specialist capabilities and acceptance boundaries

This increment adds twelve deterministic local review kernels and a persisted
typed-evidence path. Schema 20 expands the existing append-only specialist-run
table; older telemetry records remain readable. The workbench offers all twelve
roles when an evidence artifact is available. None is a qualified AI engine or
an accepted live attack detector. Source/role/privacy/behavior tests are pending
the exact-source Docker gate; no synthetic test counts as a real-console pass.

| Specialist | Implemented bounded local review | Full PRD work still required |
| --- | --- | --- |
| Telemetry health | Browser lease health; typed available/stale/missing coverage | Actual console collection freshness and continuous lifecycle visibility |
| Alert triage | Open high/critical alert review with benign alternative | Event-based attack correlation, model reasoning and operational prioritization |
| Incident scoping | Supplied distinct entity-key count and event interval | Validated identity resolution, cross-console correlations and affected scope |
| Threat intelligence | Reported matches checked against supplied validity times | Vetted current attributable intelligence enrichment and contextual evaluation |
| Threat hunting | Activity-category review and a hypothesis for an existing search | Versioned hunt playbooks, search selection/execution and evidence-driven iterations |
| DFIR evidence | Reported integrity/custody discrepancies | Admitted collection workflows, actual tool integrations and forensic timelines |
| Detection engineering | Expected versus observed test outcomes; misses and unexpected matches | Versioned rule drafting/translation, independent test cohorts and review |
| Exposure/vulnerability | Reported severity, reachability and mitigation review | Validated exposure/asset ownership and supported integration semantics |
| Identity/access | Authorization review for privilege/MFA changes; reported authentication-failure counts | Credential abuse, session correlation and attack-specific investigations |
| Cloud/container/supply chain | Reported cloud/workload/component finding and authorization review | Actual baseline comparison, provenance tools and deployment correlation |
| Response/remediation | Target/dependency/recovery planning checks; conflicts remain visible | Exact individually approved response, independent effect verification and reconciliation |
| Recovery/learning | Reported restore/health/control results against supplied baselines | Independent recovery acceptance and proposed lessons through existing memory review |

## Evidence and execution contract

The input is an engineer-approved encrypted case artifact containing strict
`specialist-facts-v1` JSON. Every fact names an existing same-case source artifact
and its digest. The backend checks the input and all cited ciphertext/custody
chains before analysis. Unknown fields/types, prompt-like free text, conflicting
digests, cross-case sources, model answers used as sources, malformed JSON and
out-of-snapshot times are denied. This establishes the bytes being reviewed;
it does not validate user-supplied fact semantics or source authenticity.

Stored packets contain metadata, digests and source references, with no original
fact bodies, entity keys or fact IDs. Result summaries contain bounded aggregate
observations, hypotheses, contradictions, benign alternatives, uncertainty and
fixed review-step names. They are historical case metadata under the existing
specialist storage model. Results remain unqualified, attacker status unknown,
and external-action authority false. Reported counts can overlap; repeated
records never establish independent corroboration. Missing relevant facts cause
explicit abstention. Model cost is zero because these engines make no model calls.

Run through the **Specialist assessments** workbench or:

```bash
python -m gabriel.identity.case_cli specialist-run \
  --token-file /operator/human-session --case-id CASE_UUID \
  --request-id REQUEST_UUID --specialist-role alert_triage \
  --evidence-id TYPED_FACTS_ARTIFACT_UUID
```

The UUID request is bound to actor, case, role and input. Concurrent repetitions
return one immutable record. Viewer access is historical summary only; current
write authority and an open case are required for execution. Both new and old
records share the 128-run case limit. The coordinator remains its earlier fixed
two-step local plan; full specialist scheduling/disagreement handling is open.

## Live attack detection is a separate required acceptance boundary

The owner explicitly requires evidence-based recognition of brute force,
credential/password misuse, worm propagation, ransomware, lateral movement and
possible rootkits as Gabriel investigates approved pages/tabs. The current
metadata/typed-fact kernels do not fulfill that requirement. Finish actual
browser adapters, deduplication/entity/event correlation, attack-pattern and
hunt evaluation, bounded ongoing observation, urgent presentation and timestamped
latency measurements. Test multiple attack scales, benign lookalikes, partial
pages, stale/late events, source loss and hostile page instructions.

Measure event time, console availability time, approved capture time, assessment
time and analyst presentation time separately. Publish observed latency and
coverage; do not guarantee real-time detection from inaccessible or delayed
console telemetry. Potential rootkit assessment specifically requires exposed
endpoint/kernel/boot-integrity evidence and independent validation.

## Migration and rollback

Migrations 19 and 20 are additive acceptance changes with unchanged historical
checksums. Migration 20 atomically replaces specialist role/engine checks and
retains prior telemetry history. Stop new work before rollback. A pre-19/20 image
rejects the newer migration history; use a compatible rollback image or a reviewed
coordinated database/evidence restore. Test-only historical reconstruction deletes
new generated reviews to reproduce the actual older schema; it is never an
operator rollback procedure. Configurable full metadata/backup erasure remains
an open product lifecycle requirement.
