# Gabriel — 240-skill delivery ledger

**Source of truth:** `gabriel/identity/skill_roadmap.json`; validate using `gabriel.identity.skill_catalog.load`.

The engineering specification has **240 candidate skills, 20 for each of 12 roles**. The catalog records **15 implemented-unqualified entries and 225 not yet implemented** across seven tranches. The earlier **11 grounded-review tools** are separate foundational capabilities and are not automatically declared identical to full catalog skills.

## Tranche 1: implemented and connected to the exact authorized role

| Catalog slot | Executable local tool | Owner | Scope |
|---|---|---|---|
| `alert_triage.20-escalation-prioritization` | `prioritize_escalation_queue` | Alert Triage | Unresolved severity, aging and unknown-state review; no suppression or auto-escalation |
| `incident_scoping.19-evidence-gap-identification` | `review_incident_evidence_gaps` | Incident Scoping | Missing entity references and absent source categories; never a complete-scope verdict |
| `identity_access.03-privileged-access-anomaly-detection` | `review_privileged_access_changes` | Identity & Access | Privilege grants and MFA changes by supplied authorization; no account action |
| `response_remediation.14-response-dependency-analysis` | `analyze_response_dependencies` | Response & Remediation | Exact reported target/dependency/recovery checks; no response execution |
| `recovery_learning.20-incident-closure-evidence-validation` | `review_incident_closure_evidence` | Recovery & Learning | Reported restore/health/security checks against baselines; no incident closure or lesson publication |

These kernels use `specialist-facts-v1` and the existing verified-entrypoint/case-role-bound tool execution. Their selection strings, skill text and implementation source are included in specialist runtime digests. They remain **unqualified for model admission** and require independent held-out review. A locally passing test does not verify customer evidence provenance.

## Tranche 2: evidence-bound coverage, provenance, and detection review

| Catalog slot | Executable local tool | Owner | Scope |
|---|---|---|---|
| `telemetry_health.07-data-source-coverage-mapping` | `map_source_coverage` | Telemetry Health | Maps supplied source aliases, time windows, reported gaps and overlapping conflicts. Expected inventory and continuous visibility remain unknown. |
| `dfir_evidence.18-evidence-provenance-validation` | `validate_evidence_provenance` | DFIR Evidence | Checks stored bytes and custody through verified case references, and reports conflicting artifact assertions. External collection authenticity remains unknown. |
| `detection_engineering.12-false-negative-analysis` | `analyze_false_negatives` | Detection Engineering | Groups reported fixture trials by rule, engine and fixture digests, deduplicates outcomes and excludes contradictory trials from miss counts. It does not replay rules. |

Coverage mapping consumes typed `source_coverage` facts with an opaque source alias and a bounded UTC interval. Detection review consumes typed `detection_trial` facts with case-bound evidence and separate rule, engine and fixture digests. Those three digests stay local. Forensic timeline cross-validation still requires shared event identifiers and source clock calibration.

## Tranche 3: indicator lifecycle, remediation deadlines, and storage access

| Catalog slot | Executable local tool | Owner | Scope |
|---|---|---|---|
| `threat_intelligence.20-threat-intelligence-lifecycle-management` | `review_intelligence_lifecycle` | Threat Intelligence | Groups versioned indicator reports by supplied feed and indicator aliases. Flags expiry, revocation, reactivation and conflicting states for analyst review. |
| `exposure_vulnerability.06-vulnerability-age-and-remediation-sla-tracking` | `review_vulnerability_sla` | Exposure & Vulnerability | Computes age and provisional deadline status from supplied dates. Preserves conflicting deadlines or lifecycle states. |
| `cloud_supply_chain.15-cloud-storage-exposure-assessment` | `assess_cloud_storage_exposure` | Cloud & Supply Chain | Reviews supplied external access paths against network, guard, and read/list/write assertions. Preserves stale and conflicting evidence. |

The case tool verifies the stored source before the local review. Source authenticity and policy authority remain unverified. Feed and storage path identifiers and policy digests stay local.

## Tranche 4: incident timeline normalization

`incident_scoping.15-incident-timeline-normalization` maps to `normalize_incident_timeline`. It subtracts the reported source clock offset from the UTC-encoded event time, applies the reported uncertainty bounds, and compares disjoint intervals within the snapshot. It preserves conflicting calibration assertions and leaves unknown, overlapping, and snapshot-crossing intervals unordered. The result does not verify the clocks, actual chronology, or causality.

## Tranche 5: PowerShell activity review

`threat_hunting.02-suspicious-powershell-activity-investigation` maps to `review_powershell_activity`. It reviews supplied execution indicators and approval assertions grouped by case-local host and process instance. It preserves conflicting approval, deduplicates repeated indicators, and flags paired behavior for analyst review. No command text or process identifiers are exported. Reported approval and process identity require independent verification.

## Tranche 6: recovery point objective review

`recovery_learning.04-recovery-point-objective-rpo-validation` maps to `review_recovery_point`. It compares reported restored data age at disruption with the supplied recovery objective. Conflicting points or objectives remain unresolved for analyst review. The tool keeps clock calibration, policy authority and actual restore verification open.

## Tranche 7: recovery time objective review

`recovery_learning.05-recovery-time-objective-rto-validation` maps to `review_recovery_time`. It compares elapsed time from disruption to reported service restoration with the supplied objective. Conflicting reports remain visible for analyst review. Clock accuracy, policy authority and service restoration require independent verification.

## Release gates

1. Exact 240-slot inventory, unique stable IDs and no unchecked status or authority escalation.
2. Strict role-only access and negative, adversarial, malformed-input and time-bound fact tests.
3. Actual Debian/Alpine Docker test stage on AMD64 and ARM64; retained Grype high/critical gate and Hermes tests.
4. Human-reviewed benign and attack lookalikes, source integrity, clock drift, cross-case denial and independent quality labels.
5. No automatic external containment, account manipulation, alert suppression, incident closure or model-context trust elevation.

**No claim is made that all 240 have been implemented.** Future tranches must build the missing vendor-neutral evidence acquisition and semantic grounding before assigning skill status to abilities the current typed-fact schema cannot support. The agent's capability must be proven through source-bound cases, not generated by duplicating labels.

## Next implementation tranches

- Telemetry: observed source coverage, drift and heartbeat history (new provenance-bearing data inputs).
- Threat hunting/incident scope: same-case read-only query plans, source-specific aliases and temporal relationship graph.
- Threat intelligence/detection: pinned feeds, rule versions, test cohorts and false-positive calibration.
- Cloud/supply chain: signed component identity, configuration drift and authorization proof.
- Response/recovery: dry-run action plans, exact approval bindings, rollback provenance and independently witnessed restoration.

The analyst-selected console is **vendor-neutral**. The tool can begin by discovering approved browser content even where a source-specific event parser is unavailable. Unknown vendor semantics are never silently promoted into trusted facts.
