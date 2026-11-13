# Gabriel — Twelve-Specialist Upgrade Matrix (Tranche 2)
**Updated:** 13 November 2026
**Scope:** Executable read-only typed-fact review tranche, not unrestricted SOC autonomy.

## Orchestration contract

Hermes remains the mandatory supervisor for autonomous investigative coordination. Its existing bound is **up to four** specialists per supervised investigation, not twelve simultaneous live model invocations. The twelve tracks below are engineering ownership lanes, not twelve background processes or separate unaudited identities.

Every tool uses the case-owned `specialist-facts-v1` schema and entrypoint verification; outputs are bounded, de-identified local review results. Do **not** interpret software test success as proven threat detection, production-model qualification, or permission to execute response actions. The tool manifest and skill source contribute to the exact AI configuration digest, so all changed model configurations are **qualification pending**.

## Capability-to-tool matrix

| Specialist | Earlier grounded tool(s) | Tranche 2 local review | Next major missing engineering capability |
| --- | --- | --- | --- |
| Telemetry Health | `assess_visibility_gaps` | Existing tool retained | Validated ingestion adapters, sensor heartbeat history, windowed completeness |
| Alert Triage | `find_duplicate_facts` | Existing tool retained | Vendor event identity, benign/admin baselines, defensible correlation |
| Incident Scoping | `find_duplicate_facts`, `cross_check_timeline` | Existing tools retained | Timestamp/source-normalized entity graph, NAT/alias safety |
| Threat Intelligence | — | `review_indicator_freshness` | Independently sourced, authorized IOC feeds and revocation handling |
| Threat Hunting | — | `summarize_hunt_hypotheses` | Falsifiable scoped live queries, benign lookalike test corpus, authorization |
| DFIR Evidence | `audit_provenance`, `cross_check_timeline` | Existing tools retained | Source-specific forensic parsers and evidence capture qualification |
| Detection Engineering | `review_detection_regression` | Existing tool retained | Versioned rule baselines and independent adversarial/benign tests |
| Exposure & Vulnerability | — | `review_exposure_context` | Asset inventory freshness, KEV/EPSS enrichment with verified connectors |
| Identity & Access | `find_duplicate_facts` | Existing tool retained | Identity alias normalization, PAM and cross-console audit adapters |
| Cloud & Supply Chain | — | `review_cloud_change_assertions` | Signed provenance, IaC baseline, cross-account/tenant safety |
| Response & Remediation | — | `review_response_dependencies` | Exact approved action plans, reversible dry-run, rollback verification |
| Recovery & Learning | — | `review_recovery_baselines` | Verified restore/live health evidence, human-approved lesson promotion |

This tranche makes **each role** the owner of at least one newly added deterministic review across tranches 1–2. It does **not** implement the entire [240-candidate skill catalog](GABRIEL_SPECIALIST_SKILL_EXPANSION.md). The catalog remains a design/acceptance backlog.

## Tranche 2 contracts

- `review_indicator_freshness`: Counts supplied indicator match/expiry assertions using the snapshot clock; no external lookup, authenticity verification or attribution.
- `summarize_hunt_hypotheses`: Counts typed identity, activity and cloud signals, leaving benign administration, compromise and live hunt scope unresolved.
- `review_exposure_context`: Counts supplied urgent reachable unmitigated high/critical exposures; exploitation and asset inventory freshness remain unproven.
- `review_cloud_change_assertions`: Counts reported types and authorization unknowns; no cloud mutation or independently verified component signatures.
- `review_response_dependencies`: Counts failed/unknown target-binding, dependency and recovery checks; no containment, remediation or rollback executed.
- `review_recovery_baselines`: Counts reported restore/service/control outcomes and stale/unknown baselines; no independent recovery verdict or lesson publication.

## Required acceptance before AI admission or release

1. Valid and adversarial/malformed typed facts, scope and evidence-digest checks.
2. Exact role-only tool selection and disabled unauthorized tools, no external effects.
3. Docker isolated tests on AMD64/ARM64 and production image vulnerability scan without lowered threshold.
4. Held-out benign/attack assessments with independent analyst labels, calibrated abstention, source attribution, and tested cost ceiling.
5. Authorized vendor-console lab evaluation, native Mac installation/UAT, human response approval and operational rollback.
6. Final human release decision with artifact digests. A merged GitHub branch alone is not a signed-off installation.

## Next engineering track

Implement provider-specific verified normalization and a case-scoped provenance-aware temporal observation graph before declaring broader autonomous attack detection. No source may be upgraded from 'reported assertion' to 'independently corroborated fact' merely because Hermes and specialists agree.
