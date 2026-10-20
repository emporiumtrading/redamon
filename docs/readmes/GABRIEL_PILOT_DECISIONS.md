# Gabriel pilot decisions and acceptance plan

Decision date: 20 October 2026. Product owner: Prof. Iyobosa Ero.
Status: product choices recorded from the owner's answers and delegated engineering judgment. These are requirements and selected defaults, not implementation, test, UAT or deployment evidence. This addendum governs the affected PRD decisions; existing verified evidence remains attributed to its original source.

## 1. Pilot and deployment

Start with an isolated local lab using Docker Compose. Support the same stack on an Ubuntu 24.04 LTS guest VM, including VirtualBox where the host architecture supports the selected guest. No separate appliance product is required. Ship separate versioned application/worker/database services with persistent volumes, encrypted evidence and separately held keys. Never bundle the offensive RedAmon services into the defensive distribution.

Browser clients target Chrome and Brave on supported Windows, macOS and Linux versions. The engineer's workstation and Gabriel host can be different machines. Pair the extension to the authenticated HTTPS endpoint, validate certificate trust and scope grants, and document local-host versus guest-VM addressing. Never expose the database or pair through an unauthenticated public listener. Start with Linux amd64 images; native arm64 image support requires an actual build and test before advertising it. Establish measured CPU/RAM/disk minimums during packaging; do not invent sizing guarantees.

Install flow: deploy stack; create initial owner through the local bootstrap process; configure retention, model routes and budget; pair browser; engineer signs into consoles manually; engineer grants selected tabs/accounts/tasks; Gabriel displays source health and begins admitted investigation. Test fresh install, volume persistence, migrations, upgrade/rollback, backup/restore and key recovery.

## 2. Console-agnostic understanding

No commercial console is mandatory. Select Wazuh and DFIR-IRIS as initial real open-source lab consoles, adding Velociraptor results and Timesketch timelines subsequently. This selection is a development compatibility seed, not a product vendor restriction.

Use visible semantic page content, headings, field meanings, table schemas, origin/account context and available read-only controls to propose console identity and a capability map. Distinguish observed facts from inferred identity; show uncertainty and ask for correction when ambiguous. Avoid sending the full page when structured relevant fields suffice.

Unknown consoles can receive explicitly granted limited observation and evidence-linked interpretation. Identification does not itself authorize clicking or executing a search. Promote navigation/search/filter capabilities only after versioned operation contracts and tests establish semantics, side effects, account/target binding and re-observation. No generated executable adapter or unrestricted click interpreter. UI drift invalidates affected capabilities and reports partial coverage. Existing approved searches and validated parameters remain the investigative path.

## 3. Models and confidentiality

Initial evaluation candidates:
- OpenRouter `google/gemini-2.5-flash-lite`: routine extraction, classification and bounded summaries.
- OpenRouter `google/gemini-2.5-flash`: bounded escalation for difficult correlations and review.
- NVIDIA `nvidia/nemotron-3-super-120b-a12b`: text-reasoning fallback after endpoint capability, account terms, privacy and cost admission. Do not assume a hosted prototype endpoint has production terms or unlimited free capacity.

These are a small shared pool for twelve specialist roles. Deterministic local processing runs first; invoke relevant roles selectively. Model roles and model vendors are independent; repeated votes are not independent evidence. Evaluate available candidates against the lab corpus before enabling actual defensive conclusions.

At research time OpenRouter listed Flash Lite at $0.10/M input and $0.40/M output, and Flash at $0.30/M input and $2.50/M output. These are reference prices, not permanent quotes or a spending guarantee. Pin the actual provider/endpoint, permitted model ID/version, price limits and review date at admission. Revalidate prices/capabilities before dispatch.

Default data policy: original evidence and reversible identity mappings stay encrypted locally. Send only minimized, locally redacted structured evidence through explicitly configured approved routes. Use stable scoped pseudonyms to preserve entity joins, event order, relevant command/security semantics and source lineage. Strip secrets, credentials, cookies, tokens, unrelated PII and unrelated tenant/customer content. Preserve uncertainties introduced by redaction. Redaction reduces exposure; it does not prove anonymity.

Require no-training/no-content-logging settings and eligible zero-data-retention routes, including the fallback. Account-specific residency constraints must match the actual endpoint; no residency promise is inferred from a model name. If no compliant route exists, retain local investigation and queue AI tasks rather than silently weaken policy. Screenshots require explicit capture permission, local preview/redaction and the same egress policy. No raw screenshot fallback to a text-only model. Content logging and provider caching must conform to the selected policy; ZDR can still permit transient provider caches, so disable provider caching when stricter confidentiality requires it.

## 4. $20 monthly budget and compression

Treat $20 as the user's monthly spending envelope; OpenRouter API usage consumes credits and is not assumed to be an unlimited subscription. Default dispatch allowance is $18 per calendar month with $2 headroom for fees, price estimation and reconciliation. Never auto-top-up. Where supported set an upstream account/key cap too; deployments sharing a key must share the ledger or use dedicated capped keys. User settings can lower the ceiling; raising it is an explicit administrative decision.

Default UTC pacing: at most $0.50 per day, $0.05 per investigation, two simultaneous provider calls, six provider calls per investigation (all retries/escalations/fallbacks included), two transport retries, 15-minute investigation slice. Show the reset timezone in settings. For each call default to 8,000 input and 1,500 total output/reasoning tokens; any exception must fit the same cost reservation and overall caps. Model-specific token accounting must count billable reasoning, cached inputs and multimodal usage.

Reserve worst-case priced cost transactionally before dispatch against tenant/month/day/case limits; reconcile actual usage afterward. Unknown charge outcomes retain their reservation until reconciliation. Restart, concurrency, cancellation and fallback cannot reset the ledger. Unknown/stale prices, unbounded usage or missing cost evidence stop new paid dispatch. No spending has been executed or account subscription verified by this documentation change.

Compression means local semantic extraction, deduplication, changed-field updates, bounded evidence retrieval and source-linked rolling summaries. Keep raw evidence local; retain hashes, identifiers, decisive event details and contradiction references. Bound any model-assisted summary cost inside the same ledger. Cache only within current tenant/case/scope and invalidate revoked, expired or superseded sources. Never discard a contradictory observation to fit context. Measure tokens, spend and quality before/after compaction. Quantization/distillation is a separate model-hosting choice, not something Gabriel can apply to a hosted provider model.

On budget exhaustion pause AI reasoning with an explicit gap and retained case state; do not claim monitoring or assurance continues at full capability. Deterministic source-health and admitted local functions can continue.

## 5. Autonomy, roles and retention

The owner's desire for all modes covers observation, autonomous admitted read-only investigation, Gabriel-local drafts and engineer-approved response as the product roadmap. R1 remains investigative. R3 admits concrete actions individually after exact target/parameter/effect/recovery tests; broad mode selection is not blanket action approval.

Trust engineers and minimize onboarding friction: local initial owner establishes the tenant, and engineers declare their operational role for the profile. Enforced permission grants derive from that owner's assignments and verified membership, not an arbitrary self-declared label or browser text. One person can hold ordinary operational roles; show that explicitly. Retain existing high-impact approval separation. Do not describe self-review as independent security or UAT review.

Retention is a tenant-admin configuration feature with separate evidence, case, audit, memory and backup policies, preview of effects, hold protection and audit of changes. Proposed lab defaults: evidence/cases 30 days, audit 90 days, backups 7 days, reviewed memory up to its existing 30-day maximum with configurable shorter TTL. Configure customer policy during onboarding. Backups and holds can delay physical erasure; display this accurately. Memory forget/reset excludes retrieval; evidence purge is a distinct controlled process.

## 6. Lab corpus and quality targets

Build a versioned manifest of at least 60 scenario families: 20 attack, 20 benign lookalike and 20 visibility/integrity/adversarial-input families. Use reproducible lab-generated artifacts and selected public OTRF Security-Datasets artifacts only after verifying each pinned artifact's license, redistribution rights, hash and provenance. The public repository has inconsistent license references; check actual files at the selected revision. Do not include customer/third-party live target data. Generated lab data is explicitly labelled and never presented as observed production telemetry.

Split by scenario family, capture and entity lineage: 30 development, 10 validation and 20 held-out; preserve class balance as far as counts permit and publish exact composition. Near-duplicates cannot cross splits. Lock held-out labels away from model prompts, tuning, retrieval and learning. Record expected evidence, benign alternatives, missing sources, acceptable abstention, escalation and forbidden actions. Include credential attacks, suspicious process/persistence, lateral-movement indicators, network egress, normal admin/patch/backup tasks, duplicate forwarded events, time skew, UI drift, logout, partial pages, injection, poisoned memory and provider outages. Browser console replay and imported telemetry must both retain their actual source provenance.

Initial engineering acceptance targets, to be ratified by an analyst before release: zero unauthorized actions, cross-tenant disclosure, login attempts or policy/budget bypasses; all seeded critical attack families escalated as suspected/confirmed or explicitly urgent-inconclusive; at least 90% attack-scenario escalation recall and no more than 10% false escalation on benign scenarios; 100% explicit reporting of seeded visibility gaps; all material claims source-linked; budget adherence under concurrency/restart. Report class denominators, confidence intervals, severity, abstention rate/coverage and every failure. Abstention never counts as successful detection or a benign finding. The small corpus is an engineering gate, not statistical proof of field effectiveness.

Measure baseline and assisted analyst minutes, time to first useful assessment, interruptions and p50/p95 latency/cost. Tentative target: 25% lower median active analyst time without worsening critical-miss rate. No workload benefit claim before actual paired human measurements. Pilot operator assigns actual UAT/release/escalation owners during onboarding. In-product urgent queue/banner is the initial destination; no guarantee an unattended browser delivers external notifications.

## 7. Selected five defensive and five IR components

This is a coverage-based initial selection, not a universal industry ranking or a claim of working integrations. Exact versions, licenses/dependencies, maintainers, resource limits and health/upgrade behavior must be pinned per admitted integration. Components are optional profiles or external installed tools; do not install all ten in the core image.

| Category | Component | Initial supported integration objective |
| --- | --- | --- |
| Defensive | Wazuh | Read-only alert/endpoint/control observations in approved browser pages |
| Defensive | Suricata | Import approved EVE JSON alerts/network events, passive IDS only |
| Defensive | Zeek | Import approved connection/DNS/TLS logs with source/time lineage |
| Defensive | osquery | Import results of already approved endpoint query packs; no arbitrary remote SQL |
| Defensive | Sigma / pySigma | Versioned detection rule interpretation and local draft translation; no automatic deployment |
| IR | Velociraptor | Inspect previously collected artifact/hunt results; collection/response requires separate admission |
| IR | Timesketch | Read timelines and correlate linked events without third-party edits |
| IR | Plaso | Parse lawfully provided artifacts in isolated, resource-limited jobs; ingest timelines |
| IR | Autopsy / The Sleuth Kit | Import exported forensic findings/reports; native desktop control is not supplied by a browser extension |
| IR | DFIR-IRIS | Read existing incident context; draft case handoff inside Gabriel; external case writes are later approved workflows |

Start with Wazuh and DFIR-IRIS browser journeys and Suricata/Zeek result imports; add the remainder progressively in R2. A log parser or detection format is not a browser console; use the appropriate import/local worker contract. Installing agents, acquiring evidence or changing external configuration requires the deployment owner's normal setup process.

## 8. Implementation order and test obligations

Each loop: requirement and threat review; implement real persisted behavior; targeted negative/regression tests; repair and rerun affected gates; capture source-specific evidence; update status. Preserve pre-release human UAT and post-release regression/UAT as distinct gates. A documentation pass cannot close any runtime gate.

| ID | Requirement | Dependencies and acceptance scenario |
| --- | --- | --- |
| GAB-041 | Docker-first and Ubuntu-guest deployment | R1; PD-01 fresh install, upgrade/rollback and restore with paired external workstation |
| GAB-042 | Six browser/OS combinations | R1; PD-02 Chrome/Brave on Windows/macOS/Linux, current permissions, suspension, disconnect and certificate behavior |
| GAB-043 | Inferred console identity with bounded admitted capabilities | R1; PD-03 unseen/rebranded console, ambiguous account, UI drift, hostile page and unsupported operation |
| GAB-044 | Confidential model egress and preserved-semantic compression | R1; PD-04 redaction/correlation/contradiction equivalence and token/cost measurement; PD-05 policy-preserving fallback/no eligible endpoint |
| GAB-045 | Durable $20-envelope pacing | R1; PD-06 concurrent reservation, restart, cancellation, retries, duplicate billing reports, month boundary and price change |
| GAB-046 | Configurable lifecycle and reproducible corpus | R1; PD-07 retention/hold/backup/restore; PD-08 manifest rights/hashes/split leakage and hidden-label scoring |

PD-09 covers actual selected integrations one at a time; PD-10 covers verified role assignment, solo operation, denied self-grant and exact R3 action approval/reconciliation. These are planned scenarios, not executable tests already delivered.

Next dependent implementation is C07: durable coordinator/model policy and spend admission, then tested real provider routing after normal private account configuration. Build the labelled lab corpus alongside it; then console recognition/adapters and packaging. Provider dispatch must not be replaced by canned responses. Windows/macOS and VM journeys need their actual environments before support can be accepted.

## 9. Primary research references

Checked 20 October 2026; revalidate before enabling or shipping.
- https://openrouter.ai/google/gemini-2.5-flash-lite
- https://openrouter.ai/google/gemini-2.5-flash
- https://openrouter.ai/pricing
- https://openrouter.ai/docs/guides/features/zdr
- https://openrouter.ai/docs/guides/features/guardrails/overview
- https://build.nvidia.com/nvidia/nemotron-3-super-120b-a12b
- https://documentation.wazuh.com/current/getting-started/index.html
- https://suricata.io/features/
- https://docs.zeek.org/en/current/about/what.html
- https://github.com/osquery/osquery
- https://sigmahq.io/
- https://docs.velociraptor.app/docs/overview/
- https://github.com/google/timesketch
- https://plaso.readthedocs.io/en/latest/
- https://github.com/sleuthkit/autopsy
- https://github.com/dfir-iris/iris-web
- https://github.com/OTRF/Security-Datasets
