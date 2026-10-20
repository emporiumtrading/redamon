# Gabriel — The Defender

## Product Requirements Document

Version **1.2** · 20 October 2026
Product owner: **Prof. Iyobosa Ero**  
Source repository: **emporiumtrading/redamon**  
Status: **Engineering specification for review; product implementation and acceptance are pending.**

This PRD converts the Gabriel conversion and testing plan v1.5 into a product contract. It defines outcomes, scope, requirements, acceptance evidence, delivery dependencies and bounded engineering loops. The accompanying [conversion and test plan](GABRIEL_CONVERSION_AND_TEST_PLAN.md) retains the detailed repository map and test catalog. This PRD governs product scope and release decisions; the companion supplies implementation and test detail. Any conflict must be resolved explicitly before implementing the affected requirement.

## 1. Product decision and problem

Gabriel is a defensive security and incident-response assistant for a team of one or two security engineers. It understands the authorized environment, actively investigates signs of an attacker, correlates evidence across existing security consoles, maintains its own cases, and prepares decisions for the engineer. It improves through verified environment memory, analyst corrections and reviewed knowledge updates.

The first release works through a Chrome or Brave extension on user-authorized security-console pages. Vendor API access is not required. Gabriel is vendor agnostic: Splunk, CrowdStrike and Palo Alto are examples, not required products or a fixed pilot shortlist. Discovery selects actual console workflows by defensive need, with exact products, versions, roles and paths recorded. Shared browser/evidence/task contracts must not depend on a named vendor; reviewed adapters provide workflow-specific compatibility. Vendor agnostic does not mean universal screen compatibility.

Small teams currently have to move between consoles, reconstruct timelines, distinguish genuine incidents from benign changes, document evidence and decide what to do. Gabriel should reduce that coordination burden while preserving the engineer's control and making visibility gaps explicit. It may uncover correlations the analyst missed, but that benefit must be measured rather than assumed.

### 1.1 Non-negotiable product principles

- Defensive purpose must be enforced in the deployment, policy and tool boundary; changing RedAmon's name or prompts is insufficient.
- Independence means vendor-independent investigation and case management. It does not mean detecting activity without accessible evidence.
- External-system sign-in is human-only. Gabriel must never authenticate to consoles, complete SSO/MFA/CAPTCHA, enter or retrieve credentials, extract session material, or silently restore an external session. Gabriel's own user authentication and internal worker credentials are separate trust boundaries, not authority to log into external systems.
- Gabriel can independently perform delegated read-only investigation. Consequential response remains governed by explicit engineer consent and policy.
- Evidence quality, incident urgency, confidence and authorization are distinct. None substitutes for another.
- Security effectiveness and compliance coverage are assessed separately. Neither proves the other.
- A working feature uses real persisted state and supported interfaces. Stubs, mocked connectors and invented live telemetry do not count as delivery.
- Product learning cannot silently change permissions, execute new code or suppress suspicious activity.
- A conclusion cannot be forced to 1.0 certainty. Unknowns and contradictions remain visible, and credible threats are escalated without waiting indefinitely for certainty.

### 1.2 Verified starting point

On 17 October 2026 the fork's `master` points to `34ab441647779a9c16580379f4f2d76e32002e0e`, the original reviewed RedAmon snapshot. Its complete default-branch tree contains no Gabriel PRD or conversion plan. The repository pull-request listing was empty at inspection. Earlier local prototypes are not verified shipped work. This documentation change does not establish that any Gabriel runtime exists.

The saved review identifies useful orchestration, graph, UI, triage, knowledge and remediation foundations. It also identifies authorization, secret storage, audit, execution-boundary and approval concerns that must be reproduced and resolved before reuse. Do not treat the source review as a penetration-test result against a deployed Gabriel service.

## 2. Users, jobs and success measures

| User | Primary job | Successful outcome |
| --- | --- | --- |
| Solo security engineer | Understand coverage, investigate urgent activity and decide next steps | A prioritized queue, attributable evidence, manageable interruptions and a clear decision request |
| Two-person defense team | Divide investigations and transfer ownership | Shared case history, no duplicate browser actions, clear handoff and accountable decisions |
| IR lead or authorized reviewer | Assess impact and approve a response | Exact target, evidence, proposed effect, recovery limits and independently verified result |
| Administrator | Configure tenant, permissions, model routes, retention and recovery | Enforced scope, visible health, revocation, auditable settings and tested restore |
| Read-only stakeholder | Understand incident status and residual risk | Plain-language report with evidence limitations and no response privileges |

Baseline the pilot before measuring improvement. Record analyst active minutes per investigation, time to useful assessment, false alarms, missed incident scenarios, interruptions, unresolved visibility gaps, cost and recovery time. Report workload, sample size and uncertainty with comparisons. Do not claim that two engineers can handle any organization's incident volume.

## 3. Release scope and priority

Every requirement below is mandatory for the release stated in its row. Optional integrations become mandatory to test once enabled. Later-release requirements are out of scope for R1 acceptance, not optional safety controls.

| Release | User-visible outcome | Exit boundary |
| --- | --- | --- |
| R0: foundations | Secure defensive deployment and trustworthy data/action contracts | No customer feature readiness claim |
| R1: browser-first pilot | Selected console observations, proactive hunts, five specialists, control profile, cases/evidence, validated environment memory | Read-only investigation and Gabriel-local drafts; no vendor API dependency |
| R2: investigation depth | Remaining specialist workflows, reviewed detection work and selected optional defensive integrations | Each role/tool supported only after its own acceptance |
| R3: controlled response | One approved response workflow with reconciliation and recovery | No blanket autonomous containment |
| R4: managed operations | Multi-customer operations, quotas, distribution and support | Demonstrated tenant isolation and declared operating capacity |

R1 explicitly excludes exploitation, credential guessing, external-system authentication, reverse shells, arbitrary shell/code execution, stealth, unrestricted browsing, automatic new query-program authoring, third-party draft entry, automatic rule changes and autonomous containment. It also excludes universal console compatibility, automatic model retraining, mobile extensions and claims of uninterrupted browser-only monitoring. Human-only external authentication remains an invariant in later releases, including approved response workflows.

## 4. End-to-end product journeys

### 4.1 Onboard and understand

The engineer authenticates to Gabriel, selects the organization, pairs the extension and sees the processing policy. They sign into security consoles themselves, including MFA, and authorize selected tabs/pages/accounts and a bounded task. Gabriel records visible systems, assets, owners, security controls, available telemetry, maintenance context and gaps. It presents an Environment and Control Profile for correction.

The extension observes and navigates only that approved browser session and explicitly approved associated tabs. A popup, child tab, new account, redirect or newly opened console gains no authority by association: validate/grant it before access. On logout, sign-in redirect, authentication challenge, lost permission or ambiguous account state, stop that console's collection/dispatch, show the visibility gap and ask the engineer to restore access manually. Never click sign-in/SSO/identity-provider controls or replay external cookies/tokens. Resume only after the engineer restores access and scope/account/document checks pass; require renewed approval for changed context.

Each control has an explicit evidence state: reported; observed in UI; configuration observed; operating with recent telemetry; effectiveness validated in an approved test; or unknown/stale. These are evidence distinctions, not an automatic maturity ladder. Configuration alone must never be described as effective protection.

### 4.2 Proactively investigate a possible attacker

Without requiring a vendor alert, Gabriel chooses a supported hunt from the approved playbook set, evaluates the environment context and runs existing authorized searches or filters. It correlates entity identifiers, timestamps and source lineage across consoles. It tests benign alternatives, records contradictory evidence, creates or links a case, and issues a qualified assessment with the next useful step.

Repeated views of the same forwarded event do not count as independent corroboration. If no useful evidence remains, a console becomes inaccessible, or the time/query/cost budget expires, Gabriel pauses with the exact unresolved question. Credible urgent indicators still generate an escalation within the configured channel and policy.

### 4.3 Draft and decide

Gabriel prepares the investigation conclusion, response proposal or request for a new query inside its own workspace. The engineer can inspect source evidence, correct scope, accept or reject the proposal and record the decision. R1 never enters a draft into a third-party form that might autosave. R3 adds exact-action approval and verified execution only for admitted response workflows.

### 4.4 Recover and learn

Gabriel compares the observed outcome with the earlier assessment, retains unresolved risk, and proposes a source-backed lesson. Validated environment facts can enter tenant memory under the memory policy. Changes to executable behavior, playbooks, prompts, models or adapters require versioned evaluation and release gates. A dismissed alert alone is not a verified benign outcome.

## 5. Functional requirements and traceability

Requirement identifiers are stable. A work item must cite at least one requirement and its applicable tests. Test IDs refer to the companion plan; new PRD-specific cases are defined in section 12. An ID mapping is a design obligation, not proof that executable tests exist.

### 5.1 Defensive foundation and data

| ID | Required behavior | Release / owner | Acceptance references |
| --- | --- | --- | --- |
| GAB-001 | Inventory every inherited entry point, tool, prompt, preset, route, job, image, listener and credential path; record retain/redesign/isolate/remove disposition and evidence | R0 / engineering lead | D-T01, T01, T02 |
| GAB-002 | Build a distinct defensive runtime with default-deny typed capabilities; excluded offensive operations must be unreachable through UI, API, MCP, jobs and specialists | R0 / platform lead | T01, T02 |
| GAB-003 | Derive tenant/user/project authority from verified authentication and membership; scope REST, streams, jobs, graph, caches and exports | R0 / security lead | T03, T04, T30 |
| GAB-004 | Persist accounts and roles in the database; store password hashes if local authentication is used; encrypt provider/connector secrets with separately controlled keys; never store plaintext admin passwords | R0 / backend lead | T04, T05, P-T01 |
| GAB-005 | Require durable authorization and audit intent before mutation; fail closed on missing mandatory configuration or audit admission failure | R0 / security lead | T04, T06 |
| GAB-006 | Make PostgreSQL authoritative for cases, tasks, action/approval state and scoped memory; use evidence storage for approved artifacts and a rebuildable graph projection | R0–R1 / backend lead | T11, T12, T17, T19 |
| GAB-007 | Preserve observation lineage, source/event/observation times, parser/adapter version, completeness, redaction, hashes and custody where applicable | R1 / evidence lead | T11, T13, T14, T16 |
| GAB-008 | Support fresh install, repeatable migrations, backup/restore and reconciliation of evidence and external action effects | R0 onward / platform lead | T10, T12, T32 |

### 5.2 Browser Companion

| ID | Required behavior | Release / owner | Acceptance references |
| --- | --- | --- | --- |
| GAB-009 | Ship a reviewed packaged extension for desktop Chrome and Brave, with visible organization, sharing state, task, scope, Pause, Stop and Disconnect | R1 / extension lead | B-T01, B-T12, B-T14 |
| GAB-010 | Scope collection/action to selected origin, path, tab, document/frame, account, task and expiry; revalidate after navigation and account changes; associated/new tabs require explicit admission | R1 / extension + security | B-T02, B-T03, B-T06, B-T28 |
| GAB-011 | Minimize rendered semantic page content before upload; exclude passwords, OTPs, hidden fields and storage/token scraping; screenshots need explicit permission and safe preview/redaction | R1 / privacy + extension | B-T04, B-T13, B-T20 |
| GAB-012 | Pair only to the approved authenticated Gabriel endpoint; validate sender/schema; page content must not forge approvals or access extension tokens | R1 / security lead | B-T05, B-T06, B-T15 |
| GAB-013 | Complete supported vendor-agnostic investigations through engineer-authenticated approved console tabs with all direct vendor API credentials/integrations absent; no required brand or autonomous external sign-in | R1 / integration lead | B-T17, B-T21, B-T27, B-T28 |
| GAB-014 | Execute existing approved read-only searches, filters and validated template parameters; refuse new query programs, saved-search edits, rule writes, scheduling and side-effecting queries in investigative mode | R1 / integration + security | B-T09, B-T22 |
| GAB-015 | Keep proposed queries, response drafts and rule changes inside Gabriel; no third-party field entry or autosave in draft mode | R1 / product + extension | B-T23 |
| GAB-016 | Use vendor-neutral shared contracts, reviewed site adapters and finite typed operations; reject remote code, arbitrary requests, external login/SSO/MFA/session replay and unsupported operations; unknown sites permit only admitted limited observation | R1 / extension lead | B-T09, B-T13, B-T15, B-T27, B-T28 |
| GAB-017 | Serialize actions with per-tab leases; check current account/target/state before each operation; re-observe to verify; refuse ambiguous or stale targets | R1 / extension lead | B-T08, B-T10 |
| GAB-018 | Survive service-worker suspension and reconnect safely; revalidate scope/freshness; authentication walls require human handoff, never autonomous login; show missing-coverage periods; no blind repeat of uncertain side effects | R1 / extension + backend | B-T07, B-T11, B-T12, B-T28, T15 |
| GAB-019 | Version extension/backend/adapter compatibility; inspect permission changes and package provenance; support revocation and documented upgrade recovery | R1 baseline, R4 managed / release lead | B-T14, B-T19 |

### 5.3 Investigation and analyst experience

| ID | Required behavior | Release / owner | Acceptance references |
| --- | --- | --- | --- |
| GAB-020 | Build the Environment and Control Profile with evidence states, ownership, coverage, authority, recovery dependencies, discrepancies and freshness | R1 / product + analyst | D-T02, B-T16, B-T17 |
| GAB-021 | Proactively choose and run scoped hunts without waiting for an alert; test benign explanations and stop when evidence or budgets are exhausted | R1 / AI + analyst | L-T01, L-T02, B-T26, D-T03 |
| GAB-022 | Maintain cases, entity/time relationships, evidence timeline, assignments, reports and unresolved questions in Gabriel; deduplicate underlying observations across tools | R1 / full-stack lead | T14, T16–T19, B-T25 |
| GAB-023 | Publish evidence-linked claim-level assessments; allow downward revision, abstention and urgent suspected-threat escalation; never assert absolute certainty or universal absence of attackers | R1 / AI + analyst | T20, T21, B-T24–B-T26 |
| GAB-024 | Provide one prioritized queue, correlated bundles, concise handoffs, approval inbox and visible operating state; batch routine items and distinguish urgent escalation | R1 / product lead | T18, L-T08 |
| GAB-025 | Deliver all in-scope screens with loading/empty/partial/error/denied/disconnected states, accessible controls and real persisted results | R1 onward / full-stack + QA | T18, T19, P-T04 |
| GAB-026 | Present exposure, incident urgency, evidence confidence and compliance mappings separately | R1 / product + analyst | T33, D-T02, D-T03 |

Required R1 screens: sign-in/team scope; operations overview and coverage gaps; investigations/case queue; incident detail and timeline; assets/identities/control profile; evidence and custody; browser sessions and source health; memory review/corrections; settings/model routes; audit; reports; and proposal review. Execution controls stay unavailable until their response backend is accepted. Every screen's controls and subpages enter the UAT inventory.

### 5.4 AI, learning and integrations

| ID | Required behavior | Release / owner | Acceptance references |
| --- | --- | --- | --- |
| GAB-027 | Implement twelve specialist contracts progressively; R1 includes health, triage, scoping, intelligence and proactive hunting; each enabled role needs real tools and evaluation evidence | R1/R2 / AI lead | T22, L-T01, L-T02 |
| GAB-028 | Coordinate specialists through bounded tasks with cost/time/step limits, cancellation, duplicate suppression, explicit disagreement and a shared policy-controlled browser gateway | R1 / AI + backend | T20–T22, T29, B-T08, B-T26 |
| GAB-029 | Support configurable approved model routing, including an NVIDIA-backed option alongside OpenRouter where validated; fallback must preserve residency, privacy, capability, budgets and evidence quality | R1 for enabled routes / AI + security | T05, T21, T22, B-T20, P-T02 |
| GAB-030 | Start with versioned analyst-reviewed defensive playbooks covering the named hunt domains, evidence criteria, benign alternatives, permissions, escalation and review dates | R1 / detection + analyst | L-T01, L-T02, D-T03 |
| GAB-031 | Learn tenant-specific environment facts and verified corrections with source, timestamps, expiry, sensitivity and supersession; offer inspect/correct/delete/reset controls subject to retention | R1 / backend + analyst | L-T03, L-T05, P-T03 |
| GAB-032 | Prevent memory poisoning, cross-tenant learning, automatic suppression from dismissals and gradual attacker normalization; separate facts/preferences from permissions and executable behavior | R1 / security + AI | L-T04–L-T06, T20 |
| GAB-033 | Promote playbook/model/prompt/adapter changes only through independent evaluation, versioned rollout and rollback; no automatic customer-session weight training | R1 onward / AI + release | L-T07, B-T15, B-T19 |
| GAB-034 | Admit optional defensive integrations individually with real-version contracts, narrow credentials, health, limits, owner, license review and upgrade tests | R2 onward / integration lead | T13–T15, T23, T24 |
| GAB-035 | Keep an approved code fix or detection change unverified until deployed state and relevant behavior are checked; isolate remediation work from production authority | R2 / remediation lead | T24, T25 |

### 5.5 Response, operations and release

| ID | Required behavior | Release / owner | Acceptance references |
| --- | --- | --- | --- |
| GAB-036 | Bind approval to immutable target/account/parameters/policy/version/expiry; separate requester/approver/executor; prohibit self-approval for high-impact actions | R0 contract; R3 use / security + IR | T07, T08, T27, B-T10 |
| GAB-037 | Persist state transitions and idempotency; reconcile unknown effects after timeout/crash; independently verify outcomes and recovery | R0 contract; R3 use / response lead | T09, T10, T26–T28, B-T18 |
| GAB-038 | Enforce Stop/kill switch/revocation at dispatch; preserve in-flight reconciliation and evidence; require explicit consent for consequential external action | R1 stop; R3 response / security + IR | T27, B-T11, B-T12, B-T18 |
| GAB-039 | Operate within declared capacity, cost and recovery limits; distinguish optional connector continuity from browser-session visibility | R1/R4 / platform lead | T15, T29, T30, D-T04, L-T08 |
| GAB-040 | Apply SSDLC, requirement traceability, bounded repair loops and G0–G5 release gates; pre/post-release UAT and regression are mandatory | All releases / engineering + release | T31, T32, T34, P-T05, P-T06 |

## 6. Twelve-specialist operating model

Twelve roles are not twelve required simultaneous models or a verified count of RedAmon providers. Enable a role only when its input contracts, permissions, tools and quality tests exist.

| Role | Responsibility | First release |
| --- | --- | --- |
| 1. Telemetry health | Detect stale sources, missing coverage and collection gaps | R1 |
| 2. Alert triage | Prioritize supported observations and explain uncertainty | R1 |
| 3. Incident scoping | Correlate identities/assets/time and distinguish unknown scope | R1 |
| 4. Threat intelligence | Enrich from vetted, attributable, current information | R1 |
| 5. Threat hunting | Generate hypotheses and choose the next permitted existing search | R1 |
| 6. DFIR evidence | Coordinate approved collection and preserve custody/timelines | R2 |
| 7. Detection engineering | Draft, validate and review versioned detections | R2 |
| 8. Exposure/vulnerability | Prioritize reachable exposures without assuming compromise | R2 |
| 9. Identity/access | Investigate privilege, authentication and session activity | R2 |
| 10. Cloud/container/supply chain | Correlate configuration and component risk to deployments | R2 |
| 11. Response/remediation | Prepare impact-aware response plans; execute only through R3 gates | R2 proposals; R3 execution |
| 12. Recovery/learning | Verify recovery and propose validated lessons | R2 specialist; foundational memory in R1 |

The shared output contract includes observations, evidence IDs, source times, hypotheses, alternatives, contradictions, uncertainty, proposed next step, model/prompt/tool versions and cost. Store concise decision/evidence records rather than private chain-of-thought. Multiple agents repeating the same inference are not independent evidence. A coordinator may request more evidence or escalate disagreement; majority voting cannot authorize an action.

## 7. Browser and backend architecture contract

Use a shared Manifest V3 extension codebase, packaged site adapters, an extension-owned panel/page, and an authenticated Gabriel browser-session gateway. The browser is a scoped observation and interaction surface. Deterministic backend policy remains authoritative for permission and action admission.

The implementation must enforce these boundaries:

1. **User to extension:** explicit selected-page/task delegation; no silent all-sites grant. Login, MFA and privileged credential entry stay user-managed.
2. **Page to extension:** page text/messages are hostile input. Validate schemas and sender/document context; sanitize content and URLs. Page instructions cannot become policy.
3. **Extension to Gabriel:** authenticated HTTPS, approved endpoint, short-lived scoped session, revocation and membership checks. No vendor or model secrets in content scripts or extension packages.
4. **Gabriel to model:** tenant-minimized evidence through approved data routes. Model output is a proposal, never an authorization token.
5. **Gabriel to stores:** scoped durable cases/actions/memory and custody, plus controlled evidence objects. Graph projection is rebuildable.
6. **Gabriel to response:** a separate admitted capability checks exact approval and current target state. Unknown effects require reconciliation.

B0 selects short-lived single-use pairing or an authorization-code/PKCE design, supported browser/OS versions, package distribution and exact console workflows. Browser operations are declarative values in a finite vocabulary, not downloaded JavaScript or a general interpreted program. Reviewed operations must account for hidden UI side effects, virtualized rows, frames, canvas and account switching.

One tab has one execution lease. After every action, the adapter re-observes and checks the expected result. Suspension/restart does not preserve assumed authority; the backend stores authoritative task/approval state and resume rechecks scope, document, account, freshness and uncertain outcomes.

## 8. Information model and security contract

Minimum entities: Organization, User, Membership, Asset, Identity, BusinessService, ControlObservation, BrowserSession, ScopeGrant, InvestigationTask, Observation, EvidenceObject, CustodyEvent, Case, Hypothesis, AssessmentRevision, MemoryRecord, PlaybookVersion, ActionRequest, Approval, ExecutionAttempt, Verification, AuditEvent and ReleaseEvidence.

All tenant data must have enforced tenant ownership at read, write, retrieval, graph and export boundaries. Observations retain event time separately from collection time and describe what was actually visible. Evidence hashes establish integrity, not the truth of a source. Normalization errors and incomplete pages remain explicit.

Case states: new → investigating → awaiting evidence/decision → resolved or closed with documented disposition. A suspected incident may be escalated at any point. Closure requires the applicable evidence/verification conditions and authorized analyst decision. Missing evidence cannot be silently converted into a benign outcome.

Action states: proposed → pending approval → approved → dispatching → succeeded/failed/unknown → verified/recovery required. Rejected, cancelled and expired are explicit terminal paths before dispatch where applicable. A timeout after submission is an unknown effect; do not blindly retry. The same idempotency key with a different request is a conflict. Provider success alone is not verified containment.

Memory records distinguish validated facts, unresolved hypotheses and explicit preferences. Store provenance, reviewer, observation/validation dates, expiry, sensitivity and supersession history. Deletion/reset must also address derived retrieval indexes and caches; retention holds and audit exceptions are disclosed. Raw session histories or credentials must not become durable model memory.

## 9. Conversion and delivery dependencies

The companion's component map is part of implementation planning. All paths must be reconfirmed against the implementation SHA. The disposition register prevents a hidden offensive import, tool dispatch path or old project setting from surviving merely because a new default was added.

| Work package | Deliverable | Acceptance dependencies |
| --- | --- | --- |
| C00 | Pin source, recover any prototypes, inventory capabilities and establish actual test baseline | None |
| C01 | Product contracts, threat model, pilot scope and decisions | C00 |
| C02 | Defensive composition and capability closure | C01 |
| C03 | Identity, tenant scoping, secrets and audit | C02 |
| C04 | Durable evidence, cases, policy/action/approval contracts | C03 |
| C05 | Browser observation intake; optional connector contracts | C04 |
| C06 | Persisted case/graph/workbench vertical slice | C05 |
| C07 | First five specialists, proactive hunting, validated baseline and memory controls | C06 |
| C08 | Read-only pilot | C07, B1 and B2 |
| C09 | Investigation depth, remaining roles and admitted optional tools | C08 |
| C10 | One controlled response workflow | C04, C08 and the selected workflow's C09 capability |
| C11 | Managed-service operations | C09, C10 and B4 for enabled browser capabilities |
| C12 / B0 | Browser threat model, permissions, protocol and console discovery | C01 |
| C12 / B1 | Pairing, selected-page observation and evidence linkage | B0, C03, C04, C06, C07 |
| C12 / B2 | Supported multi-page investigations and existing searches | B1, C07 |
| C12 / B3 | Optional approved browser response | B2, C10 and adapter-specific acceptance |
| C12 / B4 | Managed distribution, upgrades and support | B1/B2; B3 only when enabled |

C05–C07 can be developed with explicit contract fixtures; R1 acceptance requires the real B1/B2 browser path. Fixture-based development must not be reported as completed browser acceptance. Independent preparation may proceed in parallel, but prerequisite acceptance cannot be bypassed.

### 9.1 Open-source integration program

An extensible catalog replaces an untestable promise to integrate every available tool. Initial candidates are Wazuh, DFIR-IRIS, Velociraptor, osquery, Zeek, Suricata/Security Onion, OpenCTI/MISP, Sigma, YARA, Falco, Greenbone, Trivy, Prowler, Timesketch, Plaso, Volatility and a selected response provider. None is mandatory to unlock the R1 browser investigation workflow.

For each selected tool, record exact version/license, capability, deployment owner, authentication, read/write boundary, source schema, limits, evidence provenance, lab instance, contract tests, health, upgrade procedure and recovery. Source-available and open-source licenses are not interchangeable. A command wrapper or preset alone is not supported integration. Gabriel remains the canonical case store unless a later explicit authority/migration decision changes that contract.

## 10. Loop engineering: how development reaches acceptance

Loop engineering is the required development and verification process, not a promise of an endlessly self-modifying production agent. Each loop has a bounded scope, entry conditions, evidence, exit decision and escalation path.

### 10.1 L0: requirement and design loop

Decompose the requirement; identify upstream dependencies, user outcome, abuse cases and data changes. Define expected behavior and negative outcomes before implementation. Review architecture and acceptance criteria. Exit only with an owner, test mapping, scope and recovery approach. An unresolved security-critical design question blocks the affected slice.

### 10.2 L1: implementation and repair loop

1. Select one ready vertical slice and pin the source/dependency baseline.
2. Implement its real UI/backend/storage/adapter path and instrumentation.
3. Run meaningful focused checks and authorization/abuse cases in the required environment.
4. Compare expected and observed results; retain raw counts and sanitized evidence.
5. If a check fails, identify the cause, repair it and rerun the failed check plus affected regression.
6. Obtain independent review for trust boundaries and record accepted or blocked status.

After three unsuccessful repairs of the same cause, stop automated changes to that slice and escalate with the evidence, attempted fixes and precise missing input. Other independent authorized work may continue. Do not weaken tests, lower thresholds, remove an approval check or fabricate data to reach a green result. Additional attempts require a reviewed new hypothesis, not repetition until the model reports confidence 1.0.

### 10.2.1 Continue through ready dependencies

An implementation checkpoint is not a request for the engineer to say “continue.” Within the authorized conversion scope, advance from a verified slice to the next ready dependency, and use CI waiting time for independent implementation or review work. Give progress updates with findings and the next verification target. Record a real blocker when no authorized ready work remains; identify the missing evidence or decision rather than repeatedly asking permission for routine development. Independent review and human UAT may block release while other safe implementation work continues. A running CI job is not a passing gate, and ending an interactive session does not imply a persistent background engineering service exists.

### 10.3 L2: integrated release loop

Combine accepted slices into a versioned candidate. Run G1 and G2, including staging UAT and complete critical-path regression. Fix failures through L1. Review the exact artifact manifest at G3. Deploy that accepted artifact, run G4 post-release UAT/regression and complete G5 observation before closing the release.

### 10.4 L3: operational feedback and governed learning loop

Collect verified outcomes and analyst feedback; propose a fact correction, playbook update or defect. Validate provenance, tenant scope and held-out results. Promote only accepted versions through the same affected release gates. Monitor for regression and restore the last accepted configuration when required. Escaped defects become regression cases. Neither operational learning nor emergency repair may bypass deterministic policy.

### 10.5 Required loop record

For every slice record: requirement IDs, owner/reviewer, prerequisite status, source SHA, hypothesis/expected result, design decision, changed files, test commands/environment, collected/pass/fail/skip counts, evidence locations, defect cause, repair attempt count, remaining uncertainty, rollback procedure and gate result. State is one of NOT_STARTED, IN_PROGRESS, BLOCKED, IMPLEMENTED_UNVERIFIED, VERIFIED_STAGING, RELEASED_VERIFYING or ACCEPTED_POST_RELEASE. PASS, FAIL, BLOCKED, NOT_RUN and justified NOT_APPLICABLE are distinct test states.

Report implementation confidence, security confidence and operational confidence separately, with reasons. A weighted planning confidence may summarize estimates but cannot offset any failed safety or release gate. Confidence is never a substitute for the required test evidence or human UAT decision.

## 11. SSDLC embedded in each loop

| Stage | Required work | Evidence / owner |
| --- | --- | --- |
| Requirements | Abuse cases, asset/data classification, privacy, intended authority, safety invariants | Threat model and requirement links / product + security |
| Design | Trust boundaries, authentication/tenant model, secret management, approval states, data retention and recovery | Reviewed contracts and architecture decisions / security + engineering |
| Implementation | Small reviewable changes, dependency pinning, no embedded secrets, secure defaults, peer review | Reviewed diff and dependency changes / implementer + reviewer |
| Build/CI | Type/lint, required tests, SAST, dependency/license/secret/container/IaC checks, SBOM and provenance | Artifact digest and executed results / platform + security |
| Staging | Real integration contracts, browser UAT, adversarial AI/input tests, DAST, resilience and restore | Sanitized test/evaluation evidence / QA + analyst + security |
| Release | Same tested artifacts, migration/backup readiness, configuration diff and accountable approval | Release manifest and sign-off / release owner |
| Operations | Health, vulnerabilities, incidents, dependency/model changes, regression and support | Operational evidence and corrective tasks / platform + IR |

Use the companion's selected NIST SSDF and incident-response references as design guidance, not certification. Confirm reference versions when adopting the engineering baseline. Scan exceptions require an owner, expiry, rationale and compensating control. Critical tenant isolation, unauthorized action, evidence corruption or approval bypass findings cannot be waived by a score. Production secrets must not enter untrusted PR/fork jobs.

## 12. Test strategy and acceptance catalog

The companion contains **34 core cases (T01–T34), 28 browser cases (B-T01–B-T28), four conversion cases (D-T01–D-T04) and eight learning/operations cases (L-T01–L-T08)**. This PRD adds the six cases below, producing **80 acceptance obligations**. These are scenario specifications, not 80 executed automated tests. All start NOT_RUN; each requires normal, boundary and failure variants as relevant. B-T27/B-T28 add vendor neutrality and human-only external authentication; existing IDs remain stable.

| ID | Additional acceptance obligation | Required result |
| --- | --- | --- |
| P-T01 | Database-backed admin/account creation, role changes, credential reset/revocation and backup handling | Persisted identity/role changes survive restart; no plaintext password or secret exposure; unauthorized changes denied |
| P-T02 | Approved provider outage and fallback, including enabled NVIDIA/OpenRouter configurations | Data policy and budgets preserved; affected role evaluations pass; no silent fallback to an unapproved provider |
| P-T03 | Inspect/correct/expire/delete/reset memory, including retrieval caches and an active retention hold | No stale deleted fact used after the documented purge boundary; history/hold behavior accurately disclosed; tenant isolation maintained |
| P-T04 | Complete route/control inventory for each release and persona, including keyboard/screen-reader and denied/error states | Every in-scope item has an observed expected result and persisted-state check where relevant; no dead or misleading controls |
| P-T05 | A required test is missing/skipped, wrong artifact selected, or three same-cause repair attempts fail | Promotion blocked with precise status; bounded repair escalation; no weakened checks or false success |
| P-T06 | Candidate passes staging, then fails a safe production UAT/regression check or observation threshold | Expansion stops, recovery invoked as appropriate, data reconciled, failure retained and release remains unaccepted |

Test layers: unit/property; real database/object-store components; actual tool-version contracts; integrated ingestion/case workflows; packaged-browser E2E; human UAT; security/AI misuse; held-out model evaluation; performance/resilience; and affected plus critical-path regression.

Follow repository `AGENTS.md` and the testing skill before changing tests. Python tests run inside matching Docker images with per-file isolation; never use host pytest as acceptance. Existing entry points include `./redamon.sh test unit`, integration/live tiers and `./agentic/run_tests.sh`. Confirm frontend scripts in the actual checkout. Missing images, zero collected tests and required skips must block the gate rather than masquerade as green.

Deterministic labeled fixtures are permitted for isolated tests. They must never appear as customer telemetry or substitute for real-console/tool acceptance. Use authorized private lab instances for real contracts. Commit no real-world target data, credentials, captured traffic or incident evidence into the repository or PR.

### 12.1 AI and expert-baseline evaluation

Create an independently analyst-adjudicated held-out corpus covering malicious activity, benign administration, stale/incomplete evidence, entity reuse, forwarded duplicates, contradictory sources and prompt injection. Cover identity/session misuse, suspicious process ancestry, persistence, privilege changes, lateral movement, outbound/exfiltration indicators, cloud control-plane changes, application abuse, defense impairment and recovery.

Evaluate every enabled model/prompt/tool configuration. Keep tuning and held-out cases separate. Run at least five repetitions of each adversarial/ambiguous scenario and report per-scenario results, sample size and confidence intervals where meaningful. The initial triage agreement target is at least 90%, subject to pilot approval before testing; aggregate agreement cannot hide failed safety cases or missed critical scenarios. Freeze case-specific detection/false-positive and escalation criteria in C01/B0; do not move thresholds after seeing failures without a reviewed product decision and rerun.

### 12.2 UAT before and after shipping

Pre-release staging UAT includes: administrator pairing/revocation; solo engineer proactive no-alert hunt; cross-console case creation; memory correction; partial visibility/provider outage; two-person handoff; read-only stakeholder reporting; and, in R3, exact approval/effect/recovery. All relevant Chrome and Brave versions must be tested with the packaged extension and actual selected console workflows. Chromium-only automation and mock pages are insufficient compatibility proof.

Post-release UAT repeats the safe critical user journeys on the deployed versions in a dedicated authorized test scope. Confirm actual sign-in/roles, pairing/scope, observation/search, case persistence, evidence references, report access, audit, stop/revoke and health. R3 response verification uses only approved test targets. Do not run disruptive staging fault injection against ordinary customer assets. Human analyst sign-off remains required for usefulness; automated clicks alone are not UAT acceptance.

## 13. Release gates and rollback

| Gate | Required evidence | Decision owner |
| --- | --- | --- |
| G0: ready to implement | Accepted requirement, dependencies, threat/abuse cases, test mapping and recovery plan | Product + engineering |
| G1: ready for staging | Required build/tests/scans and affected regression executed; versioned candidate, migrations reviewed | Engineering + security |
| G2: staging accepted | Full in-scope UAT/regression, real contracts, browser/AI/security checks, capacity and recovery evidence | Analyst + QA + security + platform |
| G3: ready to deploy | Exact artifact manifest, configuration differences, backup/rollback readiness and release authorization | Release owner |
| G4: deployed and verified | Deployed hashes/versions confirmed; safe post-release UAT and critical regression pass | Release + analyst + QA |
| G5: accepted in operation | Proposed 24–48-hour observation completed; no blocking regression; workload and pilot acceptance recorded | Pilot owner + operations |

The manifest includes source SHA, backend image digests, extension package hash/version, adapter versions, database migration, policy/playbook/model/prompt versions, supported browser/OS/console matrix and evidence links. Relevant changes invalidate affected prior evidence. Do not test one artifact and ship a fresh untested rebuild.

Stop or rollback triggers include unauthorized execution, tenant exposure, wrong-target action, evidence corruption, unaudited mutation, unreconciled loss and failed critical post-release checks. Stop new response dispatch, preserve evidence, notify the owner and invoke the applicable runbook. Application rollback, database recovery and reversal of an external action are different operations; reconcile all effects since the recovery point. Some changes need compensating recovery rather than reversal.

G3 is not completion. A release stays RELEASED_VERIFYING until G4 and G5 pass. An extension-store update cannot be assumed instant; backend revocation/compatibility controls must provide a safe fallback.

## 14. Nonfunctional and pilot acceptance targets

These are proposed acceptance targets, not measured service guarantees. C01/B0 must freeze the actual workload, thresholds and budget before implementation acceptance.

| Dimension | Required target or decision |
| --- | --- |
| Scope | One pilot organization and one/two engineers; exact supported console workflows and browser/OS versions recorded |
| Safety | Zero unauthorized/wrong-tenant actions in required evaluations; any occurrence blocks release |
| Evidence | Every material evaluated AI claim cites attributable evidence or states its limitations; provenance/completeness preserved |
| UI responsiveness | Proposed p95 ≤2 seconds for ordinary case list/detail at declared data size, excluding model generation |
| Browser work | Freeze maximum pages, query ranges/results, concurrent tasks, task duration, observation cadence and model spend in B0; show progress/cancellation |
| Visibility | Explicit source/session health and missing windows; browser logout/closure must not imply continuing coverage |
| Optional connector load | Companion's 5 normalized events/second sustained and 50/second ten-minute burst profile applies only to enabled connector tests, never browser throughput |
| Recovery | Proposed workflow/evidence RPO ≤15 minutes and RTO ≤4 hours, demonstrated by restore and external-effect reconciliation |
| Retention | Proposed 30-day online/90-day archive evidence policy, finalized for customer needs; privacy and holds enforced |
| Accessibility | Keyboard-operable critical flows, named controls, focus management and readable error/status content verified through P-T04 |
| Small-team benefit | Compare analyst effort, interruption burden, missed scenarios and cost against measured baseline; pilot owner sets acceptance threshold before trial |

Availability, detection latency and browser capacity cannot be promised until measured in the supported environment. Record provider latency and UI delays separately from Gabriel processing. A lower-cost fallback model is not acceptable if it fails the enabled task's quality or privacy gate.

## 15. Decisions, risks and ownership

The product owner's twelve answers of 20 October 2026 and delegated selections are recorded in the normative [pilot decisions and acceptance plan](GABRIEL_PILOT_DECISIONS.md). That addendum resolves the previously open product choices and extends traceability with GAB-041–GAB-046 and PD-01–PD-10. Its defaults govern the affected requirements; adding requirements does not establish implementation or acceptance.

| Decision / risk | Current resolution | Remaining acceptance dependency |
| --- | --- | --- |
| Pilot / console agnosticism | Isolated Docker lab; Wazuh and DFIR-IRIS initial real-console journeys; general semantic discovery of unknown consoles | Actual versioned adapters, ambiguity/UI-drift tests and lab provisioning |
| Deployment / browsers | Docker Compose first; same stack in Ubuntu 24.04 LTS guest VM; Chrome and Brave on Windows/macOS/Linux | Actual install, six browser/OS journeys, recovery and measured resource limits |
| Models / confidentiality | OpenRouter Flash Lite routine / Flash escalation; NVIDIA Nemotron 3 Super fallback candidate; local redaction and policy-preserving eligible routes | Real account configuration, endpoint terms/capability/price admission, corpus evaluation |
| Spending | $20 monthly envelope, $18 dispatch allowance, $0.50 daily and $0.05/investigation defaults; durable reservations and bounded calls | Concurrency/restart/reconciliation tests and upstream account controls |
| Evaluation | At least 60 scenario families, family-disjoint development/validation/held-out split, explicit quality targets | Actual licensed/pinned corpus, hidden labels and qualified human adjudication |
| Roles / UAT | Simple owner-managed onboarding, user-declared operational profile and verified permission assignments | Named operator/reviewer/release/escalation owners at deployment; human UAT remains required |
| R3 response | Full mode roadmap retained; R1 read-only and local drafts; consequential actions admitted individually | Exact target, action, approver, effect verification and recovery tests before enabling each action |
| Retention | Tenant-admin feature; separate evidence/case/audit/memory/backup settings and holds | Persisted configuration, expiry/purge/backup tests and customer onboarding choices |
| Open-source integrations | Five defensive and five IR components selected in addendum | Per-tool version/license/provenance, health, least privilege and real workflow evidence |
| UI drift / poisoned learning | Invalidate stale capabilities; source-backed reviewed memory; uncertainty and contradictions remain visible | B-T/L-T negative tests and qualified outcome review |

Accountable roles describe responsibilities, not confirmed staffing. Engineers can hold multiple ordinary roles, with explicit ownership; user-declared labels do not self-grant privileges. Existing high-impact approval separation and truthful independent-review claims remain. Security effectiveness and compliance coverage continue to require separate assessment.

Product choices no longer require repeated clarification. Continue independent authorized engineering loops; stop only the dependent path when required account configuration, actual test environment, action-specific authority or human acceptance is absent. Do not promise a fixed delivery date or universal console compatibility before measurement.

## 16. Definition of done and handoff

A requirement is complete only when its real implementation, accepted contracts, observability, documentation, security/negative tests, applicable UAT/regression and recovery evidence exist. Shipping requirements additionally need G4/G5 evidence. The conversion register must have no unexplained inherited capability, and every in-scope route/control must be accounted for.

The first implementation increment is C00/C01: pin the actual baseline, inventory conversion scope, establish truthful test gates and resolve pilot/browser decisions. Then close defensive capability and trust foundations before exposing autonomous investigation. The end result sought is a tested defensive product, not merely a renamed pentest dashboard.

This PRD and the supporting plan are documentation deliverables. **No product tests, staging UAT, production deployment or post-release regression are represented as completed by publishing them.** Documentation validation checks requirement/test references, release consistency, dependencies and status accuracy only.

Confidence in requirement/design coverage: **high; the selected product defaults and remaining implementation/acceptance dependencies are recorded in section 15 and the pilot addendum**. Runtime effectiveness, exact console compatibility and staffing benefit: **unverified until measured**. No weighted score or repeated model review establishes factual certainty or production readiness.

## 17. Reference baseline

- [Supporting conversion and testing plan v1.5](GABRIEL_CONVERSION_AND_TEST_PLAN.md): detailed repository conversion map, 74 companion acceptance obligations, incident scenarios and browser/learning specifications.
- [Pinned repository engineering instructions](https://github.com/emporiumtrading/redamon/blob/34ab441647779a9c16580379f4f2d76e32002e0e/AGENTS.md).
- [Pinned repository testing guide](https://github.com/emporiumtrading/redamon/blob/34ab441647779a9c16580379f4f2d76e32002e0e/docs/readmes/README.TESTING.md).
- The supporting plan retains primary Chrome/Brave and NIST references with their original verification context. Recheck applicable versions and platform behavior during B0/C01 and before packaging.

Change control: new product requests must update requirement IDs, release/dependency placement, threats, acceptance mappings and affected loop/gate obligations together. Preserve earlier decisions and rationale through version control. Never mark a requested capability implemented merely because its requirement was added here.

Version 1.1 records the 18 October 2026 clarification: named security products are examples only; external-console authentication belongs exclusively to the engineer, with approved-tab/session visibility supplied by the extension. Internal Gabriel account/worker identity remains required. New browser acceptance obligations are design requirements, not claims that an extension has shipped.


Version 1.2 records the 20 October 2026 product-owner decisions, Docker/Ubuntu deployment direction, all three desktop operating systems, console recognition boundary, confidential OpenRouter/NVIDIA model evaluation candidates, $20 spending envelope, configurable retention, lab corpus plan, role onboarding and ten selected open-source integrations. See [the normative addendum](GABRIEL_PILOT_DECISIONS.md) for defaults, new requirement IDs and planned tests. No runtime or human acceptance gate is closed by this revision.
