# Gabriel — Project Memory and Next Steps
**Updated:** 10 November 2026  
**Repository:** https://github.com/emporiumtrading/redamon  
**Default branch inspected:** `master`

## Product and architecture
Gabriel (formerly RedAmon) is a defensive investigation workbench. The product uses a Docker-first deployment, encrypted case/evidence storage, a browser companion with explicitly approved tab/session scope, twelve bounded specialist roles, and mandatory Hermes supervision for autonomous case orchestration. Provider credentials remain user/organization controlled and encrypted; tool services are isolated from provider credentials, database access and evidence volumes.

## Verified implementation present in the repository
- Twelve specialist role identities and persisted typed local review kernels exist. Their outputs are bounded, source-linked, historical assessments, not proof of attacker activity or qualified AI decisions.
- Specialist AI agents have separate role prompts/configuration identities, permitted local read tools and bounded reasoning loops.
- Hermes is the required supervisor for autonomous orchestration. It selects up to four eligible specialists and shares a single investigation budget/call ceiling with them.
- Packaged investigation tools include source verification, local rule review, timeline inspection, reviewed-memory availability, YARA file-pattern analysis, offline PCAP parsing with dpkt, normalized JSONL correlation, typed-fact correlation, exposure prioritization and installed-tool inspection.
- Runtime skill text is packaged and bound to model configuration digests.
- Personal OpenRouter keys and organization keys are separately scoped. NVIDIA vault storage does not mean NVIDIA inference is implemented.
- Production qualification remains closed. No specialist or Hermes configuration should be treated as production-admitted merely because a key works, a skill exists, or software tests pass.
- Existing documentation describes Docker gates, x86/ARM coverage, restart/restore checks, generated-data UI evidence and the remaining live-model, held-out quality, real-console, native Mac, operational/security and release acceptance gaps.

## Important distinctions and guardrails
1. A specialist role, a deterministic local review, an installed tool, a packaged usage skill, a model-enabled configuration and a production-qualified capability are different states.
2. Skill catalog entries are candidate capability definitions until code, tests and acceptance evidence prove implementation.
3. No arbitrary shell, package installation, external search, credential access or remediation is granted to a specialist by adding a skill.
4. Response/remediation recommendations do not authorize external effects. Every action requires exact human authorization and verification.
5. Evidence references and hashes verify stored-byte consistency, not source authenticity or semantic truth.
6. Agent agreement is not independent corroboration. Missing/stale/incomplete visibility must remain explicit.
7. Do not run host pytest; use the repository's documented Docker test gates. Never place live target data, credentials or customer evidence in code/tests/fixtures.

## Work completed in this update
- Inspected the actual GitHub repository and current specialist, tools, Hermes, skills-management and production-readiness documentation.
- Added a specialist skill expansion design document defining 240 additional candidate skills (20 per specialist), a reusable skill contract, permission/evidence boundaries and role-specific acceptance criteria.
- Added this project memory file to the repository.

## Next work — ordered
### 1. Convert selected candidate skills into executable modules
Do not activate all 240 at once. Select a small, evidence-backed first tranche from existing tool paths and high-value analyst workflows. For each module:
- assign a stable skill ID, owner specialist, version and trigger;
- define strict typed inputs, required source artifacts and provenance checks;
- specify the existing permitted tool(s), limits and no-go actions;
- define an investigation procedure and bounded typed output;
- add positive, negative, adversarial and regression tests;
- bind skill/tool/source versions into the configuration digest;
- update packaged skill manifest and role assignments;
- run the relevant Docker gates on supported architectures.

### 2. Extend test corpus and qualify
Build independently sealed development/validation/held-out scenarios with benign lookalikes, missing visibility, conflicting evidence, stale data and critical cases. Use independent analyst adjudication. Do not use authored development examples as held-out qualification evidence. No production admission until the exact configuration passes its full gates.

### 3. Validate real environment semantics
Continue authorized Wazuh and DFIR-IRIS lab acceptance, approved browser-tab visibility, source freshness, attack-chain correlation, latency measurement and analyst UAT. Keep simulated fixtures separate from real-console evidence.

### 4. Close release gates
Complete native Mac UAT, operational/security review, final image scanning/SBOM/dependency provenance, retention/purge and key-custody review, backup/restore and rollback evidence, resource/cost measurements, and release-owner sign-off.

## Current status statement
The repository contains meaningful specialist and Hermes infrastructure, but the expanded 240-skill catalog is a design backlog, not 240 implemented capabilities. The next engineering step is a small, tested tranche integrated into the existing runtime skill/tool manifest without weakening current isolation, evidence, authorization or qualification controls.


## 13 November 2026 implementation update (feature branch)

Source changes prepared for review on `feature/gabriel-grounded-skills-20261113`:
- `gabriel/identity/grounded_skills.py`: five bounded pure local review kernels.
- `gabriel/identity/investigation_tools.py`: role-bound dispatch, explicit tool catalog and skill/configuration digest inclusion, toolkit v2.
- Five packaged runtime `SKILL.md` files under `gabriel/identity/investigation_skills/`.
- Generated-only behavior, negative/role-bound contract and PostgreSQL/custody integration tests under `testing/gabriel_identity/`.
- `docs/readmes/GABRIEL_KNOWLEDGE_GROUNDED_AGENTS_ROADMAP.md`: public University of Oslo research inspiration, OCSF/STIX/MITRE references and future graph/normalization/evaluation plan.

The first tranche reuses current typed facts. Repeat candidates are **not** cross-source event deduplication; window overlap is **not** clock validation or causality; detection-test disagreements are **not** proven versioned regressions. No external action or model activation is added. Test and merge outcomes must be checked on the exact proposed branch before updating any production claim.

### Next engineering gate
Run and record PR checks for identity component, investigation-tool contract and supported architectures. Repair failures before merge. Revalidate the exact runtime skill hash and model-qualification records, then conduct authorized lab and native Mac UAT. The feature branch itself does not make Gabriel production ready.
