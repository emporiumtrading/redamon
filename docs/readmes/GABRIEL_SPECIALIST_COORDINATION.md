# Twelve-specialist local plans

A local-specialist-coordinator-v2 plan binds one approved specialist-facts-v1 evidence artifact and the current case evidence vector. It schedules all twelve roles in fixed order: telemetry health, alert triage, incident scoping, threat intelligence, threat hunting, DFIR evidence, detection engineering, exposure and vulnerability, identity and access, cloud and supply chain, response and remediation, and recovery and learning.

Each role writes an independently inspectable specialist result and a coordinator receipt. The results contain source references, alternatives, uncertainty and bounded review suggestions. Missing relevant facts cause abstention. Confidence remains unqualified, attacker status remains unknown, and no model, external tool or response action is enabled. These are local rule kernels; scheduling all roles does not qualify twelve AI agents or establish complete attack coverage.

## Workbench and CLI

Open a case's Local investigation plan page, select its approved typed facts artifact, and create a twelve-specialist plan. Run remaining specialist reviews executes the bounded remaining local steps without a separate click for each role. Each result links to the specialist assessment. Run next local step remains available for inspection between steps. The original two-step metadata inventory and telemetry plan remains supported.

The private case CLI accepts coordinator-begin with --case-id, --request-id and --evidence-id. Supplying --evidence-id selects the twelve-role plan; omitting it retains the two-step plan. coordinator-complete with --run-id drains remaining local steps; coordinator-next and coordinator-stop remain available. Neither command enables provider calls.

## Authority and recovery

The actor must have current case write access. A same-case foreign key binds the input, and real encrypted input and cited source bytes are verified before a plan is created. Model-generated input or sources are rejected. The plan freezes all current case evidence IDs and digests, expires within fifteen minutes, and cannot silently adopt added or unavailable evidence.

Each specialist uses a saved request ID. A failed completion receipt can replay the already persisted specialist result without creating another review. Access, creator role, deadline, evidence scope and durable Stop are checked before each step and again before its receipt. For this plan, the specialist writer also checks admission inside its own transaction, so a Stop already recorded before that writer prevents a new result. Stop is terminal. An in-progress local transaction may finish before another transaction records Stop; existing historical results remain readable.

The synchronous drain performs at most twelve iterations. It is not a background scheduler, continuous browser monitor, or automatic lease renewal. The workbench serializes its requests; a Stop submitted through that same workbench is handled after the current request. Independent authenticated clients can record Stop between writer transactions. No long external operation is wrapped by this protocol.

## Release acceptance

Tests must verify twelve roles, exact input/result links, concurrent replay, receipt failure, authority and source loss, Stop before a specialist writer, Stop between roles, historical two-step compatibility, HTTPS/CSRF forms, atomic migration, and physical restart plus fresh restore of a partially completed plan. Docker CI provides runtime evidence; syntax checks alone do not establish acceptance.

Production work still includes qualified provider models, browser-event-to-specialist-facts normalization, admitted real console adapters, continuous observation coverage, independent quality evaluation and native deployment UAT.
