# Hermes — required Gabriel investigation supervisor

Hermes is a required service in the Gabriel Docker installation. Autonomous case orchestration goes through Hermes; an unavailable runtime or failed mandatory preflight blocks that workflow. Local evidence tools and explicitly selected manual specialist work remain accessible under their existing permissions.

The integration uses the genuine NousResearch Hermes `AIAgent` loop from the MIT-licensed v0.22.5 source, commit `bf0203a794a07aac3ff764972ab9087baa4e4f4e`. Its upstream source image is pinned to the immutable multi-platform digest recorded in `gabriel/hermes/Dockerfile`. The deployed text-supervisor profile repackages that verified source on a separately pinned minimal Alpine/Python base, with an exact dependency closure derived from the immutable upstream installation. It omits unused browser, Node, Docker, document-extraction, image-conversion and native Relay utilities; the agent loop remains genuine and runtime lazy installation is disabled. The original full image failed the unchanged security threshold and is not the deployment candidate. The initial SDK test verified the image's install stamp and source provenance against that commit; it exercised a native streaming turn with an offline model client. That is compatibility evidence, not model-quality qualification.

## Model and analyst keys

Hermes has a dedicated supervisor prompt, configuration digest, conversation context and planning/reporting turns. Its initial candidate is **OpenAI GPT-OSS-120B through Cerebras on OpenRouter**, using the same fixed privacy, route, price and usage checks as Gabriel's existing model gateway. This is an explicit OpenRouter implementation, not an OpenAI API-key integration.

The analyst selects their personal encrypted OpenRouter key; owners/admins can explicitly select the organization key. Hermes never receives the real key. Sharing a provider key or model with specialists does not share their conversation contexts. A missing or revoked personal key never silently falls back to another account.

No new supervisor or specialist configuration is production admitted. Both Hermes planning and reporting configurations, and the relevant specialist/tool configurations, need independent exact-configuration evaluation before live use is enabled. The production admission registry remains empty. Fixture replies, a working API key, a passing Docker build and a model catalog entry cannot grant qualification.

## Preflight and workflow

Open a case's **Hermes supervisor** page, select typed evidence and either local evidence scope or the explicitly paired selected tab sessions, then choose **Check readiness**. This makes no inference call.

The preflight checks:

1. Current analyst identity, open-case access and verified stored source bytes.
2. For every selected tab: current owner-bound lease, active task/session, fresh heartbeat, a completed visible-text capture within 120 seconds, and typed facts linked to that current capture. A heartbeat alone is insufficient. Common explicit access walls block the check; wall recognition is limited and does not establish complete visibility.
3. The required pinned Hermes runtime and exact local adapter fingerprint.
4. Actual packaged tool versions and skill/configuration identities.
5. Current checked personal or explicitly selected organization key, available reservation capacity and spending limits. Provider funding/route checks run again immediately before dispatch.
6. Exact production qualification for Hermes planning/reporting and every eligible specialist.

After analyst export consent and a successful preflight, Hermes can select up to four relevant specialist roles. Gabriel validates those names and dispatches its designated specialists with their own prompts, tools and source bindings. Hermes then reports source-linked observations, actual completion states and explicitly unreviewed specialist assessment labels to the analyst. A critical reachable unmitigated exposure cannot be labeled benign or omitted from the required exposure-review assignment.

The supervisor and all supervised specialists share **one model investigation**, its spending allowance and an aggregate **six paid-call ceiling**. Each specialist still has at most three reasoning rounds. Limits can leave planned work unfinished; the UI reports that partial state instead of implying completion or retrying paid work. This is bounded sequential delegation, not unlimited simultaneous agent execution.

Stop, logout, lost membership/case authority, source changes, expired scope, changed key revision and selected-tab revocation block subsequent dispatch/publication. Child jobs retain their supervisor binding in PostgreSQL; reopening a child directly cannot bypass a stopped supervisor. An already sent provider call may still be charged. A claimed request with an unresolved outcome is never automatically resent. Deterministic request IDs and encrypted receipts support inspection/replay without duplicate inference.

## Isolation and installation

The private Hermes service has no provider credentials, database connection, evidence volumes, published port or outbound network. A fixed HTTP bridge passes only minimized typed facts, role names, bounded progress states and a provider reply. Each native SDK turn runs in a fresh temporary home with a conservative 65,536-token working context pinned locally. This avoids network metadata discovery; the gateway’s smaller input/output limits still apply. Built-in Hermes shell, browser, network, delegation, memory, skill discovery and persistent session tools are disabled. Gabriel performs the actual specialist delegation and permitted local tool execution.

The bridge first checks the exact model/messages produced by the native SDK; Gabriel applies its fixed nonstreaming route/reasoning/token parameters, reserves and sends that bounded request through its credential-owning model gateway. The real response is replayed through the native loop and checked for exact model/message/answer binding before Gabriel validates and publishes an encrypted receipt. The preparation sentinel is never a model verdict, evidence or a production qualification result. There is no hidden paid inference or upstream credential fallback.

`gabriel_install.py open` builds the pinned supervisor image and starts it as a required workbench dependency. Allow additional image download space and a 2 GiB service memory limit. The service is rebuilt from the current checked source on reopen; source fingerprints prevent silently mixing adapter versions. Stop includes Hermes. Backups retain the durable supervisor/child bindings in PostgreSQL; the supervisor has no persistent private home to back up. The opaque localhost TLS relay retains its four-connection/4 MiB bounds and allows a 240-second window for a bounded investigation response.

The native Hermes test job runs on x86 and ARM with actual PostgreSQL, local engines and the isolated SDK service. It tests native request/reply binding, supervisor-to-specialist-to-report flow, aggregate budget/call limits, revocation, stopped-parent enforcement and replay without extra provider calls. All model responses in these tests are generated fixtures, with zero paid calls.

## Current limits

The browser companion's existing scoped capture/navigation mechanisms remain separate. This integration does not give Hermes unrestricted control over arbitrary analyst tabs, automatically authenticate dashboards, turn generic screen text into independently verified telemetry, or renew expired analyst authority. Browser-bound supervision requires validated typed facts linked to current captures. Unsupported console semantics and incomplete visibility remain explicit; universal dashboard understanding and unattended indefinite monitoring are not established by this change.

Hermes drafts findings and reports for review. It cannot perform vendor containment/remediation, approve its own response actions, promote unreviewed claims into trusted memory or treat agent agreement as independent corroboration. External response connectors, live model qualification, upstream-image security acceptance and deployment/UAT remain release gates.
