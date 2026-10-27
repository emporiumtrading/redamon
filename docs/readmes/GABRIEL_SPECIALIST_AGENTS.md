# Gabriel specialist AI agents

Gabriel has twelve designated agent roles. Each has a distinct mission/prompt, model configuration identity, permitted local read tools and a durable investigation job. Roles may share the same hosted model; they retain separate reasoning contexts and evidence links. Agreement between agents is not independent corroboration.

The implemented agent runtime is separate from the existing deterministic specialist reviews. The required Hermes AI supervisor selects relevant roles from the supplied typed facts after preflight; see [Hermes supervision, its own model, selected-tab checks and shared budgets](GABRIEL_HERMES.md). Each agent can reason, request an allowed local read, inspect its result and reason again, for at most three model rounds. Final answers are encrypted, source-linked, unreviewed evidence. Unknown claimed provider outcomes never automatically resend. Repeated tool requests, missing scope, Stop, credential revocation and exhausted budgets stop the loop.

| Agent | Investigation focus |
| --- | --- |
| Telemetry health | Missing/stale visibility and collection failures |
| Alert triage | Alert context and plausible benign explanations |
| Incident scoping | Supported entity relationships and timeline |
| Threat intelligence | Supplied match validity and attribution limits |
| Threat hunting | Evidence-linked hypotheses |
| DFIR evidence | Supplied integrity and custody assertions |
| Detection engineering | Missed and unexpected detector test outcomes |
| Exposure and vulnerability | Reachability, mitigations and exposure priorities |
| Identity and access | Authentication and authorization changes |
| Cloud and supply chain | Configuration and component findings |
| Response and remediation | Dependency and recovery-readiness analysis |
| Recovery and learning | Recovery checks and reviewed lessons |

The role-bound catalog includes source integrity, local rule review, supplied timelines, reviewed-memory availability, YARA file-pattern analysis, offline dpkt packet analysis, normalized JSONL correlation, typed-fact correlation, exposure prioritization and installed-tool inspection. Packaged usage skills are loaded into the model context and bound to its configuration hash. Analysts can also run local tools and review encrypted reports without an AI key. See [tool assignments, licenses, formats and isolation](GABRIEL_INVESTIGATION_TOOLS.md).

These tools do not grant arbitrary shell execution, package installation, external searches or remediation. Browser capture/navigation remains governed by the companion's separately approved session. The case-agent coordinator does not automatically replace the browser's shared AI triage path.

## Personal keys and member accounts

Owners/admins can create analysts through **Team members**. Each analyst signs in under their own member account and opens **My AI key**. A dedicated OpenRouter inference key is validated and stored encrypted in PostgreSQL under that organization and user. Other users, including administrators using the personal-key API, cannot retrieve or select it. Organization credentials remain a separate owner/admin flow. The agent UI defaults to the current user's personal key and never silently falls back to an organization or development key.

OpenRouter remains the implemented inference transport for this agent runtime. Its fixed endpoint, exact route, privacy and price checks apply. Personal setup retains the existing dedicated-key requirement: an $18 monthly cap and at least $18 initially available in both account credit and key allowance. Normal subsequent use can reduce available balance. Organization-level reservation limits still apply collectively: at most $18/month, $0.50/day and $0.05 per model investigation, with two held/in-flight slots. Personal keys do not grant budget administration or response-action permission. NVIDIA storage in the organization vault does not imply implemented NVIDIA inference.

An existing installation can be rebuilt using the backed-up rebuild command. Migrations 29–30 retain the original owner, evidence/provider encryption keys and volumes. To open a member's workbench with provider connectivity:

```bash
python3 tooling/scripts/gabriel_install.py open "$HOME/gabriel-private-test" --username ANALYST_USERNAME --ai-egress
```

The password is prompted privately. This uses the member account previously created by an owner/admin. The installation remains a single active workbench; opening another account revokes the previous workbench session. The provider-connectivity overlay attaches only the workbench to an outbound network; the database stays private. Ordinary `open` remains private. The API client accepts only its fixed OpenRouter endpoints, never a user-supplied provider URL. Connectivity does not grant configuration admission.

In a case, open **Specialist AI agents**, select an approved `specialist-facts-v1` artifact, select a manual specialist or open **Hermes supervisor** for required autonomous orchestration, choose the model/key scope and approve minimized-fact export. The projector preserves role-relevant typed semantics and opaque entity grouping while excluding private case/evidence/entity identifiers and raw source text. Oversized contexts require a narrower scope rather than silent truncation. Source bytes, case authority, key revision and budget are checked before dispatch and before publishing an answer.

## Qualification and production admission

`ai_capable` describes implemented wiring. `model_enabled` reports whether the exact role/model/prompt/projection/tool-loop configuration is production-admitted. It becomes true through an admitted configuration; a catalog edit or an API key cannot manufacture qualification. No exact specialist-agent configuration has yet passed independent real-model qualification.

`specialist_qualification.evaluate_agents` requires submissions for all twelve roles, rejects stale configuration digests, and applies the existing 60-family development/validation/held-out criteria, source-linked claim review, critical-case, recall, false-escalation and visibility-gap gates per role. It never substitutes simulated answers or self-authored development examples for independent model evidence, and it never automatically writes production admission. Independent corpus rights/sealing, analyst adjudication, tool-loop/real-console acceptance, operational/security review and release acceptance still need real evidence.

The offline exporter in `testing/gabriel_specialist_ai/trial.py` prepares 24 authored development scenarios, two per role, and enumerates all 240 possible request bodies for the allowed non-repeated tool paths. The approved run allowed up to 72 calls (three rounds per scenario), capped at $0.453888. The owner-approved October 27 batch completed 24 calls for $0.01236255, all contract-valid. All answers ended at round one without requesting tools, and one reachable critical unmitigated exposure received a benign disposition. See the [evaluation findings](GABRIEL_SPECIALIST_AI_EVALUATION_20261027.md). This is development compatibility evidence, not held-out qualification or proof of live autonomous investigation. The earlier five-call browser trial belongs to a different configuration and supplies no admission for these role-specific agents.


## Source-specific engineering evidence

The focused Docker gates at source `3ff7d9dba62bc2508badf7bd68d721c93a06574d` passed **100 checks** in [Actions 40269657426](https://github.com/emporiumtrading/redamon/actions/runs/40269657426), including all twelve model→local-tool→model paths, personal ciphertext ownership, revocation, Stop responsiveness, replay, delegation and analyst HTTPS permissions. These provider responses were simulated; they are software evidence, not production model qualification. Existing-installation schema 28→29 upgrade and named-member fresh-installation journeys passed on x86/ARM. Native Mac and actual customer-console acceptance remain separate.

The expanded closed-set agent-loop packet is generated by the offline workflow. It enumerates initial requests and all permitted one/two-read-tool follow-ups; raw model-generated claims are not sent back as input. No credential or network is used during export. The earlier, different five-call approval is exhausted. The new body set and $0.453888 maximum were explicitly approved and the bounded batch is now complete. The unused call allowance does not authorize a new run or changed requests. Revised evaluations require their own exact packet and spending authorization.
