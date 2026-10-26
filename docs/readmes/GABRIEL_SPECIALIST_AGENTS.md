# Gabriel specialist AI agents

Gabriel has twelve designated agent roles. Each has a distinct mission/prompt, model configuration identity, permitted local read tools and a durable investigation job. Roles may share the same hosted model; they retain separate reasoning contexts and evidence links. Agreement between agents is not independent corroboration.

The implemented agent runtime is separate from the existing deterministic specialist reviews. The coordinator selects relevant roles from the supplied typed facts. Each agent can reason, request an allowed local read, inspect its result and reason again, for at most three model rounds. Final answers are encrypted, source-linked, unreviewed evidence. Unknown claimed provider outcomes never automatically resend. Repeated tool requests, missing scope, Stop, credential revocation and exhausted budgets stop the loop.

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

The tools currently implemented are source-byte/custody verification, local role-rule review, supplied-timeline inspection and reviewed-memory availability. Tool summaries may be included in later reasoning requests. Raw reviewed-memory text remains local. These tools do not grant general browsing, arbitrary shell execution, external searches, changes to firewall/cloud settings, or remediation. Browser capture/navigation remains governed by the companion's separately approved session. The new case-agent coordinator does not automatically replace the browser's earlier shared AI triage path.

## Personal keys and member accounts

Owners/admins can create analysts through **Team members**. Each analyst signs in under their own member account and opens **My AI key**. A dedicated OpenRouter inference key is validated and stored encrypted in PostgreSQL under that organization and user. Other users, including administrators using the personal-key API, cannot retrieve or select it. Organization credentials remain a separate owner/admin flow. The agent UI defaults to the current user's personal key and never silently falls back to an organization or development key.

OpenRouter remains the implemented inference transport for this agent runtime. Its fixed endpoint, exact route, privacy and price checks apply. Personal setup retains the existing dedicated-key requirement: an $18 monthly cap and at least $18 initially available in both account credit and key allowance. Normal subsequent use can reduce available balance. Organization-level reservation limits still apply collectively: at most $18/month, $0.50/day and $0.05 per model investigation, with two held/in-flight slots. Personal keys do not grant budget administration or response-action permission. NVIDIA storage in the organization vault does not imply implemented NVIDIA inference.

An existing installation can be rebuilt using the backed-up rebuild command. Migration 29 retains the original owner, evidence/provider encryption keys and volumes. To open a member's workbench with provider connectivity:

```bash
python3 tooling/scripts/gabriel_install.py open "$HOME/gabriel-private-test" --username ANALYST_USERNAME --ai-egress
```

The password is prompted privately. This uses the member account previously created by an owner/admin. The installation remains a single active workbench; opening another account revokes the previous workbench session. The provider-connectivity overlay attaches only the workbench to an outbound network; the database stays private. Ordinary `open` remains private. The API client accepts only its fixed OpenRouter endpoints, never a user-supplied provider URL. Connectivity does not grant configuration admission.

In a case, open **Specialist AI agents**, select an approved `specialist-facts-v1` artifact, select a specialist or the coordinator, choose the model/key scope and approve minimized-fact export. The projector preserves role-relevant typed semantics and opaque entity grouping while excluding private case/evidence/entity identifiers and raw source text. Oversized contexts require a narrower scope rather than silent truncation. Source bytes, case authority, key revision and budget are checked before dispatch and before publishing an answer.

## Qualification and production admission

`ai_capable` describes implemented wiring. `model_enabled` reports whether the exact role/model/prompt/projection/tool-loop configuration is production-admitted. It becomes true through an admitted configuration; a catalog edit or an API key cannot manufacture qualification. No exact specialist-agent configuration has yet passed independent real-model qualification.

`specialist_qualification.evaluate_agents` requires submissions for all twelve roles, rejects stale configuration digests, and applies the existing 60-family development/validation/held-out criteria, source-linked claim review, critical-case, recall, false-escalation and visibility-gap gates per role. It never substitutes simulated answers or self-authored development examples for independent model evidence, and it never automatically writes production admission. Independent corpus rights/sealing, analyst adjudication, tool-loop/real-console acceptance, operational/security review and release acceptance still need real evidence.

The offline exporter in `testing/gabriel_specialist_ai/trial.py` prepares 24 authored development requests, two per role, capped prospectively at $0.151296. This is an initial-request compatibility packet, not a paid run, autonomous-follow-up approval or held-out qualification. The earlier five-call browser trial belongs to a different configuration and supplies no admission for these role-specific agents.
