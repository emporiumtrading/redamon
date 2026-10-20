# Gabriel acceptance decisions and remaining deployment inputs

Updated 20 October 2026 following the product owner's twelve answers. Product choices and delegated defaults are now recorded in the normative [pilot decisions and acceptance plan](GABRIEL_PILOT_DECISIONS.md) and PRD section 15. Do not repeat the prior twelve-question blocker list.

| Area | Selected direction | Remaining concrete input/evidence |
| --- | --- | --- |
| Pilot workflows | Isolated Docker lab; console-agnostic semantic observation; Wazuh/DFIR-IRIS initial real-console journeys | Provision actual versioned consoles; test admitted controls and unknown-console degradation |
| Browser/VM delivery | Chrome/Brave on Windows/macOS/Linux; Docker Compose first, same stack inside Ubuntu guest VM | Real OS/hypervisor journeys and install/upgrade/recovery evidence; architecture-specific build proof |
| Model policy | OpenRouter Flash Lite/Flash candidates; NVIDIA Nemotron 3 Super fallback candidate; local minimization/redaction and eligible confidential routes | Normal private account configuration; exact endpoint capability, price, retention/residency admission and held-out quality evaluation |
| Budget | $20/month envelope; $18 dispatch allowance; $0.50/day and $0.05/investigation defaults | Durable spend ledger/reservations/reconciliation tests; account/key limits; no automatic top-up |
| Evaluation | Build at least 60 scenario families with disjoint hidden-label evaluation and published denominators | Actual pinned licensed corpus, qualified adjudicator and real human workload evaluation |
| Hosting/operations | Local lab first; tenant-owned deployment and persistent storage | Actual TLS, identity/key/backup owners and deployment/rollback process before staging/customer release |
| Roles/review/UAT | Owner assigns permissions; users declare operational roles; solo operation supported | Named reviewers and UAT/release/escalation owners during deployment. Self-review is not independent review |
| Response modes | Observation, autonomous admitted read-only investigation, local drafts; engineer-approved response in later release | Each consequential action requires exact target/parameters, authorization, verification and recovery acceptance |
| Retention | Engineer/admin configuration, distinct evidence/case/audit/memory/backup policies and legal holds | Working persisted controls, purge/restore tests and customer-specific settings |
| Optional integrations | Five defensive and five IR components selected in addendum, enabled progressively | Exact version/license review and real per-tool workflow, health and upgrade evidence |

Independent authorized engineering can proceed with these defaults. Remaining deployment/account/human inputs gate only their dependent paths; they are not reasons to ask routine permission to continue. No chat checkpoint creates an unattended background service.

20 October host/account checkpoint: the owner confirmed saving `OPENROUTER_API_KEY` as a GitHub Actions secret and using an Apple Silicon Mac with Docker Desktop and 18 GB memory. The restricted probe authenticated its read-only key-metadata request but stopped before paid calls because the key did not meet the combined requirement of a nonzero cap at most $18 and monthly reset. Exact missing field is not inferred. Update those settings on the existing key; a replacement secret is unnecessary if the key value is unchanged. Native Linux ARM64 core build/import and thirteen probe software tests passed; this is not macOS UAT or model qualification. See the implementation ledger for exact-source outcomes.

Browser sign-in remains human-only. Direct vendor APIs remain optional. Do not place passwords, MFA codes, cookies, model keys or sensitive live telemetry in chat, public issues, code or PRs. Use normal private configuration channels.

Choices recorded in documents are not working integrations, corpus artifacts, tests, human UAT or release approval. The established component evidence remains valid only for its recorded source and scope. New PD scenarios are planned until executable implementation and results exist.
