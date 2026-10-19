# Gabriel acceptance decisions requiring an accountable owner

Development and isolated tests are authorized. That does not identify a customer environment, approve data egress/model spending, provide deployment authority or constitute analyst acceptance. These decisions are open; none is filled with invented customer data. See PRD section 15 and the complete requirement reconciliation.

| Decision | Minimum answer needed | Gate affected | Current safe behavior |
| --- | --- | --- | --- |
| Pilot workflows | Authorized organization/lab; exact console editions/pages; existing read-only search/filter journeys; engineer role; supported Chrome/Brave and OS versions; permitted test access process | B0/B2, C08; GAB-010/013/014/017/020/021 | Generated console only; no real console adapter, external login or API credential prerequisite |
| Model policy | Approved providers/routes and exact models; allowed data classifications; retention/residency terms; per-task and total spending limits; approved account configuration | C07; GAB-023/027/028/029 | No live model dispatch, invented model response or spend |
| Expert evaluation | Lawfully usable scenario corpus, held-out split, qualified analyst adjudicator, benign alternatives, escalation destination and quality/workload thresholds | C07/C08; GAB-021/023/027/030/033 | No claim of expert-level detection, exhaustive attacker absence or certainty 1.0 |
| Hosting and operations | Approved staging/production targets, identity/TLS/secret custody owners, backup/retention policy, capacity/load profile and deployment/rollback authority | C01/C08/C13; GAB-003/004/008/039/040 | Isolated disposable CI and loopback/private operator gateway only; no production release |
| Independent review and UAT | Security/privacy/protocol reviewer; one/two engineer pilot users; staging and post-release scenario sign-off owners | All release gates, GAB-009/025/040 | Draft PRs and source-specific component evidence; human UAT remains NOT_RUN |
| R3 response workflow | Exact admitted action/target/exclusions, approvers, effect-verification criteria and recovery authority | C10/B3; GAB-035/036/037/038 | No external containment, rule write, third-party draft entry or response dispatch |
| Optional open-source integration | Exact tool/version/license, supported workflow, maintainer/operations owner and authorized lab | C09, GAB-034 | Candidate catalog, not claimed working support for every listed tool |

Provide non-secret choices and use the normal approved configuration/access process for credentials. Do not place passwords, MFA codes, browser profiles/cookies, model keys, live telemetry or sensitive target details in public issues, code or PRs. Browser sign-in remains human-only even after a pilot is selected. Direct vendor APIs remain optional, not a requirement to unlock supported browser investigations.

These decisions block their dependent implementation/evaluation or shipping path, not independent safe development. Engineering checkpoints do not request routine permission to continue. The loop must still stop on missing authority, after the documented same-cause repair limit, or for required human acceptance. No chat checkpoint establishes a persistent background engineering or production-monitoring service.
