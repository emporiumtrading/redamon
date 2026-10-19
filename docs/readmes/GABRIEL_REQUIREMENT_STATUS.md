# Gabriel PRD requirement reconciliation

Baseline: draft PR 16 head `41ed782a99d44334a12b9f8bb4bcb990b1bc94dd`; PR 17 server/package source `35d2d38da6241ad2e17a1c0a48c3aedb8936a4ca` passed the 579-case/recovery gate. Actual client lab is in progress. This maps all 40 requirement IDs to actual implementation gaps. Component CI evidence is in the implementation ledger. None of the forty requirements has full post-release acceptance; a component pass does not accept a complete release requirement.

| Requirement | Implemented evidence / remaining work |
| --- | --- |
| GAB-001 | Static tracked-tree inventory exists; complete inherited disposition review and full-stack baseline remain open. |
| GAB-002 | Separate default-deny local runtime tested; complete UI/API/MCP/job/specialist conversion remains open. |
| GAB-003 | Database identities, tenant predicates and bounded worker/browser grants tested; new HTTPS gateway and all future interfaces require acceptance. |
| GAB-004 | Hashed accounts and encrypted provider vault tested; enabled provider/connector and operational secret custody acceptance remain open. |
| GAB-005 | Transactional audit admission tested for current mutations; new product interfaces need equivalent tests and review. |
| GAB-006 | Cases/tasks/approval state persist; scoped memory, graph projection and workbench are outstanding. |
| GAB-007 | Encrypted evidence/custody and unverified observation lineage tested; actual client/source adapters and deduplication outstanding. |
| GAB-008 | Fresh migrations, restart/dump/restore and interrupted evidence operations tested; integrated product and external-effect recovery outstanding. |
| GAB-009 | MV3 client implementation in progress; actual Chrome/Brave package tests and reviewed distribution outstanding. |
| GAB-010 | Backend exact page/tab/document/account scope tested; actual browser lifecycle/associated-tab acceptance outstanding. |
| GAB-011 | Bounded envelope and conservative secret filter tested; actual rendered-text minimization, preview and browser privacy acceptance outstanding. |
| GAB-012 | Single-use native-TLS gateway network/component tests passed; actual browser abuse tests and independent protocol review outstanding. |
| GAB-013 | Vendor-neutral backend contracts exist; selected real console investigation with no vendor API and human-only login outstanding. |
| GAB-014 | No search executor admitted; reviewed existing-search/template adapters and side-effect tests outstanding. |
| GAB-015 | No third-party draft entry admitted; Gabriel proposal workspace and draft/autosave acceptance outstanding. |
| GAB-016 | Finite backend capabilities reject unsupported operations; packaged adapter vocabulary and browser proof outstanding. |
| GAB-017 | Backend serialization exists; actual tab action leases, targets and postcondition checks outstanding. |
| GAB-018 | Backend heartbeat/revocation/recovery tested; client suspension, permissions and human-handoff lab outstanding. |
| GAB-019 | Extension/backend version bound in leases; package provenance, compatibility and managed upgrade recovery outstanding. |
| GAB-020 | Environment/control profile with evidence states and freshness not implemented. |
| GAB-021 | Proactive hunt selection/execution and benign alternatives not implemented or evaluated. |
| GAB-022 | Core cases/evidence persist; assignment, entity/time correlation, deduplication, timelines and reports outstanding. |
| GAB-023 | No model assessment engine admitted; evidence-linked revisions, abstention and escalation outstanding. |
| GAB-024 | Shared queue, handoff and approval inbox not implemented as product screens. |
| GAB-025 | Required R1 screen/control inventory and accessible integrated workbench outstanding. |
| GAB-026 | Product must separately present urgency, exposure, confidence and compliance; screens/evaluation outstanding. |
| GAB-027 | Twelve specialist contracts and their real-tool/held-out evaluations outstanding. |
| GAB-028 | Bounded local tasks tested; specialist coordinator, model budgets and duplicate/disagreement handling outstanding. |
| GAB-029 | Provider vault exists; approved NVIDIA/OpenRouter routing, actual model evaluations and policy-preserving fallback outstanding. |
| GAB-030 | Reviewed defensive hunt playbooks, versioning, alternatives and escalation evaluation outstanding. |
| GAB-031 | Tenant memory provenance/correction/expiry/supersession/reset and retrieval lifecycle outstanding. |
| GAB-032 | Memory poisoning/drift/cross-tenant defenses require implementation and adversarial evaluation. |
| GAB-033 | Prompt/model/playbook/adapter promotion and rollback governance outstanding. |
| GAB-034 | Open-source candidates are a catalog, not supported integrations; exact tool/version/license/owner and real lab acceptance required per enabled integration. |
| GAB-035 | Detection/code changes and deployed-effect verification not admitted. |
| GAB-036 | Exact local closure/purge approval contracts tested; selected external response approval/effect workflow outstanding. |
| GAB-037 | Durable local intents, receipt replay and interrupted crypto/disposition recovery tested; external-effect reconciliation outstanding. |
| GAB-038 | Worker/browser revocation tested; actual browser Stop/Pause, product kill switch and selected response dispatch acceptance outstanding. |
| GAB-039 | Component quotas and expiry tested; product load/model cost, measured RPO/RTO and managed operations outstanding. |
| GAB-040 | Source-specific component gates and repair records exist; complete scans/SBOM/provenance, independent review, integrated pre/post-release UAT and operational observation outstanding. |

The eighty acceptance obligations remain scenario-level gates until their exact source, environment, artifacts, observed outcomes and reviewer are recorded. Previously verified component tests remain valid at their cited source, without converting unrun product scenarios into passes.

## External decisions and acceptance dependencies

The [PRD decision register](PRD_GABRIEL_DEFENDER.md#15-decisions-risks-and-ownership) requires the actual pilot organization/console workflows and authorized lab access, browser/OS matrix, staging/production targets, approved model routes/residency/spend, analyst-adjudicated corpus and escalation destination. R3 also requires the selected response target, approvers and recovery authority. Generic lab implementation can proceed; real-console/model/response and human release acceptance cannot be invented from fixtures. User-authorized development does not supply those missing accounts, adjudications or customer operating decisions.
