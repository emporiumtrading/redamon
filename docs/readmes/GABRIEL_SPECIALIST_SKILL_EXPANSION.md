# Gabriel — Specialist Skill Expansion and Implementation Specification
**Status:** Candidate design and acceptance contract; not a claim that these skills are implemented.  
**Updated:** 10 November 2026

## 1. Purpose
This document expands the existing twelve specialist roles with 20 additional candidate skills each (240 total). It is an implementation backlog for Gabriel's existing role-bound runtime skill system, not a second agent framework. The existing specialist tools and packaged usage skills described in [investigation tools](GABRIEL_INVESTIGATION_TOOLS.md) remain authoritative. Hermes remains the required supervisor for autonomous orchestration.

**Do not implement or activate all 240 in one release.** Select a small, testable tranche based on actual data availability, existing tool support, analyst value and measurable acceptance. A candidate skill is not an operational capability until code, tests, manifest binding and acceptance evidence exist.

## 2. Shared skill contract
Every executable skill must provide these fields in its manifest/spec:
- `skill_id`: stable lowercase identifier; never reused for a different behavior.
- `name`, `version`, `owner_specialist`, `description`, `trigger_conditions`.
- `required_inputs`: typed fact schema, allowed source kinds, required fields and time bounds.
- `evidence_requirements`: same-case source references, content digests, custody/integrity state, freshness and known visibility limitations.
- `knowledge_references`: pinned local references and version/review date; no unreviewed page content as executable instructions.
- `allowed_tools`: exact existing catalog identifiers and permitted arguments only.
- `procedure`: bounded deterministic steps; explicit abstention conditions.
- `output_schema`: typed findings, source references, confidence/uncertainty, benign alternatives, contradictions, recommended analyst review and status.
- `safety_boundaries`: no arbitrary shell, URL fetch, package install, credential access, cross-tenant access or external response action.
- `tests`: positive, negative, adversarial, regression and resource-limit cases.
- `configuration_binding`: skill text/version, implementation source, tool versions and schema digest.
- `owner`, `last_reviewed`, `change_history`.

All model-facing skill text is untrusted data relative to system policy. Evidence text, browser text, logs, filenames and threat-intelligence descriptions must never override Hermes/system policy or tool permissions. No skill may silently expand tool permissions.

## 3. Cross-cutting acceptance gates
A skill is accepted only when all applicable checks pass:
1. **Schema:** valid typed input accepted; unknown fields, malformed values, invalid timestamps, unsupported source types and oversized payloads rejected.
2. **Provenance:** every finding maps to same-case source references; missing, corrupt, stale, cross-case or digest-mismatched evidence causes explicit abstention.
3. **Correctness:** positive case produces the expected bounded result; benign lookalike does not become a confirmed attack.
4. **Contradiction:** conflicting records remain visible; no majority vote or duplicate-count inflation.
5. **Visibility:** missing, partial, delayed, inaccessible and stale telemetry are represented as uncertainty, never as clean bill of health.
6. **Adversarial input:** prompt injection in logs/pages/files/IOC descriptions cannot alter instructions, invoke new tools or escape scope.
7. **Authorization:** wrong role, tenant, case, actor, revoked session, closed case and unapproved action are denied and audited.
8. **Isolation:** only the exact registered tool can run; bounded input/output/time/CPU/memory; no network egress or credential propagation.
9. **Replay/idempotency:** repeated request IDs do not duplicate side effects or model calls; stored result and source binding are immutable/auditable.
10. **Resource use:** test limits and measured runtime/cost; over-budget requests abstain visibly.
11. **Configuration:** exact skill/tool/source digest appears in the configuration identity and qualification packet.
12. **Regression:** run the correct Docker component gates, supported x86/ARM checks and relevant persistence/restart tests. Never use host pytest as a substitute.
13. **Human review:** specialist output is an unreviewed assessment until an authorized analyst reviews it. External action remains separately authorized.

### Standard test cases for every skill
- Valid, complete evidence packet.
- Valid packet with benign lookalike.
- Empty/missing required source.
- Stale evidence and out-of-window events.
- Corrupt or changed source bytes/digest.
- Cross-case and cross-tenant reference.
- Duplicate and out-of-order events.
- Conflicting evidence sources.
- Prompt injection embedded in an otherwise valid source.
- Unknown tool request and unauthorized tool request.
- Revoked user/session and closed case.
- Maximum-size packet and over-limit packet.
- Deterministic replay/idempotency.
- Explicit abstention with a reason and no fabricated result.

## 4. Candidate skill catalog

The 20 skills below each are candidate additions, not current feature claims.

### 4.1 Telemetry Health Specialist
1. Log source integrity verification
2. SIEM ingestion pipeline diagnostics
3. Log parsing and normalization validation
4. Missing event detection
5. Event timestamp drift detection
6. Log retention and expiration monitoring
7. Data source coverage mapping
8. Endpoint heartbeat anomaly detection
9. Network sensor health analysis
10. EDR agent health monitoring
11. Security connector authentication monitoring
12. Telemetry volume anomaly detection
13. Log tampering and deletion detection
14. Duplicate event identification
15. Event correlation quality assessment
16. Monitoring blind-spot discovery
17. Cloud audit logging coverage verification
18. Security control status reconciliation
19. Telemetry outage impact assessment
20. Monitoring service-level reporting

**Role-specific acceptance:** inject known collection gaps, timestamp skew, duplicate bursts, dropped partitions and source outages. Gabriel must distinguish “no event observed” from “event did not occur,” report affected source/time windows, quantify coverage only where denominators exist, and avoid asserting continuous visibility from a heartbeat.

### 4.2 Alert Triage Specialist
1. Alert deduplication and clustering
2. Multi-alert correlation
3. Alert severity recalibration
4. Behavioral anomaly assessment
5. Contextual risk scoring
6. Known-good activity recognition
7. Alert fatigue analysis
8. Attack-chain alert correlation
9. Multi-stage incident identification
10. Business asset criticality assessment
11. User behavior deviation analysis
12. Geolocation anomaly assessment
13. Suspicious administrative activity triage
14. Malware alert correlation
15. Phishing alert investigation
16. Ransomware precursor identification
17. Alert suppression effectiveness review
18. Historical incident similarity matching
19. Alert confidence calibration
20. Escalation prioritization

**Role-specific acceptance:** test repeated alerts, correlated but independent alerts, benign admin work, approved travel/VPN, phishing simulations and multi-stage attacks. Deduplication must not erase independent evidence; severity changes must expose their rationale and never silently suppress critical alerts.

### 4.3 Incident Scoping Specialist
1. Attack-chain reconstruction
2. Cross-system event correlation
3. Enterprise asset relationship mapping
4. Hostname and IP history reconciliation
5. Compromised account relationship mapping
6. Parent-child process relationship analysis
7. Lateral movement path reconstruction
8. Initial access vector identification
9. Incident entry-point analysis
10. Data exposure scope determination
11. Affected business service identification
12. Network segment impact mapping
13. Cloud resource impact mapping
14. Third-party access impact assessment
15. Incident timeline normalization
16. Persistence footprint identification
17. Potential attacker dwell-time estimation
18. Incident boundary determination
19. Evidence gap identification
20. Multi-tenant incident isolation analysis

**Role-specific acceptance:** test shared NAT, DHCP/IP reuse, hostname reuse, identity aliases, clock skew and incomplete asset inventories. Entity links must retain time bounds and provenance; inferred relationships must be labeled as hypotheses, never asserted as verified identity.

### 4.4 Threat Intelligence Specialist
1. MITRE ATT&CK technique enrichment
2. Threat actor profiling
3. Campaign tracking
4. Malware family intelligence
5. Ransomware group intelligence
6. IOC reputation assessment
7. Domain and DNS reputation analysis
8. IP infrastructure relationship analysis
9. Certificate reputation analysis
10. Threat intelligence feed quality scoring
11. Intelligence source reliability scoring
12. CVE exploitation intelligence
13. Known exploited vulnerability monitoring
14. Adversary infrastructure clustering
15. Threat campaign timeline reconstruction
16. Industry-specific threat profiling
17. Geopolitical threat context assessment
18. Dark-web intelligence assessment using authorized sources
19. Intelligence-to-detection mapping
20. Threat intelligence lifecycle management

**Role-specific acceptance:** test stale/revoked IOCs, shared hosting, sinkholes, benign infrastructure reuse, conflicting feed claims and attribution uncertainty. External enrichment is disabled unless a separately approved connector exists; source, retrieval time, expiry and confidence must be retained. Actor attribution requires corroboration and must default to unknown.

### 4.5 Threat Hunting Specialist
1. Living-off-the-land activity detection
2. Suspicious PowerShell activity investigation
3. Linux command-line anomaly investigation
4. macOS persistence investigation
5. Unauthorized scheduled task detection
6. Suspicious service creation investigation
7. Registry persistence investigation
8. Unusual parent-child process detection
9. Credential dumping indicator investigation
10. Kerberos anomaly investigation
11. Pass-the-Hash and Pass-the-Ticket indicator investigation
12. Remote desktop misuse detection
13. SMB lateral movement investigation
14. DNS tunneling investigation
15. Command-and-control beaconing analysis
16. Data staging and exfiltration investigation
17. Shadow IT discovery
18. Unauthorized remote access investigation
19. Ransomware pre-encryption behavior hunting
20. APT behavior hunting

**Role-specific acceptance:** every hunt must define a falsifiable hypothesis, exact permitted data scope, query/tool identifier, expected benign explanations and stop conditions. Tests include benign administration, sparse logs, adversary emulation fixtures and missing telemetry. No live scanning or unapproved target interaction.

### 4.6 DFIR Evidence Specialist
1. Windows event artifact analysis
2. Linux system artifact analysis
3. macOS forensic artifact analysis
4. Browser history artifact examination
5. Email header forensic analysis
6. File metadata examination
7. Deleted file recovery assessment
8. Memory dump analysis coordination
9. Disk image integrity verification
10. Malware artifact examination
11. Registry artifact examination
12. Prefetch and execution artifact analysis
13. Windows Amcache and Shimcache analysis
14. PowerShell history examination
15. Authentication artifact reconstruction
16. Cloud audit trail forensic analysis
17. Container forensic artifact collection
18. Evidence provenance validation
19. Forensic timeline cross-validation
20. Legal hold and evidence preservation tracking

**Role-specific acceptance:** validate byte-preserving handling, hash mismatch detection, custody gaps, time-zone normalization and source-specific parser limitations. Never claim deleted-file recovery, memory acquisition or forensic authenticity unless an implemented and validated tool actually performed it. Preserve legal-hold state; never purge held evidence.

### 4.7 Detection Engineering Specialist
1. MITRE ATT&CK detection coverage mapping
2. Sigma rule development and validation
3. YARA rule development and validation
4. KQL detection development
5. SPL detection development
6. EQL detection development
7. Behavioral detection engineering
8. Correlation rule engineering
9. Detection-as-code management
10. Detection regression testing
11. Detection logic optimization
12. False-negative analysis
13. False-positive root-cause analysis
14. Detection threshold optimization
15. Detection dependency mapping
16. Adversary emulation test mapping
17. Detection drift monitoring
18. Detection version control
19. Detection performance benchmarking
20. Detection coverage gap remediation

**Role-specific acceptance:** rule proposals are drafts only; validate syntax against pinned engine versions, run positive/negative fixtures, measure false positives/negatives and retain version/diff. Never deploy or modify production detections without separate human approval.

### 4.8 Exposure and Vulnerability Specialist
1. CVSS risk interpretation
2. EPSS exploitation probability assessment
3. CISA KEV catalog correlation
4. External attack surface management
5. Internet-exposed asset discovery from authorized inventories
6. Vulnerability age and remediation SLA tracking
7. Patch compliance verification
8. End-of-life software detection
9. Misconfiguration risk assessment
10. Certificate expiration exposure monitoring
11. Weak encryption configuration identification
12. Network segmentation exposure assessment
13. Vulnerability-to-business-service mapping
14. Exploitability context analysis
15. Vulnerability exception management
16. Compensating control effectiveness assessment
17. Vulnerability recurrence detection
18. Attack path exposure prioritization
19. Remediation validation
20. Risk-based vulnerability reporting

**Role-specific acceptance:** test stale CVEs, asset identity ambiguity, compensating controls, reachability changes and false-positive scanner findings. Scores must show source/date and separate severity, exploit probability, reachability, asset criticality and mitigation; no unapproved scanning.

### 4.9 Identity and Access Specialist
1. Active Directory security posture assessment
2. Entra ID security posture assessment
3. Privileged access anomaly detection
4. Dormant account identification
5. Orphaned account detection
6. Service account security analysis
7. Non-human identity governance
8. MFA coverage and bypass analysis
9. Conditional access policy assessment
10. Privilege escalation path analysis
11. Excessive permission identification
12. OAuth application permission analysis
13. Suspicious token usage detection
14. Session hijacking indicator investigation
15. Impossible travel detection
16. Identity lifecycle control verification
17. Joiner-mover-leaver access review
18. Privileged group membership monitoring
19. Federation and SSO configuration assessment
20. Zero-trust access policy evaluation

**Role-specific acceptance:** distinguish shared IP/VPN, travel, service principals, workload identities and stale directory snapshots. Do not infer session compromise from impossible travel alone. No password/token retrieval, credential reset, account disablement or privilege change without a separately authorized workflow.

### 4.10 Cloud, Container and Supply Chain Specialist
1. AWS security posture assessment
2. Microsoft Azure security posture assessment
3. Google Cloud security posture assessment
4. Kubernetes security posture assessment
5. Docker container security assessment
6. Container escape risk identification
7. Image provenance verification
8. SBOM generation and analysis
9. Dependency vulnerability correlation
10. Software signing verification
11. CI/CD pipeline security assessment
12. Infrastructure-as-Code security review
13. Terraform configuration analysis
14. Kubernetes RBAC analysis
15. Cloud storage exposure assessment
16. Cloud network security analysis
17. Serverless function security assessment
18. Cloud workload runtime anomaly detection
19. Cloud secret exposure detection
20. Software supply chain compromise investigation

**Role-specific acceptance:** test multi-cloud schema differences, stale IaC plans, mutable tags, unsigned images, SBOM gaps and dependency false positives. Use read-only, explicitly scoped evidence; never deploy, pull arbitrary images, execute build steps or expose secrets.

### 4.11 Response and Remediation Specialist
1. Automated incident response planning
2. Response playbook selection
3. Endpoint isolation recommendations
4. Account suspension and revocation planning
5. Credential rotation coordination
6. Malicious domain blocking recommendations
7. Firewall containment recommendations
8. Network segmentation recommendations
9. Malware quarantine coordination
10. Vulnerability remediation planning
11. Patch deployment prioritization
12. Emergency change impact assessment
13. Business continuity impact assessment
14. Response dependency analysis
15. Containment effectiveness verification
16. Remediation rollback planning
17. Response action authorization validation
18. Incident escalation coordination
19. Response SLA tracking
20. Post-remediation evidence verification

**Role-specific acceptance:** output a dry-run plan, exact target, expected effect, dependencies, impact, rollback and verification method. All execution is denied by default; an authorized human must approve the exact action and target. Test partial failure, duplicate approval, expired approval and rollback failure.

### 4.12 Recovery and Learning Specialist
1. Disaster recovery readiness assessment
2. Backup integrity verification
3. Backup immutability assessment
4. Recovery point objective (RPO) validation
5. Recovery time objective (RTO) validation
6. System restoration verification
7. Endpoint security revalidation
8. Identity revalidation after compromise
9. Persistence removal verification
10. Post-recovery vulnerability reassessment
11. Business service availability verification
12. Incident lessons-learned analysis
13. Root cause analysis
14. Recurring incident pattern identification
15. Security control effectiveness reassessment
16. Detection rule improvement recommendations
17. Threat hunting playbook improvement
18. Recovery dependency mapping
19. Residual risk acceptance tracking
20. Incident closure evidence validation

**Role-specific acceptance:** distinguish backup job success from restore validation, retain RPO/RTO measurement provenance, test recovery dependencies and require human approval for lessons entering trusted organizational memory. Never convert unreviewed model output into approved memory or close an incident solely from an agent assertion.

## 5. Shared services required across skills
These are shared platform services, not additional specialist roles:
- **Evidence confidence engine:** transparent evidence-quality indicators; no opaque probability presented as fact.
- **MITRE ATT&CK mapper:** map observed behavior to versioned techniques with source links and uncertainty.
- **MITRE D3FEND mapper:** map defensive countermeasures to observed risks and controls; distinguish recommendation from deployment.
- **Knowledge retrieval engine:** retrieve only approved, versioned local knowledge relevant to the current case.
- **Environment memory:** human-approved, tenant-scoped and expiring environment facts.
- **Investigation memory:** case-scoped history with explicit retention/forgetting and source links.
- **Contradiction detector:** preserve and surface conflicts; never silently resolve them by vote.
- **Prompt-injection defense:** treat all external/evidence content as data, never policy.
- **Cost/resource manager:** shared budgets, hard call/time/token limits and visible partial completion.
- **Specialist evaluation engine:** exact-configuration qualification, independent held-out sets and analyst adjudication.

## 6. Integration order
1. Reconcile this backlog against existing role-bound tools and skills; mark existing behavior as reuse rather than creating duplicate modules.
2. Select a first tranche that can be fully supported by current local data/tools. Prefer source integrity, event deduplication/normalization, timeline cross-validation, evidence gap/visibility analysis and detection regression support.
3. Implement each as a discrete skill module in the existing runtime skill/manifest mechanism. Keep the current Hermes dispatch and permission chokepoints.
4. Add tests before activation. Bind exact skill/tool/source versions into configuration digests.
5. Extend independently sealed evaluation data and analyst review; qualify the exact configuration. No fixture-based self-qualification.
6. Only then admit a configuration through the existing reviewed production-admission process.

## 7. External knowledge alignment
The skill catalog should be maintained against versioned defensive references, not copied as a static prompt:
- MITRE ATT&CK for adversary behavior taxonomy.
- MITRE D3FEND for defensive countermeasure relationships.
- NIST SP 800-61 Rev. 3 and CSF 2.0 for incident response and lifecycle alignment.
- CIS Controls v8.1 for prioritized safeguards and operational coverage.
- OWASP API Security Top 10 (2023) for API-specific risk patterns.
- Cloud Security Alliance Security Guidance v5 and CCM v4.1 for cloud control coverage.

Review source versions periodically. Record the specific version and review date used by each skill; do not make network retrieval an implicit runtime permission.

## 8. Definition of done
A skill is not “done” because its Markdown exists. It is done only when its implementation, strict schema, role/tool permission, provenance checks, positive and negative tests, adversarial tests, configuration digest, Docker test evidence, analyst review and exact-configuration qualification status are recorded. Until then, it remains a candidate in this backlog.
