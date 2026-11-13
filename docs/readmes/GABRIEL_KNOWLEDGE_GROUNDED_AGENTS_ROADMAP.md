# Gabriel — Knowledge-Grounded Defensive Agents Research and Engineering Roadmap

**Updated:** 13 November 2026  
**Status:** External research synthesis, implementation roadmap; no claim of production-qualified AI.

## Research inspiration

The University of Oslo's [2026 PhD research fellowship description](https://www.jobbnorge.no/en/available-jobs/job/309937/phd-research-fellow-position-in-knowledge-grounded-llm-agents-for-defensive-cyber-operations) describes work on knowledge-grounded, neuro-symbolic defensive cyber agents in collaboration with the Norwegian Defence Research Establishment. The published concept emphasizes transforming heterogeneous telemetry/evidence into structured cybersecurity knowledge and semantic graphs, combining symbolic checks with LLM reasoning and validating provenance, uncertainty, robustness and actions.

**We are using the public research themes as architecture inspiration, not implying collaboration, endorsement, access to research results, or permission to copy unpublished work.**

Supporting open references:

- [OCSF security event normalization](https://github.com/ocsf/ocsf-schema): vendor-neutral event schema, class and object types; see its versioned release history. The 2026 v1.9.0 release includes an optional record-integrity profile and AI-operation delegation metadata.
- [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html): cyber intelligence entities, relationships, provenance and confidence for knowledge graphs.
- [MITRE ATT&CK](https://attack.mitre.org/): adversary behavior vocabulary, not a proof of technique occurrence.
- [MITRE D3FEND](https://d3fend.mitre.org/): defensive countermeasure graph; its taxonomy neither prescribes nor proves effectiveness.
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final): cyber incident-response lifecycle and organizational readiness.

## Target architecture

```text
Analyst-approved browser tabs / case-owned evidence / authorized integrations
       |
       v
Source provenance and custody verification (existing)
       |
       v
Vendor-specific adapters -> versioned, normalized OCSF-like typed events
       |                    (do not assume adapter semantics)
       v
Case-scoped observation records -> deterministic symbolic checks
       |                            (five grounded review kernels)
       v
Provenance-aware, temporal security knowledge graph (future)
       |
       v
Hermes planning -> up to four role-bound specialists -> Hermes reporting
       |
       v
Evidence-linked, uncertainty-aware human review
       |
       v
Human-approved exact response / human-reviewed organizational memory
```

The graph must distinguish: observed source data; normalized assertions; analyst-validated facts; hypotheses; contradiction edges; reviewed knowledge; and authorized actions. These must never collapse into a single undifferentiated "fact" node.

## This implementation tranche

Five new **local read-only** tools are bound to the existing role/tool/skill manifest:

| Runtime skill / tool | Specialist scope | What it does | Important limit |
| --- | --- | --- | --- |
| `audit_provenance` | DFIR | Reports stated integrity/custody discrepancies and repeated assertions per verified source | Stored-byte integrity is not origin authenticity |
| `find_duplicate_facts` | Alert triage, incident scoping, identity/access | Finds exact same-source repeated typed fact candidates | Cannot deduplicate cross-source events without reliable event IDs |
| `cross_check_timeline` | Incident scoping, DFIR | Compares source event-time windows and overlap | Cannot independently confirm clocks, causality or entity equivalence |
| `assess_visibility_gaps` | Telemetry health | Reports missing, stale and available coverage assertions | Cannot prove continuous observation or absence of attacks |
| `review_detection_regression` | Detection engineering | Counts test agreements, misses, unexpected matches and absent cohorts | Cannot prove regression without versioned rule baseline |

All five use `specialist-facts-v1` and the already-enforced source and case validation path. They emit only de-identified bounded results. No external data retrieval, detection deployment, agent self-approval or response execution is added. Skill text and implementation source are included in existing configuration hashes; **all altered exact configurations must be independently qualified**.

## Next research-to-engineering increments

1. **Event identity and vendor normalization.** Design a reviewed OCSF-compatible adapter contract with source product/version, mapping version, immutable event ID if present, event time, ingestion time, source integrity, tenant scope and known mapping loss. A deterministic source-specific dedup key should be used only when justified by adapter semantics. Cross-source dedup remains correlation, not deletion.
2. **Case-scoped knowledge graph.** Start with a read-only, tenant-scoped graph projected from verified observations. Separate evidence, observation, entity hypothesis, timeline and analyst-reviewed nodes. No global graph writes from a specialist. Reconcile with Gabriel's current case_graph and environment view, rather than introducing a new graph database by default.
3. **Neuro-symbolic decision contract.** Symbolic constraints are decisive for permission, provenance, contradiction and action gating. LLM agents can propose explanations and bounded next questions, but cannot override rules by confident prose.
4. **Trust and uncertainty.** Track coverage, temporal validity, source independence, negative evidence, confidence basis and analyst review separately. Do not require a numeric "confidence 1.0" as proof; a fully confident model can still be wrong.
5. **Independent evaluation.** Build frozen, legally obtained development/validation/held-out cases with controlled ground truth, benign lookalikes, tool availability failures, inconsistent timestamps, prompt injections and reversible response simulations. Measure recall/precision, false escalation, abstention quality, evidence attribution, resource cost and human-action safety, separately from software test passes.
6. **Lab deployment and product release.** Validate with authorized Wazuh/DFIR-IRIS and TryHackMe SOC simulations after exact-model qualification and native Mac UAT; keep simulations separate from learned organizational memory and production decisions.

## Acceptance and safety

- Check original timestamps and source versions; no browser heartbeat proves complete visibility.
- Never treat a graph edge, vector similarity, repeated alert or multiple-agent agreement as independent evidence.
- Never let logs/pages/IOC fields inject instructions, remote commands, URLs or new tool permissions.
- Preserve separate governance for analyst consent, data minimization, model cost, trusted TLS, secrets and rollback.
- Keep evidence and acceptance claims source-specific. A passing unit test is not a confirmed real-world attack detection.
