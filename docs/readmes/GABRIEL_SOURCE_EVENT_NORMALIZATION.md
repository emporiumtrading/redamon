# Gabriel — Source-Aware Event Normalization (Tranche 3)

**Status:** Implemented pure adapter/review module with generated-data tests. Not yet a live-console ingestion endpoint or production-qualified detection engine.

## Scope

The first strictly admitted adapter maps the **existing, pinned Wazuh 4.14.9 invalid-user SSH-failure native event** into `gabriel-source-events-v1`. It reuses the source-specific validation already implemented in `gabriel/identity/wazuh_events.py`. The new entrypoint is `gabriel.identity.source_events.normalize_wazuh_invalid_user`.

This is an internal Gabriel schema with OCSF-inspired provenance intent; **it is not represented as OCSF-compliant**. Palo Alto, CrowdStrike, Splunk, generic JSON, arbitrary Wazuh rules and other products are **not** accepted as implemented parsers. Adding an adapter requires a separately reviewed source-specific mapping and generated-data negative tests.

## Source event structure

The normalized projection retains only:
- Current `case_id`, `source_id`, original `native_event_id`, product/version and adapter version.
- Reported UTC event time and explicit received/observed time.
- Original `evidence_id` and `evidence_digest` (supplied by caller).
- Bounded behavior category `authentication_failure_invalid_user`.
- Pseudonymous, **source-namespaced** actor, asset and origin aliases, not raw usernames, source IP addresses or log contents.
- Explicit `source_authenticated: false`, `source_bytes_verified: false`, `source_clock_verified: false`, `external_actions_authorized: false`. The normalization routine cannot itself authenticate custody, bytes or live collection.

## Correlation contract

`review_source_events` accepts **1–128** strictly validated same-case events and returns aggregate counts, not raw identifiers:
- Repeated *same-source* native event identifiers with identical semantic records are **repeat candidates**, never deleted.
- Identical native event IDs with contradictory content are **source identity conflict groups**, not automatically chosen by majority vote.
- Events on **different sources** within 300 seconds are **temporal coincidences**; they are not matched identities, attack chains, or independent corroboration.
- Reported event clocks more than five minutes ahead of receipt are flagged. The source time is not corrected or independently verified.
- Cross-source deduplication, entity joins, live queries and response actions are explicitly reported **not performed**. `attack_status` is always `unknown`.

The module is deliberately read-only and local. Any integrated service must still verify current organization, case, human role, evidence bytes, evidence digests, time bounds and source authenticity separately, both before processing and before publishing.

## Validation included

- Deterministic normalization of the supported Wazuh source contract.
- Repeated copies from the same source and same native event ID.
- Conflicting semantics for one native event ID.
- Different sources with identical reported event IDs and timestamps.
- Incomplete and unsupported source mappings, malicious extra fields, wrong versions, untrusted claims.
- Cross-case input rejection; 128-record cap and event-clock drift disclosure.
- Re-run in real Docker x86_64 and ARM64 `Gabriel open-source investigation tools and skills` CI.

## Integration with existing candidate detection

`project_attack_pattern_document` converts a validated same-case batch into the existing `security-events-v1` document, retaining the Wazuh-reported authentication-failure category, source/native event ID, evidence linkage and explicitly unknown authorization. The caller must supply the snapshot time and any documented coverage gaps; the projection rejects contradictory native IDs and future-to-snapshot event times.

The resulting document can be passed to Gabriel's existing `gabriel.identity.attack_patterns.investigate` **offline**. A generated ten-failure SSH sequence is tested end-to-end for a **suspected brute-force candidate requiring analyst review**, never a verified attack. This does not bypass the existing attack review's case, role and evidence source revalidation; the pure adapter is not a separate authenticated ingestion endpoint.

## Not implemented by this tranche

Case-evidence service integration and source authentication, persistent normalized-event storage, ingestion adapters for other products, generic OCSF transformation, graph entity resolution, response automation, independently verified brute-force detection, or real-world held-out qualification.

**Next step:** integrate case-owned verified normalized events into a read-only temporal observation graph and then add vendor adapters one at a time. Never treat inferred graph edges as confirmed compromise or authorization.
