# Gabriel case provenance projection

This C06 slice rebuilds a bounded provenance graph from the existing authoritative PostgreSQL case report. It is a real read path with current human/tenant/role checks, custody validation and mandatory audit. There is no graph database, persistent derived index, background cache or new schema/grant. The inherited offensive Neo4j schema and recon machinery are not used. Entity resolution and attack correlation remain separate, unimplemented requirements.

## Operator and browser paths

Use the existing identity image, restricted application DSN, evidence store/keyring and a private live human session file:

```bash
python -m gabriel.identity.case_cli graph --token-file /operator/human-session --case-id CASE_UUID
```

The workbench case detail links to **Explore provenance** at `/cases/CASE_UUID/relationships`. Accessible record/link tables show actual case metadata. The authenticated **Download provenance graph** link returns JSON at `/cases/CASE_UUID/graph`. All page metadata is HTML escaped; POST to these read-only paths is denied. A viewer can inspect the same metadata permitted by the existing report, without evidence bodies or analyst question/answer text. Current revocation, original session loss, corrupt custody, audit failure and foreign cases deny access.

## Version 1 projection contract

Every node identifier starts with `organization/ORGANIZATION_UUID/case/CASE_UUID/`. Every edge references two included nodes. Stable node ordering, edge hashes and canonical JSON produce a reproducible SHA-256 checksum for unchanged included records. A fresh source-report checksum and generation timestamp accompany the projection but are outside its stable checksum. The checksum authenticates neither the source nor a stored content body and is not a digital signature.

| Record/link | Stored basis and interpretation |
| --- | --- |
| Case → evidence: `contains_evidence` | Existing tenant/case evidence foreign key; includes state, disposition and report metadata |
| Evidence → evidence: `derived_from` | Recorded parent-artifact relationship, without a claim that the transformation is correct |
| Case → task: `linked_task` | Existing case/task association; current task execution authority is not assessed |
| Case → browser lease: `has_browser_lease` | Lease associated through a recorded observation, without current visibility/authority claims |
| Browser lease → observation: `received_observation` | Recorded observation association and distinct server/client timestamps |
| Observation → evidence: `captured_as` | Existing evidence linkage; pending observations can have no evidence link |
| Evidence → identical-byte group: `has_identical_bytes` | Same digest and length within this case; separate artifacts retained, without event deduplication or independent corroboration |

The projection explicitly reports partial coverage, no incident assessment and unchecked stored-content integrity. It excludes report timelines, questions/answers, account/page URLs, credentials, storage paths and encryption key IDs. Evidence report metadata and browser observation metadata retain their source-unverified labels. No inferred assets, identities, attacker, causality, risk score, model conclusion or learned fact is invented. Limits of 4,096 nodes, 8,192 edges and 2 MiB canonical projection fail explicitly instead of truncating. Source report limits also apply.

Rebuild after a case, evidence disposition or observation changes; stale exported JSON does not update itself. Included-record changes alter the checksum. Changes outside the projection, such as new custody-access events or analyst comments, need not alter it. The authoritative report/custody/workflow paths remain available for those records. No derived storage needs a purge/reset; downloaded files still require the operator's approved retention controls.

## Engineering loop and acceptance

Status: **COMPONENT_VERIFIED at code source `dcaaaf2ecffb840e281ca7141cf2fbe649991991`**. Owner: implementation agent; independent reviewer/human UAT unassigned. A fresh service and actual database restart/dump-restore reproduced the same unchanged provenance graph without reading evidence bodies or weakening authorization. Tests cover real records, parent lineage, duplicate-byte groups, browser observations, both exact browser/local task links and idempotent relinking, empty/change states, foreign/machine denial, viewer revocation, corruption/audit failure, bounds, actual CLI, native HTTPS screen/download and native Chrome/Brave navigation. Matching-image gate passed 644 component/regression cases plus 30 developer-journey checks per browser; artifact hashes/source-tree equivalence and the initial fixture failure are retained in the implementation ledger. This is not release acceptance.

Human UAT inventory: case-detail link, records, stored links, partial/unverified labels, checksum, JSON download, empty/error/revoked/foreign/role states, keyboard access and hostile escaped text. Human UAT and post-release regression are **NOT_RUN**. Full C06 and GAB-006/022/025 are not accepted by this component alone. Entity/event correlation and deduplication, asset/control profile, memory, specialists/models, real-console adapters and release gates remain open.

Rollback stops the new workbench image and restores its predecessor; PostgreSQL and evidence data are unchanged. Existing CLI reports/custody remain authoritative. No deployment or external-console action is performed by this slice.
