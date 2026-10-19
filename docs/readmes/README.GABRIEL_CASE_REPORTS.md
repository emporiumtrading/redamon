# Gabriel case metadata reports

`python -m gabriel.identity.case_cli report --case-id <uuid> --token-file <private-session-file>`

Uses the existing identity DSN and evidence-store/keyring configuration. This is a real authenticated PostgreSQL snapshot, not a generated incident narrative. Current owner/admin/analyst/viewer memberships may read metadata; worker/browser credentials cannot. Audit admission is mandatory. Reports contain potentially sensitive case titles and source labels: handle stdout as tenant-restricted case metadata.

The JSON envelope includes a SHA-256 digest of `canonical(snapshot)` (sorted compact UTF-8 JSON, unescaped Unicode). It is a consistency checksum, **not** an independent signature, immutable archival receipt or evidence authenticity claim. The report is generated from authoritative persisted state; the report itself is not saved by this command. Save it only to approved storage. Each successful generation creates an audit event; it does not access/export evidence content or extend custody with a content-read event.

The timeline distinguishes unverified source-event times, server collection/custody times and unverified browser-client observation clocks. No clock correction or inferred causal ordering occurs. Browser observations remain partial, including a prepared observation whose evidence/receipt is not yet confirmed. Identical content hashes retain all artifact IDs and are explicitly not counted as independent corroboration or event-level deduplication.

Custody hashes are validated before inclusion. Damaged chains deny the report. Content decryption/integrity is **not checked** by reporting; use the separate `verify` operation and retain its exact outcome. Purged and pending-disposition metadata are not represented as available content. Source authenticity, incident assessment, entity correlation, assignments, analyst questions and knowledge of off-screen events are not supplied by this slice.

Limits are 64 artifacts, 1,000 browser observations, 1,000 linked tasks and 4,096 combined timeline entries per report. Overflow fails explicitly instead of silently truncating. No encryption keys/IDs, object paths, session digests, browser tickets or raw artifact bodies are serialized. The organization lock serializes application writes with the snapshot; direct database-administrator alterations are outside that application concurrency guarantee.

## Loop record

- Requirements: GAB-006/007/022/026/040, partial C06 reporting/timeline component only. Owner: implementation agent; independent reviewer and analyst UAT unassigned.
- Baseline: browser candidate `845497ce6fd8779490e58862bd1639289d42585a`; schema 12, no migration or new database grants.
- Hypothesis: a fresh service/CLI can reconstruct a bounded tenant-only report from persisted case/evidence/browser records without leaking artifact content or conflating source truth with custody consistency.
- Verification: nine dedicated actual-PostgreSQL cases plus the existing real CLI round trip extended with `report`; the real restart/dump-restore probe also requires report evidence equality, preservation of prior timeline entries and closed-case report availability. Full source-specific Docker identity/runtime/foundation gate required. Local compile/diff checks are not acceptance.
- State: IMPLEMENTED_UNVERIFIED until the exact hosted gate result is recorded. First hosted gate at source `76633c2606af4d70374f3a2b3bec382c0b0d373b` collected 518 component cases: 508 passed, 10 failed, zero errors/skips. All nine report cases and the extended CLI round trip failed. Inspection found the new module absent from the Dockerfile's explicit runtime COPY list; repair 1 adds it to the shipped image. No assertion or authorization requirement is relaxed. Full affected regression is required again.
- Rollback: remove the new report CLI/method/module; existing schema and artifacts remain unchanged. Issued reports are point-in-time metadata copies, not retractable external messages.
- Remaining: integrated workbench, persisted report workflow/history, entity/event correlation, graph projection, assignment/questions, human/independent acceptance and pre/post-shipping UAT. This component does not close any full PRD requirement.
