# Generated browser-event correlation candidate

An approved section tour can collect strict event rows from the generated console,
retain the original visible JSON as encrypted browser evidence, normalize those
rows and request a candidate attack review. The generated browser lab divides ten
authentication failures between two sections: the first capture has no candidate;
the second snapshot combines both captures and produces a suspected brute-force
pattern with both evidence references. The popup shows that analyst review is
required and confidence remains unqualified.

## Authority and provenance

Only the reviewed generated-console-v1 navigation contract can use this path.
Production contracts remain disabled. The client checks the generated console
marker, visible account and event section in the assigned document. Event rows
must use compact, unambiguous JSON and exact typed fields; form/hidden data and
arbitrary page instructions are excluded. A browser-supplied reported_authority
enum becomes untrusted authorization context, never suppression or permission.

The events-review gateway operation accepts only current context and an already
captured observation ID. Current original-human, task, case, lease, sharing and
contract authority are checked. Pending captures or navigation block progress.
Encrypted source bytes, custody and observation bindings are verified.

Schema 24 freezes the source vector on the first request for an observation.
Metadata contains observation/evidence IDs, digests and omission counts, without
raw events or supplied entity identifiers. Subsequent explicit retries use that
same vector. Derived encrypted snapshots and candidate reviews use deterministic
idempotency IDs; later captures cannot silently expand an earlier review.
The derived artifact points to the triggering capture, while its typed events
and review packet cite every contributing source artifact.

The input is bounded to 32 captures and 256 events. Unsupported older captures
are counted as omissions and force explicit source gaps; a malformed current
snapshot is rejected. Case evidence and review quotas also apply. Stop prevents
further capture/navigation and admission of a new review. A local transformation
already in flight may leave a derived artifact for operator inspection; it does
not dispatch a model or response. Uncertain outcomes stop the tour and do not
automatically repeat the capture or review request.

## Measurement and acceptance

capture_to_review_ms measures the database capture-receipt timestamp to the
persisted review timestamp. It measures processing after capture, not time since
an attacker began. A backwards server-clock interval is reported as unavailable.
Source event clocks, actual account identity and collection completeness remain
unverified. These are sampled case snapshots, not uninterrupted monitoring.

PostgreSQL checks cover cross-capture correlation, frozen replay, concurrent
idempotency, malformed/corrupted sources, lost authority, Stop during derivation,
pending capture barriers and atomic migration. Restart/restore fixtures replay
the source vector without new captures or duplicate reviews. Actual Chrome and
Brave scenarios exercise the two-section event path, evidence links, a visible
candidate notice and a bounded generated capture-to-review interval.

CI execution and artifact inspection are required for acceptance. Generated
scenarios do not qualify thresholds, production latency, benign discrimination,
vendor semantics, independent source authenticity or model quality. The normalizer
and candidate rules make no model request and grant no response authority.
