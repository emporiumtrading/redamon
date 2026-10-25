# Persisted candidate attack reviews

An analyst can review an approved `security-events-v1` artifact in a case through
the workbench's **Attack pattern review** page, or with `case_cli attack-run`.
Every cited source must belong to that case and its encrypted bytes, custody
and digest must verify. Model-generated answers cannot serve as source evidence.
The caller examines at most 256 supplied events referencing 32 source artifacts.

The existing candidate kernel evaluates brute force, password spray/misuse,
worm-like spread, lateral movement, ransomware-like file activity and possible
kernel/boot integrity violations. Results persist in an append-only schema 23
ledger with input and result digests, source references, counts, reported time
intervals, alternatives and missing coverage. Raw events and supplied entity
identifiers remain in encrypted evidence rather than the review metadata.

The workbench displays suspected patterns as urgent review work. It links the
supporting evidence and states that source authenticity, detection quality and
current visibility remain unverified. An unmatched snapshot never establishes
that activity is safe. Current case authority gates each new run; replay is
bound to the original actor and input. Viewers can read historical results but
cannot create them. Each case is limited to 64 reviews and history reads to 32.
No model, browser search or response action is dispatched by a review.

PostgreSQL tests exercise source/case/actor binding, malformed documents,
ciphertext corruption, model-source denial, concurrency/replay, audit rollback,
claim validation, no-match uncertainty and atomic schema upgrade. HTTPS tests
exercise the workbench form, CSRF, persisted hypotheses and source links. Physical
restart/restore fixtures retain the review and verify its cited source bytes.
Execution evidence is required before claiming these checks passed.

This is a persisted caller for explicitly supplied typed snapshots. Automatic
browser-event normalization, continuous correlation, live alert delivery,
measured detection latency, vendor semantic qualification and independent
quality evaluation remain separate integration work. The browser executor's
current visible-text captures do not automatically become typed security events.
