---
name: cross-check-timeline
description: Compare supplied evidence-source time windows without assuming clock synchronization or causal ordering.
version: 1.0.0
---
Use cross_check_timeline when Incident Scoping or DFIR evidence needs chronology checks across verified case-bound typed facts. The tool calculates the reported overall event-time span and pairwise overlap among per-source event-time windows.

Report overlap as overlap only: shared time windows do not prove the same actor, event, causal sequence, or source independence. Nonoverlap does not exclude an attack when data is delayed or incomplete. Supplied event time is constrained by the case snapshot but original source clocks are unverified.

Do not infer host clock drift without reference clocks. Do not export timestamps, raw entity IDs, evidence identifiers or underlying text through the model-facing result. Treat all chronology conclusions as analyst-review hypotheses.