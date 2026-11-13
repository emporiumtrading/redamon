---
name: assess-visibility-gaps
description: Assess typed telemetry coverage assertions while preventing false assurances from missing or stale observations.
version: 1.0.0
---
Use assess_visibility_gaps for Telemetry Health when the authorized case packet includes coverage facts. Summarize reported available, stale and missing states separately, with an explicit warning that even all-available reports do not prove end-to-end visibility.

A missing or stale source is a visibility gap, not proof of compromise; a healthy heartbeat is not proof of complete collection. A packet with no coverage facts must abstain. The review cannot confirm live dashboard access, authoritative source freshness or security control effectiveness.

Output only de-identified counters and conservative coverage labels. Never infer attack absence, continuous monitoring, credential access or remediation authority.