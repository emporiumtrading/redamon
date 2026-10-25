# Candidate attack-pattern correlation kernel

`attack_patterns.py` implements bounded, deterministic correlations over strict
`security-events-v1` documents. A source-verifying persisted caller is available
through the case workbench's Attack pattern review page; automatic browser event
normalization and specialist orchestration remain pending. No live detection or production quality is
claimed. The module performs no network request, model call, page operation or
response. Its results are candidate hypotheses for review, never confirmations.

| Family | Initial candidate pattern |
| --- | --- |
| Brute force | At least ten distinct native failure events for the same supplied account key within five minutes |
| Password spraying | At least ten failures covering at least five supplied account keys from one supplied origin within five minutes |
| Password misuse | A reported unauthorized authentication success, or a same-account/asset success following repeated failures |
| Worm propagation | Same reported process hash spreading to three destination assets from multiple source assets, with a propagation edge, within five minutes |
| Lateral movement | An ordered remote-execution chain across assets under the same supplied identity, with matching preceding authentication successes |
| Ransomware | At least twenty distinct file-object changes in one minute, correlated with a ransom-note or backup-interference indicator |
| Possible rootkit | A reported kernel or boot integrity violation requiring specialized validation |

Thresholds and semantics are provisional development choices. They require
independent attack/benign/visibility evaluation before admission. Low-and-slow
attacks and alternative behaviors can fail these patterns; an unmatched packet
is never a benign verdict. A firewall may expose some relevant observations and
lack others, particularly endpoint/file/kernel evidence.

Events bind source-native identity, source/artifact digest, time, supplied entity
keys and typed event details. Same native identity repeated in multiple captures
is deduplicated; conflicting descriptions are rejected. This cannot deduplicate
forwarded events that an adapter incorrectly assigns unrelated identities.
Adapter semantic and identity mapping acceptance remains mandatory. Reported
approval never suppresses a candidate: page data cannot approve its own behavior.

Results retain evidence references, event interval, observed event count,
affected asset count, a benign alternative, unverified-source labels and
unqualified confidence. Missing source classes remain explicit. Current runtime
authority, same-case source bytes and digests are checked by `attack_pattern_runs`;
the pure kernel itself provides neither. The accepted product path must connect source
capture, normalization, correlation, specialist assessment, urgent presentation
and measured end-to-end latency.

New generated-event tests exercise seeded patterns, overlapping windows,
forwarded duplicates, slow failures, missing identity bindings, unrelated remote
activity, bulk-file lookalikes, marker correlation, source/time/field conflicts
and prompt-like values. They are software behavior tests, not live malware,
real-console compatibility, human usefulness or detection-quality acceptance.

The [assigned-section browser executor](GABRIEL_BROWSER_INVESTIGATION_EXECUTOR.md)
defines the required autonomous navigation journey and the Playwright boundary.
