# Candidate model corpus review register

This is a draft evaluation input, not qualification evidence. All 60 scenario families are fictional repository-authored lab data, including the original twelve development examples unchanged. There are 30 development cases (10 of each class), 10 validation cases (4 attack, 3 benign, 3 visibility), and 20 candidate held-out cases (8 attack, 6 benign, 6 visibility). Each family occurs in one partition. All new labels are provisional, including critical attack designations.

## Review and sealing

A qualified defensive analyst must review each observation, label, acceptable decision and rationale, document corrections and rights, and attest review under an accountable identity. Before acceptance runs, independently choose and seal the held-out inputs and labels by hash. The current held_out field is a candidate partition seen by its author, not a claim of independent holdout. Do not tune prompts against acceptance answers; changes require a new controlled evaluation version. The register below intentionally contains no fabricated signatures, model answers or analyst attestations.

## Limits

The small, two-observation fictional scenarios do not represent production distributions. A family name is a scenario category, not verified attack-technique coverage. Separate source names do not prove independence. One scenario per family does not establish robustness, adversarial resistance or field effectiveness. Explicit gap identifiers measure contract compliance rather than independent gap discovery. Console/UI drift, real adapter normalization, semantic redaction/compaction equivalence and analyst workload remain unevaluated. Critical cases and benign authorization narratives require specialist review before use.

Packet generation excludes labels, class, rationale, gaps and critical flags. Corpus schema/partition checks and a failing empty-result evaluation are software checks, not model evaluation. No paid provider calls are enabled by adding this corpus. Existing fixed development probes remain unchanged. Production admission stays false even if an offline report passes.

| Case | Partition | Draft class | Analyst review |
| --- | --- | --- | --- |
| dev-auth-attack | development | attack | Pending |
| dev-persistence | development | attack | Pending |
| dev-lateral | development | attack | Pending |
| dev-egress | development | attack | Pending |
| dev-backup | development | benign | Pending |
| dev-patch | development | benign | Pending |
| dev-rotation | development | benign | Pending |
| dev-admin | development | benign | Pending |
| dev-logout | development | visibility | Pending |
| dev-forwarded | development | visibility | Pending |
| dev-injection | development | visibility | Pending |
| dev-skew | development | visibility | Pending |
| candidate-token-replay | development | attack | Pending |
| candidate-malicious-mail-rule | development | attack | Pending |
| candidate-unapproved-oauth-grant | development | attack | Pending |
| candidate-webshell-upload | development | attack | Pending |
| candidate-dns-beacon | development | attack | Pending |
| candidate-credential-memory-read | development | attack | Pending |
| candidate-authorized-assessment | development | benign | Pending |
| candidate-cloud-bootstrap | development | benign | Pending |
| candidate-kerberos-renewal | development | benign | Pending |
| candidate-approved-hr-export | development | benign | Pending |
| candidate-healthcheck-scan | development | benign | Pending |
| candidate-software-inventory | development | benign | Pending |
| candidate-unknown-pagination | development | visibility | Pending |
| candidate-wrong-tenant-view | development | visibility | Pending |
| candidate-lost-redaction-join | development | visibility | Pending |
| candidate-truncated-command | development | visibility | Pending |
| candidate-stale-only-evidence | development | visibility | Pending |
| candidate-timezone-ambiguous | development | visibility | Pending |
| candidate-cloud-key-minting | validation | attack | Pending |
| candidate-scheduled-persistence | validation | attack | Pending |
| candidate-database-bulk-copy | validation | attack | Pending |
| candidate-anti-tamper-disable | validation | attack | Pending |
| candidate-golden-image-snapshot | validation | benign | Pending |
| candidate-vpn-geolocation | validation | benign | Pending |
| candidate-approved-secrets-read | validation | benign | Pending |
| candidate-console-rate-limit | validation | visibility | Pending |
| candidate-offline-agent | validation | visibility | Pending |
| candidate-asset-name-collision | validation | visibility | Pending |
| candidate-mass-encryption-renames | held_out | attack | Pending |
| candidate-mfa-fatigue-session | held_out | attack | Pending |
| candidate-cloud-detection-deletion | held_out | attack | Pending |
| candidate-container-mining | held_out | attack | Pending |
| candidate-directory-replication-abuse | held_out | attack | Pending |
| candidate-critical-backup-deletion | held_out | attack | Pending |
| candidate-service-account-escalation | held_out | attack | Pending |
| candidate-removable-media-payload | held_out | attack | Pending |
| candidate-approved-dr-failover | held_out | benign | Pending |
| candidate-certificate-rollover | held_out | benign | Pending |
| candidate-new-hire-provisioning | held_out | benign | Pending |
| candidate-approved-vulnerability-scan | held_out | benign | Pending |
| candidate-signed-data-migration | held_out | benign | Pending |
| candidate-authorized-containment | held_out | benign | Pending |
| candidate-hostile-markdown-content | held_out | visibility | Pending |
| candidate-cloned-alert-chain | held_out | visibility | Pending |
| candidate-clock-reversal | held_out | visibility | Pending |
| candidate-partial-network-path | held_out | visibility | Pending |
| candidate-retention-window-gap | held_out | visibility | Pending |
| candidate-unreadable-view | held_out | visibility | Pending |

## Software verification checkpoint

Candidate source `b46f266f73578004c400364acb45e9d856a8efa7`, tree `441a73695236fc8bc7f419ac9ec63398d07d241f`, passed isolated Docker job 118835610532: 43 tests, zero failures/errors/skips. Native ARM64 run 39482852702 and x86 run 39482852690 each passed **754 component + 49 runtime + 21 foundation = 824 tests**, zero failures/errors/skips, plus real PostgreSQL restart and fresh dump/restore preserving coordinator claims/replay/Stop. Browser run 39482852670 and separate runtime run 39482852639 passed. The live provider job intentionally skipped. These are software integrity/regression results, not reviewed labels, sealed holdout, model answers or quality evidence. All analyst review entries remain pending.
