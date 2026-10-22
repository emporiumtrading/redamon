# Case environment and control view

Requirement scope: GAB-007, GAB-020, GAB-022, GAB-025 and GAB-026. Exact-source Docker acceptance is pending. This increment supplies a bounded source view; full environment onboarding, asset ownership, control configuration/corrections and validated effectiveness remain open.

The case Environment and control profile page summarizes the latest persisted attack-review snapshot. A metadata view shows the supplied snapshot time, server review time, distinct event count, forwarded-copy count and reported source gaps. It explicitly identifies omitted older snapshots. A future supplied clock is flagged. No current-environment or continuous-coverage claim is made.

Owner/admin/analyst users can explicitly request the reported identifiers through a CSRF-protected form. That read verifies the actual encrypted typed input, every cited same-case source, digests, custody and model-origin exclusions. Native source/event identities are deduplicated before entity/path counts are calculated. Source and destination keys, actor keys, event kinds, intervals and evidence links are displayed as unverified assertions. A reported event path does not prove a live connection or causality. A corrupt, purged, mismatched or unavailable latest source blocks the content view; it does not silently fall back to an older snapshot.

Read-only viewers can see historical metadata but cannot obtain source-derived identifiers through the UI or backend. Tenant membership, content permissions and case scope are checked at every read. No profile content is sent to a model or third party. Source-derived identifiers are not copied into another persistent metadata store; PostgreSQL case/review state and encrypted evidence remain authoritative. The view is rebuilt and audited when requested.

## Control and assessment boundaries

Assets and identities have evidence_state=reported and owner=null. Control configuration, ownership and recovery dependencies remain unknown. Security-control effectiveness is not validated; compliance coverage is not assessed. They have separate UI status fields and no combined score. Recent supplied activity, a stored configuration or a matching attack-rule hypothesis cannot establish control effectiveness or compliance coverage.

Cases with no supported reviewed event snapshot display an explicit unknown-coverage state. A source that declares no gaps still does not establish completeness. The view covers only the latest bounded snapshot, not an independently resolved whole-organization inventory. It does not infer ownership from a case assignee, infer permissions from a role label, promote browser text into configuration truth or learn executable behavior.

## API, CLI and recovery

CaseService.environment_profile(token,case_id) returns metadata and a view checksum. include_identifiers=True requires content authority and checks source bytes. The private case CLI exposes environment-get with --case-id; --include-identifiers explicitly requests content. The workbench uses GET for metadata and POST /cases/{id}/environment/content with a valid CSRF token for identifiers.

The historical view remains accessible to an authorized case analyst after browser Stop; Stop still prevents new delegated collection/review. Physical restart and fresh restore must reproduce the same source-backed view. This is distinct from proving live console availability or accepting production recovery objectives.

Tests cover unknown/empty states, source bindings and counts, forwarded-event deduplication, identifier privacy, viewer/foreign-tenant denial, corrupt sources and receipts, future clocks, omitted snapshots, audit rollback, actual HTTPS form behavior, browser empty-state controls and physical restart/fresh restore. Remaining real-console, ownership/control evidence and human usefulness acceptance must not be replaced by these generated component fixtures.
