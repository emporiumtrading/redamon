# Gabriel release blocker checkpoint — 25 October 2026 UTC

Release state: IN_PROGRESS. Production deployment and acceptance have not occurred.

## Current repair stack

PRs 63–67 build on PR61. PR62 is an independent offline human-review worksheet branch. Keep the branch dependencies intact; this record does not authorize a merge or production promotion.

| Gate | Observed evidence | State and next action |
| --- | --- | --- |
| High-severity core image findings | PR61 Debian image: 55 High OS matches, 0 Critical; no ignores. PR63 minimal-image run 40146094958 passed x86 and ARM scans, 1,045 isolated component tests each, PostgreSQL recovery and exact-image installation/HTTPS/fresh-project restore. | Candidate scan failure resolved: 0 High/Critical, 9 Medium, 1 Negligible, 0 source-secret matches on both architectures. PR67 pins the evaluated base; final-source checks are pending. Independent security review remains pending. |
| Real Wazuh least-privilege journey | PR64 creates a generated indexer read-only user and Wazuh readonly authorization-context mapping. Indexer search/read, denied writes/security reads and unchanged state passed before server-token failures. IRIS viewer journeys passed. | NOT accepted. PR67 waits beyond the Wazuh role-change second before issuing the viewer token. Require real browser identity, all twelve native records and unchanged-state 403 checks on the final source. Never use administrator browser fallback. |
| Native Wazuh semantics | PR65 introduces a versioned parser for complete native SSH invalid-user records, conflict checks, scoped entity identities, timestamps and source-linked manifests. | Software and integrated final-source gates pending. Source authenticity, customer authorization and navigation/model admission remain separate. |
| Model validation | PR66 has six passing offline software tests, no network or credentials. Ten exact authored validation request bodies are prepared. No new inference occurred. | Paid batch blocked by automatic approval review pending explicit payload/destination/spending approval. New-call maximum reservation $0.063040, OpenRouter → exact Cerebras route, existing budget constraints and carried unresolved holds. Independent human adjudication and sealed held-out qualification remain pending regardless of batch outcome. |
| Native OS and release acceptance | Linux x86/ARM and isolated headless browser results exist. | Native Mac/Windows UAT, independent security review, qualified analyst adjudication and operational/release acceptance remain open. Container tests do not replace these gates. |

## Immutable candidate evidence

Evaluated base: `python@sha256:5fb4bc53dd0180955e31e5245b648bbb24a4ac4ab03a1de81513642325220bcd`.

Candidate source PR63 head: `d16e1907577336141717afeabb42b0b7bddc49da`.

[Candidate acceptance run](https://github.com/emporiumtrading/redamon/actions/runs/40146094958). Downloaded ZIPs were independently SHA-256 checked against GitHub metadata; both contained matching base pins, actual image IDs, scanner identities, SBOM, full vulnerability reports and isolated test reports with zero failures/errors/skips.

| Architecture | Artifact | Independently checked ZIP SHA-256 |
| --- | --- | --- |
| x86 | 12581018860 | 486a86e203abcc007beb1cea6402515c5d2a8ebb53b4a6141214d256ac03d904 |
| ARM64 | 12580393803 | 47daab3560ff929437efdfe9d902e9534ff31b70d46f0c0cd40b216eaa986203 |

Nine Medium matches remain (seven unique advisory IDs across Python and BusyBox), with one Negligible match. No advisory was suppressed or accepted by an independent reviewer. High-severity scan acceptance is limited to the scanned image and database snapshot.

## Final-source validation

PR67 head `cfa5ccac12c08f571ab1f4b89046dbe2acba7274` pins the accepted base in the core runtime, Compose and signer defaults. Browser binaries have a separate Debian harness with native dependencies installed there; Alpine binary packages are not copied into Debian. Core production remains non-root and excludes pip/setuptools/wheel.

The Wazuh timing fix follows upstream v4.14.9 `framework/wazuh/rbac/orm.py`: `is_token_valid` requires token issuance strictly later than each revocation cutoff. This fixes setup sequencing, without relaxing authorization checks or modifying vendor state. Numeric vendor error identifiers may be logged; credentials, response bodies and tokens may not.

Final-source CI and downloaded artifacts must be recorded before declaring final-source acceptance. Production model and browser-contract registries remain empty. Test-driven local rule candidates are not live attack confirmation or autonomous production investigation.
