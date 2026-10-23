# Gabriel installation checkpoint — 23 October 2026

Full PRD status remains IN_PROGRESS. The [46-requirement register](GABRIEL_REQUIREMENT_STATUS.md) and [previous checkpoint](GABRIEL_PRODUCTION_CHECKPOINT_2026_10_22.md) retain the broader release scope. This increment is a local operator-led test installation; no production release, merge, deployment, model qualification, real-console integration or post-release acceptance is established here.

## Verified installation increment

[PR 52](https://github.com/emporiumtrading/redamon/pull/52) head: 9a4e722fe8a08f5661b6afd45e8baea187a9877f. Actual CI checkout: 43b2e13df87a0767e6b88fd5fb12ad9e580e428c. Its tree a046a48beb0865a52a3f8cd5ed38e7d39992b83b was independently fetched and matched to the local staged tree and submitted head.

The new controller prepares separate database/evidence/provider/TLS material outside Git, enrolls one hashed owner identity, opens a fresh authenticated short-lived workbench, retains PostgreSQL and encrypted evidence in named volumes, stops/revokes access, and makes a quiesced backup for same-source restoration into a fresh project. A non-root, credential-free relay forwards opaque TLS to the fixed private workbench service. Only that entry publishes a localhost port; the application and database remain on an internal network. No inherited offensive services, shared developer key, model egress or external response are enabled.

Actual Linux x86 and native ARM64 installation journeys passed: private network/mount admission, fresh enrollment and duplicate-enrollment denial, trusted host-side HTTPS claim and CSRF rejection, case creation/persistence, encrypted evidence acquisition, physical database restart, old-cookie denial after fresh login, stopped-write backup, fresh-project recovery with original evidence/provider keys, decryption of recovered evidence and fresh login after Stop. The test controller removed only its own generated CI projects/volumes afterward.

All five workflows passed at the cited final source. Both architectures passed 1,045 component tests across 46 isolated files, 49 runtime tests and 21 foundation tests, with zero failures/errors/test skips. The focused 83-test suite overlaps the component suite and is not an additional unique count. Eight new component tests check certificate identity/usage, exact encrypted-object restoration and rejection of traversal, links, unknown names, duplicate members and invalid object sizes. Physical restart/fresh dump-restore also retained the existing browser-specialist and historical environment behavior.

Downloaded Chrome for Testing and Brave reports each passed 59 unique checks with extension 0.3.0. This remains generated-console testing, with the container browser sandbox disabled in that isolated lab, not native OS or Wazuh/IRIS acceptance. The provider software gate passed; optional paid live inference was deliberately not run.

## Repair evidence

The initial installation journeys failed on both architectures because an unquoted YAML flow-list value split tmpfs options into separate mount paths. Two diagnostic-only commits were needed to expose the Docker startup reason without logging generated secrets. Quoting the mount and checking its rendered form fixed enrollment. The next journey then found that a published port on the internal-only application network did not provide host access. The bounded, credential-free TLS relay and its readiness check fixed the actual host path while preserving the private application/database network. The final source passed the unchanged enrollment/recovery requirements; CSRF and relay-isolation assertions were added. No failing assertion or security boundary was waived.

## Downloaded and checked evidence

| Evidence | Run / artifact ID | Independently verified ZIP SHA-256 |
| --- | --- | --- |
| x86 installation | [39986858040](https://github.com/emporiumtrading/redamon/actions/runs/39986858040) / 12516276198 | b9b8c14b1c3a5761bfdb979348ea3f28ceafbb5970d048d2bdee96be5f5485aa |
| ARM64 installation | [39986858040](https://github.com/emporiumtrading/redamon/actions/runs/39986858040) / 12515918482 | 580b3d8b9d5726cac39d03e6b45fcda58dd4087205786cfc3c2bab0eedf05689 |
| Matching packaged browser | [39986858550](https://github.com/emporiumtrading/redamon/actions/runs/39986858550) / 12516271250 | 3caa921bc4df521370a40ce621aad08d33245f19aa4578d0eff28abaee259e74 |

All three archives' recorded source equals the fetched CI checkout above. Installation image IDs recorded inside the accepted journeys: x86 sha256:fa2535f6f1e9e9883eaee7cb0bcf73b6a2481ef6bf236b8a241bb766ec56afaa; ARM64 sha256:377b395b3457df7694a61b4976375bda9d3417091160d0d8d69a287492579718. These are installation-job image identities, distinct from any separately built core candidate images. Evidence expires on 6 November 2026. The small installation archives contain sanitized acceptance records, not a downloadable all-in-one installation image or runtime credentials/state.

Both architecture jobs exported existing checked core images without rebuilding, verified their archive configurations, reloaded them and passed the default-deny no-network import smoke. These are separate core testing bundles; their ZIP hashes below are GitHub-reported metadata, not independently downloaded/hash-checked copies in this session.

| Core candidate | Run / artifact ID | ZIP bytes | GitHub-reported ZIP SHA-256 |
| --- | --- | --- | --- |
| AMD64 | [39986858376](https://github.com/emporiumtrading/redamon/actions/runs/39986858376) / 12517500330 | 62,832,747 | c550a8d49ad75a48dbcf2e3c3c71f51af5b6a046a55672ae78142c943117d21c |
| ARM64 | [39986858356](https://github.com/emporiumtrading/redamon/actions/runs/39986858356) / 12516397270 | 64,705,056 | 5e1bca22829549ebf596abb59a4a04c1938be5683e29468ed08f20ba6131a97f |

## Boundaries and next work

Use the [installation guide](GABRIEL_TEST_INSTALLATION.md). The controller currently requires a POSIX host. Sessions remain ten minutes with a 60-second one-use claim; there is no automatic authority renewal or continuous monitoring. Local certificates expire after 30 days; managed certificate renewal, multi-user product login, installation distribution, image/dependency pinning/scanning, upgrades/rollback, large-scale recovery and measured RPO/RTO remain open. The same-source backup is not a database downgrade or signed-release rollback mechanism. Original encryption keys must be retained separately. All complete PRD requirements still need scenario-level release acceptance.

The next concrete lab sequence and reviewed upstream source pins are in the [controlled lab record](GABRIEL_PRIVATE_LAB.md). Wazuh and DFIR-IRIS have been inspected as source candidates only; neither is deployed, connected or admitted. Build and verify the isolated real consoles, inspect their actual pages, implement scoped read-only adapters and run independently reviewed attack/benign/coverage scenarios. Model suitability, full workflows, the remaining tool profiles, native OS/browser tests, independent security review, human UAT and operational observation remain separate gates. Security-control effectiveness and compliance coverage stay separate throughout.
