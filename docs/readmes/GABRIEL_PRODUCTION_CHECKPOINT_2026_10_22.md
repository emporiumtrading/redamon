# Gabriel production checkpoint — 22 October 2026

Full PRD status: IN_PROGRESS. Changes remain draft and unmerged. No production release, model admission, deployment, real-console acceptance or post-release observation is established here. The previous [21 October checkpoint](GABRIEL_PRODUCTION_CHECKPOINT_2026_10_21.md) retains earlier evidence; the [46-requirement register](GABRIEL_REQUIREMENT_STATUS.md) remains the complete scope record.

## Completed and verified increments

| Increment | Exact source | Verified component behavior | Boundary |
| --- | --- | --- | --- |
| [PR 49](https://github.com/emporiumtrading/redamon/pull/49): captured events to twelve specialists | 04a8ec03fc5ef807e2914536ed956428e22b1a6a | Both architectures: 1,027 component + 49 runtime + 21 foundation tests; focused 74. Actual restart/fresh restore preserved source-bound twelve-role results without duplicate work or charges; Stop denied replay. Chrome/Brave each passed 57 checks. | Local rules over generated-console-v1 only; unsupported facts cause abstention. No AI qualification, real vendor adapter or continuous monitoring. |
| [PR 50](https://github.com/emporiumtrading/redamon/pull/50): historical environment view | 0927c764ee0b9bae631641cf00c3c435ac87c19f | Both architectures: 1,037 component + 49 runtime + 21 foundation tests; focused 83. Actual HTTPS permission/CSRF checks, corrupted source/input rejection, mandatory audit rollback, tenant isolation and exact profile reconstruction after physical restart/fresh restore and Stop. Chrome/Brave each passed 59 unique checks. | Latest bounded reviewed snapshot only. Identifiers need explicit content authorization; metadata-only viewers receive no raw keys. Reported paths are not proven network topology. Security effectiveness and compliance remain separately unassessed. |

Both increments passed all four workflows on their first completed attempt, with zero failures, errors or test skips in the cited suites. Focused suites overlap component suites and are not additional unique tests. The optional live provider probe was deliberately skipped; these increments made no paid model calls. Browser tests used isolated generated consoles with the container browser sandbox disabled, not native OS/vendor-console UAT.

PR 49 adds GAB-027/028 component evidence for the browser-event-to-specialist bridge; PR 50 adds GAB-020 evidence for a bounded historical view. Neither closes its complete release requirement. All twelve specialist implementations remain local rule kernels with unqualified confidence, attack truth unknown and no response authority. Production console adapters and model configurations remain empty.

## Latest exact source and artifact evidence

PR 50 CI checkout: 09a5eb7c7d3e402436b90a5410343b779aa14ab5. Its tree 40c85ca609eca88626f2eab1978e1c69f64b11e6 was independently fetched and matched to the submitted head and local staged tree. This verifies tested contents without claiming the PR was merged.

| Artifact | Workflow / artifact ID | ZIP bytes | ZIP SHA-256 |
| --- | --- | --- | --- |
| AMD64 core candidate | [39872301646](https://github.com/emporiumtrading/redamon/actions/runs/39872301646) / 12467960390 | 62,825,816 | e49f4a64464a331468aa80b0acf377844c97fb1e53d9a22bf42c9e6630df720c |
| ARM64 core candidate | [39872301635](https://github.com/emporiumtrading/redamon/actions/runs/39872301635) / 12467129101 | 64,703,006 | f2c245055a1d7d7bca8a6a462f5c6da56fab6eed90871207aa8bfd9d34ee81aa |
| Matching browser package and evidence | [39872301650](https://github.com/emporiumtrading/redamon/actions/runs/39872301650) / 12466388867 | 120,066 | e0dc3e62274eb2ac59ebd941487596d3758427f8577f7955da091d6e778581de |

The browser ZIP was independently downloaded and hash-verified; parsed reports confirmed PASS, extension 0.3.0 and 59 unique checks per browser, including environment unknown-state and separate security/compliance states. Core ZIP digests above are GitHub-reported metadata. CI independently verified their inner image archive configurations, reloaded the existing checked images and passed the default-deny no-network core import smoke. Large core ZIPs were not independently downloaded in this session. All artifacts expire on 5 November 2026.

These are core testing bundles with reports, not a complete production installer. They contain no runtime database/evidence state or customer provider credentials. Keep encryption keys and runtime state separately; image loading is not database rollback. Test-only migration downgrade helpers are not supported production rollback.

## Remaining release work and next sequence

| Workstream | Concrete completion gate | Dependency |
| --- | --- | --- |
| Product workflows | Complete environment ownership/control/configuration/correction and recovery dependencies; proactive hunt selection, reviewed playbooks, priority/escalation and approval inbox; complete product states/accessibility. | Engineering plus representative analyst review. |
| Browser investigation | Implement and accept selected real-console adapters, supported searches/filters, pagination/completeness, UI drift and authority-loss/human-login handoff. Measure observable detection coverage/latency before claiming live monitoring. | Simulated environment URL, actual product/version and authorized account/page scope; human signs in. No such console has been accepted. |
| Model suitability | Independent analyst adjudication, sealed evaluation, repetitions and role-specific quality/privacy/cost checks; admit only exact passing routes. Complete NVIDIA entitlement/transport where enabled. | All 24 existing human development reviews remain pending; generated labels cannot supply independent approval. Production route registry remains empty. |
| Specialist tools and response | Accept exact versions of selected tool profiles with license/provenance, least privilege and real workflow/failure tests. Individually admit any external response's exact target/action/effect/recovery. | Actual lab tools and authorized response scenarios. Catalog entries are not supported integrations. |
| Installation and operations | Complete persistent services, TLS/authentication, key custody, installation, upgrade/rollback, backup restoration, resource/load limits and measured RPO/RTO. | Target Docker host and operating environment. Linux ARM64 CI is not Mac Docker Desktop acceptance. |
| Security and distribution | Complete SAST, dependency/license/secrets/container scanning, SBOM/provenance and independent security review; review extension distribution/updates. | Exact release artifacts and configuration. Existing negative tests do not replace scans or review. |
| Release acceptance | Native Chrome/Brave Windows/macOS/Linux matrix, human staging UAT, exact deployed-artifact checks, post-release UAT and 24–48-hour observation. | Customer staging/production environments and human acceptance owners. No complete requirement is ACCEPTED_POST_RELEASE. |

Customer-owned OpenRouter keys and funding gates remain in scope: initial account balance and dedicated-key allowance of at least $18, monthly key cap and lower operational spending limits. Customer NVIDIA keys remain isolated; entitlement validation is still pending. No development/shared credential fallback is introduced. More OpenRouter candidates can be evaluated, but catalog presence and development answers do not establish qualification. Gemini's earlier fixed route being unavailable is not a general judgment that Gemini models cannot qualify.

Continue independent product, packaging and security engineering while real-console, human model-adjudication and environment acceptance paths await their concrete inputs. The priority is a complete, reviewable test installation and realistic source-to-specialist investigation, followed by exact-source acceptance; do not convert missing evidence into passing status.
