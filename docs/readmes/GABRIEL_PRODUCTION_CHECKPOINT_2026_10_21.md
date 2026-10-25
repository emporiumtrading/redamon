# Gabriel production checkpoint — 21 October 2026

Full PRD status: IN_PROGRESS. No production release, model admission, merge, deployment, real-console acceptance or post-release observation is established by this checkpoint.

## Verified increments

| Increment | Source | Component evidence | Remaining boundary |
| --- | --- | --- | --- |
| Source-bound browser event correlation, PR 45 | e563172c701d0b44ad3acfa1f01cdf0b28dfe0de | Both architectures: 990 component, 49 runtime, 21 foundation; focused 46. Physical restart/fresh restore; Chrome and Brave 54 checks each | Generated console only; source authenticity and detection quality unqualified; no continuous observation |
| Twelve-role local coordination, PR 46 | 8dff78ec4f408c98c799b582cd650f1599a248ab | Both architectures: 1,001 component, 49 runtime, 21 foundation; focused 56. Four saved steps resumed to twelve on restart and fresh restore; HTTPS/CSRF flow | Local rules, not twelve qualified AI agents; browser-event-to-specialist-facts projection and full specialist tools remain open |
| Exact core Docker test candidates, PR 47 | 0421b38997813df33ff26e3eee5ba7d049613278 | Both architectures: 1,009 component, 49 runtime, 21 foundation; focused 56. Archive config digests, reload and no-network core smoke checks passed. All four workflows passed | Core testing bundle; complete installation and production acceptance remain open |

All cited component suites passed with zero failures, errors or test skips. Additional focused suites overlap the component suites and are not extra unique tests. Generated container browsers run without their sandbox only in the isolated lab; this is not native OS acceptance.

## Requirement and loop evidence

PR 45 covers GAB-007/017/022/023/028 through finite generated-console normalization, real encrypted receipts, frozen source vectors, native-event duplicate suppression, provisional attack hypotheses and Stop/authority checks. PR 46 covers GAB-027/028 with GAB-005/008/025 regression. PR 47 covers GAB-008/019/040/041 for exact checked-image retention. The full [46-requirement reconciliation](GABRIEL_REQUIREMENT_STATUS.md) remains the scope register.

The engineering hypothesis was that saved source bindings and request IDs could produce a review or resume local specialist work without new captures, duplicate results, model charges or external effects. Tests exercised real PostgreSQL, encrypted evidence, physical restart, fresh pg_dump/restore, HTTPS forms and packaged Chrome/Brave generated-console paths. Source-specific workflow records and PR descriptions retain the exact results and artifact references. Product effectiveness and human usefulness are separate unclosed gates.

PR 46 and PR 47 have no hidden same-cause repair loop at this checkpoint: both passed their first completed CI attempt; no source repair was needed. Implementation confidence is supported for the tested component contracts. Security confidence is bounded by those negative tests and does not replace independent review. Operational confidence remains unverified for a customer deployment. No complete requirement is marked ACCEPTED_POST_RELEASE.

## Open release work

| Area | Remaining work |
| --- | --- |
| Console coverage | Actual simulator/console endpoints, product/version and authorized page/account scope; reviewed adapters, existing-search/filter operations, pagination/completeness, drift and human-login handoff tests |
| Investigation product | Environment/control profile, proactive hunt selection and reviewed playbooks, priority/escalation workflows, complete states/accessibility and end-to-end specialist input integration |
| Models | Independent analyst-adjudicated sealed evaluation, required repetitions and role-specific quality/privacy/cost checks; production route admission and NVIDIA entitlement/transport acceptance where enabled |
| Tools and response | Each of the ten selected integration profiles needs its own real-version workflow, license/provenance, least-privilege and failure tests; external response requires individually admitted exact action/effect/recovery |
| Distribution and operations | Full installer/persistent services, secret custody, dependency/license/container scans and SBOM/provenance, resource/load tests, upgrade/rollback and measured recovery; native Chrome/Brave OS matrix |
| Release acceptance | Human staging UAT, exact artifact/configuration acceptance, deployed-version checks and safe post-release UAT, then the required observation period |

Customers supply their own provider credentials. Production model configuration admission remains empty. No development key fallback or new paid inference is introduced by these increments.

## Recovery and next inputs

Keep the tested image IDs, extension hash/source, source-specific reports and separately retained evidence/provider keys. Candidate archives contain no runtime database or evidence state. Loading an image is not database rollback. Schema-25 removal helpers are disposable test fixtures and must not be used as a production downgrade. Installation, migration backup, supported rollback and external-effect reconciliation still need deployment acceptance.

The next console-validation path requires the simulated environment URL(s), actual product/version and scoped test account/pages; the engineer signs in through the browser. Model admission requires independent qualified adjudication rather than replacing missing human review with generated labels. Continue independent engineering while those dependent paths await their actual inputs.

## Candidate artifact evidence

CI checkout for PR 47: 7b18be519c0620a6e4ec9ab1f0115012add0bd36. Production admission is false. The candidate's own manifest contains the inner images.tar.gz hash and exact image IDs.

| Artifact | Workflow and ID | ZIP bytes | GitHub-reported ZIP SHA-256 |
| --- | --- | --- | --- |
| AMD64 core candidate | [run 39596102257](https://github.com/emporiumtrading/redamon/actions/runs/39596102257), artifact 12345220621 | 62,758,351 | db0a02514df7263afb5c0e81fcac9a6fc19bc30d2b80aac5f00659a7438ab4d6 |
| ARM64 core candidate | [run 39596102263](https://github.com/emporiumtrading/redamon/actions/runs/39596102263), artifact 12344079474 | 64,632,257 | 60e00dfc26c30f604e782d10dc5d650e0c401914345b6a502334e1ac3bb32be7 |
| Matching browser package/evidence | [run 39596102138](https://github.com/emporiumtrading/redamon/actions/runs/39596102138), artifact 12343793594 | 120,773 | 4051ebe345294ed8a361a630a19a7953d05709f4e97123c33297df60778448af |

The workflow verified image archive contents and reload. The ZIP digests above are GitHub artifact metadata, not independently downloaded/hash-checked copies. The bundles expire on 4 November 2026. They contain core test images and reports, not a complete production installation. See [candidate usage and boundaries](GABRIEL_CORE_CANDIDATES.md).
