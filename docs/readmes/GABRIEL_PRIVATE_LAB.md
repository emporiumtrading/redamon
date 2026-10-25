# Gabriel controlled defensive lab

The owner approved a private lab path on 23 October 2026: complete a test installation, connect Wazuh and DFIR-IRIS, run controlled investigations, qualify models independently, then complete product/security/operational acceptance. This record prepares that path; it does not claim either tool is deployed, integrated, admitted or production-qualified. Start with the [local test installation](GABRIEL_TEST_INSTALLATION.md).

## Reviewed upstream candidates

These source checkouts were inspected directly, including tag peeling. They are reproducible evaluation candidates, not a recommendation that every dependency is safe or that their container images match these commits. Image manifests, platform support, vulnerability/advisory review, licensing and real workflow acceptance remain required before admission.

| Component | Candidate source | Inspected files and SHA-256 |
| --- | --- | --- |
| Wazuh single node | [wazuh-docker v4.14.9](https://github.com/wazuh/wazuh-docker/tree/56ece955b1107b7b62823afae5b7057e1dab9d98), peeled commit 56ece955b1107b7b62823afae5b7057e1dab9d98 | single-node/docker-compose.yml: 680a2bdc4444d51fe929706bbb13bed483341aac54ecbff3b71f41046d4cc1f9; single-node/generate-indexer-certs.yml: 038523da7ff4c93e51aaff8e46f13121c79d45e7fcbb50f2f1cb7ec6c115249d; LICENSE: edfece046050f6f3df3d1020b35a99ea9f67ee0af4b38c5693988049bb2d6499 |
| DFIR-IRIS v2 evaluation | [iris-web v2.4.24](https://github.com/dfir-iris/iris-web/tree/3e1e42d6088d950cf5c51ed8ad708adfb900beae), peeled commit 3e1e42d6088d950cf5c51ed8ad708adfb900beae | docker-compose.yml: d6da0fb1985aaa58a15cf60d6a467b03034d2d7a5fc3a89fa737912292140664; .env.model: 4996d84b04594515081453582486d89cac550cec815bb292258b8b477b272a20; LICENSE.txt: e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118 |

The [current Wazuh deployment guide](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html) specifies a four-core, 8 GB RAM, 50 GB single-node host and vm.max_map_count of at least 262144. That is Wazuh's baseline, not a measured budget for Gabriel plus two tools and browsers. Do not silently change a user's host kernel settings. Use a dedicated Linux lab host or explicitly configured Docker VM, record resource allocations, and measure peak usage before accepting the 18 GB Mac target.

The [current IRIS quick start](https://docs.dfir-iris.org/latest/getting_started/) points to v3.0.0-beta.1 and explicitly describes beta versions as unsuitable for production. The v2 candidate above avoids silently switching the investigation UI/API generation. It still needs security-advisory and maintenance assessment; if it cannot pass, select and revalidate another supported release. Do not confuse candidate selection with production support. Preserve upstream license notices and review component/transitive distribution obligations rather than treating the product license alone as complete provenance.

## Deployment and browser admission sequence

1. Resolve every selected image tag to a platform manifest digest; record source, Docker Engine/Compose version, architecture, image IDs, licenses and scan results. Review all inherited compose includes and mounted scripts, not just the top-level file.
2. Generate separate per-lab database, dashboard, service and owner secrets. Replace upstream defaults and disable external enrichments and response integrations. Keep lab credentials and output outside Git and sanitized artifacts. Neither Gabriel customer keys nor developer keys belong in upstream sample environment files.
3. Expose only the required console entry points on loopback or an approved private interface; keep databases/indexers/service APIs and collectors private. Use trusted TLS. Assign a separate read-only analyst account to each console after setup. Setup administration does not become Gabriel's browser authority.
4. Confirm actual source data appears in each real console, then inspect its real pages/DOM and account/page boundaries. Define a version-specific browser contract with exact known navigation and read-only search/filter operations, pagination/window limits, visibility gaps and stale/UI-drift rejection. Generated-console-v1 is not a Wazuh or IRIS adapter.
5. The human signs in and assigns exact tabs/pages/accounts. Gabriel receives bounded observation/navigation permission through the existing preview, sharing, lease, Stop and receipt controls. No password entry, broad browser control or lease auto-renewal is admitted. IRIS notes and other autosaving fields stay outside read-only scope; proposals remain in Gabriel until an exact external-write workflow is accepted.
6. Run observed browser-to-source-to-specialist investigations and measure them. Only then consider enabling an exact adapter for that accepted version, scope and environment. A healthy dashboard or successful API response does not establish autonomous browser investigation acceptance.

## Scenario and measurement matrix

Each scenario requires a producer record, scope, independently reviewed expected observations/decision, visible evidence references and cleanup. Separate actual controlled producer activity from log replay; replay can test ingestion/correlation but cannot establish malware execution or endpoint sensor effectiveness. Never use real ransomware, worms or rootkits on the host. Use harmless controlled behaviors and clearly labeled indicators, with stronger behavior claims requiring a separately isolated malware-analysis process.

| Scenario | Required observations and negative control | What a pass can establish |
| --- | --- | --- |
| Brute force and password spraying | Controlled failed-login patterns with actor, source, target and timestamps; contrast benign mistakes and distributed low-rate attempts | Source-bound correlation, count/window accuracy, alternative explanations and missed-event reporting |
| Password misuse | Authentication plus independently supplied authorization context; contrast legitimate successful login | Unauthorized-use reasoning when supporting context exists; otherwise explicit abstention |
| Lateral movement | Ordered source/destination/authentication/process records; contrast approved remote administration | Evidence-linked activity paths and bounded hypotheses; path similarity alone does not prove compromise |
| Ransomware indicators | Harmless file-operation simulation and labeled supporting markers; contrast bulk backup/rename activity | Indicator correlation and false-positive behavior; no claim that Gabriel executed or contained ransomware |
| Worm-like propagation | Harmless multi-host marker/process activity with native identifiers; contrast planned software distribution | Propagation-pattern reasoning over observed sources, with source/coverage limits |
| Possible rootkit indicators | Relevant endpoint integrity/kernel/boot observations where the sensor supplies them; contrast legitimate updates and missing telemetry | A bounded suspicion or abstention. Browser pages alone cannot establish rootkit absence |
| Benign, stale and incomplete evidence | Benign workload, delayed/missing sources, duplicate forwarding, contradictory events and clock skew | False-positive rate, duplicate suppression, freshness handling and explicit unknown states |
| Authority and interface failures | Wrong account/document, pagination, UI drift, logout, timeout, network loss and Stop during investigation | Collection/action admission, uncertain-outcome handling, recovery and prevention of further unauthorized work |

Measure producer event time, sensor ingestion time, first visible console time, Gabriel capture time, review completion and human escalation separately. Report end-to-end and visible-console-to-review latency, missing/late events, false positives/negatives, evidence-link accuracy, abstentions, analyst usefulness, model cost and resource peaks. Preserve clock provenance; do not label replay timing as real attack-detection latency. Establish and review explicit pass thresholds before scoring the acceptance set.

## Model and release separation

Use author-visible cases for development. Independent analysts must label and seal acceptance cases; the assistant must not create its own supposedly independent labels or inspect withheld answers. Public training-room solutions and simulator AI feedback do not replace expert adjudication. Compare exact affordable provider routes under customer-owned key budgets, using role-specific quality, abstention, privacy and cost gates. Keep production routing empty until actual acceptance and promotion records exist.

This lab can supply evidence for console, specialist, model and workflow acceptance. It does not complete the installer, certificate lifecycle, upgrades/rollback, scans/SBOM/provenance, native OS/browser matrix, load, measured recovery, human UAT or post-release observation. Assess security effectiveness and compliance coverage separately throughout.
