# Gabriel verified repair checkpoint — 25 October 2026 UTC

Release state: IN_PROGRESS. No merge, production deployment or production acceptance occurred.

Later on 25 October, the owner approved the ten-case paid validation batch. Its observed results and the subsequent browser revocation repair are recorded in the [validation and release handoff](GABRIEL_MODEL_VALIDATION_2026_10_25.md). That follow-up supersedes the pending-paid-batch and earlier browser status below; the source-specific evidence remains historical.

## Gate status at the earlier repair checkpoint

| Gate | Verified engineering result | Remaining acceptance |
| --- | --- | --- |
| Core image security | Replaced the failing Debian runtime with a pinned Alpine multiarch base. Final x86 and ARM reports show 0 High/Critical, 9 Medium, 1 Negligible and 0 source-secret matches. No suppression. | Nine Medium findings remain; independent security review and release acceptance remain pending. |
| Core compatibility and recovery | Both architectures passed 1,070 isolated component + 49 runtime + 21 foundation tests, zero failures/errors/skips, actual PostgreSQL restart/fresh restore, installation HTTPS and fresh-project recovery. Chrome for Testing and Brave passed 60 checks each. | Native macOS/Windows/browser UAT and broader operational acceptance remain open. Linux container evidence does not replace native OS acceptance. |
| Real read-only console journey | Actual Wazuh viewer read agents/search, received 403 on index creation, security administration read, valid group write and explicit protected-user read; denied objects remained absent and groups unchanged. Fresh viewer browser identity was verified; all 12 native documents matched manager bytes. IRIS viewer read its case, received 403 on writes/admin reads, and its case remained unchanged. | Isolated generated labs only. Customer authorization, source authenticity and production browser navigation admission remain open. |
| Native event semantics and persistence | Versioned Wazuh SSH invalid-user parser passed 19 new software tests within the 1,070. Actual native-event normalization and duplicate-inflation controls passed. Case, encrypted evidence, candidate review and 12 specialist receipts survived a physical PostgreSQL restart; replay returned existing receipts. | Local rule candidates and abstentions are unqualified. This is not live attack confirmation, model reasoning or autonomous production investigation. |
| Model qualification | Six offline validation software tests passed without network or credentials. Ten exact authored validation request bodies are prepared; no new paid inference occurred. Existing 24-answer worksheet retains pending human reviews. | Automatic approval review blocked the proposed paid batch pending explicit payload/destination/spending authorization. Independent adjudication and a genuinely sealed held-out evaluation remain open regardless of batch outcome. |

The three broad release concerns are not all closed: production quality, independent review and native OS acceptance still require their own evidence. The full requirement register remains IN_PROGRESS. Production model and browser-contract registries remain empty.

## Accepted source identities

| Scope | Code head | Actual CI checkout | Identical Git tree |
| --- | --- | --- | --- |
| Pinned runtime, PR67 | cfa5ccac12c08f571ab1f4b89046dbe2acba7274 | b1bb96b31975df13cf51fe4a7638cbeb1f94c3d8 | 2ae6581a34b7bd295c3edabf9ee52c077bbfed41 |
| Read-only console harness, PR68 | ea786c2f68468af9f10dfda968c15b403efb3372 | efaa0257ab598318a77b76056afb1e706ac835fe | e6f6f1db47251e28e8bb8eff668a56b5ba9ba8fd |

Both pairs were fetched independently through the GitHub commit API and their trees matched. PR68 changes the isolated console harness and documentation; the accepted production implementation remains that verified in PR67. Subsequent checkpoint documentation does not establish a new runtime acceptance.

Pinned base: `python@sha256:5fb4bc53dd0180955e31e5245b648bbb24a4ac4ab03a1de81513642325220bcd`.

Production, Compose, component-test and checkpoint-signer defaults use that pin. Browser binaries use a separate Debian test harness with native dependencies installed there. Production remains non-root and excludes pip, setuptools and wheel.

## Independently downloaded evidence

All ZIP hashes below were checked against downloaded bytes, not merely copied from GitHub metadata. Recorded source files matched the checkouts above.

| Evidence / run | Artifact | ZIP SHA-256 |
| --- | --- | --- |
| Default production security / 40147715159 | 12581054798 | 46927fcb77028f4d6a2f91b0ac8ac4c829ff2b62435a713ba8dccb755d8e8f0b |
| x86 full tests/recovery / 40147715154 | 12582155764 | 605c9b9fde08325895346ce7a21206c2a0176db92c18413bdba937d35eca7311 |
| ARM full tests/recovery / 40147715150 | 12581631195 | 85b716fe66ac41e12e36f34d348ba7aa8643e32895bd0a7ed3e2243c188bac1a |
| Chrome/Brave / 40147715174 | 12581430420 | b18c54ad6512c0754d142858f36be0398f0c89e24450fd7fa2ccf917bb694fd3 |
| x86 installation / 40147715162 | 12581134594 | b9864a478ac0d9e23f8ddf4be9763eedd49999b3957bbed54f245fda2f0ebb33 |
| ARM installation / 40147715162 | 12580209998 | 185d65c09644f963ba1072fb5593658c124de3f5d519209c1bb7f4031599b376 |
| x86 image scan + 1,070 + recovery/install / 40147715148 | 12582496289 | 386823f7d524b8299a7f3ee1bff8d85e950218fb948a5b1e88bf32f9c6c8313a |
| ARM image scan + 1,070 + recovery/install / 40147715148 | 12581344900 | 3cf7082e0c5786d0a413e5b371fcfe2b1d80250d3eb22a525391ff4d870b1045 |
| Wazuh read-only browser/reconciliation/persistence / 40150212992 | 12581768027 | 6e24a039227feda850679f6d3920dd95d9c9294df2f2077e9665c5c806632e34 |
| IRIS read-only browser/denials / 40150212992 | 12581524362 | 73c5e3049962211ea6ba8686a185885e3789ce19fb7578347874622d3b0abd6d |

Focused 83-test results overlap the 1,070 and are not an additional unique count. Repeated workflows are repeated evidence, not additional unique test cases. Both final minimal-image reports resolved exactly the pinned base. Nine Medium matches span seven unique advisories; no reviewer has accepted them.

## Repair details and limits

The original viewer test sent an invalid group request and received 400 before authorization. A valid JSON body now receives 403. Wazuh 4.14.9 revokes run-as tokens through the role-change second; issuing the test token after that cutoff fixed a 401. An untargeted security-user list can return 200 with no accessible protected resources; the final test targets an existing user distinct from the API credential identity and requires 403.

A fresh dashboard needs operator initialization of shared settings/index patterns. The generated operator performs that setup in its own isolated browser container, before viewer enrollment. The acceptance browser then uses only the generated viewer credentials in a fresh profile. No administrator fallback satisfies viewer assertions. The initial account-menu check incorrectly omitted upstream h5 usernames and clicked the enclosing header button rather than the avatar's popover handler; both test errors were fixed. The vendor kibana_read_only UI role hid the Wazuh application and was removed; backend read-only permissions remain enforced and tested.

The analyst-access JSON describes setup-time backend tests and deliberately retains browser_session_verified:false. Browser identity is established separately by the passing browser.json, with matching viewer username; neither immutable report is rewritten to pretend the setup test performed the browser check.

The Wazuh journey searched for a generated marker, verified an empty-result control, inspected 12 native JSON documents, matched all eight projected fields to the manager alert bytes, rejected altered/missing/duplicate controls and retained explicit source-authenticity unknowns. Twelve local specialist kernels produced bounded rule reviews or abstentions, not qualified AI judgments. The generated repeated-failure candidate remains suspected_requires_review. Normalized evidence, case, candidate review and specialist receipts persisted through restart with no duplicate dispatch on replay.

The proposed model batch is ten authored validation cases on GPT-OSS-120B through OpenRouter's exact Cerebras route, with no fallback, existing privacy/budget preflight, carried unresolved holds and a maximum new-call reservation of $0.063040. It has not run. Review the exact prepared payloads and obtain explicit approval before publishing or invoking any paid workflow. No tool/identity/workflow substitution may bypass the automatic rejection.

See [PR67](https://github.com/emporiumtrading/redamon/pull/67), [PR68](https://github.com/emporiumtrading/redamon/pull/68), the [full requirement register](GABRIEL_REQUIREMENT_STATUS.md) and the [human model review queue](GABRIEL_MODEL_REVIEW_QUEUE.md). Independent analyst/security review, native OS UAT and operational/release acceptance remain mandatory.
