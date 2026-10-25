# Gabriel authored validation and release handoff — 25 October 2026

Status: IN_PROGRESS. No production model admission, merge or deployment occurred.

## Approved inference result

The owner explicitly approved the previously prepared ten synthetic payloads sent to OpenRouter/Cerebras with a maximum new-call reservation of $0.063040. The approved batch ran once in [run 40194998344](https://github.com/emporiumtrading/redamon/actions/runs/40194998344), after all six offline software tests passed.

- 10 attempts; 10 contract-valid answers; no failures.
- 10/10 matches to provisional authored labels: four escalate, three benign, three abstain.
- Provider-reported total cost: $0.00457325; no new unresolved charges.
- Historical unresolved reservation $0.012608 remains; it was not written off.
- No held-out cases, fallback, tool actions, retries or production activation.
- Offline request-body admission matched the exact reviewed digest 7f85505680802add12540134470df6db4e3305a1b421c5f0fcef5ea5e180047a.

| Case | Actual decision | Provisional label match |
| --- | --- | --- |
| Cloud key minting | escalate | yes |
| Scheduled persistence | escalate | yes |
| Database bulk copy | escalate | yes |
| Anti-tamper disable | escalate | yes |
| Golden-image snapshot | benign | yes |
| VPN geolocation | benign | yes |
| Approved secrets read | benign | yes |
| Console rate limit | abstain | yes |
| Offline agent | abstain | yes |
| Asset-name collision | abstain | yes |

These are authored cases with provisional labels. Ten matching decisions do not establish claim support, reasoning quality, general detection accuracy, independent sealing or production safety. Endpoint confidentiality and costs are provider-reported, not independently attested.

Code head 9dc2fb7febbb2c176931ef98ff1c62dbed1bdbc2 and CI checkout 232962c504389e1287ef9ba138db867b434249c5 share tree c97fdc03af1a137ef0fa13139b409ef112f6ee56. Independently downloaded artifact 12599820318 ZIP SHA-256: 5ca963efda51e7153a46063ccf497aab8000e7ff1860695f8ad6680e6c6e40eb.

The live job is restricted to the approved branch's PR-open event and first workflow attempt, with key-wide serialization. Synchronizing, reopening or rerunning a PR does not authorize another paid batch. Further paid validation requires a new authorized bounded batch.

## Independent review packet

[PR71](https://github.com/emporiumtrading/redamon/pull/71) binds each actual answer to its exact source observations, configuration and run digest. Every human verdict remains blank. The local no-network worksheet exports only self-attested reviews with reviewer identity unverified and production admission false. No AI screening is presented as a human verdict.

Both 24-answer development and 10-answer validation worksheets passed isolated Chromium checks in run 40195340857: blank verdicts, incomplete-review denial, edit invalidation, corruption rejection, unadmitted-partition rejection and rejection of prefilled adjudication. Human reviews produced: zero.

Head 1b926c6f27685367153eb432b798714a4063fd05 and CI checkout 93cd3b99e1d32bae24a042ef35beea04e619f386 share tree 714d1b8a83f7b8e3da4e0dbd200f2e01cb1ec7ba.

| Worksheet | Independently downloaded artifact | ZIP SHA-256 |
| --- | --- | --- |
| Ten validation answers | 12599349037 | 351f26e3c43049d59449be7b7a03ba8fb88e6daf63a10ccd8ab5d765310e6e54 |
| Twenty-four development answers | 12599134447 | 3286a6dcda87fe0fae42ed1508407d9e6e5121a1b2d0b97c9a644af2622e0c62 |

The new ten-answer worksheet HTML SHA-256 is 8ab421cc64cfe69d362728b65754b704f3668e1b86d9279f957d1fab747ef1a1. Independent reviewers must assess every claim against cited observations and judge alternatives, contradictions, uncertainty and the decision. Reviewer identity and expertise require separate verification. The candidate held-out corpus is author-seen; a genuinely independently sealed acceptance set remains necessary.

## Redirect/Stop regression

The separate browser regression at run 40194998395 failed in Brave while waiting for a redirected lease to become disconnected. This result is retained as a failure, not reclassified as a pass.

[PR72](https://github.com/emporiumtrading/redamon/pull/72) coalesces overlapping Stop requests into one revocation promise and prevents Stop/Pause work cancellation from aborting that disconnect. The existing timeout and explicit unconfirmed-revocation response remain. A real-browser check sends three Stop messages and Pause concurrently through the actual extension, with a deliberate half-second delay confined to the generated localhost test gateway. It requires one confirmed backend revocation, no capture and no section navigation. Existing redirect, wrong-account and Stop checks remain.

Both Chrome for Testing and Brave passed 61 checks in run 40195988845; this includes the new concurrency check. Security run 40195988855 passed with 0 High/Critical, 9 Medium, 1 Negligible and 0 source-secret matches. Code head 9fe8fd52170053fa00bfa677102d70fe1aceb491 and CI checkout c6c35aa9f43652f378d4ef6fac6d459a5ab91f08 share tree 4a0f7f94673032aead5ff303b28edfc5abec9fcc. The full database/recovery gate is pending at document preparation and must be recorded before final-source acceptance.

| Evidence | Independently downloaded artifact | ZIP SHA-256 |
| --- | --- | --- |
| Chrome/Brave 61 checks | 12600116717 | 65c14fc67272e22b4b86b5e503cf997f6f8f153f5607744cfc66c9d976d38692 |
| Production security | 12600021301 | 7646d6d3c4cfd54412d77bd6c65c37fd37ba4bde87dfdb3244e4cf6bad4cb623 |

## Remaining human acceptance

| Gate | Concrete next evidence |
| --- | --- |
| Model review | A qualified independent analyst completes the actual-answer worksheet with source-linked rationales and verified identity; resolve failures and run a separately authorized sealed evaluation. No production model is qualified now. |
| Security review | An independent reviewer assesses the pinned images, SBOM, remaining nine Medium matches, tenant/credential/capture boundaries, revocation behavior and operational configuration. A passing automated scan is not sign-off. |
| Native OS UAT | Run the accepted source on the actual target Mac/Docker Desktop and native Chrome/Brave; record OS, hardware, Docker/Compose/browser versions, exact source/image/package hashes and observed outcomes. Linux ARM is not macOS UAT. |
| Release acceptance | Record deployment identity, operational ownership, rollback/recovery and signed acceptance for the intended scope. Production registries remain empty. |

### Native Mac operator checklist — UNRUN

Use the [test installation guide](GABRIEL_TEST_INSTALLATION.md) on the actual Mac after the final source is accepted. Preserve any existing installation; create a new private operator-owned directory outside Git. Do not use real customer telemetry or put passwords, access tickets, cookies or provider keys in reports.

1. Record `sw_vers`, architecture, Docker Desktop/Compose versions and native Chrome/Brave versions. Record the checked-out source, prepared image ID and packaged extension SHA-256.
2. With the accepted checkout, run the guide's `prepare`, `initialize` and `open` commands against a new private test directory. Enter the owner password only at the private prompt.
3. In a dedicated native browser profile, trust only that installation's generated CA, claim the short-lived localhost ticket and verify authenticated case/evidence/provenance screens. Repeat in the other native browser.
4. Verify unauthenticated access is refused, Stop closes authority, old access cannot be reused and a fresh authenticated open is required.
5. Create a generated case/evidence item, perform the guide's stopped backup, prepare a separate fresh restore target using the same image, restore with original keys and verify recovered evidence after fresh login. Preserve the original installation.
6. Review generated-console extension consent, preview/minimization, Pause/Resume/Stop, redirect/account drift and pairing behavior in the native profiles. The Linux container results do not count as these human checks.
7. Record pass/fail, unexpected behavior and sanitized evidence. Keep every item unaccepted until actually observed; no checkbox here is prefilled.

This checklist is not a tested Mac installation claim. Native Windows and any wider release scope require their own supported paths and acceptance. See the [prior verified repair checkpoint](GABRIEL_RELEASE_BLOCKERS_2026_10_25.md) and the [full requirement register](GABRIEL_REQUIREMENT_STATUS.md).

