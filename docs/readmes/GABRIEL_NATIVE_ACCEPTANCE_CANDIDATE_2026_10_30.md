# Gabriel native acceptance candidate — 30 October 2026

The original final regression is complete. The patched candidate passed all **19 triggered workflows**, including x86 and ARM full component/database recovery and installation/restore. The original nine Medium core-image matches are absent after upgrading Python and removing the affected BusyBox runtime packages. This clears the engineering candidate to **begin native Mac, Chrome and Brave installation/observation acceptance**. Native execution, autonomous investigation and production admission remain unaccepted.

| Source binding | Value |
| --- | --- |
| Candidate | `b35d50b70c46e556435b0727e162f2972989714c` |
| Actual tested merge | `7cb9f6c72075b10573966991760f7c4e877b8fd9` |
| Identical Git tree, independently checked | `5575e13ceeac30f644173cea0d91135e372587ec` |
| Remediation | [PR104](https://github.com/emporiumtrading/redamon/pull/104) |
| Admission | Production false; native/human acceptance pending |

**Security evidence.** The actual x86 core scan image is `sha256:71b616025cf9b3719f621346b2444a4f491cb510d992faa708d9049302baba0e`. [Core security run](https://github.com/emporiumtrading/redamon/actions/runs/41073193344) reports zero vulnerability matches, zero ignored matches and zero Gabriel-source secret matches. Its downloaded ZIP independently matched `acfbd8a0a70c69bf66058996d44cfcbb1947122d37010467a57a746a371a4a0d`. The parsed SBOM retains Alpine Linux 3.24.3 metadata, Python3.15.2 and no BusyBox/compiler packages. Both architecture candidates also reported empty severity counts and zero source-secret matches in the completed [base acceptance logs](https://github.com/emporiumtrading/redamon/actions/runs/41073193497).

The base is pinned to official index `sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211`. [Registry metadata](https://github.com/emporiumtrading/redamon/actions/runs/41071707216) and the downloaded ZIP/index/architecture-manifest bytes were independently checked. YARA compiles in a separate dependency stage. Production removes BusyBox and its provisioning dependents while explicitly retaining CA and base-layout data, package records and a working certificate store. Backups use Python's archive writer. Medium/High/Critical findings now fail the core and both architecture candidate gates. No CVE/application-specific suppression was added; unchanged scanner kernel-header defaults excluded zero matches.

| Original finding | Original matches | Candidate change and observed result |
| --- | --- | --- |
| CVE-2025-12781 | 1 Medium, Python3.11.18 | Python3.15.2; absent in new scan |
| CVE-2026-3446 | 1 Medium, Python3.11.18 | Python3.15.2; absent in new scan |
| CVE-2025-15366 | 1 Medium, Python3.11.18 | Python3.15.2; absent in new scan |
| CVE-2025-15367 | 1 Medium, Python3.11.18 | Python3.15.2; absent in new scan |
| CVE-2026-12345 | 1 Medium, Python3.11.18 | Python3.15.2; absent in new scan |
| CVE-2026-6019 | 1 Medium, Python3.11.18 | Python3.15.2; absent in new scan |
| CVE-2025-60876 | 3 Medium, busybox/busybox-binsh/ssl_client | Runtime packages uninstalled; absent in new scan |
| CVE-2026-3479 | 1 Negligible, Python3.11.18 | Absent after interpreter upgrade; no risk acceptance of old image |

The downloaded [baseline report](https://github.com/emporiumtrading/redamon/actions/runs/40985616513) independently matched `ca994eac3182e88d08706bea9822a5e020c859902e2c4cf7e501663c1b33f60f` and retained nine Medium plus one Negligible matches. Historical [review proposals](GABRIEL_SECURITY_REVIEW_2026_10_30.md) concern that earlier image and remain unaccepted. Scan scope is the named images and scanner/database state; it does not certify every host/dependency image or eliminate independent security review.

**Functional evidence.** Each architecture passed 1,294 component checks and an overlapping 142 focused checks, with no failed/error/skipped cases in those strict gates. Runtime49 and foundation21 checks passed, and the packaged runtime denied all80 inherited tool names. The installer passed 12 collector +14 network +15 browser/renewal offline checks per architecture. Actual generated-data journeys covered HTTPS, certificate renewal with old-CA/old-cookie denial, fresh login, owner/key retention, encrypted evidence/custody, backup and fresh-project restore, finite gateway scope, outage Stop/retry and original expiry. Active gateway reports attested seven services and identical 28-file source hash maps in gateway/workbench.

Both schema28→31 rebuilds passed with original owner, keys and encrypted evidence retained. Chrome and Brave each passed110 named generated-console checks (20structure,6AI protocol,9discovery,9monitoring,18navigation,20base,28workbench). Hermes passed179 isolated checks plus the overlapping44-case regression before/after and native generated-response orchestration on both architectures. Repeated/focused denominators overlap; they are not additional unique tests. Generated model responses and software qualification tests do not qualify a production model. Paid live-validation and live-provider jobs were intentionally skipped; no provider inference or TryHackMe scenario was started.

**Browser driver review requested by the owner.** A read-only subagent review, followed by primary code checks, confirmed that [channel.js](https://github.com/emporiumtrading/redamon/blob/b35d50b70c46e556435b0727e162f2972989714c/gabriel/browser_extension/channel.js#L234) obtains a backend intent, calls `chrome.tabs.update` on the assigned tab, rechecks URL/account/document and completes a transition receipt. Playwright is not the shipped navigation driver. The inherited Playwright MCP/testing dependencies are separate; the defensive image does not package that inherited offensive server.

The advanced extension supports up to eight independent channels and bounded same-origin URL tours/discovery under separate grants. The current private `browser-open` creates one finite **observation-only** gateway: navigation, scheduling, discovery and AI remain off. General menu/form/filter/pagination interaction, script-only transitions, frames and canvas are not implemented as a general autonomous actuator. Path/query blacklists, visible links and GET navigation do not establish read-only semantics. The next bounded slice is an exact operator-reviewed URL tour with explicit destination/query policy, a verified read-only console role, original tab/lease authority and native transition/Stop/expiry tests; automatic discovery and AI should remain off during that initial acceptance.

**Start native acceptance.** Use the immutable candidate above and the [Mac/Chrome/Brave procedure](https://github.com/emporiumtrading/redamon/blob/b35d50b70c46e556435b0727e162f2972989714c/docs/readmes/GABRIEL_MAC_BROWSER_ACCEPTANCE.md). Open Docker Desktop on the actual Apple Silicon Mac. Record native OS/browser/Docker versions, real memory pressure, image identities, certificate trust and separate Chrome/Brave observations. Copy [the unfilled record](GABRIEL_NATIVE_ACCEPTANCE_RECORD.example.json) outside Git; keep actual operational records private. Its pending fields are not approvals.

Checked test candidates exported without rebuilding are available as [ARM64](https://github.com/emporiumtrading/redamon/actions/runs/41073193314/artifacts/12988037287) and [AMD64](https://github.com/emporiumtrading/redamon/actions/runs/41073193549/artifacts/12987374384). Verify the downloaded ZIP against the GitHub-reported digest in the [evidence manifest](GABRIEL_NATIVE_ACCEPTANCE_EVIDENCE_2026_10_30.json), then verify `images.tar.gz` against its included manifest before loading. Select the manifest's core image for the private installer; other bundled roles are not certified by the narrow core-image scan. A fresh local build has its own identity and needs its own security/dependency evidence. The image archives were exported and round-trip checked by CI; their full binary ZIPs were not independently downloaded in this review.

**Retained failed attempts.** [Initial slim evaluation](https://github.com/emporiumtrading/redamon/actions/runs/41070956760) lacked a YARA wheel/compiler. [Debian follow-up](https://github.com/emporiumtrading/redamon/actions/runs/41071148827) reported55High/48Medium matches and was rejected; its HTTPS learning-isolation check exposed strict-certificate incompatibility. [Initial Alpine removal](https://github.com/emporiumtrading/redamon/actions/runs/41072836504) failed its build assertion because BusyBox was still retained by provisioning dependencies. The final source fixes those issues; no failed result was relabeled as passed.

Raw CI artifacts use14-day retention. This record retains sources, results, links, digest verification scope and an unfilled native checklist; hashes are not independent signatures or human release approval. No browser screenshots, credentials, keys, customer observations or local installation state are committed here. Native acceptance, broader navigation/dashboard/Hermes integration, independent model qualification and operational/security/release decisions remain open. No production registry, deployment, merge or admission was changed.

| Final workflow | Result |
| --- | --- |
| [Gabriel approved authored validation batch](https://github.com/emporiumtrading/redamon/actions/runs/41073193211) | PASS |
| [Gabriel sealed release qualification software](https://github.com/emporiumtrading/redamon/actions/runs/41073193604) | PASS |
| [Gabriel defensive runtime](https://github.com/emporiumtrading/redamon/actions/runs/41073193385) | PASS |
| [Gabriel proposed release compatibility packet](https://github.com/emporiumtrading/redamon/actions/runs/41073193645) | PASS |
| [Gabriel local visible-structure drafts](https://github.com/emporiumtrading/redamon/actions/runs/41073193400) | PASS |
| [Gabriel defensive image security](https://github.com/emporiumtrading/redamon/actions/runs/41073193344) | PASS |
| [Gabriel official runtime patch metadata](https://github.com/emporiumtrading/redamon/actions/runs/41073193510) | PASS |
| [Gabriel real console lab](https://github.com/emporiumtrading/redamon/actions/runs/41073193250) | PASS |
| [Gabriel specialist agents and personal keys](https://github.com/emporiumtrading/redamon/actions/runs/41073193358) | PASS |
| [Gabriel existing installation rebuild](https://github.com/emporiumtrading/redamon/actions/runs/41073193577) | PASS |
| [Gabriel open-source investigation tools and skills](https://github.com/emporiumtrading/redamon/actions/runs/41073193593) | PASS |
| [Gabriel reviewed AI memory context](https://github.com/emporiumtrading/redamon/actions/runs/41073193374) | PASS |
| [Gabriel packaged browser lab](https://github.com/emporiumtrading/redamon/actions/runs/41073193353) | PASS |
| [Gabriel performance-test learning isolation](https://github.com/emporiumtrading/redamon/actions/runs/41073193427) | PASS |
| [Gabriel private Docker installation](https://github.com/emporiumtrading/redamon/actions/runs/41073193372) | PASS |
| [Gabriel required Hermes supervision](https://github.com/emporiumtrading/redamon/actions/runs/41073193432) | PASS |
| [Gabriel bounded provider probe and ARM64 build](https://github.com/emporiumtrading/redamon/actions/runs/41073193314) | PASS |
| [Gabriel database identity](https://github.com/emporiumtrading/redamon/actions/runs/41073193549) | PASS |
| [Gabriel updated runtime acceptance](https://github.com/emporiumtrading/redamon/actions/runs/41073193497) | PASS |
