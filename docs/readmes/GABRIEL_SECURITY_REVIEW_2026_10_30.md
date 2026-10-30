# Gabriel runtime security review — 30 October 2026 UTC

Status: proposed dispositions only. Every remaining finding is unaccepted. This record does not enable production admission, suppress a scanner result or replace independent review.

## Evidence under review

The patched Linux x86 core image is `sha256:6a88e795291e2ac5b72fa51a6eeb3a1f63753805bca0011273c04cce070922b2`. Its actual CI checkout is `31e44b0711a1656831fe6d3e5e4a1b97e62edeec`, with the identical Git tree `bcb40dab92cfcb6f6d149a840b136d969d97da05` as candidate head `fe61611e1730bf665f127e9034812189aad6b4b3` in [PR101](https://github.com/emporiumtrading/redamon/pull/101).

[Security run 40985616513](https://github.com/emporiumtrading/redamon/actions/runs/40985616513), artifact `12946837281`, retains the SBOM, scanner digests, vulnerability report, redacted Gabriel-source secret report and exact image/source identities. Downloaded ZIP SHA-256 independently matched `ca994eac3182e88d08706bea9822a5e020c859902e2c4cf7e501663c1b33f60f`.

Observed result: zero High/Critical findings, nine Medium matches, one Negligible match and zero Gabriel-source secret matches. The ten matches represent eight unique CVEs. This scan concerns the named image, not every host, architecture, dependency image or application in the inherited repository. Compare the final ARM and Hermes evidence separately before release.

The SBOM reports Python 3.11.18. CVE-2026-114583 is absent after the compatible runtime patch. The [official Python release](https://www.python.org/downloads/release/python-31118/) documents that fix. [Registry verification 40985396254](https://github.com/emporiumtrading/redamon/actions/runs/40985396254) checked index `sha256:09d17d5e4c16d0a7a1eea690bcb7c6ab8616b211f8421e429e97c1bef5bd0ed2` and both Linux x86/ARM child manifest bytes. Its downloaded metadata ZIP matched `fe94fe60cde2104682af7ce07bf3399c2d28ebe2586a4faef5dd0e46b93afea0`.

## Proposed dispositions

These are code observations and review proposals, not proof that a dependency cannot invoke an affected API. Primary CNA version constraints take precedence over incomplete scanner fix suggestions. None of the observations below removes a match from the original report.

| Finding and matches | Primary advisory and observed scope | Proposed reviewer action |
| --- | --- | --- |
| CVE-2025-12781 — Python 3.11.18, 1 Medium | [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/12xxx/CVE-2025-12781.json). The alternate-alphabet Base64 issue includes releases below 3.13.10. Reviewed Gabriel decoders use the standard alphabet without `altchars` or URL-safe decoding. | Retain the finding. Confirm the owned call sites and inspect dependency reachability before accepting a conditional mitigation. No same-3.11 fix was established. |
| CVE-2026-3446 — Python 3.11.18, 1 Medium | [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/3xxx/CVE-2026-3446.json). Padding ambiguity includes releases below 3.13.13; the CNA recommends `validate=True`. Reviewed checkpoint, keyring and toolbox decode calls already set that option. | Retain the finding and record the existing mitigation only after independent confirmation. Do not substitute the incorrectly named option in an older mailing-list summary. |
| CVE-2025-15366 — Python 3.11.18, 1 Medium | [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/15xxx/CVE-2025-15366.json). IMAP command injection includes releases below 3.13.15 and requires an affected IMAP command path. No owned `imaplib` call was found in the reviewed production source. | Candidate disposition: affected API not observed in owned paths. Dependency-wide reachability and a compatible backport remain unproven. |
| CVE-2025-15367 — Python 3.11.18, 1 Medium | [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/15xxx/CVE-2025-15367.json). POP3 command injection lists releases below 3.15.0a6. No owned `poplib` call was found. | Retain the finding. Confirm call paths and dependency use; do not infer a 3.11 fix from the listed later-series threshold. |
| CVE-2026-12345 — Python 3.11.18, 1 Medium | [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/12xxx/CVE-2026-12345.json). TemporaryDirectory cleanup can race with an actor able to modify its tree. Updated thresholds include 3.12.15, 3.13.18 and 3.14.9. Core 3.11.18 remains in the affected range. Owned uses were found in host candidate export and the separate Hermes runtime, not the core application path. | Retain the core-image finding. Assess the actual host Python and filesystem access separately. Hermes has its own Python 3.14.10 base; this does not establish complete immunity on every filesystem/platform. |
| CVE-2026-6019 — Python 3.11.18, 1 Medium | [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/6xxx/CVE-2026-6019.json). `Morsel.js_output()` can generate unsafe inline script; the below-3.13.14 range includes this runtime. The workbench emits Set-Cookie headers directly; no owned `js_output()` call was found. | Candidate conditional non-reachability evidence. Confirm dependency paths and preserve the match pending review. |
| CVE-2025-60876 — BusyBox 1.37.0-r31, 3 Medium | [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/60xxx/CVE-2025-60876.json). One wget request-target injection advisory matches `busybox`, `busybox-binsh` and `ssl_client`. Its machine-readable version bounds are imprecise. No owned runtime wget invocation was found. The [Alpine 3.24 APKBUILD](https://github.com/alpinelinux/aports/blob/3.24-stable/main/busybox/APKBUILD) does not by itself establish a fix for this advisory. | Leave packaging/backport status unresolved until supported by Alpine or a verified patch. Do not infer another distribution's fix from a similar package version, or count these as three distinct vulnerabilities. |
| CVE-2026-3479 — Python 3.11.18, 1 Negligible | [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/3xxx/CVE-2026-3479.json) marks the pkgutil report disputed and clarifies its documented security model. No owned `pkgutil.get_data()` call was found. | Candidate disputed/documentation disposition, requiring reviewer approval. Keep the original scanner result. |

## Owned call-site evidence and limits

The reviewed source uses standard-alphabet `base64.b64decode(..., validate=True)` in `gabriel/identity/checkpoints.py`, `vault.py`, `evidence_store.py`, `gabriel/toolbox/server.py`, `engine.py` and `tooling/scripts/gabriel_provider_keys.py`. The review found no owned production calls to the listed IMAP, POP3, JavaScript-cookie, pkgutil or wget interfaces. Static search cannot establish the absence of dynamic or dependency calls.

`gabriel/hermes/server.py` uses TemporaryDirectory in its separate runtime. `tooling/scripts/gabriel_candidate_export.py` and the isolated test runner use the actual host Python. Their host/architecture and filesystem conditions need their own assessment; a core-image patch does not patch a host interpreter.

Readonly roots, non-root users, dropped capabilities, internal networks, fixed loopback entry and isolated secret mounts are useful containment controls. They do not repair a vulnerable function or authenticate a release reviewer. New console adapters, parsing libraries, mail clients, Base64 variants, temporary-directory use or network tools require this review to be repeated.

## Independent decision still required

For each unique CVE, the release owner must retain the qualified reviewer's identity, role, date, exact source/image and artifact hash, verified reachability or uncertainty, disposition, rationale, compensating controls, owner, expiry/retest trigger and any required remediation. Leave any unknown field unknown. No risk decision has been recorded here.

The final release still needs native OS/browser/TLS and operational acceptance, independent model qualification, and the remaining dashboard/Hermes implementation and validation. A source review, passing scanner threshold or CI-generated browser journey does not satisfy those gates. No production registry, provider route, merge or deployment is authorized by this record.
