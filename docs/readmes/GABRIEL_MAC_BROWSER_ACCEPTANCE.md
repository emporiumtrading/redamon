# Mac, Chrome and Brave acceptance

Status: procedure ready; native execution and human acceptance pending. Use a dedicated local lab with generated data. A Linux CI browser pass does not certify the Mac. This stage checks installation, browser trust, selected-tab sharing and safe shutdown; model effectiveness and autonomous investigation require separate qualification.

## Freeze the candidate first

Use the final tested source from [runtime remediation PR104](https://github.com/emporiumtrading/redamon/pull/104), after both architecture security and regression results have been reviewed. Do not install an intermediate failing commit or substitute the documentation branch. Record the full source SHA and final image ID. A change to runtime source, dependency pin, extension bytes or Docker build requires the affected checks again.

From that exact checkout, record locally:

```bash
git rev-parse HEAD
git status --porcelain
sw_vers -productVersion
uname -m
python3 --version
docker version --format '{{.Server.Version}}'
docker compose version --short
```

The checkout must be clean. Record Chrome's and Brave's actual versions from their About pages, the Mac model/RAM, Docker Desktop version, allocated VM memory and free disk space. On the 18 GB Apple Silicon target, record actual memory pressure and any resource failure; a declared allocation is not a measured workload pass. No npm package is required. The installer uses host Python 3.9+ and Docker Compose; application dependencies run inside Docker.

Create a new private evidence directory outside Git and shared/synced folders:

```bash
mkdir -m 700 "$HOME/gabriel-mac-acceptance"
```

If it already exists, choose a new directory and use it consistently. Keep all tickets, keys, passwords, cookies and installation state out of reports. Keep failure reports alongside the eventual passing reports.

## Install and establish native HTTPS trust

Follow [private installation](GABRIEL_TEST_INSTALLATION.md) using a new `$HOME/gabriel-private-test` directory. Run prepare, initialize and open; use the prompted owner password and enter the single-use workbench ticket privately. For an existing installation, follow its backed-up rebuild procedure instead of preparing or initializing over it.

Verify this installation's CA identity before importing only `tls/ca.pem` through the Mac's certificate settings:

```bash
openssl x509 -in "$HOME/gabriel-private-test/tls/ca.pem" -noout -subject -dates -fingerprint -sha256
```

Use [Apple's Keychain Access guidance](https://support.apple.com/guide/keychain-access/kyca11871/mac) to inspect and set the required trust for this local test certificate. Record its fingerprint and the actual trust scope. Mac keychain trust can extend beyond a dedicated browser profile. Do not import private keys, disable TLS checks, bypass a warning or change trust for unrelated certificates. Record how to remove this specific test CA after acceptance.

Create dedicated ordinary Chrome and Brave lab profiles. In each browser, verify the actual localhost claim page opens without a certificate warning. An unauthenticated cases request must remain denied. Use normal manual login/MFA for any external test console. A cloud preview or Linux guest does not meet this check.

After open and while the session is current, collect the stopped-gateway baseline:

```bash
python3 tooling/scripts/gabriel_acceptance.py \
  --installation "$HOME/gabriel-private-test" \
  --output "$HOME/gabriel-mac-acceptance/runtime-baseline.json"
```

The report must identify Darwin as the collector host and Linux as the Docker engine, verify the source/image, and pass all container/network/mount/source/TLS checks. Its `production_admitted` field remains false. A mount failure must be diagnosed; do not weaken the collector or publish private services to pass.

## Package and load the exact extension

```bash
python3 tooling/scripts/gabriel_extension_package.py \
  gabriel/browser_extension \
  "$HOME/gabriel-mac-acceptance/gabriel-extension.zip"
```

Record the printed package SHA-256. Unzip that package into a new private directory and load that directory in both dedicated profiles. Chrome's documented workflow is Extensions, Developer mode, Load unpacked ([official instructions](https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world)). Use Brave's extension-management page for its equivalent controls. Record each installed extension ID and origin; they may differ. Do not grant access to all websites. Managed-policy denial is a blocked acceptance result, not permission to bypass the policy.

## Run separately in Chrome and Brave

Create an open case with purpose **Performance test — learning disabled** before importing test observations. Use an approved HTTPS generated-data console page. In the extension, choose the actual browser, enter a non-secret account label and select the current tab. Save its context JSON privately at `$HOME/gabriel-private-test/context.json`. Use its displayed case UUID and extension origin in the command below; replace the capitalized placeholders.

```bash
python3 tooling/scripts/gabriel_install.py browser-open \
  "$HOME/gabriel-private-test" \
  --case-id CASE_UUID \
  --context-file "$HOME/gabriel-private-test/context.json" \
  --extension-origin chrome-extension://EXTENSION_ID \
  --gateway-port 8443 --duration 300 --max-steps 20 \
  --approve-observation-sharing
```

Enter only the returned short-lived pairing ticket into the extension, grant its exact local gateway origin and keep the ticket private. The general human token stays inside the trusted containers. This command enables finite selected-tab observation only. It does not enable scheduled monitoring, navigation, AI dispatch or provider egress.

While the gateway is active, collect a new report, first using `runtime-chrome-active.json`, then `runtime-brave-active.json` for the separate Brave run. Use the baseline collector command with the new output filename. Both reports must attest seven services and the actual gateway source. After each run, use browser-stop before beginning a new run or collecting a stopped-gateway report.

For each row below, retain the actual action, expected and observed outcome, local timestamp, browser version, evidence filename/hash and pass/fail/blocked status. No row is preapproved.

| Check | Expected outcome |
| --- | --- |
| Native trust and pairing | No TLS warning; exact origin prompt; valid ticket claims once; reuse denied. |
| Selected tab and privacy | Only selected top-frame visible text is previewed; inputs/editable/hidden content excluded; unrelated tabs absent. Review/remove sensitive text before sharing. |
| Encrypted observation | Approved generated text produces a receipt and corresponding case evidence/custody. An uncertain receipt requires reconciliation before retry. |
| Scope change | Tab navigation/close, account-label change or gateway-origin change ends or refuses the old scope; new approval/pairing required. |
| Pause and Stop | Pause prevents sharing and clears preview. Extension Stop clears local authority; record confirmed versus unconfirmed server disconnect. |
| Explicit installation Stop | browser-stop closes the listener and confirms lease revocation/task cancellation. A saved old pairing cannot be reused. |
| Real expiry | With a fresh 60-second lease, both gateway and relay exit after the original deadline, allowing documented child-shutdown grace; no automatic restart or renewal. Run browser-stop afterward to remove stopped containers. |
| Session/account switch | Reopen or switch to a separately created authorized analyst; the old gateway closes and old workbench authority is rejected. Re-pair under the intended account only. |
| Partial/stale display | Unsupported frames, canvas, virtualized rows and incomplete pages remain explicitly unverified. Record UI drift and failures; do not turn partial text into a complete-console claim. |
| Restart and recovery | Stop/reopen requires fresh login and pairing. Rehearse backup and fresh-target restore using the original keys, retaining owner and generated encrypted evidence; record elapsed recovery. |

Use `browser-stop` from the installation guide for the explicit Stop checks. The UI's **Disconnect workbench** only closes its UI cookie; it is not human logout or installation Stop. The original human session lasts ten minutes; an expired session requires explicit fresh open. Keep the popup active during the initial sharing check; a heartbeat gap beyond 45 seconds requires fresh pairing and does not prove continuous coverage.

Before backup/restore, finish or stop the active browser run. Use new backup and restore-target directories. Keep the original installation and its encryption keys. Never delete volumes or reinitialize to hide a failed recovery. The same-source restore procedure is in the installation guide; it does not implement a database downgrade.

## Acceptance decision and handoff

Retain separate Chrome and Brave records with source SHA, exact core/Hermes/database image identities, extension package hash and ID, native OS/browser versions, CA fingerprint/trust scope, collector report hashes, checks performed, original failures, defects, tester identity/date and independent reviewer decision. Store operational identifiers privately. Do not send raw installation directories, tickets, DSNs, cookies, keys, sensitive page captures or full Docker inspections in chat or public issues.

Advance to isolated TryHackMe performance evaluation only after the candidate security/compatibility evidence and both native browser records are accepted. Select **Performance test — learning disabled** before intake. Record the exact scenario/version, start/end time, expected attack events, Gabriel observations, missed detections, false positives, latency and costs. External-console access and simulation start are separate human actions. Do not claim model effectiveness from this observation-only gateway: admitted model routes, independent qualification and the investigative path must be ready before evaluating autonomous detection. Live production and external remediation still require their own release/engineer acceptance.
