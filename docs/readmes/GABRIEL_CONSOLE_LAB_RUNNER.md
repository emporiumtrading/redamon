# Isolated real-console lab runner

This increment prepares pinned Wazuh 4.14.9 or DFIR-IRIS 2.4.24 source configurations, creates new generated lab accounts/secrets, resolves pulled image tags to digests before starting services, and checks trusted localhost HTTPS. A separate container exercises generated-account browser login and records rendered page structure without form values. Wazuh uses the setup operator; IRIS uses the case-scoped viewer described below. It does not give Gabriel password-entry authority or enable either production adapter. Detection, specialist integration, full read-only analyst admission and real-console navigation/search acceptance remain separate gates.

The [controlled lab record](GABRIEL_PRIVATE_LAB.md) explains the source pins, scenario plan and required acceptance. This runner uses those evaluation versions; it does not establish that every upstream dependency is supported, secure or licensed for a future distribution. No customer/provider credentials, paid model calls or third-party accounts are used.

## Local operator commands

On a dedicated Linux Docker host with Compose v2, Git and OpenSSL, choose one tool and a new private directory outside Git:

```bash
python3 tooling/scripts/gabriel_console_lab.py prepare iris /absolute/private/new-iris-lab
python3 tooling/scripts/gabriel_console_lab.py up iris /absolute/private/new-iris-lab
python3 tooling/scripts/gabriel_console_lab.py check iris /absolute/private/new-iris-lab
```

Replace `iris` with `wazuh` and choose a different new directory for the Wazuh lab. Its kernel vm.max_map_count must already be at least 262144; the command checks and refuses to change a user's host automatically. Only the disposable CI Wazuh runner explicitly configures its own kernel. Wazuh's lab listener is localhost:18447; IRIS uses localhost:18446. A new directory is required; the runner will not replace an existing installation. Sources, private credentials/configuration and one-day localhost TLS material remain in that directory under operator permissions. Inspect credentials.json privately for the generated setup account, and use a dedicated browser profile trusting only that lab certificate.

The normalized Compose configuration removes upstream fixed container/network names and externally published data-service ports, replaces sample application/database/service secrets, prevents automatic restart and pins the resolved service image digests. Backend networks remain internal. Only the console entry container has a normal bridge attachment and a published IPv4 loopback port. IRIS's broker uses its own generated account. Wazuh's internal user file contains only generated setup/service credentials; optional public demo accounts are removed. The original source checkout/license notices remain in the private lab directory. No modified upstream package is redistributed by this increment.

The lab image roles/capabilities/filesystem settings are not yet a production hardening profile. In particular, upstream databases/manager/worker privileges and transitive dependencies require review. Wazuh gets bounded manager/indexer/dashboard memory budgets; IRIS services get separate budgets. These are explicit CI test limits, not measured customer capacity or acceptance of an 18 GB Mac. Image IDs, registry digests, architectures, source pin and configuration hash are recorded in lab.json. They identify what ran, without claiming an image cryptographically corresponds to an upstream Git commit.

## Browser evidence and CI

The dedicated workflow runs each tool on its own Linux x86 runner. It verifies the console using a trusted certificate, then runs Chromium with an isolated NSS trust store, read-only root filesystem, dropped capabilities, bounded resources and no provider/database credentials. The browser harness receives only the generated console login and its public certificate. It uses host networking to reach the loopback-published console inside the disposable runner. Browser sandboxing is disabled only for this isolated test, and external browser requests use a dead proxy. This is not native browser/OS acceptance or Gabriel's scoped browser lease.

Artifacts contain only the source revision, sanitized lab/image provenance and browser title/headings/table headers/link routes/input metadata. Passwords, API tokens, input values, private configurations, certificates' private keys and raw service logs are excluded. IRIS's upstream startup may log its generated administrator password, so never publish the container logs or treat them as sanitized evidence. Form/hidden values are not captured in the discovery report. A passing console/login check does not establish attack detection, least-privilege analyst operation or an accepted adapter.

## Collection and viewer checks

After startup, the Wazuh-only command below appends twelve generated SSH failure records to a dedicated lab input file. Wazuh's real log collector and analysis engine must emit a matching alert with the fresh replay marker and exact source path. The report retains native IDs, rule metadata and timestamps. It records the number of emitted records separately from the number observed; one matching alert does not prove complete collection or correlation of all twelve.

```bash
python3 tooling/scripts/gabriel_console_lab.py replay wazuh /absolute/private/new-wazuh-lab
python3 tooling/scripts/gabriel_console_lab.py analyst iris /absolute/private/new-iris-lab
```

The IRIS command creates a separate generated viewer, a group with only standard-user permission, and read-only access to the initial generated demo case. Using the viewer's private API key, the lab requires a successful case read, HTTP 403 for a case-summary write and administrator user listing, and an unchanged summary after the denied write. The browser receives only analyst-credentials.json (username/password/port/case ID), never the API key. It checks the visible viewer identity and renders the assigned case. These limited permission checks do not establish every IRIS permission or browser operation is read-only.

Both commands refuse to overwrite their completed report/credential files. A partial failure retains generated state for inspection; cleanup removes the entire dedicated lab project. The Wazuh replay is synthetic log ingestion, not an executed brute-force attack, endpoint-sensor test, indexer-forwarding check or Gabriel browser capture. No real authentication attempt occurs. Replay timestamps must not be reported as live attack detection latency.

The Wazuh browser check now waits for application categories to appear after login. A login redirect or empty application shell cannot pass. Sanitized browser structure and aggregate HTTP response status counts are retained on failure; raw response bodies, headers and service logs remain excluded. CI publishes generated replay/viewer access reports alongside source and image provenance. Production adapters and model routes remain disabled until their separate acceptance gates pass.

The event-view extension follows the observed Threat Hunting link and opens its Events tab. A generated impossible-marker search must show the real no-results state before the replay-marker search can pass with a matching manager rule ID in rendered event cells. This proves a limited marker-filtered UI result only; the default columns do not expose native alert IDs, no completeness or latency threshold is accepted, and this operator harness is separate from Gabriel's privacy preview, scoped lease and source receipts. Sanitized request-error routes help investigate startup failures; queries, headers, bodies and identifier-bearing routes are excluded.

## Destructive lab cleanup

## Twelve-record replay acceptance increment

The next lab gate requires twelve distinct rule-5710 manager alerts and twelve browser-visible native documents from the generated replay. It reconciles the complete native projections, unique native IDs and all twelve generated source ports; changed IDs, timestamps, logs, missing records and duplicate records must fail without a receipt. The browser uses the existing search and document-detail UI, including bounded pagination. An absent search remains a required negative control.

The existing local candidate kernel then reviews the twelve typed authentication failures. It must return a repeated-failure candidate with benign alternatives, while nine distinct events padded with duplicate copies remain below threshold. The normalized event document, candidate review and twelve specialist receipts are stored in the disposable case database; restart and idempotent replay must retain exactly one candidate review. Other telemetry, source authenticity, AI quality, real-attack effectiveness and Gabriel's scoped browser admission remain unverified. Validation is pending the actual Docker lab run; syntax checks alone do not accept this increment.

## Destructive lab cleanup commands

```bash
python3 tooling/scripts/gabriel_console_lab.py down iris /absolute/private/new-iris-lab
```

`down` removes that generated lab project's containers and volumes, permanently deleting its lab data. It does not remove the private source/configuration directory or touch the separate Gabriel installation. The CI cleanup does this only for the newly generated project recorded by that job. Do not put real customer data into these disposable labs. A failed prepare retains private state for inspection rather than silently replacing credentials; never upload that directory as a report.
