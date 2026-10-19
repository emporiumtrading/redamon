# Scoped browser pairing foundation

Schema 11 and `BrowserSessionService` implement durable human-approved browser session contracts. This component pairs a credential to one exact HTTPS page, tab, document, declared account, browser/extension version, installation, case, task and originating Gabriel human session. It collects no page content, logs into no external system and provides no navigation, query, form, screenshot or response executor. Backend tests that name Chrome/Brave are typed contract tests, not packaged-browser compatibility passes.

## Authority and privacy

The engineer first authenticates to Gabriel and creates a dedicated `browser-observation-v1` task. This resource admits only the separately scoped `browser.observe` contract; local inspection worker grants cannot inherit it. Pairing currently enables only heartbeat and disconnect. No `browser.observe` dispatch/intake command is exposed by this increment.

Pairing requires a current owner/admin/analyst, an active authorized browser task and an open case. The credential expires after at most five minutes and no later than the task or original human session. The server stores a domain-separated digest, never the bearer token. A peer must present the exact approved context before confirmation or heartbeat. A new tab/document/account, URL/path/fragment/port, installation or browser requires new human approval and a new lease. No wildcard scope or silent renewal exists. Chrome and Brave are distinct scope values; extension version is pinned to contract `0.1.0`.

Each peer call rechecks the original human session, membership/role/user, task creator's authority, task state/expiry and open case. Original logout, downgrade, cancellation, expiry, closed case and explicit revocation stop the delegation. Browser credentials cannot call general human operations. Heartbeats older than 45 seconds or from a future clock window require fresh pairing; replaying confirmation does not refresh the heartbeat or extend expiry. Disconnection is terminal and cannot be revived by runtime SQL. The metadata status separates stored state from current authorization and heartbeat freshness, and always reports `page_content_received: false`.

The approved context is metadata, not evidence of a logged-in account or a truthful page. URLs must be canonical HTTPS, contain no userinfo/query or unsafe control characters and exclude recognized sign-in/SSO/MFA/password paths. Query-bearing and token-like fragment routes are unsupported by this initial contract, requiring a later reviewed local minimization/route-binding design. Do not strip a real route and falsely assert it matches. Account labels are engineer-declared, not independently authenticated. No backend request is made to a supplied URL, including internal hosts. This component stores only approved context and authority metadata, not cookies, passwords, external tokens or DOM bodies.

## Operator and peer workflow

Use the private identity project's existing case-data image/secrets/evidence volume and override its entry point to `python -m gabriel.identity.browser_cli`. Mount only an approved private operator directory. The context JSON contains exactly:

```json
{
  "browser": "chrome",
  "extension_version": "0.1.0",
  "installation_id": "EXTENSION_INSTALL_UUID",
  "tab_id": 7,
  "document_id": "CURRENT_DOCUMENT_UUID",
  "page_url": "https://APPROVED_HOST/security#events",
  "account_label": "Engineer-approved account"
}
```

Identifiers must come from the intended local browser context when a packaged client is integrated; never invent a live document/account to bypass pairing. Generated test UUIDs and `.invalid` domains are used only in the isolated backend lab and are never fetched.

The CLI arguments below are concrete human/peer contract operations; paths are inside the operator container:

```bash
task-create --name 'Approved browser investigation' --ttl 900 --max-steps 20 --token-file /operator/human-session
lease-issue --task-id TASK_UUID --case-id CASE_UUID --context-file /operator/context.json --ttl 300 --output /operator/browser-pair.json --token-file /operator/human-session
connect --credential-file /operator/browser-pair.json --context-file /operator/context.json
heartbeat --credential-file /operator/browser-pair.json --context-file /operator/context.json
lease-get --lease-id LEASE_UUID --token-file /operator/human-session
disconnect --credential-file /operator/browser-pair.json
lease-revoke --lease-id LEASE_UUID --token-file /operator/human-session
```

Credential output uses exclusive mode-0600 durable file publication; it never prints either browser or human secrets. A failed output attempt revokes the newly issued lease where the human session still permits it; session expiry independently makes an abandoned lease unusable. Protect and remove obsolete bootstrap files under the operational secret-retention policy. Browser-token files must remain private; they cannot be installed into web pages, logs, command URLs or ordinary synced extension storage. A future packaged client must use extension-owned memory/session storage and validated sender boundaries. Current code is an operator/peer CLI, not an installable browser extension.

Every mutation requires transactional audit admission. Failed audit writes roll back task/pairing/heartbeat changes. Reconfirmation is idempotent for the same context without credential/expiry renewal; scope and digest columns cannot be rewritten by the application role. Limits are 32 non-disconnected, unexpired leases per tenant, the existing 100 active tasks and dedicated task TTL/step bounds. A task budget does not yet represent actual observations because no content intake exists.

## Browser B0 review package and next boundary

The planned extension permission set starts with `activeTab`, `scripting`, `storage` and a reviewed native-message transport if selected. No broad silent host grant, cookies, password collection, debugger attachment, remote executable code or external login capability is authorized. User-initiated page selection must occur in extension-owned UI, bind current document/account context, minimize content locally, and show Stop/Disconnect and incomplete visibility. Native transport host installation, exact supported OS, final permission manifest and distribution route require explicit B0 review before deployment. No transport is silently selected or installed by the pairing backend.

Next implementation work is the browser observation envelope and encrypted evidence linkage with exact scope, replay/order/budget controls and interruption recovery, followed by the packaged Chrome/Brave client and real browser lab. Observation intake must reuse case/evidence authorization and custody instead of introducing an unbounded text/upload endpoint. Content is untrusted evidence, never instructions, action approvals or an assertion of attack certainty. Human external login and vendor-agnostic scope remain mandatory. Later navigation/search/action authority is separate from pairing and needs reviewed adapters and exact consent.

Automated checks run in the strict matching image against real PostgreSQL, covering scope, secret audience, role/tenant/task/session loss, TTL/gaps, concurrent confirmation, terminal revoke, immutable grants, CLI, upgrade/rollback and restart/dump-restore. Hosted evidence remains pending until recorded in the ledger. Packaged Chrome and Brave installation, selected-page visibility, local minimization, prompt injection, browser lifecycle and console workflow UAT remain **NOT_RUN**. This backend mechanism does not close B0/B1, C05 or product acceptance.

Rollback disables pairing/peer entry points and preserves leases, task types, revocations and audit state. Do not reinterpret a browser task as a local-worker task. Existing peers expire or are explicitly revoked; no older runtime is permitted to mint broader authority from the new resource. Earlier migration files remain unchanged.
