# Approved browser observation intake

Schema 12 adds an intake service and operator CLI for engineer-approved text. This is the backend contract for a future packaged Chrome/Brave extension. It does not install a browser client, read a real page, navigate consoles, submit searches, authenticate externally, or detect an attacker. External console sign-in stays human-operated; no vendor API is required.

## Explicit sharing and authority

A pairing-only lease cannot collect content. Existing leases migrate with `intake_enabled=false`. To share observations, the engineer issues a fresh lease with `lease-issue --approve-observation-sharing`. This immutable grant remains bound to the exact page, document, tab, browser, installation, declared account, case, task and original Gabriel session, for at most five minutes. There is no silent upgrade or renewal.

Submission requires both the scoped peer credential and that exact current Gabriel human session. The future trusted Gabriel HTTPS gateway holds the human credential on the trusted operator/backend side; an extension or web page must never receive it. A different session for the same human cannot substitute for the original session. Every new submission and receipt completion rechecks scope, session, role, task, case, consent and heartbeat. Revocation stops new admission; it cannot retroactively erase content already admitted into the evidence protocol.

Each new observation consumes one browser task step. The final allowed step may complete and replay after the task becomes exhausted, but may not admit another observation. Cancellation, expiry and authority loss still deny replay through the peer. Requests are sequential per lease, with one unresolved intent at a time. Exact retries reuse one observation, encrypted artifact and immutable receipt; changed content under an existing request ID is rejected.

## Envelope and evidence

The payload JSON contains exactly these fields:

```json
{
  "schema_version": 1,
  "operation": "browser.observe",
  "request_id": "REQUEST_UUID",
  "sequence": 1,
  "context": {
    "browser": "chrome",
    "extension_version": "0.1.0",
    "installation_id": "INSTALL_UUID",
    "tab_id": 7,
    "document_id": "DOCUMENT_UUID",
    "page_url": "https://APPROVED_HOST/security#events",
    "account_label": "Engineer-approved account"
  },
  "observed_at": "2026-10-19T00:00:00+00:00",
  "visibility": "partial",
  "client_minimized": true,
  "content": "Engineer-approved visible text"
}
```

Use the actual capture time and selected context, not the illustrative placeholders above. New captures must be at most 60 seconds old and at most five seconds ahead of the database clock. Content is 1–65,536 UTF-8 bytes; only `partial` or `visible_text_only` visibility is admitted, never a claim of complete visibility. Control characters except newline/tab/carriage return are rejected. Secret-like password, authorization, cookie, OTP, token, API-key and client-secret assignments, including quoted JSON keys, require privacy review instead of silently removing bytes. This conservative filter is not a secret detector or proof of effective minimization. The future client must minimize locally and obtain engineer approval before transmission. The server's `client_minimized` flag records an unverified claim.

Observation metadata stores hashes, length, time, scope references and state. Text goes through the existing encrypted evidence store, actual authenticated readback and custody chain. No plaintext body is added to the observation tables, receipt, CLI output or audit event. Receipt metadata identifies the collection as `engineer_approved_browser_claim`; the artifact remains `user_supplied_text`. Source authenticity and current page visibility are explicitly false/unverified. Prompt-like text remains inert evidence; no model, tool or response executor consumes it here.

The metadata endpoint reports historical captured counts. `page_content_received=true` means at least one completed observation exists, not that the currently open page is visible or complete. Base pairing heartbeat responses still describe the pairing operation and report no content received by that operation.

## CLI and interrupted intake

Use the existing private case-data image, evidence volume and identity secrets, with entry point `python -m gabriel.identity.browser_cli`. Issue and connect the lease following the [pairing guide](README.GABRIEL_BROWSER_PAIRING.md), adding the explicit sharing flag. Submit and inspect:

```bash
observe --token-file /operator/human-session --credential-file /operator/browser-pair.json --payload-file /operator/approved-observation.json
observation-get --token-file /operator/human-session --observation-id OBSERVATION_UUID
observation-reconcile --token-file /operator/human-session --observation-id OBSERVATION_UUID
```

The CLI is an operator tool, not a transport design that distributes the human session to the browser. Protect payload files as sensitive evidence and remove them under the retention policy. JSON input is bounded at 256 KiB to accommodate the content envelope; the text itself remains capped at 64 KiB. Existing checkpoint-document limits remain unchanged by default.

Intake persists a browser intent, acquires evidence through the existing durable protocol, then publishes a receipt. If authority or receipt admission fails after the encrypted artifact is written, the observation remains prepared and must not be reported as captured. An authorized original issuer or owner/admin may reconcile using authenticated existing ciphertext after peer revocation, without another capture or task charge. Missing, corrupt or mismatched artifacts cannot produce a receipt. Reconciliation never renews the browser lease or restores revoked authority. An intent without a stored artifact must be retried with the exact approved request while its scope is still valid; this increment provides no force-complete, discard or budget-refund operation.

## Verification and next loop

Matching-image PostgreSQL/crypto/CLI tests exercise approval defaults, tenant and original-session binding, encrypted custody, concurrent retries, budget exhaustion, order/conflicts, malformed/stale/secret-like content, audit rollback, missing ciphertext, receipt-write interruption, upgrade rollback and restart/dump-restore. Generated text is labeled lab data; no live telemetry or target data is committed. Source-specific VM results belong in the implementation ledger; until recorded, this increment is implemented but unverified.

Next is the packaged client and bounded authenticated HTTPS gateway. Native messaging remains excluded from the MVP under the conversion plan; a backend helper contract does not authorize installing a native host. Follow this with actual Chrome and Brave lifecycle, visible-content/minimization, prompt-injection and vendor-neutral console lab tests. B0 permission/privacy/OS/distribution review, independent security review, integrated human UAT, and pre/post-release regression remain open. No attack conclusion can be guaranteed with certainty 1.0; missing evidence or visibility must remain explicit.

Rollback disables observation entry points and revokes sharing leases while retaining encrypted objects, intents, receipts, custody and audit. Never rewrite a captured receipt or run an older runtime as a way to skip new checks.
