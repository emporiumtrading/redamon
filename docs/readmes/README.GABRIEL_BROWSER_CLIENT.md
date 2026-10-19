# Browser client and native-TLS gateway

Status: implemented candidate undergoing verification. This adds a real Manifest V3 extension and a finite HTTPS gateway to the existing observation service. It does not establish accepted B0 review, actual console compatibility, autonomous hunting or release readiness. The [requirement reconciliation](GABRIEL_REQUIREMENT_STATUS.md) tracks all forty PRD requirements.

## Operator workflow

Use the identity/case image with its existing private application DSN, evidence keyring and encrypted evidence volume. The operator authenticates to Gabriel through its existing CLI. External-console sign-in remains entirely human. The initial gateway supports one approved lease per process, one worker, and at most its original five-minute expiry. Loss/restart of the process requires a fresh private bootstrap and pairing; a durable start marker prevents reuse.

1. Load the reviewed extension directory in a dedicated Chrome/Brave lab profile using the browser's unpacked-extension developer workflow. This is a development package, not a published store distribution.
2. Open an already authenticated approved HTTPS console page. Open Gabriel from its browser action, choose Chrome or Brave and enter a non-secret account label. Select the current page. Copy the displayed context to an operator-owned private JSON file; it contains browser-produced tab/document identity and no credentials.
3. Create a case/browser task with the existing operator CLI. Prepare a new absolute private bootstrap directory using the exact endpoint and extension origin displayed by the client:

```bash
python -m gabriel.identity.gateway_cli prepare --token-file /operator/human-session --task-id TASK_UUID --case-id CASE_UUID --context-file /operator/context.json --endpoint https://GABRIEL_HOST:8443 --extension-origin chrome-extension://EXTENSION_ID --directory /operator/new-pair --approve-observation-sharing
python -m gabriel.identity.gateway_cli serve --configuration /operator/new-pair/gateway.json --certificate /operator/server.pem --key /operator/server.key --bind 127.0.0.1:8443
```

The endpoint must be an exact HTTPS origin with a certificate trusted by the engineer's browser. The default listener is loopback; remote exposure, certificate ownership and deployment require explicit operational configuration/review. Native TLS is required; unreviewed reverse-proxy forwarding is refused. The app has no HTTP login or lease-issuance endpoint, arbitrary request proxy, shell or tool dispatcher. One process/worker owns one in-memory claim state; do not launch multiple workers with the same bootstrap.

Preparation writes private mode-0600 human-session, peer, ticket and configuration documents inside a newly created mode-0700 directory. Existing files/directories are never overwritten. A preparation publication failure attempts to revoke the issued lease; incomplete bootstraps stay unusable and need operator inspection. Keep these files under the operational credential-retention policy. The general human token stays on the trusted gateway side and never enters the extension or a page.

4. In the extension, enter the exact endpoint, explicitly grant access only to that Gabriel origin, and enter the ticket from the private `claim.json`. Claiming is single-use and lasts at most sixty seconds from gateway worker start, never beyond the underlying lease. The configuration stores only the ticket digest; the plaintext ticket file is the operator handoff artifact. No ticket/token is placed in a URL.
5. Preview the selected page text, remove sensitive text, check the sharing approval and send. The text is stored through real encrypted evidence/custody. Read the receipt; uncertain outcomes require receipt lookup or operator reconciliation, never blind recapture. A pairing-only lease cannot share.
6. Pause disables local sharing; resume checks current scope/heartbeat and requires a new preview. Stop immediately clears local authority and aborts local requests, then attempts server disconnect. The UI distinguishes confirmed and unconfirmed disconnect. Server-side revocation and expiry remain authoritative for already admitted work.

## Boundaries and lifecycle

The extension uses `activeTab`, `scripting` and restricted `storage`; the optional HTTPS host pattern enables a user gesture to grant only the selected Gabriel origin. It installs no broad host grant, content-script listener, externally connectable command channel, cookie/history/debugger/native-messaging/clipboard authority or remote executable code. Page scripts never receive a credential. Sender validation accepts only the extension-owned popup page.

Collection initially covers fully rendered text nodes within the top-frame viewport, excluding form/editable/hidden/script content and clipped elements. It refuses excessive text/complexity rather than silently truncating. Frames, virtualized rows, overlays, images and canvas remain unverified; previews are always partial. Preview bodies live only in the popup's memory and are cleared on hiding/sharing/pause/stop. No ordinary storage contains collected text. A non-sensitive pending request cursor survives worker suspension so the next attempt must inspect receipts rather than duplicate a possibly admitted capture.

Current tab/document/URL checks precede operations. Tab close/navigation or permission removal stops the local pairing. Page/account/endpoint changes need new approval; the account label remains an engineer declaration, not independent authentication. Popup heartbeats run while the visible paired popup is active. Browser suspension/background scheduling does not establish continuous coverage; a gap beyond forty-five seconds requires fresh pairing. Original logout, downgrade, cancellation and expiry are enforced by the backend.

Gateway responses are no-store JSON with exact extension-origin CORS. Origin is defense in depth, not authentication. Request/body/schema/method/path/host/forwarding restrictions, short-lived cryptographic credentials, original-session binding, serialized operations, one-use claims and per-process request limits all apply. The gateway fetches no console URLs. Observation failures report `not_confirmed`, because an encrypted artifact may already have been admitted before receipt failure. The engineer's existing `observation-list` and `observation-reconcile` CLI remain the recovery authority after peer loss.

## Acceptance

Native-TLS/real PostgreSQL tests exercise valid claims, replay/concurrency, wrong origin/host/context/ticket, duplicate JSON, invalid TLS trust, audit failure, original-session loss, cancellation, bootstrap restart and actual encrypted observation receipts. Packaged-browser execution and real console/human UAT must be recorded separately; passing server tests is not a browser pass. Exact dependency/browser/package/source evidence belongs in the ledger. Full product UAT, independent security/privacy/protocol review, managed distribution and post-release acceptance remain open.
