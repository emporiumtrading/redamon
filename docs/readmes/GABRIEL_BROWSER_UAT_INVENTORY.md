# Browser Companion control and UAT inventory

Candidate: extension `0.1.0`, six reviewed package files. Native-browser lab at source `cfef1ffe37477c76d5be34bd0c8e817cfc03855e` passed the 15-check subset per browser in hosted run `39217905170`; expanded checks are pending. Human UAT is **NOT_RUN** throughout this inventory. Server/package source `35d2d38da6241ad2e17a1c0a48c3aedb8936a4ca` passed 579 component/regression cases. Neither result accepts all scenarios below or establishes real security-console compatibility.

| Control / selector | Expected normal result | Required denial, gap or failure result |
| --- | --- | --- |
| Browser / `#browser` | Engineer chooses the actual Chrome/Brave family; scope records it. | Wrong or changed family requires fresh selection/pairing; a label is not browser-version proof. |
| Account / `#account` | Non-secret engineer-declared account label enters approved context. | Missing/control-character/oversized labels denied; independent account detection is not claimed. |
| Select / `#select` | Native action grant binds the active HTTPS top-frame document, tab and exact URL. | Internal/incognito/auth routes, changed document or missing permission denied; associated tabs gain no authority. |
| Context / `#context` | Read-only exact context can be given to the trusted operator. | It contains no peer/human token, password, cookie or page text. |
| Extension origin / `#extension-origin` | Exact installed extension origin displayed for operator binding. | Origin alone cannot authenticate or authorize a request. |
| Endpoint / `#endpoint` | Exact approved HTTPS gateway origin selected. | Credentials, path/query/fragment or insecure transport rejected. |
| Allow endpoint / `#permission` | Browser prompt grants only the selected Gabriel endpoint pattern. | Denial leaves no pairing; broad installed host access never appears. |
| Ticket / `#ticket` | Masked single-use claim ticket consumed once and input cleared. | Wrong, expired, reused or mismatched-scope ticket denied; no ticket in URLs/logs/page storage. |
| Pair / `#pair` | Scoped peer stored only in trusted extension session storage. | Original human/session/task loss, wrong origin/host or endpoint failure leaves sharing unavailable. |
| Status / `#status` | Current document/context and server heartbeat rechecked; expiry shown. | Stored pairing is not represented as live visibility after gap, expiry or authority loss. |
| Pause / `#pause` | Local new sharing stops, in-flight local requests abort and preview clears. | An already admitted capture may need receipt review; no claim of retroactive erasure. |
| Resume / `#resume` | Current scope/freshness rechecked, new reviewed preview required. | Expired heartbeat requires new pairing; no silent renewal. |
| Preview / `#preview` | Supported rendered text is shown as partial, before any upload. | Hidden/form/editable/script content excluded; excessive text/complexity rejected; frames/canvas/overlays remain gaps. |
| Redaction / `#preview-text` | Engineer can remove sensitive text before sharing. | Text is inserted as text, never executed HTML; hiding/pause/stop/share clears local preview. |
| Approval / `#approved` | Explicit reviewed-text sharing consent required. | Unchecked consent, stale preview or pairing-only lease cannot share. |
| Share / `#share` | Exact approved bytes yield encrypted evidence and an immutable receipt. | A network/storage/receipt error remains not confirmed; no automatic new capture or blind retry. |
| Receipts / `#receipts` | Captured/pending metadata can be inspected; sequence reconciles without duplicate charge. | Pending result requires engineer reconciliation; an inaccessible peer cannot regain authority. |
| Stop / `#stop` | Local credentials/cursors clear immediately; server disconnect attempted. | Outage clearly reports unconfirmed server disconnect; backend expiry/revocation still govern admitted work. |
| Status text / `#message` | Visible and live-announced working, denied, gap, paused, paired and stopped states. | No raw exception/secret or misleading success after denied/unknown outcome. |
| Receipt/scope / `#result` | Receipt IDs, expiry and relevant tenant/case/task context are readable. | No evidence body, token or false source-authenticity/attack-certainty assertion. |

## Required persona and lifecycle scenarios

- Solo engineer: select, private operator pairing, preview/redact/cancel, share, inspect exact evidence, pause/resume and stop.
- Two engineers: original-session binding, no cross-tenant peer reuse, cancellation/revocation and documented handoff without transferring general credentials.
- Browser lifecycle: popup close/reopen, worker suspension/restart, same-URL document replacement, SPA route change, tab close, account change, endpoint permission removal, browser restart/update and heartbeat expiry.
- Hostile console: prompt-like text remains inert; page messages cannot invoke the popup command channel, inspect tokens or forge consent. Validate form/hidden/editable exclusions and state partial visibility.
- Accessibility: keyboard order, labels, visible focus, checkbox confirmation, readable error/gap states and screen-reader announcements across actual supported browsers.
- Recovery: receipt loss after encrypted write, prepared-ID lookup through operator CLI after peer revocation, authenticated reconciliation and no duplicate evidence/task charge.

The native-browser script exercises a subset against an explicitly generated lab console. Browser/OS versions, package hash and source/image IDs must accompany each result. Chrome for Testing is recorded as a development variant; it does not replace consumer Chrome or actual pilot-console human acceptance. Managed distribution, real console adapters, independent privacy/protocol review, staging UAT and post-release verification remain open.
