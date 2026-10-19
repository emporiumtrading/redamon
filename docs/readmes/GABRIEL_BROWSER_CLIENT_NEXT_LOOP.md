# Browser client and HTTPS gateway: next engineering loop

Status: **DESIGN_CANDIDATE**, not an implemented extension, accepted B0 review or release. Depends on verified pairing and observation intake. This record narrows the next vertical slice; unresolved findings must be repaired before browser acceptance. No vendor API or external login automation is introduced.

## Outcome and scope

An engineer selects one already authenticated HTTPS page, reviews its exact context, pairs it to a Gabriel case/task, previews minimized text, and explicitly shares that text into encrypted custody. The same packaged Manifest V3 source targets Chrome and Brave. Both actual browsers must pass their own lab; Chromium compatibility is not a substitute for Brave acceptance.

The first client supports selected-page observation, Stop/Disconnect, scope/expiry display, visible gaps and receipt inspection. It does not navigate, run searches, fill forms, capture screenshots, switch accounts or execute response actions. Those need separately tested B2/B3 contracts. The extension is never an external login agent.

## Proposed trust boundaries

| Boundary | Required behavior | Rejection/stop condition |
| --- | --- | --- |
| Engineer → extension-owned UI | User-invoked selection and context/preview confirmation | No active permission, wrong tab, unsupported page or cancelled preview |
| Page → packaged collector | Read only selected visible text; exclude input/editable/script/hidden content; mark partial visibility | Document change, unsafe/auth route, unknown frame, collection limit or privacy review |
| Collector → trusted extension context | Validate tab/frame/document sender and fixed schema; never accept page-supplied commands | Missing/mismatched browser-produced document ID or unexpected message |
| Extension → configured Gabriel HTTPS gateway | Exact endpoint, verified TLS, short-lived scoped peer; bounded body, no redirect or credential forwarding | Endpoint change, certificate failure, expired/missing peer, origin mismatch or oversized input |
| Trusted gateway → observation service | Bind original human credential internally; invoke the current dual-credential intake contract | Original human logout/expiry/downgrade, missing server binding, task/case/scope loss |
| Evidence → investigator | Source-linked untrusted text with incomplete visibility and explicit uncertainty | No receipt, pending intent, missing bytes or unverified source |

CORS and extension IDs are defense in depth, not authentication. Website scripts and content scripts must never receive the peer token or the original human credential. The gateway cannot fetch a submitted console URL. It accepts only typed pairing/heartbeat/disconnect/observation operations; no arbitrary tool, path, shell or HTTP proxy operation exists.

## Pairing and credential lifecycle to implement

1. The extension obtains browser-produced tab/document identity after a user gesture and shows the exact HTTPS URL and engineer-declared account label. Label declaration is not proof of the console account.
2. A trusted operator flow supplies that context, case/task and original live Gabriel session to the gateway. The operator explicitly chooses pairing-only or observation sharing. There is no public unauthenticated lease issuer.
3. The gateway creates the existing bounded lease and a separate random, single-use, short-lived claim ticket. Ticket storage contains only its digest; the original human binding stays on the trusted side. Ticket consumption must be atomic, context-bound and rate limited. It must not renew the underlying lease.
4. The extension claims through the exact approved HTTPS endpoint and stores only its scoped peer in extension-restricted session storage. Claim replay, mismatched context and ticket expiry fail closed. Tickets and tokens never appear in URLs, ordinary logs, page messages or synced storage.
5. The gateway uses its bounded original-human binding when invoking `observe_browser`; the extension never submits a general human credential. Loss of that binding after gateway restart requires fresh engineer pairing. It cannot silently reconstruct or extend authority.
6. The client confirms current browser identity before each operation. Document navigation, account declaration change, endpoint change, permission removal, browser restart/update, Stop, expiry or heartbeat loss stops sharing and clears local authority. Server revocation remains authoritative even if browser cleanup fails.

The backend helper currently implements no claim-ticket exchange or network gateway. This is a required new protocol, not a claim that the existing CLI already provides it. Gateway certificate/endpoint configuration, operator enrollment channel, quotas, secret ownership and exact supported deployment OS must be recorded and threat-reviewed with the implementation. Native messaging remains excluded from the MVP.

## Package and collection constraints

Begin with `activeTab`, `scripting` and `storage`; do not request blanket installed host access. Any optional HTTPS host declaration must request only the selected Gabriel endpoint origin at runtime. Do not request cookies, history, debugger, native messaging, clipboard, downloads or incognito access. Use packaged scripts in isolated execution contexts, restrictive extension CSP, no remote executable code and no externally connectable page-command surface.

Use `scripting.executeScript` results for browser-produced document identity, then target that exact document for collection. Do not invent a UUID in page code and treat it as browser identity. Never fall back to collecting the currently active tab if the bound document disappears. Restrict collection to the top frame initially; inaccessible frames, canvas, closed shadow roots and unloaded/virtualized rows remain visible gaps. Use rendered-text semantics and inspect exclusions; DOM presence alone does not prove visibility. Do not read form values, browser/local/session storage or hidden DOM text.

Keep preview text in the extension-owned view, insert it as text rather than HTML, and do not persist it in ordinary extension storage. Allow the engineer to remove sensitive text or cancel before sending. The server's conservative secret-like assignment filter remains a final denial, not proof of redaction. Bound collection before serialization; never silently truncate while claiming completeness. Preserve exact request UUID, sequence, capture time and approved bytes for a bounded retry; a changed preview is a new approved request.

Manifest V3 suspension cannot be treated as permanent connectivity. Session storage is not an audit store or durable background worker. If the browser cannot meet the server's 45-second freshness requirement, display the gap and require repair; do not weaken the backend threshold or invent heartbeat success. Stop works locally immediately even during outage; queued captures are discarded, and server disconnect is attempted without false acknowledgement. Any unacknowledged receipt stays unknown/prepared until inspected or reconciled.

## Required real test matrix

| Layer | Tests and observable result |
| --- | --- |
| Gateway + PostgreSQL + TLS | Real server requests, single-use ticket concurrency, exact origin/context, bad certificate/redirect, malformed/oversized payload, expiry, logout/downgrade, audit loss and queue bounds; no secret/body in access/error logs |
| Packaged Chrome | Install actual package, user-selected page, browser-produced document binding, preview/edit/cancel/share, exact encrypted bytes and receipt, scope drift, SPA/navigation and permission removal |
| Packaged Brave | Repeat the complete critical path in actual Brave and record binary/version/package hash; test Shields/permission behavior without assuming parity |
| Hostile generated console lab | Hidden/password/editable content, prompt injection, hostile HTML, page messages, cross-origin frames, canvas and virtualized rows; excluded content absent and visibility partial |
| Lifecycle | Worker suspension/restart, extension reload/update, browser restart, lost endpoint, heartbeat gap, Stop offline, expired claim/peer and abandoned pending receipt; no silent re-pair or duplicate evidence/charge |
| Regression/recovery | Existing identity/runtime/foundation suites, pairing and intake checks; actual gateway interruption plus PostgreSQL/object restore and revoked-session denial |
| Human UAT | Engineer confirms useful preview, understandable scope/gaps, manual external-login handoff, genuine console workflow and Stop; pre-release and post-release gates remain distinct |

Generated lab consoles must be clearly labeled, deterministic and isolated; passing them does not establish detection accuracy against a live attacker or compatibility with an arbitrary vendor console. Later pilot selection adds actual authorized console workflows and records coverage gaps. Preserve negative-case assertions and source/artifact evidence. Advance from test failure through cause/repair/regression, not by changing the expected security boundary.

## API evidence checked for the design

- [Chrome scripting API](https://developer.chrome.com/docs/extensions/reference/api/scripting): packaged injection, result document identity and exact-document targets. These support a candidate implementation; actual package tests must establish its behavior.
- [Chrome storage API](https://developer.chrome.com/docs/extensions/reference/api/storage): session-storage lifecycle and access restrictions. Explicitly restrict access to trusted extension contexts; do not use sync for credentials.
- [Brave extension support](https://support.brave.com/hc/en-us/articles/360017909112-How-can-I-add-extensions-to-Brave): Chromium extension support justifies a shared source candidate, not a compatibility pass.

Documentation checked 19 October 2026. Exact browser/OS versions and package hashes are pinned by the eventual lab evidence, not inferred from this document. Independent permission/privacy/protocol review and integrated human UAT remain open.
