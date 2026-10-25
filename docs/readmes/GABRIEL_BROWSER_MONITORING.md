# Multiple-tab scheduled browser review

Implementation under verification. This is not acceptance of continuous threat detection, a vendor-console adapter, a qualified AI route or native Mac execution.

## Scope and use

Load the packaged extension in Chrome or Brave. Select each intended tab using the native action popup and its non-secret account label. Up to eight independently paired tabs are retained. Selecting a new tab does not replace other approvals. The tab selector switches the current controls; Stop this tab revokes that tab, while the sticky Stop all tabs and Pause apply to all selected sources.

The operator creates a separate browser task and gateway bootstrap for each selected browser-produced context. For scheduled operation, pass both `--approve-observation-sharing` and `--monitor-seconds 300` (60–3600 seconds) to `python -m gabriel.identity.gateway_cli prepare`, with its existing case/task/context/endpoint/origin/private-directory arguments. Ordinary pairing still defaults to five minutes and cannot authorize scheduling. The lifetime is clipped to the original human session and task; it cannot renew itself.

For one shared HTTPS endpoint, write a private mode-0600 JSON document with `purpose: "gabriel-browser-group-v1"` and `configurations: ["/absolute/private/tab-one/gateway.json", "/absolute/private/tab-two/gateway.json"]`. Start `python -m gabriel.identity.gateway_cli serve-group --configuration /absolute/private/group.json --certificate /private/server.pem --key /private/server.key --bind 127.0.0.1:8443`. All members must have the same original operator, endpoint and extension origin, and distinct lease IDs. Each ticket and bearer credential still reaches only its own gateway. Bootstrap start markers remain single use; an uncertain partial group startup requires new bootstraps.

Pair each tab using its own short-lived ticket. In Scheduled investigation, choose selected-page or previously reviewed tour, read the collection scope and approve future minimized-text sharing. The extension uses Chrome alarms, rather than popup timers, to request review approximately every 30 seconds. The popup may be closed. Browser scheduling is best effort: a gap longer than 45 seconds interrupts automatic collection and requires fresh pairing rather than asserting continuous coverage.

Each approval allows at most eight changed captures, with per-tab/per-page SHA-256 deduplication; plaintext is not stored in the scheduler. Budget, task, move and expiry limits can interrupt review earlier. Evidence, server receipts and typed specialist outcomes retain their existing durable audit and replay behavior. An unresolved observation/navigation cursor prevents automatic retries after a worker interruption.

## Navigation and interpretation

Existing generated-console tours remain test-only. An operator may issue an exact same-origin destination plan using `operator-reviewed-pages-v1`. It admits at most 20 listed HTTPS URLs, no queries/fragments in the client adapter, with bounded moves (up to 1000 only for an explicitly scheduled lease). Common action/configuration/authentication routes are denied. It navigates by browser URL, never by page-supplied executable instructions or arbitrary form submissions. Each destination requires the declared account label to remain visibly identifiable. This identifies a declared visible label, not independent account authenticity or vendor semantics. Operator-reviewed page lists do not qualify Palo Alto, Wazuh, IRIS or any other vendor adapter.

Supported generated typed event snapshots can drive the existing cross-capture/cross-lease same-case correlation and twelve local specialist reviews. Plain-text changes are evidence awaiting assessment: they are not automatically labeled attacks. Existing event/specialist source and case limits remain enforced. Learned organizational knowledge still uses the existing case memory proposal and human review workflow; untrusted page instructions never become authority or accepted learned facts.

## Acceptance still required

Verification must include real Chrome/Brave pairing of two tabs to one TLS gateway, capture with popup closed, changed-content deduplication, isolated per-tab Stop, scheduling-gap interruption and existing consent/revocation/tenant/custody regressions. Real console data/DOM contracts, model qualification and separately authorized provider payload/cost admission, actual Mac UAT and operational review remain open. No new paid inference is implied by this feature. Source-health screens show capture receipts and scheduling permission, not proof of current live monitoring.
