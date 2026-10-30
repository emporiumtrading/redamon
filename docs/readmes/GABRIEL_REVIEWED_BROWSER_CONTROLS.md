# Reviewed controls in assigned Chrome and Brave tabs

This increment implements menu disclosure, native select filters, text/search fields, link and button pagination, and reviewed GET search forms. The existing extension drives the assigned tab; no inherited Playwright server, debugger permission, arbitrary script/selector tool or external-console API is enabled. A finite control plan runs its reviewed steps after one popup approval. The operator-approved plan is retained as encrypted case evidence. Each step rechecks its target, page, document/account and expected visible result, then records a durable transition receipt and encrypted minimized observation.

Status: implementation candidate. See its exact PR/CI results before choosing an installation source. Native Mac and real-console acceptance are still required. Generated tests do not establish every vendor/framework, console identity or read-only semantics. The ordinary installation remains observation-only when no control plan is provided.

## Operator setup

Use an actual read-only role in the external console and have the engineer review the exact destinations, query keys/values and controls. A DOM label, visible link or GET method cannot establish read-only semantics. Unknown controls, credentials, mutation labels, uploads, POST forms, hidden form fields, cross-origin destinations and ambiguous targets are refused. Controls must be visible and uncovered in the selected top-frame view. Frames, closed shadow roots, canvas, custom non-native widgets and offscreen controls are not silently guessed.

Select the tab and declared account in the extension, then choose **Show visible control identities**. This local inventory includes bounded tag/ID/accessible-name descriptors, omits values and excludes recognized credential/action controls. It is not authority to execute. Save the selected context and reviewed plan in the private installation directory, outside Git and shared/synced folders. Never copy a general human token into the extension.

A plan has this shape; the example is generated documentation data and must be replaced with exact reviewed local console values:

```json
{
  "version": "gabriel-reviewed-controls-v1",
  "request_id": "8f337197-6b03-482c-85f4-3f2e223963ae",
  "read_only_role_confirmed": true,
  "query_keys": [],
  "steps": [{
    "kind": "menu",
    "target": {"tag": "button", "id": "sections", "name": "Open sections"},
    "source_url": "https://generated-console.invalid/security",
    "destination_url": "https://generated-console.invalid/security",
    "expect": {"id": "menu", "text": "Investigation sections"}
  }]
}
```

Each later `source_url` must equal the preceding destination. The query policy explicitly lists all allowed query keys; each destination contains its exact reviewed values. Plans have 1–20 steps, at most 20 unique same-origin URLs and a 6,000-byte encoded limit. Field values are bounded to 256 characters and may not contain control characters. Original human/task/lease expiry and move/capture budgets remain authoritative.

| Kind | Supported target and extra fields | Result check |
| --- | --- | --- |
| `menu` | A closed button menu with `aria-haspopup`, `aria-controls` and `aria-expanded=false`, or a closed native details/summary | Reviewed panel/visible result appears |
| `filter` | A native `select`; `value` must match an enabled option | Selected value and reviewed visible result |
| `fill` | Editable native text/search/date/number input or textarea; explicit `value` | Value accepted and reviewed visible result |
| `paginate` | Reviewed same-origin link, or non-submit button with no form and unchanged URL | Exact destination and reviewed visible result |
| `submit` | Native GET form, explicit `fields` matching every enabled named field and exact destination query | Exact destination and reviewed visible result |

The GET form actuator validates the action and fields, then navigates to the reviewed URL instead of invoking arbitrary submit handlers. Hidden or additional fields, passwords, file inputs, changed method/action, duplicate fields and unreviewed queries are denied. Custom POST/JavaScript-only forms require a separate typed adapter and acceptance; this driver does not convert them into a general submission capability.

After a backed-up rebuild to an image advertising the controls capability:

```bash
python3 tooling/scripts/gabriel_install.py browser-open "$HOME/gabriel-private-test" \
  --case-id CASE_UUID \
  --context-file "$HOME/gabriel-private-test/context.json" \
  --extension-origin chrome-extension://EXTENSION_ID \
  --duration 300 --max-steps 20 --approve-observation-sharing \
  --controls-file "$HOME/gabriel-private-test/controls.json" --approve-browser-controls
```

Keep the controls file owner-only (`chmod 600`) in an operator-owned private directory (`chmod 700`). The manifest's read-only-role assertion and the explicit controls/sharing flags are required. A legacy image is rejected before enrollment. The plan reaches only the trusted private operator/bootstrap, and its general human token remains inside the private container. The gateway grants the bounded plan after the one-use pairing claim. Ordinary URL-tour calls cannot bypass a controls plan's typed dispatcher. Controls cannot be combined with automatic discovery, scheduled review or AI dispatch in this increment.

The advanced private gateway CLI also accepts `prepare --controls-file PATH --approve-browser-controls --approve-observation-sharing` with the existing private token/task/context options. The plan must be present before starting the gateway; it cannot be attached to an already-started bootstrap.

## Analyst execution and recovery

Pair normally, choose **Review assigned control plan**, and review every field value, destination and expected result. Select the controls/sharing approval, then **Run reviewed controls**. This runs the bounded sequence without requesting approval for each individual step. A changed plan requires review again. The browser stores only the reviewed plan hash, and clears the visible plan on hiding or stopping the popup. Each step targets one exact, unambiguous tag/ID/accessible-name descriptor; no arbitrary CSS, scripts or model-generated executable code is accepted.

Prepare, actual browser dispatch, postcondition and completion are distinct. The original context is rechecked immediately before dispatch. Same-document actions retain that document; URL transitions rebind through the existing backend receipt. A lost prepare response, expired intent, unresolved result, Stop race or restart cannot authorize an automatic second dispatch. An uncertain step stops the local channel and disconnects its authority; inspect the original receipts before explicitly creating a new plan/lease. Stop prevents further steps but cannot roll back an already-dispatched browser event.

The existing per-tab and all-tab Stop, permission removal, original-session revocation and expiry remain in force. Other selected/unassigned tabs do not acquire this plan. Nothing renews authority, grants provider egress, qualifies a model, trains on a performance case or authorizes containment/remediation.

## Acceptance

The generated Chrome/Brave journeys exercise menu/link subpages, select filtering, text entry, button pagination, GET search navigation, exact postconditions, encrypted observations, excluded credentials, unassigned-tab isolation, missing approval, ambiguous targets, password drift, POST/hidden-field denial, invalid fields without validation events, restored rejected values, covered/stale/failed postconditions and Stop after preparation. PostgreSQL tests cover same-document commits, scope/order/digest denials, old request replay/restart, logout/Stop, expiry, exact form queries and rejected mutation policies. Installer fault tests cover explicit approval, image capability, private plan-file access and keeping plans out of host state.

Run the real console/version with a genuine read-only console role before acceptance. Record actual requests/state before and after, partial/stale views, menu/filter/pagination/form outcomes, account changes, redirects, Stop/expiry, native TLS and separate Chrome/Brave results. Qualify dynamic adapters and investigative/model behavior separately. A passing generated actuator test is not a vendor authenticity, model-effectiveness or production-release decision.
