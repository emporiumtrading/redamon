# Autonomous investigation within assigned console sections

Owner clarification: after the engineer signs into a firewall or other console,
Gabriel must independently investigate the assigned pages, subpages and tabs.
Palo Alto firewall dashboards/log sections are a concrete acceptance journey,
not a restriction to one brand. This includes identifying credible live attack
indicators and periodically revisiting admitted views within the active grant.
The initial candidate does not yet implement this journey.

## Current boundary and required implementation

Extension 0.1.0 binds one exact tab/document/page/account. It previews and captures
engineer-approved visible text. Navigation currently stops pairing. Neither
Playwright installation nor twelve specialist registrations changes this fact.
Production investigation requires the following connected implementation:

1. The engineer grants organization/case/task, console account, exact tabs and
   allowed sections, observation policy, duration, operation/rate limits and
   whether supported existing searches/filters may run. Sharing consent can
   cover the bounded task; a separate manual share click per page is not the
   intended autonomous experience. Privacy previews and revocation remain.
2. Discovery proposes a console/capability map. Page text is untrusted input.
   Unknown controls are not executable authority. Show supported, unsupported,
   unreadable and out-of-scope sections. Persist the versioned map and corrections.
3. A backend plan selects an admitted investigation operation, such as opening
   a known log section or applying a validated time filter. Bind it to current
   actor/task/grant, tab, account, source-page state, operation contract version,
   validated parameters and expected destination/postcondition.
4. A local trusted executor checks the grant and exact current browser state,
   performs one admitted operation, re-observes the result and records a receipt.
   A child tab, changed document or changed account needs an explicit transition
   under the grant. Unrecognized redirects/UI changes stop affected capabilities.
5. Normalize captured facts with versioned source/field semantics. Deduplicate
   forwarded/repeated events; correlate entities and time without inventing
   identity/causality. Specialists choose the next relevant admitted search or
   escalate an evidence-backed suspected incident. Contradictions remain visible.
6. A bounded revisit schedule detects changed observations and source staleness.
   Pause/Stop, revoked authority, browser suspension, lost connectivity, changed
   scope/account and sign-in/MFA challenges halt dispatch. External sign-in stays
   human-only. Restart reconciles receipts and uncertain operations before reuse.

Use an available read-only console role for investigative sessions. Navigation
labels, HTTP GET methods and model assurances do not prove absence of side
effects. Validate each supported operation against its real console/version.
Configuration writes, Commit/Apply, deletes, account changes and third-party
draft entry remain outside investigative permission and use separate R3 gates.

## Playwright and extension responsibilities

Playwright supports connection to existing Chromium browsers and has an extension
bridge for existing signed-in tabs. It is suitable for a prototype executor and
repeatable compatibility tests. Its ability to operate a browser does not enforce
Gabriel's organization/tab/section/action boundaries. Do not expose a general
Playwright MCP server or CDP endpoint directly to model instructions.

Keep credentials, browser storage and raw CDP/Playwright handles local to the
trusted executor. The model receives minimized observations and requests typed
operations; it cannot request arbitrary JavaScript, selectors, destinations,
cookies, storage exports, downloads or authentication. The executor is responsible
for enforcing those limits regardless of prompt content. A remote Docker backend
needs an authenticated local workstation bridge; it cannot silently attach to
the user's Mac browser. Prefer extending the existing signed-in-session extension
boundary where practical; select the runtime actuator after contract tests.

Browser grants need a supported multi-page transition protocol, appropriate
explicit origin permissions, per-tab enforcement, document/account checks,
privacy-preserving capture and postconditions. Chrome/Brave and platform behavior
require actual compatibility evidence. A permissive browser permission alone is
not a Gabriel grant. Unassigned tabs remain inaccessible to the investigator.

## Palo Alto acceptance journey

In an authorized lab, sign in manually and assign selected dashboard, application
activity and traffic/threat/system log sections. Seed supported attacks and benign
lookalikes, including multiple affected assets. Verify autonomous movement into
relevant details, supported existing filters and return/revisit paths. Confirm
no authentication or configuration mutation. Inject UI drift, stale data,
duplicate events, missing logs, logout, context changes, hostile instructions,
Pause/Stop and restart at each transition.

Record source-event time, console availability, capture, assessment and analyst
presentation separately. Acceptance must report observed detection delay, missed
scenarios, false escalations and covered/unavailable sections. Browser visibility
cannot establish absence of attacks in inaccessible telemetry. Rootkit suspicion
requires surfaced endpoint/kernel/boot evidence. A firewall alone does not expose
every endpoint behavior. The operator's supplied simulated environment is a
development/contract environment; product compatibility and human acceptance
need their declared real versions as well.

Primary references reviewed:
- https://playwright.dev/docs/api/class-browsertype
- https://playwright.dev/docs/chrome-extensions
- https://playwright.dev/mcp/configuration/browser-extension
- https://origin-docs.paloaltonetworks.com/ngfw/administration/monitoring/use-the-dashboard
- https://origin-docs.paloaltonetworks.com/ngfw/administration/monitoring/monitor-applications-and-threats
