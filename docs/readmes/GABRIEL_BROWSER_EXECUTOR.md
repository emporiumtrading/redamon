# Browser executor candidate 0.2.0

The extension can fetch an assigned section plan, display its exact destinations
and expiry, and run a bounded tour after the user approves navigation and
automatic sharing of minimized visible text. The paired lease must already have
operator-approved sharing authority. Every move uses the durable prepare and
complete protocol; every capture has its own encrypted evidence receipt.

The only implemented client adapter is `generated-console-v1`, restricted to
HTTPS localhost and the fixed `/security`, `/traffic`, `/threats` paths. It checks
a generated console marker and visible account label before capture. The
production backend contract catalog remains empty. The browser lab admits this
contract using a helper included only in the test image. Production images do
not contain that helper, and page text cannot create a contract.

## Operator flow

The user selects a signed-in console tab and pairs with the private gateway.
The operator grants reviewed destinations with `gateway_cli navigation-grant`
using the private gateway configuration and a JSON file containing exactly
`request_id`, `contract_version`, `destinations`, and `max_moves`. Production
grants require a contract admitted in reviewed backend code.

The extension's **Review assigned section tour** button retrieves the grant;
the user approves the displayed list and automatic text sharing once, then
starts the tour. The executor visits only these destinations in the assigned
tab, checks each resulting document/account claim, and shares text through the
existing minimizer. Form controls, hidden content and unsupported regions stay
excluded. Frames, images, unloaded rows and covered content remain visibility
gaps. Raw text stays in memory and encrypted server storage; extension session
storage contains scope, cursors and receipt IDs.

Stop interrupts further work and disconnects the lease. One already requested
page load may finish. Redirects or account changes stop capture and subsequent
moves. A worker restart with an unresolved move requires Stop and fresh pairing;
the executor never automatically repeats that move or an uncertain capture.
The navigation interface has no general script, click, sign-in, Commit or Apply
operation. Customer keys remain outside the extension.

## Verification and remaining work

Schema 22 admits versions 0.1.0 and 0.2.0 without rewriting historical version 11.
PostgreSQL tests exercise plan authority, migration rollback and version binding.
The actual Chrome/Brave lab adds unchecked-consent denial, a two-section tour
with fresh document bindings and encrypted capture receipts, wrong-account
denial, unexpected-redirect denial, Stop during a pending move and exclusion of
forms/hidden text. CI execution and artifact review are required for acceptance.

These generated console/account checks do not qualify a vendor adapter or prove
external account authenticity. Palo Alto navigation, pagination, filters,
cross-page event normalization and specialist analysis need additional adapters
and end-to-end tests. Live attack detection latency and model quality remain
separate production gates.
