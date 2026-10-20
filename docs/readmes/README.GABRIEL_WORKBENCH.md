# Gabriel analyst workbench

Implements the first C06 browser screens using actual Gabriel PostgreSQL cases, reports and encrypted evidence. New case submission persists a real case and redirects to its detail. Detail shows evidence links, custody, a timeline with separate clock bases, partial browser observations and a metadata-report download. Evidence content requires an explicit form submission and the existing content-reading role/audit/integrity checks. There are no fabricated counts, incident conclusions or disconnected dashboard widgets.

## Run

Use the identity image with its existing application DSN, evidence keyring and evidence volume. The operator authenticates to Gabriel using the existing identity CLI and keeps that general session token private. Prepare a new private directory for each workbench process:

```bash
python -m gabriel.identity.workbench_cli prepare --token-file /operator/human-session --endpoint https://localhost:8444 --directory /operator/new-workbench
python -m gabriel.identity.workbench_cli serve --configuration /operator/new-workbench/workbench.json --certificate /operator/server.pem --key /operator/server.key --bind 127.0.0.1:8444
```

Open the approved endpoint's `/claim` page and enter the ticket from the private `claim.json`. The certificate must be trusted by the browser. Ticket entry is Gabriel authentication; external security-console sign-in remains human-only. The ticket is single use and expires sixty seconds after process startup. The resulting browser cookie grants access only to this workbench, lasts at most ten minutes from process startup, is Secure/HttpOnly/SameSite=Strict, and never contains the general Gabriel session token. Current original account/session/membership checks still govern every request. Viewer access is metadata-only. Disconnect clears local workbench authority; the original Gabriel session remains available for its other approved tasks.

Configuration, general session and plaintext ticket are private operator files. A new exclusive start marker prevents restarting a bootstrap to regain its ticket/cookie authority. Restart or expiry requires fresh preparation. One process supports one original operator/session and one browser claim, one worker and serialized bounded requests. A second engineer prepares a separate process/endpoint. Remote exposure, production SSO/MFA, managed multi-user availability and accepted deployment/retention policy remain later operational work.

## Implemented controls and UAT inventory

Human UAT is NOT_RUN. Matching-image network tests and generated-console native-browser checks must be recorded at their exact source before component verification is claimed.

| Page/control | Actual operation | Required failure behavior |
| --- | --- | --- |
| `/claim` ticket / Connect | Single-use scoped cookie after live session and audit admission | Wrong/replayed/expired ticket, unavailable audit or reused process bootstrap denies access |
| Team scope | Current organization UUID and role on authenticated screens | Revocation/logout and foreign case IDs deny subsequent reads |
| `/cases` queue | Up to 100 most recently created real tenant cases | Empty state or explicit service/access error; no synthetic incident scores |
| `/cases/new` title / Create | Audited PostgreSQL case creation, fresh one-use form nonce, redirect to detail | Viewer, CSRF, duplicate submission, unknown fields or invalid title denied; uncertain database outcome asks for queue inspection |
| Case detail | Existing evidence metadata, typed timeline and partial browser observations | Bounded report overflow/corrupt custody deny instead of omitting entries silently |
| Download metadata report | Authenticated audited JSON snapshot/checksum | No artifact body, object path, encryption key ID or general credential disclosed |
| Evidence custody | Validated custody sequence and storage state | Foreign/unlinked artifact denied; source authenticity remains unverified |
| `/sources` browser health | Individually sampled current session/task/authority and heartbeat checks for up to 32 recent lease records | Pending, disconnected, expired/authority loss and heartbeat gaps stay explicit; recent heartbeat does not establish live page visibility |
| `/audit` activity | Up to 200 actual tenant audit events, ordered by server time/ID | Viewer denied; actor/target identifiers never substitute for a complete audit archive; omitted older records disclosed |
| `/spending` controls | Real UTC monthly/daily used-or-reserved amounts and unresolved slots; owner/admin can lower allowances or pause new reservations | Invalid amounts, higher-than-ceiling allowances, viewer/analyst writes, stale access, CSRF or wrong Origin deny; claimed unknown costs remain held. Models/transport remain inactive; billing is operator-attested |
| View evidence content | Explicit POST, live content role, actual decryption/integrity and audit | GET, viewer, CSRF, purged/corrupt object or audit failure denied; hostile HTML rendered as text |
| Disconnect workbench | Clear local cookie/authority, audit session handoff | Existing browser cookie cannot access cases afterward |

The service enforces native TLS, exact Host/POST Origin, duplicate-field rejection, no proxy forwarding, no cross-site/same-site fetch context, bounded bodies/responses and 120 requests/minute/process. Responses use no-store, strict CSP with hashed static CSS, framing denial, same-origin resource policy and no external scripts/assets. Forms expose only a CSRF value and one-use local create nonce. PostgreSQL service methods remain the authorization and audit authority. Creating another form replaces the previous create nonce; after an uncertain create outcome, inspect the queue before obtaining a new form.

## Loop and remaining work

Scope: partial GAB-003/005/006/007/022/025/026/038/040. Owner: implementation agent; independent reviewer and analyst UAT owner unassigned. Baseline: `af6e335f72b8f617e81c369606f3a962b2e47e30`, schema 12. No migration or new database grants. Status: IMPLEMENTED_UNVERIFIED until hosted checks are recorded. Hypothesis: real browser forms can create and inspect persisted tenant cases while preserving existing identity/content controls. Verification includes actual native TLS/PostgreSQL negative tests, full identity/runtime/foundation regression and Chrome for Testing/Brave workbench journeys with generated-only screenshots.

Rollback removes the workbench module/launcher from the image, stops its processes and discards their scoped cookies/tickets. Existing cases/evidence remain accessible through the prior CLI. No external effect, vendor login or response operation is implemented. Full sign-in/team administration, prioritized operations, assignment/questions, correlation/graph, control profile, proposal/memory/model screens, historical pagination/export, specialists, real console workflows, independent review and staging/post-release UAT remain open in the PRD.
