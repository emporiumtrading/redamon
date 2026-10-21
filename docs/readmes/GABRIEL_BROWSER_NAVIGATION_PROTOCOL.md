# Browser navigation transition protocol — candidate, not admitted

This increment adds a PostgreSQL-backed service protocol. It does not drive a
browser. The installed 0.1.0 extension still disconnects on navigation. The
network gateway does not expose navigation operations. No production console
contract is registered: `browser_navigation.CONTRACTS` is empty.

## Authority and transitions

The original signed-in Gabriel operator may grant an active paired observation
lease one immutable navigation contract, an exact same-origin destination list
(at most 20), and at most 20 moves. A contract must already exist in reviewed
local code. Neither the model nor page content can register one. A grant cannot
extend the original lease, human session, task, case, installation or tab scope.

Each move has an immutable preparation intent with a 30-second maximum lifetime.
Preparation records authority and the previous context but performs no external
action. Evidence intake is blocked while any intent remains unresolved, even
after its deadline. No automatic repeat or inference of a successful move is
permitted. An unresolved outcome requires stopping and pairing again.

Completion accepts a strict browser-supplied context claim. Only the exact
granted URL and document ID may change. Receipt, one-time database commit,
lease context transition and audit event share one transaction. Application
credentials cannot directly update the lease URL/document or insert a commit.
Replaying a completed move returns its historical receipt without rewinding the
current page. Grants and moves are serialized with existing tenant locks.

These are unverified browser claims. Keeping the same account label is not
proof of the actual external console account or session. No telemetry or
attack-detection quality claim follows from a navigation receipt.

## Verification and remaining integration

Generated PostgreSQL integration tests cover bounded transitions, concurrent
replay, stale-page denial, unresolved/expired outcomes, audit rollback, current
authority, immutable scope, restricted database privileges and atomic upgrade
from schema 20 to 21. Docker CI execution is required; authored tests alone are
not acceptance evidence. The physical restart/restore fixture also checks a
completed receipt, an unresolved second move, capture denial and terminal Stop;
execution evidence for these new checks is pending.

Next: wire narrowly scoped gateway operations, a local executor and extension
handling, then admit a simulated console adapter with page/account checks and
postconditions. Real Palo Alto support requires its own adapter and testing.
Configuration writes, Commit/Apply actions and external sign-in remain outside
this read-only navigation protocol. There is no arbitrary Playwright/CDP port
or general-purpose click tool exposed to a model.
