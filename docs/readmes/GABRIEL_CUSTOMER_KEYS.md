# Customer-owned model credentials

Product-owner direction: customers supply their own OpenRouter and/or NVIDIA
credentials. Development/CI credentials are never a bundled service or fallback.
An open-source model does not make its hosted API credentials public.

## Setup behavior

The authenticated workbench exposes **Your AI keys** to owners/admins. A password
field submits a credential over the existing authenticated same-origin HTTPS/CSRF
boundary. The credential is encrypted in the organization-scoped provider vault;
it is not returned in HTML, status, reports, audit events or URLs. Removal revokes
the local credential and clears its ciphertext. Remote key revocation remains an
action in the customer's provider account. Keys belong to the organization in
this release, rather than being shared across organizations.

OpenRouter setup performs only GET `/api/v1/key` and GET `/api/v1/credits`.
Both account credit (`total_credits - total_usage`) and remaining key allowance
must be at least $18. Use a dedicated inference key with an $18 monthly cap.
Unbounded, management/provisioning, insufficient and unverifiable accounts fail
setup without replacing an existing key. A successful check creates an immutable
schema-19 receipt bound to the exact stored credential ID/revision. Changing the
key invalidates that admission until setup is checked again. This is a historical
funding check, not model qualification or a promise about future account credit.

After setup, the balance may fall below $18 through normal use. Each dispatch
still checks current provider credit against its cost reservation and the
existing per-key/daily/monthly policy. Local limits remain $18/month, $0.50/day,
$0.05/investigation, two unresolved slots, and the existing attempt/time/token
bounds. No top-up, hidden retry or developer-key fallback is introduced. Other
programs spending the same account can invalidate a reported balance; a dedicated
key/account and provider-side caps remain necessary. A new worker configuration
version (`restricted-model-worker-v3`) records the changed dispatch boundary.

NVIDIA keys can be stored/revoked through the same private flow. Status remains
**validation pending** with no claimed dollar balance, account entitlement or
inference admission. A catalog response is insufficient proof of production
terms or model access. NVIDIA transport, route/privacy/cost admission, bounded
entitlement verification and model-quality acceptance still require implementation.

## Verification and outstanding work

New generated-response tests cover funding boundaries, strict metadata, revision
binding, tenant isolation, missing environment fallback, role/CSRF denial,
revocation, ciphertext, append-only receipts and worker denial before a cost
claim. HTTPS workbench tests store/revoke a generated NVIDIA key; they do not
contact either provider. Restart/restore includes the new receipts in actual
database row reconciliation and generated worker setup. These tests must pass in
the matching Docker CI image before this increment is component-verified.

Docker is unavailable on the implementation host. No host pytest is used. Real
customer onboarding, human UAT and a production installation are not yet accepted.
The host must supply its private vault encryption keyring separately; no customer
provider key is read from `OPENROUTER_API_KEY` or `NVIDIA_API_KEY` by this flow.

References checked for this implementation:
- https://openrouter.ai/docs/api/api-reference/credits/get-remaining-credits
- https://openrouter.ai/docs/api/api-reference/api-keys/get-current-api-key
- https://docs.api.nvidia.com/nim/docs/product
