# Confidential model input: typed local projection

Scope: partial GAB-033/044/045 and C07. This increment is a pure, local transformation library. It is not connected to browser intake, an authenticated dispatcher, a specialist engine or a provider. It does not authorize model activation or production release. Verification remains pending until matching-image tests execute.

## Acceptance and rollback

Accept this component only if the matching Docker image tests demonstrate that identities never occur in the wire projection, pseudonyms correlate within a case but separate across organization/case/key/type, all compacted rows retain source references, and tampering/unknown fields/over-limit input fails closed. Existing database, recovery and browser regressions must remain green. Model decision quality after transformation needs separate real-model and analyst evaluation. Rollback removes the module and its explicit Docker COPY; no database schema or existing data changes.

## Input and private binding

The input is up to 64 already-normalized typed records: local record/evidence UUIDs, evidence digest, explicit UTC event time, event kind/outcome, actor, asset, IP address and count. Only authentication, process, network, file, alert and visibility kinds and their declared outcomes are accepted. Extra content, queries, commands, URLs, arbitrary event fields and free-text questions are denied. The builder does not guess event semantics from a console. An authorized adapter still has to perform that normalization correctly and prove its mapping against the original source.

A caller supplies a 32-byte private pseudonym key. HMAC domain separation includes version, organization, case and identity kind. Identity values are not lowercased or trimmed because that could merge different principals. Literal IP addresses are parsed and canonicalized; scoped addresses are rejected. Exact UTC times and counts remain. This is pseudonymization, not anonymity: time patterns and event relationships may still identify people or environments.

The local manifest holds original identities, source lineage, source/wire digests and a keyed integrity binding. It contains sensitive material and must never be included in provider requests, logs or public artifacts. Reference resolution verifies its keyed binding and caller-supplied organization/case. These checks do not replace current database access checks or encrypted persistence/key custody. The key has not yet been integrated with the deployment vault or case lifecycle; callers must not introduce ad hoc key files.

## Compaction and limits

Rows with identical projected typed facts share an event and retain every opaque observation alias. Counts are not added. Distinct times, outcomes, actors or counts remain distinct. Multiple references do not establish independent corroboration. Input order does not change the wire projection. Source order is still bound separately in the private manifest.

The default wire cap is 12,000 UTF-8 bytes. Over-limit input is refused, never silently cropped or partially returned. This cap is not a tokenizer certification or a guaranteed token saving: a small record may grow after pseudonymization. Before network dispatch a provider-specific token/cost check and durable reservation are still required. Compression quality and useful context retention are not established by software tests. Unstructured context is explicitly excluded rather than falsely described as safely redacted.

No model, network call, prompt authority, content decryption, source authenticity claim or action permission is supplied by this library. Its packet explicitly labels partial scope, unverified sources and missing context/visibility. The caller must recheck consent, tenant/case/evidence authority, retention and current provider policy immediately before any future dispatch.

## Provider checkpoint, 20 October 2026

The owner-authorized settings change saved and survived reload: the dedicated OpenRouter key has an $18 cap and monthly reset. In workflow 39458714816, live job 118765377853 passed key preflight and attempted one request, then received HTTP 404 before a validated response. No automatic retry occurred. Its possible charge remains unresolved in probe accounting; no zero-cost claim is made.

The unauthenticated live model endpoint catalog for both `google/gemini-2.5-flash-lite` and `google/gemini-2.5-flash`, retrieved 20 October, listed only Google AI Studio variants. No Google Vertex route was listed. This is consistent with the failed Vertex-only request; an HTTP status alone does not prove every underlying cause. The repaired probe checks catalog model/provider/tag/status before paid requests and reports `approved_vertex_route_unavailable`. It keeps the existing ZDR/data-collection denial/price constraints; catalog presence alone would not attest privacy or account eligibility.

Reference endpoints: https://openrouter.ai/api/v1/models/google/gemini-2.5-flash-lite/endpoints and https://openrouter.ai/api/v1/models/google/gemini-2.5-flash/endpoints . Historical model pages are not evidence that a route is available now. Gemini remains a candidate, not qualified. Production routing still requires an available policy-compliant route, separately assessed alternatives/fallback, actual quality evaluation and operational acceptance. No further owner account change is inferred from this route failure.
