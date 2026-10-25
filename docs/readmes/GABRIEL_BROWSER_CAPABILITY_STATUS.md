# Browser investigation and learning status

This document separates implemented investigation features from production AI qualification. Screenshots are available in the [Gabriel gallery](../assets/gabriel/screenshots/README.md).

| Requested capability | Implemented behavior | Boundary |
| --- | --- | --- |
| Background investigation | Browser service-worker alarms revisit approved pages with the popup closed, discover visible same-origin read-only links, capture changed minimized text and create evidence-linked candidate reviews. | Browser must remain running. Approval lasts 60–3600 seconds, clipped to the original session/task. A scheduling gap over 45 seconds interrupts collection. Eight changed captures per page/tour approval or 32 in discovery mode. This does not establish uninterrupted monitoring. |
| Multiple selected tabs | Up to eight independently paired tabs; parallel alarm dispatch, separate tickets/credentials and per-tab Stop; global Pause/Stop. | Real simultaneous two-tab journeys are exercised in Chrome and Brave. Eight is the enforced limit, not a claim that eight-tab load acceptance has been completed. |
| Qualified live AI detection | Provider worker, input minimization, spending reservations and encrypted answer receipts exist. Local browser candidate rules and typed specialist reviews run without provider inference. | **Disabled and not connected to automatic provider dispatch.** The browser scheduler currently invokes local text/specialist reviews, not the provider model worker. The privacy-preserving typed-input/dispatch integration and exact-configuration end-to-end evaluation still need completion. The production model configuration allowlist is empty. Pending analyst adjudication and independent held-out qualification cannot be replaced by a configuration switch. No new paid call or raw browser-text export is introduced by the browser learning feature. |
| Reviewed continuous learning | Candidate-bearing captures create case-scoped proposals automatically. Explicit analyst approval admits references. Later browser reviews retrieve approved, content-verified references and attach up to eight as encrypted historical context. | No automatic approval, incident confirmation or model training. Rejected, expired, reset, forgotten and inaccessible references are excluded from new retrieval. Case references stay in their case; explicitly approved organization references may span cases in that organization. |

## Reviewed learning workflow

1. Pair an approved tab and start scheduled investigation with sharing consent.
2. Open the case's **Memory review** page. Candidate passages appear as proposals, with links to their source evidence.
3. Inspect the source, then explicitly approve or reject the proposal. Approval is reference review, not proof of source truth or a confirmed attack.
4. Later changed captures attach applicable approved references as separate **Browser reviewed reference context** evidence. The companion shows the proposal state and number of attached references.
5. Forget a reference to exclude it from later retrieval. Existing evidence and historical context remain subject to case retention and legal holds.

Proposals retain exact quotes and source hashes, are limited to 4096 UTF-8 bytes and expire after 24 hours. Up to four passages fit in a proposal; omissions are recorded. Existing memory limits (128 records per reset epoch and 4096 lifetime records per organization) remain. A full review queue is reported as `review_queue_full`; no automatic reset or approval occurs. Reference context discloses references omitted beyond the eight-reference bound. Existing source verification, authority checks and tenant boundaries remain enforced.

Reviewed references accompany the local candidate review for analyst use. They do not automatically suppress a finding, change its severity or turn a candidate into a qualified AI verdict. Page instructions never become executable authority.

## Qualification still required

The [model review queue](GABRIEL_MODEL_REVIEW_QUEUE.md) contains pending development adjudications. Completing those alone does not qualify the current production worker configuration: independent held-out selection/sealing, realistic multi-source/adversarial evaluation, repeatability and release acceptance remain necessary. Native Mac UAT, real-console coverage acceptance and independent operational/security review also remain open.

Source integration and exact test evidence are recorded in PR75 (browser monitoring) and PR78 (reviewed learning). Their current merge and validation status must be checked before treating a candidate build as the integrated source. These features do not constitute a production-admission attestation.
