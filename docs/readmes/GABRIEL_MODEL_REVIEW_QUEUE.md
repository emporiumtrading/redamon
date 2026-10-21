# Model development review queue

The attached repository packet contains 24 actual generated provider answers: eight distinct development inputs for each of the three leading v2 configurations. It binds exact input/configuration/run hashes and both source journals, and includes the supplied observations plus complete model claims, references, alternatives, contradictions and uncertainty. Labels are provisional and visible for development review. No reviewer identity, verdict or attestation has been fabricated. Every adjudication field is null and every review status is pending.

Packet: `testing/gabriel_model_lab/review_packets/protocol-v2-development-pending.json`.
Packet SHA256: `fcf6ae7a8fd725ef4943b56371874d9ad7971c807e9c359c98b0d76b5d0e0d05`.

| Development case | Provisional expected decision | GPT-OSS / Cerebras | Nemotron / Crusoe | Llama / Cloudflare | Human adjudication |
| --- | --- | --- | --- | --- | --- |
| dev-auth-attack | escalate, urgent_inconclusive | escalate | escalate | escalate | Pending |
| dev-backup | benign | benign | benign | benign | Pending |
| dev-logout | abstain | abstain | abstain | abstain | Pending |
| dev-persistence | escalate, urgent_inconclusive | escalate | escalate | escalate | Pending |
| dev-egress | escalate, urgent_inconclusive | escalate | escalate | escalate | Pending |
| dev-admin | benign | benign | benign | benign | Pending |
| dev-injection | abstain | abstain | abstain | abstain | Pending |
| dev-skew | abstain, urgent_inconclusive | abstain | abstain | abstain | Pending |

A qualified analyst must inspect each claim against its actual cited observation, assess whether alternative explanations, contradictions and uncertainty are substantive, and decide whether the bounded disposition is justified. Nonempty arrays and a matching expected label cannot establish those judgments. Record accountable reviewer identity, time, rationale and claim-level verdicts against the exact run digest. This pending packet is intentionally not an accepted model-evaluation review file and cannot grant qualification or deployment authority.

GPT-OSS-120B/Cerebras is the leading development candidate based on these observed responses, latency and reported cost; Nemotron and Llama remain comparison candidates. No model is production-admitted. Independent corpus review, independent held-out selection/sealing, realistic multi-source/adapter/adversarial workloads, repeatability and full evaluation remain open. Do not tune against held-out acceptance answers or replace a missing analyst attestation with an AI-generated one.


## Provisional AI screening notes

The packet flags seven specific answers for analyst attention without filling any human review field. GPT-OSS's backup answer uses "none" for uncertainty. GPT-OSS and Llama's exfiltration claims may overstate the association between an archiving process, the host upload and actual content; similar byte volume alone does not prove identity. Nemotron's backup alternatives array says an alternative is unnecessary. These are AI screening observations tied to the exact run digests, not adjudicated failure rates or a substitute for independent review. A matching disposition remains distinct from supported claims and adequate uncertainty.

The live comparisons use authored development text rather than the production typed-input projection. Model-family results do not qualify that different worker/adapter configuration; semantic projection equivalence and actual end-to-end evaluation remain open.

Additional AI screening flags cover Llama treating missing visible events as contradictory incident evidence, Llama offering unauthorized testing as a benign alternative, and Nemotron dismissing alternatives in authorized administration. These remain questions for accountable analyst review, not human verdicts or adjusted outcome scores.
