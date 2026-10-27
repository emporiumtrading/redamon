# Gabriel specialist AI development evaluation — October 27, 2026

## Outcome

The approved batch completed all 24 authored synthetic scenarios across twelve designated specialist configurations. All 24 replies passed structural, reference, model/provider, token and per-call cost validation. This is transport/contract compatibility evidence. It is **not a pass for autonomous investigation or production detection quality**.

- Calls attempted/validated: **24 / 24**; two per role.
- Reported provider cost: **$0.01236255**, below the approved maximum reservation of $0.453888.
- Dispositions: **15 abstain, 5 benign, 4 escalate**.
- Requested local tools: **0**. Every scenario ended in the first round.
- Retries, unresolved outcomes, new unresolved reservations: **0**.
- Input/output tokens: **20,688 / 6,829**.
- Raw responses and model claim text exported: **none**.
- Production configurations admitted: **none**. Independent semantic review remains pending.

The cap authorized up to 72 conditional calls, not a requirement to send 72 calls. The batch is complete; the unused allowance is not permission to change bodies, rerun it or add scenarios.

## Material findings

1. **No live tool loop was exercised.** The model chose a final answer for every initial request. Offline tests prove exact follow-up-body selection, non-repeated tool handling, maximum rounds and dispatch bounds using test doubles; they cannot establish live tool use or end-to-end execution against the encrypted case store.
2. **Exposure prioritization requires review.** In exposure_vulnerability-1, the supplied facts were severity=critical, reachable=yes and mitigated=no. The returned disposition was benign. This creates an operational concern: a reachable critical unmitigated exposure still needs attention even when exploitation is not established. Because raw claim text was deliberately not exported, this report cannot adjudicate the model's full reasoning or whether the generic incident-disposition vocabulary contributed.
3. **Abstention is not proof of either safety or missed attacks.** These single-fact cases lack independently adjudicated labels and realistic corroboration. No attack recall, false-positive rate or production accuracy is claimed.
4. **Distinct role prompts work at the request/response boundary.** Two valid replies were received for each exact role configuration. This does not qualify coordinator delegation, personal-key isolation, real browser navigation or reviewed memory in live inference; those remain separate acceptance concerns.

## Per-role observations

The first/second authored case are not independent attack/benign ground-truth labels.

| Specialist | Case 1 | Case 2 |
| --- | --- | --- |
| telemetry_health | abstain | abstain |
| alert_triage | abstain | benign |
| incident_scoping | abstain | abstain |
| threat_intelligence | abstain | benign |
| threat_hunting | abstain | abstain |
| dfir_evidence | abstain | abstain |
| detection_engineering | escalate | benign |
| exposure_vulnerability | benign | benign |
| identity_access | escalate | abstain |
| cloud_supply_chain | escalate | abstain |
| response_remediation | escalate | abstain |
| recovery_learning | abstain | abstain |

## Evidence

- [PR89](https://github.com/emporiumtrading/redamon/pull/89)
- [Successful offline gate and single live batch](https://github.com/emporiumtrading/redamon/actions/runs/40524371259)
- [Sanitized summary artifact](https://github.com/emporiumtrading/redamon/actions/runs/40524371259/artifacts/12742518116)
- [Committed sanitized metrics](../../testing/gabriel_specialist_ai/results/20261027-summary.json)
- Eight credential-free Docker behavior tests passed before any inference.
- Allowed-body-set SHA256: `e8d67be2c3eac2d65638b10053daff1daba3d82fdbd1eefe2fc2816ee175253d`.
- Downloaded result ZIP SHA256: `d7757d69dd99eeb83f66189327362ec746531202ea091292301248733070ca7b`.
- The downloaded ZIP was independently checked: all 24 dispatched body hashes and role configuration digests match the approved packet; costs sum exactly; 24 reservations, 24 validated results and one final report are present.
- Built source merge SHA recorded in the artifact: `55668021d594a89dede54916ed0f995e4be6f117`; PR head `92387e391ae16d59180f6366300bf0d3ce118796`.

## Remaining production acceptance

Resolve the exposure finding through analyst review and role-appropriate output semantics; prepare independently labeled realistic multi-evidence cases; exercise actual local tools and coordinator/browser/key boundaries end to end; then perform the independent held-out evaluation and release review required by specialist_qualification.py. Do not force tool calls merely to count them or populate PRODUCTION_CONFIGURATIONS from this development smoke test.

Any revised prompts or scenarios create a new request set. A future paid batch needs its own exact packet and spending authorization. No additional paid calls are performed by recording or merging this evidence.
