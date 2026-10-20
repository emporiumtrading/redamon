# Model suitability evaluation

Gemini Flash and Flash Lite are candidates, not presumed qualified defenders. NVIDIA fallback must pass the same applicable gates. The evaluator at `gabriel/identity/model_evaluation.py` is a real offline artifact validator/scorer shipped in the identity runtime image. It makes no network requests, handles no provider credentials, and cannot enable a model or execute browser actions.

## Evidence and decision contract

Supply a versioned corpus, exact configuration, actual run artifacts and separately prepared analyst reviews. Corpus cases contain family/split/class/criticality, question, source-tagged observations, expected gap identifiers and adjudicated labels. `packets` exports only case ID, question, observations and an input hash; labels, class, split, criticality and expected gap answers are excluded. Gap identifiers use a prompt-defined vocabulary; the model must infer which gaps apply from observations. Do not send the entire corpus file to the provider.

Configuration binds provider/model, endpoint policy version, prompt SHA-256, adapter/redaction/compression versions and inference parameters. Run artifacts bind this configuration hash and packet hash, generation identifier, origin, actual token counts, latency, cost and structured decision. Any changed configuration needs new results and reviews. Redirects or fallback to a different endpoint/model are separate configurations; never mix their results to hide failures.

Decisions contain disposition (`escalate`, `urgent_inconclusive`, `benign`, `abstain`), source-linked claims, alternatives, contradiction assessment, uncertainty, reported gaps and requested external actions. Nonempty explanations are required, but their presence does not prove their quality. R1 evaluation fails requested external execution. Recommendations belong in Gabriel-local drafts rather than this execution field. A valid citation ID alone does not prove that its source entails a claim.

Analyst reviews bind the entire run hash, every claim's entailment verdict, alternative/contradiction/uncertainty adequacy and decision justification. Review metadata declares reviewer, role, time and rationale. These are operator-supplied offline attestations, not authenticated identity or proof of independence. The production review/admission integration must verify actual membership and reviewer authority. Provider generation IDs and hashes bind records, but cannot authenticate that a provider really generated the answer. Preserve original provider usage and run artifacts through the approved evidence process; independent provenance verification remains a human release gate.

## Commands

Use the built identity image with explicitly mounted operator artifacts and no network, for example:

```bash
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --mount type=bind,src=/absolute/operator-evaluation,dst=/evaluation,readonly \
  --entrypoint python gabriel-identity:dev -m gabriel.identity.model_evaluation \
  packets --corpus /evaluation/corpus.json --split held_out

docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --mount type=bind,src=/absolute/operator-evaluation,dst=/evaluation,readonly \
  --entrypoint python gabriel-identity:dev -m gabriel.identity.model_evaluation \
  report --corpus /evaluation/corpus.json --configuration /evaluation/configuration.json \
  --runs /evaluation/runs.json --reviews /evaluation/reviews.json
```

The report is JSON on stdout. Exit 0 means the automatic gate passed; exit 2 means failed or invalid/incomplete artifacts. Reports always retain `production_admission: false` and pending human release acceptance. No runtime allowlist consumes these reports yet. The CLI never sends an artifact to a provider, and error output excludes supplied content.

## Gate behavior

Require at least 60 distinct scenario families, 30 development cases, 10 validation cases and 20 held-out cases, with at least five held-out cases per class and critical attack coverage. Reject exact capture reuse and family overlap between splits; these checks do not detect all semantic near-duplicates or shared upstream lineage. The corpus curator must inspect those before locking the held-out set. Evaluate unseen console layouts and separate redacted/compressed versus full laboratory context to measure decision degradation.

Report escalation recall, false escalation, visibility-gap reporting, abstention, analyst-justified answers and supported claims with denominators and Wilson intervals. Missing attack results remain misses. Abstention is not successful attack detection; urgent inconclusive is counted as escalation, never a confirmed attack. Require 90% attack escalation recall, at most 10% benign false escalation, all critical scenarios escalated, all required gaps disclosed, every completed decision matching its scenario's acceptable decisions, all claims/reasoning accepted by the analyst and per-investigation cost at most $0.05. The per-case correctness requirement can be stricter than the aggregate rate targets. Report every failure. This scorer checks supplied cost; durable provider spend enforcement is a separate upcoming dependency.

`test_fixture` results can exercise software behavior but always fail model qualification. Even artifacts tagged `live_provider` remain operator-supplied provenance and cannot close human admission. No made-up responses substitute for actual Gemini/NVIDIA tests. Compare each exact configuration on the same locked cases; models failing the gate remain disabled until corrected and reevaluated. Fresh independent held-out scenarios are needed if tuning uses earlier failures.

## Initial corpus and current limits

`testing/gabriel_model_lab/development_corpus.json` contains twelve explicitly authored synthetic development families: four attack, four benign and four visibility/adversarial examples. They are narrative development inputs, not logs from an executed attack simulation, a held-out benchmark or the required 60-family acceptance corpus. They can be used to develop the prompt/runner only; do not promote them into a held-out claim after tuning. The software tests also generate sixty deliberately simple fixtures to exercise gate boundaries; those fixtures are not expert evaluation data.

Current delivery is the scorer, strict decision/review contracts, CLI, container packaging and initial development examples. Actual provider dispatch, automatic provenance capture, budget reservations, the remaining acceptance corpus, model-to-model comparison, human adjudication/UAT and authenticated production admission remain open. No Gemini suitability result is claimed. GAB-023/027/028/029/033/040/044/046 and PD-04/05/08 apply.
