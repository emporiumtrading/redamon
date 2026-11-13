# Sealed fourteen-configuration qualification

The offline `gabriel.identity.release_qualification` command evaluates Hermes planning, Hermes reporting and all twelve specialists together. It makes no provider requests and never activates a production model. Run it inside the checked Gabriel container, not with host Python.

An independent evaluator prepares a private submissions JSON object with `supervisor` and `specialists` keys. The first has the existing `plan`/`report` submission objects; the second has all twelve existing role submission objects. Each uses the current runtime configuration digest, a family-disjoint corpus and the existing evaluator schema. Planning labels stay in the evaluator sidecar, never in a model request. Initially every `runs` and `reviews` list must be empty.

Before collecting model answers, create the seal:

```bash
python -m gabriel.identity.release_qualification \
  --submissions /private/qualification/inputs.json --seal-inputs \
  --curator-id CORPUS_CURATOR --operator-id MODEL_RUN_OPERATOR \
  --sealed-at ISO_8601_UTC_TIME > /private/qualification/seal.json
```

The seal binds fourteen exact runtime configuration digests, complete corpus hashes including withheld labels, and planning-label hashes. Independently retain and approve its canonical JSON SHA256, using `model_evaluation.digest`, before running the model. Hash the canonical object, not pretty-printed file bytes. Retain external evidence of seal time, artifact rights and the curator/operator identities. The software cannot prove when an operator actually created a file or whether a claimed identity or license is genuine.

After separately authorized exact-input live runs and independent analyst review, keep the corpus, configurations and labels unchanged and add original runs/reviews to a private submissions file:

```bash
python -m gabriel.identity.release_qualification \
  --submissions /private/qualification/completed.json \
  --seal /private/qualification/seal.json \
  --approved-seal-sha256 INDEPENDENTLY_RETAINED_CANONICAL_SEAL_SHA256
```

Changed inputs/configurations/labels, missing roles, generation IDs reused anywhere across the fourteen configurations, reviews predating the declared seal and declared curator/operator self-review are rejected. Original answers and human-review hashes are preserved. All existing corpus coverage, source binding, family/split separation, critical-case, recall, false-escalation, uncertainty, cost and planning-assignment gates remain mandatory. Fixture-origin answers still fail. Invalid artifacts produce a generic error without printing private contents; a failed gate returns exit code 2.

A pass remains `production_admission: false`. Actual independent review and licensed/source-authenticated artifacts, native Hermes request preparation, real specialist tool loops, selected-dashboard adapters and console semantics, native-device UAT, operational/security acceptance and owner promotion remain separate evidence. The browser AI adapter is a separate configuration; the fourteen-role report cannot qualify that adapter or arbitrary dashboards.

The 26-request compatibility packet is authored development data, has no dispatch approval and cannot substitute for this independent evaluation. Neither this command nor its Docker software tests perform paid inference, model training or TryHackMe testing. No independent completed evidence bundle is presently supplied by the repository.
