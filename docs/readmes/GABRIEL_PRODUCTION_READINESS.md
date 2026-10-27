# Gabriel production release gates

Gabriel is not yet accepted for production. Software tests, generated-data screenshots and a funded key do not establish defensive decision quality or real-console compatibility. The owner-approved [pilot decisions](GABRIEL_PILOT_DECISIONS.md) remain the release scope; this checklist does not silently reduce it.

## Engineering evidence

PRs [90](https://github.com/emporiumtrading/redamon/pull/90) and [91](https://github.com/emporiumtrading/redamon/pull/91) merge role-bound open-source tools/skills and the actual UI/action gallery. Required Hermes supervision, shared budgets, preflight, durable child bindings and private Docker packaging are tracked in [92](https://github.com/emporiumtrading/redamon/pull/92). That integration must pass its native x86/ARM workflows, the full component suite, browser/console labs, actual HTTPS installation, upgrade and fresh-project recovery before merge.

The upstream all-purpose Hermes image failed the high-severity scan threshold. The minimal text-supervisor profile passed with zero high/critical findings; medium findings still require release review. Every release must retain the actual image ID, pinned bases/source, dependency lock, SBOM, vulnerability report and exact tested source. Scan the final deployed image with the existing high-severity threshold.

## Live AI qualification

There are fourteen exact candidate configurations: Hermes planning, Hermes reporting and twelve specialist roles. The CI artifact `gabriel-qualification-configurations-<runner>` records their current runtime hashes and the tested checkout. It contains no provider key, customer evidence or inference result. Run these entry points inside the checked Gabriel image/container, never on the host. Export the configuration identities without inference:

```bash
python -m gabriel.identity.hermes_qualification --configurations
```

For both supervisor stages, provide a submission object with `model`, `runtime_configuration_digest`, `corpus`, `runs`, `reviews` and `planning_labels`. Reporting uses `planning_labels: null`. Planning uses a local sidecar keyed by every held-out case ID; each entry contains `input_sha256`, `eligible_roles` and `expected_roles`. The expected list is unique, limited to four roles and a subset of the eligible catalog. Seal these labels before model execution and keep them out of model input packets. Retain their digest with the independent review record.

```bash
python -m gabriel.identity.hermes_qualification --submissions /private/qualification/supervisor.json
```

Planning requires an exact match to the independently adjudicated assignment set. Unknown, irrelevant, omitted or duplicate assignments fail. Reporting still prohibits requested actions. Original run and human-review hashes are preserved; no response is edited to remove requested roles or make it pass. Fixture-origin answers remain failures. All existing corpus coverage, family/split separation, claim/reasoning review, recall, false-escalation, critical-case, gap and cost gates remain in effect.

The specialist qualification entry point remains `specialist_qualification.evaluate_agents`; all twelve current configurations and separate real tool-loop/console evidence are required. A supervisor pass cannot qualify its children. The common evaluator requires at least sixty disjoint families, at least thirty development, ten validation and twenty held-out cases, including attack/benign/visibility coverage and critical attacks. Existing authored fixtures are not an independently sealed held-out set.

Concrete remaining evidence: authorized/licensed artifacts with verified hashes and rights; independently sealed labels; qualified analyst review of the actual original model answers and assignments; exact provider/route, privacy, cost and configuration provenance. A software evaluator cannot authenticate the reviewer or establish source truth. Both evaluation entry points return `production_admission: false`; reviewed release promotion is a separate step. Do not populate the production registry from fixtures or a connectivity test.

## Integrated deployment acceptance

Use the owner's Apple Silicon/Docker Desktop host with the checked images and separately retained keys. Record actual Mac certificate trust, extension pairing, selected-tab scope, visible capture/privacy, Stop/logout/revocation, source drift, spending exhaustion and restart behavior. Repeat the supported consumer-browser/OS and guest-VM matrix before advertising those combinations. Linux ARM CI does not substitute for Mac or Windows UAT.

Exercise Wazuh and DFIR-IRIS under authorized lab accounts, with human-only login. Record versioned read/navigation semantics, account/target binding, missing/partial/stale visibility and UI drift. The current Hermes case path requires typed facts bound to current captures; it does not establish autonomous understanding of arbitrary dashboards or indefinite unattended monitoring. Close that implementation/acceptance gap before promising the broader product requirement.

The release owner must record retention/hold/purge settings, protected key custody, trusted TLS, measured CPU/RAM/disk and workload/cost behavior, backup restoration, recovery objectives and a tested rollback procedure. Define the operator, analyst reviewer, UAT owner and escalation contact. The existing backed-up forward rebuild and same-source restore are useful evidence; they do not establish a signed release rollback or measured disaster recovery.

External containment/remediation stays disabled until each action has its own exact target/parameter authorization, verification and recovery acceptance. Local drafts and AI agreement do not authorize those effects.
