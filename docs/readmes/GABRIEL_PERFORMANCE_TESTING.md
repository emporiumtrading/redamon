# Gabriel performance testing

The owner plans to provide TryHackMe SOC Simulator access after production readiness. That exercise evaluates Gabriel's performance; it is not model training or a source of learning memory. No TryHackMe access, active monitoring service or completed simulator result is established by this document.

Create a dedicated test organization and a new case with purpose **Performance test — learning disabled**. The CLI equivalent is `case_cli create --case-purpose performance_test` with the normal private identity and key configuration. Choose the purpose before acquiring test evidence. Purpose cannot be changed later. Existing investigation cases retain their normal reviewed-memory behavior after migration.

Performance cases preserve observations, encrypted evidence, investigation results, custody and audit history for evaluation. They cannot propose learning references or retrieve operational learning memory, including organization references. Automatic browser review records `performance_test_excluded` instead of a learning proposal. Database guards also reject inserting performance-case memory or changing the case purpose. This is application-level learning isolation; no fine-tuning or model weight update is performed. Provider handling still requires the separately admitted endpoint/privacy policy.

Case isolation cannot detect someone manually copying test text into a new operational case. Keep the test organization, operator exports, telemetry and source artifacts separate; do not manually promote simulator data or answer keys into operational memory, model prompts, retrieval collections, training datasets or public repositories. Apply the normal evidence retention and legal-hold controls to retained evaluation records.

## Before the first exercise

- Complete the production release gates separately. The simulator does not replace independent model qualification, native OS acceptance or security/operational review.
- Record the exact Gabriel source and image IDs, extension version, model/provider route and all configuration hashes, tool/skill versions, spending limits and memory-disabled case IDs. Freeze that baseline before revealing the test cases.
- Confirm the owner's authorized platform account, available scenarios, selected tabs/pages and permitted read/navigation actions after access is provided. Keep login, credentials, MFA and account changes human-controlled. Do not assume access, platform permissions or a working adapter.
- Keep scenario answer keys, grading panels, walkthroughs and analyst labels outside Gabriel's browser scope and inference context. An independent evaluator retains the scoring key.
- Establish an explicit scenario manifest with expected attack/benign/visibility cases, critical cases, observable opportunities, time limits and a fixed scoring rubric. An unobserved event is a visibility gap, not evidence of a successful detection.

## Observe and score

Retain the original evidence-linked output, references, disposition, abstention and gaps for each case. Record capture, alert and analyst-review times; visible pages and failed navigation; specialist/tool execution; inference usage/cost; scope/Stop/revocation events; crashes, unresolved outcomes and analyst effort. Preserve platform outcomes as separately sourced evaluator evidence, not source truth supplied to Gabriel.

Publish counts and denominators for true/false positives, missed attacks and critical misses; precision, recall, benign false-escalation rate, abstention and visibility-gap reporting; detection latency and navigation/task completion; evidence support, scope violations, cost and analyst workload. Separate unavailable visibility, unsupported actions and incomplete runs from successful cases. Do not claim perfect confidence, production suitability or attack coverage from a small successful demonstration.

## Fix and repeat without changing the baseline

During an active scored round, freeze Gabriel's build, prompts, tools, model configuration and learning state. Record defects as they occur. Pause the exercise for a necessary fix, create a new versioned engineering change, run regression/security checks, and start a separately identified round. Retain the original failures and baseline scores; do not overwrite them with the retest.

Use synthetic engineering regressions for a discovered product defect without copying platform content or answers. Report a replay of a previously seen scenario as a regression retest. Use new, unseen evaluation scenarios for a fresh performance claim. Compare results per build and scenario set; do not mix versions into one headline score. These are software updates based on measured behavior, not AI training on TryHackMe.

Monitoring starts only after access, scope and the observation mechanism are available. Gabriel's scoped runtime collection and a separately configured outcome-review process must be demonstrated; a chat instruction or this plan does not start continuous observation. Any scheduled ChatGPT review is limited to its supported cadence and cannot substitute for real-time runtime telemetry.
