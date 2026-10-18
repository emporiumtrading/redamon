# Gabriel implementation ledger

## Foundation increment 1 — truthful test gates

Date: 18 October 2026 UTC. Source baseline: `017fe462bb2557e8cf7ffe9e6b238cb803e915ab`.
PRD links: GAB-040, T34, P-T05. Related evidence: T31/P-T06 final-result reporting.
Status: **IMPLEMENTED_UNVERIFIED for Python runtime behavior; local shell contracts verified.**

### Delivered code

- The isolated pytest runner now preserves failed-test exit status in coverage mode, applies a per-file timeout in that mode, and rejects failed/missing coverage reports even when no floor was requested.
- Strict mode (`--strict` or `REDAMON_TEST_STRICT=1`) rejects empty selections, marker-filtered empty files, skips, expected failures, unexpected expected-failure passes and missing JUnit evidence. Legacy non-strict optional empty selections remain compatible.
- Case counts come from each subprocess's fresh JUnit report. An optional JSON report records file exit codes, case counts, evidence errors and aggregate status without copying test output into the report.
- Strict CLI prerequisites cannot be bypassed with `REDAMON_TEST_ALLOW_MISSING`, including integration/live tiers. Docker sections receive the strict setting.
- The overall green banner is emitted only after shell and webapp sections finish successfully.
- A dedicated foundation Docker image and least-privilege execution script run real disposable pytest-project regressions plus the existing tier-selection tests. No vendor/model credentials or external network are available during the test container run.
- A GitHub-hosted Ubuntu VM workflow builds/runs that image and retains JSON/source/image evidence. A workflow definition is not evidence that the job executed.

### Local verification

Shell syntax and `git diff --check` passed. The new shell contract suite passed eight scenarios, covering strict missing prerequisites across five tiers and final result reporting after shell/webapp failure/success. Its dependency doubles are explicitly simulated, not product integrations.

The existing missing-input suite reported 25 passing assertions; one reports an unexercised Docker-image check because Docker is absent. Do not interpret that report as a Docker test pass.

The real foundation runner exits 2 with **BLOCKED** when Docker is unavailable. No host pytest fallback was used. Local VM testing is unavailable: Docker/Podman/QEMU are absent, `/dev/kvm` and the Docker socket are unavailable, and package provisioning was denied by environment permissions. No attempt was made to weaken those restrictions.

### Commands

```bash
bash tests/gabriel_strict_gate_test.sh
bash tests/redamon_gate_unskippable_test.sh
bash tooling/scripts/gabriel_foundation_check.sh /absolute/path/to/evidence
# Full legacy stack gate after the matching images and services exist:
REDAMON_TEST_STRICT=1 ./redamon.sh test unit
```

The foundation image validates only test infrastructure. It is not a replacement for agent/recon/webapp images or the full stack gate. Legacy shell/webapp suites still need their own structured per-case skip/evidence enforcement; strict Python results and prerequisite checks alone do not complete T34 for every surface.

### Remaining dependencies

Record the hosted workflow outcome before accepting Python behavior. Then complete C00's inherited-capability disposition inventory and real full-stack test baseline, close C01's pilot/browser decisions, and implement C02's separate defensive runtime. C03/C04 and the browser product are not implemented by this increment. No staging UAT, production shipment or post-shipment UAT/regression is claimed.

Release readiness remains **BLOCKED**. This engineering increment must not be described as a usable or deployed Gabriel defender.
