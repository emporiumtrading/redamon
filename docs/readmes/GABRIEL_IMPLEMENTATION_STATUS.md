# Gabriel implementation ledger

## Foundation increment 1 — truthful test gates

Date: 18 October 2026 UTC. Source baseline: `017fe462bb2557e8cf7ffe9e6b238cb803e915ab`.
PRD links: GAB-040, T34, P-T05. Related evidence: T31/P-T06 final-result reporting.
Status: **Foundation test infrastructure verified in isolated CI; full-stack and product acceptance remain NOT_RUN.**

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

The first hosted push/PR jobs failed during checkout, before tests ran: the inherited `redamon.wiki` gitlink had no `.gitmodules` URL. The fix declares the upstream wiki URL already referenced by the repository documentation; CI still leaves submodule fetching disabled. A fresh evidence subdirectory per attempt also prevents an old result from being reused after a failed build. These failures remain failed runs, not test passes.

The repaired source commit `6e3b8737ea17fd8759dbe9dc7659f24f8f4b2422` passed both [push VM verification](https://github.com/emporiumtrading/redamon/actions/runs/39098433202) and [pull-request VM verification](https://github.com/emporiumtrading/redamon/actions/runs/39098437130). The PR job ran on Ubuntu 24.04, built the dedicated foundation image and ran it with no network, a read-only root, dropped capabilities and no new privileges. Its result was **21 cases collected, 21 passed, zero failures/errors/skips**, across the new regression module and the existing tier-selection module. The VM also passed eight new shell scenarios and the existing missing-input suite (26 reported assertions with Docker available).

The PR job's built image ID was `sha256:c4c856d53a8f12381194271d319215d157169cccddb03ffabb6715148435c853`. Its [retained evidence artifact](https://github.com/emporiumtrading/redamon/actions/runs/39098437130/artifacts/12126055200) includes JSON counts, checkout source SHA and image ID. The foundation tests use clearly labeled disposable test projects; they do not simulate a functioning Gabriel service or attack detection.

Next complete C00's inherited-capability disposition inventory and real full-stack test baseline, close C01's pilot/browser decisions, and implement C02's separate defensive runtime. C03/C04 and the browser product are not implemented by this increment. No staging UAT, production shipment or post-shipment UAT/regression is claimed.

Release readiness remains **BLOCKED**. This engineering increment must not be described as a usable or deployed Gabriel defender.

## Runtime increment 2 — local defensive boundary and conversion inventory

Source baseline: `0dc15e313a3b765f826356150661d92dc8f2afb9`. PRD links: GAB-001, GAB-002, T01/T02 and D-T01. Status: **IMPLEMENTED_UNVERIFIED pending matching-image VM checks**.

The new `gabriel/` package and `compose.gabriel.yml` provide a separate local inspection runtime with two real operations: capability inspection and hashing supplied evidence text. The image excludes the inherited agent/MCP/scanner trees. A fixed dispatcher rejects all unadmitted names and arguments; malformed/oversized input has bounded handling. The runtime profile has no network, host mounts, published ports or response authority.

The inventory utility enumerates every tracked entry at an explicit Git commit and discovers static tool/registry/route/deployment anchors without importing source or reading dirty/untracked content. All proposed dispositions require review. Dynamic registration, parse failures, symlinks/gitlinks and lexical deployment discovery remain explicit gaps; this is not acceptance of the complete conversion register.

The new VM workflow renders the separate Compose configuration, builds production/test targets, runs the strict runtime/inventory tests, checks discovered legacy names against the actual production dispatcher, checks excluded image contents and runs the prior foundation regression. Full inherited-stack tests and C01 pilot decisions remain outstanding. The local runtime profile is intentionally limited while C03 identity and C04 durable state are absent. See [runtime instructions and boundaries](README.GABRIEL_RUNTIME.md).
