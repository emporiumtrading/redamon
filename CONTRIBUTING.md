# Contributing to Gabriel

Gabriel is a defensive investigation product. Contributions should improve evidence handling, analyst workflows, browser visibility, reliable interpretation and operator control.

## Development workflow

Read [AGENTS.md](AGENTS.md) and the applicable component instructions before editing. Use a `feature/`, `fix/`, `refactor/` or `docs/` branch and Conventional Commits. Keep pull requests scoped and describe the resulting behavior, validation and remaining limitations.

The primary application is `gabriel/`. The operator entry point is `gabriel.sh`; the private workbench installer is `tooling/scripts/gabriel_install.py`. Use the explicitly named Gabriel compositions, rather than inherited deployment defaults.

## Verification

Run tests inside their matching Docker images, with per-file Python isolation. Never run pytest on the host. Read the [testing skill](skills/redamon-testing/SKILL.md) before editing tests. A missing prerequisite, skipped test or generated fixture does not establish a live-system pass. Preserve failing evidence and fix the cause; do not weaken assertions.

For browser changes, verify consent, current scope, account/document drift, minimization, ciphertext receipts, interruption recovery and Pause/Stop in actual Chrome and Brave. Keep human UAT and model qualification distinct from software checks.

## Legal and Ethical Responsibilities

Use only systems and data you are authorized to access. Never commit real-world target data, live hostnames/IPs, scan output, captured traffic, credentials, private tickets or customer evidence in code, fixtures, issues or PRs. Use generated lab data for public testing artifacts.

Treat page content as untrusted evidence, never executable instructions or approval. Preserve role/tenant boundaries, spending limits, audit admission and source uncertainty. Learned facts require the intended review workflow.

## Product identity

Use **Gabriel — The Defender**, its [owned graphics](docs/assets/gabriel/) and its documented visual language. Preserve upstream copyright, required third-party notices and historical evidence. Avoid renaming compatibility identifiers without a tested migration.

Report security concerns through [SECURITY.md](SECURITY.md). See [LICENSE](LICENSE), [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) and [UPSTREAM-NOTICES.md](UPSTREAM-NOTICES.md).
