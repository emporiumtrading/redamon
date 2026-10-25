#!/usr/bin/env python3
"""Per-file-isolated pytest runner (the RedAmon test gate engine).

Runs each test FILE in its own pytest subprocess, in parallel, and aggregates
the results. This reproduces the isolation the legacy per-file
`python -m unittest tests.test_x` runner gave for free: a large body of these
tests stub langchain/langgraph into sys.modules at import time (and bake real
tool objects against a fake decorator during import), which is order-dependent
in a single shared pytest process. One process per file makes the gate
deterministic. See docs/readmes/README.TESTING.md.

Tiers are inferred from the filename (kept in sync with each conftest.py):
  live:        live_*, *_live*, *_smoke*, smoke_*
  integration: *_integration.py, *_skill.py, *_e2e*
  unit:        everything else

The tier is ALSO passed to pytest as `-m`, so an explicit
``@pytest.mark.{unit,integration,live}`` on a single test inside an otherwise
unit-tier file is honoured. Filename selection alone cannot see inside a file,
which is how a wall-clock test that had opted out of the unit tier still ran in
it - and failed whenever the parallel gate loaded the host.

Usage:
  python tooling/scripts/pytest_isolated.py <tier> <testdir> [<testdir> ...]
        [--parallel N] [--cov PKG --cov-floor N]
  tier ∈ {unit, integration, live, all}   (all = unit+integration, skips live)

Exit code: non-zero on test/coverage failure. --strict additionally rejects
empty selection, missing evidence, skipped tests and expected failures.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

_INT = ("_integration.py", "_skill.py", "_e2e")
_LIVE = ("live_", "_live", "_smoke", "smoke_")


def tier_of(basename: str) -> str:
    n = basename.lower()
    if any(f in n for f in _LIVE):
        return "live"
    if any(f in n for f in _INT):
        return "integration"
    return "unit"


def wanted(t: str, want: str) -> bool:
    if want == "all":
        return t in ("unit", "integration")
    return t == want


_SUMMARY_RE = re.compile(r"\b(\d+) (?:passed|failed|error|errors|xpassed|xfailed)\b")


def tests_executed(output: str) -> int:
    """
    How many test CASES a pytest run reported, from its summary line.

    File counts hide an empty gate: twenty files that each collect one trivial
    test look identical to twenty real suites. The case count is what a reader
    can sanity-check against what the suite is supposed to contain.
    """
    total = 0
    for line in reversed(output.splitlines()):
        if "passed" in line or "failed" in line or "error" in line:
            found = _SUMMARY_RE.findall(line)
            if found:
                return sum(int(n) for n in found)
    return total


def collect_files(testpaths, want, exclude=()):
    """Collect test files from the given paths. Each path may be a directory
    (walked for test_*.py) or an explicit file. `exclude` is a set of basenames
    to skip (used to route certain files to a different section/image)."""
    exclude = set(exclude or ())
    files = []
    for p in testpaths:
        if os.path.isfile(p):
            base = os.path.basename(p)
            if base.startswith("test_") and base.endswith(".py") and base not in exclude:
                if wanted(tier_of(base), want):
                    files.append(p)
            continue
        if not os.path.isdir(p):
            continue
        for root, _dirs, names in os.walk(p):
            if "__pycache__" in root or "/node_modules/" in root:
                continue
            for name in sorted(names):
                if not (name.startswith("test_") and name.endswith(".py")):
                    continue
                if name in exclude:
                    continue
                if wanted(tier_of(name), want):
                    files.append(os.path.join(root, name))
    return sorted(set(files))


_PER_FILE_TIMEOUT = int(os.environ.get("REDAMON_TEST_FILE_TIMEOUT", "600"))


# The pytest marker expression for a tier. Mirrors the conftest auto-marking, so
# a file whose name puts it in this tier still contributes every test that has no
# explicit marker of its own.
_MARKEXPR = {
    "unit": "unit",
    "integration": "integration",
    "live": "live",
    "all": "unit or integration",
}


def run_one(path, extra):
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
           "--no-header", *extra, path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=_PER_FILE_TIMEOUT)
    except subprocess.TimeoutExpired:
        # A hung file must not block the whole gate forever — treat it as a
        # failure so it is surfaced, not silently waited on.
        return path, 124, f"TIMEOUT after {_PER_FILE_TIMEOUT}s (per-file cap)"
    return path, proc.returncode, proc.stdout + proc.stderr


def run_verified(path, extra, report_dir, index):
    """Count test cases from fresh machine-readable evidence, not log text."""
    junit = Path(report_dir) / f"{index}.xml"
    path, code, output = run_one(path, [*extra, f"--junitxml={junit}"])
    counts = dict(collected=0, passed=0, failed=0, errors=0, skipped=0)
    evidence_error = None
    try:
        root = ET.parse(junit).getroot()
        if root.tag not in {"testsuites", "testsuite"}:
            raise ValueError("unexpected JUnit root")
        for case in root.iter("testcase"):
            counts["collected"] += 1
            if case.find("failure") is not None:
                counts["failed"] += 1
            elif case.find("error") is not None:
                counts["errors"] += 1
            elif case.find("skipped") is not None:
                counts["skipped"] += 1
            else:
                counts["passed"] += 1
    except (OSError, ET.ParseError, ValueError) as exc:
        evidence_error = str(exc)
    return {"path": path, "exit_code": code, "counts": counts,
            "evidence_error": evidence_error, "output": output}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tier", choices=["unit", "integration", "live", "all"])
    ap.add_argument("testdirs", nargs="+", help="directories and/or explicit test files")
    ap.add_argument("--parallel", type=int, default=int(os.environ.get("REDAMON_TEST_PARALLEL", "8")))
    ap.add_argument("--cov", default=None, help="package/path to measure coverage for")
    ap.add_argument("--cov-floor", type=float, default=None)
    ap.add_argument("--exclude", default="", help="comma-separated basenames to skip")
    ap.add_argument("--strict", action="store_true",
                    default=os.environ.get("REDAMON_TEST_STRICT") == "1")
    ap.add_argument("--report", type=Path, help="write this invocation's JSON evidence")
    args = ap.parse_args()

    def finish(status, results, reason=None, coverage=None):
        counts = {k: sum(r["counts"][k] for r in results)
                  for k in ("collected", "passed", "failed", "errors", "skipped")}
        report = {"schema_version": 1, "tier": args.tier, "strict": args.strict,
                  "status": status, "reason": reason, "counts": counts,
                  "coverage": coverage,
                  "files": [{k: v for k, v in r.items() if k != "output"}
                            for r in results]}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f">> gate status: {status}; counts: {counts}")
        return 0 if status == "PASS" else 1

    exclude = [x for x in (args.exclude or "").split(",") if x]
    files = collect_files(args.testdirs, args.tier, exclude=exclude)
    if not files:
        print(f">> {args.tier}: no test files found under {args.testdirs}")
        return finish("BLOCKED" if args.strict else "PASS", [], "no test files selected")

    # Coverage: run SERIALLY with --cov-append into one data file (parallel
    # appends can corrupt it), then report + enforce the floor.
    if args.cov:
        cov_file = os.environ.get("COVERAGE_FILE", "/tmp/redamon.coverage")
        for suffix in ("", *(f".{i}" for i in range(64))):
            try:
                os.remove(cov_file + suffix)
            except OSError:
                pass
        # All children and the report must use the same freshly erased file.
        os.environ["COVERAGE_FILE"] = cov_file

    parallel = 1 if args.cov else max(1, args.parallel)
    print(f">> {args.tier}: {len(files)} files (parallel={parallel}, per-file isolation)")
    failures = []
    empty_files = []
    passed = 0
    executed = 0
    with tempfile.TemporaryDirectory(prefix="redamon-test-evidence-") as evidence_dir:
        markexpr = ["-m", _MARKEXPR[args.tier]]
        if args.strict:
            markexpr.extend(["-o", "xfail_strict=true"])
        if args.cov:
            markexpr.extend([f"--cov={args.cov}", "--cov-append"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
            results = list(ex.map(
                lambda pair: run_verified(pair[1], markexpr, evidence_dir, pair[0]),
                enumerate(files)))
        for result in results:
            path, code, out = result["path"], result["exit_code"], result["output"]
            counts = result["counts"]
            if code == 5:            # no tests collected in this file
                empty_files.append(path)
            executed += counts["passed"] + counts["failed"] + counts["errors"]
            strict_failure = args.strict and (result["evidence_error"] or
                                              counts["collected"] == 0 or counts["skipped"])
            if code not in (0, 5) or counts["failed"] or counts["errors"] or strict_failure:
                failures.append((path, code, out))
            elif code == 0:
                passed += 1

    for path, code, out in failures:
        print(f"\n==== FAIL {path} (exit {code}) ====")
        lines = [ln for ln in out.splitlines() if ("FAILED" in ln or "ERROR" in ln)]
        print("\n".join(lines[-8:]) if lines else out.splitlines()[-8:])

    # A file that collects nothing reads as a pass. It is a signal, not a
    # result: a script-style test with no `def test_` exits 5 and the gate has
    # gone green having asserted nothing. Name them so the count is actionable.
    if empty_files:
        print(f"\n>> {args.tier}: {len(empty_files)} file(s) collected NO tests:")
        for path in empty_files:
            print(f"     {path}")

    print(f"\n>> {args.tier}: {passed} files passed, {len(failures)} failed, "
          f"{len(empty_files)} empty/skipped")
    print(f">> {args.tier}: TESTS EXECUTED: {executed}")
    coverage = None
    if args.cov:
        command = [sys.executable, "-m", "coverage", "report", "--skip-covered"]
        if args.cov_floor is not None:
            command.append(f"--fail-under={args.cov_floor:g}")
        try:
            rep = subprocess.run(command, capture_output=True, text=True,
                                 timeout=_PER_FILE_TIMEOUT)
            print(rep.stdout + rep.stderr)
            coverage = {"exit_code": rep.returncode, "floor": args.cov_floor}
        except subprocess.TimeoutExpired:
            coverage = {"exit_code": 124, "floor": args.cov_floor}
    failed = bool(failures) or bool(coverage and coverage["exit_code"] != 0)
    return finish("FAIL" if failed else "PASS", results, coverage=coverage)


if __name__ == "__main__":
    sys.exit(main())
