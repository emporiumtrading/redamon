"""Exercise the real isolated runner against disposable, labeled test projects."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

RUNNER = Path(__file__).resolve().parents[2] / "tooling/scripts/pytest_isolated.py"


def invoke(tmp_path, source=None, *, strict=True, extra=(), timeout=None):
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\nmarkers =\n unit: fixture unit tier\n integration: fixture integration tier\n"
    )
    (tmp_path / "conftest.py").write_text(
        "def pytest_collection_modifyitems(items):\n"
        "    for item in items:\n"
        "        if not any(item.iter_markers('integration')):\n"
        "            item.add_marker('unit')\n"
    )
    if source is not None:
        (tmp_path / "test_fixture.py").write_text(source)
    report = tmp_path / "evidence.json"
    env = os.environ.copy()
    env.pop("REDAMON_TEST_STRICT", None)
    env.pop("PYTEST_ADDOPTS", None)
    env["COVERAGE_FILE"] = str(tmp_path / ".coverage")
    if timeout is not None:
        env["REDAMON_TEST_FILE_TIMEOUT"] = str(timeout)
    proc = subprocess.run(
        [sys.executable, str(RUNNER), "unit", str(tmp_path),
         "--parallel", "1", "--report", str(report),
         *(["--strict"] if strict else []), *extra],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert report.is_file(), proc.stdout + proc.stderr
    return proc, json.loads(report.read_text())


def test_real_pass_has_case_evidence(tmp_path):
    proc, report = invoke(tmp_path, "def test_ok():\n    assert 2 + 2 == 4\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert report["status"] == "PASS"
    assert report["counts"] == dict(collected=1, passed=1, failed=0, errors=0, skipped=0)


@pytest.mark.parametrize("source", [None, "# Deliberately empty fixture.\n"])
def test_strict_empty_selection_cannot_pass(tmp_path, source):
    proc, report = invoke(tmp_path, source)
    assert proc.returncode != 0
    assert report["status"] in {"BLOCKED", "FAIL"}
    assert report["counts"]["passed"] == 0


@pytest.mark.parametrize("source", [
    "import pytest\ndef test_skip():\n    pytest.skip('fixture unavailable')\n",
    "import pytest\n@pytest.mark.xfail(reason='known fixture failure')\ndef test_xfail():\n    assert False\n",
    "import pytest\n@pytest.mark.xfail(reason='unexpected fixture pass')\ndef test_xpass():\n    assert True\n",
])
def test_strict_skip_xfail_and_xpass_block(tmp_path, source):
    proc, report = invoke(tmp_path, source)
    assert proc.returncode != 0
    assert report["status"] == "FAIL"


def test_partial_skip_is_not_hidden_by_a_pass(tmp_path):
    proc, report = invoke(tmp_path,
        "import pytest\ndef test_ok():\n    assert True\n"
        "def test_missing():\n    pytest.skip('fixture missing')\n")
    assert proc.returncode != 0
    assert report["counts"]["passed"] == report["counts"]["skipped"] == 1


def test_collection_error_cannot_pass(tmp_path):
    proc, report = invoke(tmp_path, "raise RuntimeError('collection fixture')\n")
    assert proc.returncode != 0
    assert report["counts"]["errors"] == 1


def test_timeout_cannot_reuse_old_success(tmp_path):
    (tmp_path / "evidence.json").write_text('{"status":"PASS"}')
    proc, report = invoke(tmp_path,
        "import time\ndef test_slow():\n    time.sleep(20)\n", timeout=1)
    assert proc.returncode != 0
    assert report["status"] == "FAIL"
    assert report["files"][0]["exit_code"] == 124
    assert report["files"][0]["evidence_error"]


def test_marker_filtered_file_is_empty_not_passed(tmp_path):
    proc, report = invoke(tmp_path,
        "import pytest\n@pytest.mark.integration\ndef test_other_tier():\n    assert True\n")
    assert proc.returncode != 0
    assert report["counts"]["collected"] == 0


def test_legacy_optional_empty_selection_retained(tmp_path):
    proc, report = invoke(tmp_path, strict=False)
    assert proc.returncode == 0
    assert report["reason"] == "no test files selected"


@pytest.mark.parametrize("strict", [False, True])
def test_failing_test_cannot_pass_coverage_even_at_zero_floor(tmp_path, strict):
    (tmp_path / "fixture_module.py").write_text("def value():\n    return 3\n")
    proc, report = invoke(tmp_path,
        "from fixture_module import value\ndef test_wrong():\n    assert value() == 4\n",
        strict=strict, extra=("--cov", "fixture_module", "--cov-floor", "0"))
    assert proc.returncode != 0
    assert report["status"] == "FAIL"
    assert report["counts"]["failed"] == 1
    assert report["coverage"]["exit_code"] == 0


def test_successful_coverage_meets_floor(tmp_path):
    (tmp_path / "fixture_module.py").write_text("def value():\n    return 3\n")
    proc, report = invoke(tmp_path,
        "from fixture_module import value\ndef test_ok():\n    assert value() == 3\n",
        extra=("--cov", "fixture_module", "--cov-floor", "100"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert report["counts"]["passed"] == 1
    assert report["coverage"]["exit_code"] == 0


def test_coverage_below_floor_fails(tmp_path):
    (tmp_path / "fixture_module.py").write_text(
        "def used():\n    return 3\ndef unused():\n    return 4\n")
    proc, report = invoke(tmp_path,
        "from fixture_module import used\ndef test_ok():\n    assert used() == 3\n",
        extra=("--cov", "fixture_module", "--cov-floor", "100"))
    assert proc.returncode != 0
    assert report["counts"]["passed"] == 1
    assert report["coverage"]["exit_code"] != 0


def test_missing_coverage_data_fails_without_floor(tmp_path):
    proc, report = invoke(tmp_path, "def test_ok():\n    assert True\n",
                          extra=("--cov", "nonexistent_fixture_module"))
    assert proc.returncode != 0
    assert report["coverage"]["exit_code"] != 0


def test_multiple_files_keep_per_file_process_isolation(tmp_path):
    (tmp_path / "test_first.py").write_text(
        "import builtins\ndef test_first():\n    builtins.gabriel_fixture = True\n")
    proc, report = invoke(tmp_path,
        "import builtins\ndef test_isolated():\n    assert not hasattr(builtins, 'gabriel_fixture')\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert report["counts"]["passed"] == 2
    assert len(report["files"]) == 2


def test_strict_environment_flag_is_honored(tmp_path, monkeypatch):
    sys.path.insert(0, str(RUNNER.parent))
    try:
        import pytest_isolated
    finally:
        sys.path.pop(0)
    monkeypatch.setenv("REDAMON_TEST_STRICT", "1")
    monkeypatch.setattr(sys, "argv", [str(RUNNER), "unit", str(tmp_path)])
    assert pytest_isolated.main() != 0
