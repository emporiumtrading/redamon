"""Contract and abuse tests for the real local runtime, in its matching image."""
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from gabriel.capabilities import CapabilityDenied, InvalidRequest, execute


def request(operation="capabilities.list", arguments=None):
    return {"schema_version": 1, "operation": operation, "arguments": arguments or {}}


def cli(raw, **env):
    return subprocess.run([sys.executable, "-m", "gabriel"], input=raw,
                          capture_output=True, env={**os.environ, **env}, timeout=10)


def test_describe_matches_real_catalog_and_limits():
    result = execute(request())
    assert {c["name"] for c in result["capabilities"]} == {"capabilities.list", "evidence.hash"}
    assert result["external_access"] is result["response_execution"] is False
    assert result["production_ready"] is False


@pytest.mark.parametrize("operation", [
    "kali_shell", "execute_nmap", "execute_nuclei", "metasploit", "execute_hydra",
    "proxy_brain", "python.exec", "shell", "stdio", "mcp.register", "browser.click",
    "response.isolate", "evidence.hash.__globals__", "EVIDENCE.HASH", " evidence.hash",
])
def test_unadmitted_operations_denied_at_broker_and_cli(operation):
    with pytest.raises(CapabilityDenied):
        execute(request(operation))
    proc = cli(json.dumps(request(operation)).encode() + b"\n")
    assert proc.returncode == 1
    assert json.loads(proc.stdout) == {"status": "denied", "code": "operation_not_allowed"}


@pytest.mark.parametrize("content", ["", "incident evidence", "é🚨", "x" * (128 * 1024)])
def test_hash_is_real_utf8_integrity_not_a_source_truth_claim(content):
    result = execute(request("evidence.hash", {"content": content}))
    assert result["digest"] == hashlib.sha256(content.encode()).hexdigest()
    assert result["byte_length"] == len(content.encode())
    assert result["source_verified"] is False
    assert "content" not in result


def test_content_is_never_executed(tmp_path):
    marker = tmp_path / "should-not-exist"
    content = f"__import__('pathlib').Path({str(marker)!r}).write_text('executed')"
    result = execute(request("evidence.hash", {"content": content}))
    assert result["digest"] == hashlib.sha256(content.encode()).hexdigest()
    assert not marker.exists()


@pytest.mark.parametrize("arguments", [
    {"path": "/etc/passwd"}, {"url": "http://127.0.0.1"}, {"content": "ok", "command": "id"},
    {"content": 123}, {"content": "é" * 65537}, {"content": "\ud800"},
])
def test_hash_does_not_admit_files_network_commands_or_invalid_content(arguments):
    with pytest.raises(InvalidRequest):
        execute(request("evidence.hash", arguments))


@pytest.mark.parametrize("payload", [
    [], None, {**request(), "tenant_id": "forged"}, {**request(), "approved": True},
    {**request(), "schema_version": True}, {**request(), "schema_version": 2},
    {**request(), "arguments": []}, {**request(), "operation": []},
])
def test_strict_request_schema(payload):
    with pytest.raises((InvalidRequest, CapabilityDenied)):
        execute(payload)


def test_parallel_callers_share_the_same_denial_boundary():
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(execute, request("shell")) for _ in range(8)]
        for future in futures:
            with pytest.raises(CapabilityDenied):
                future.result()


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"operation":"shell","operation":"capabilities.list","arguments":{}}\n',
    b'{"schema_version":NaN,"operation":"capabilities.list","arguments":{}}\n',
    b'\xff\n', b'not json\n', b'[' * 2000 + b']' * 2000 + b'\n',
])
def test_malformed_or_ambiguous_json_rejected_without_echo(raw):
    proc = cli(raw)
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["status"] == "invalid"
    assert not proc.stderr


def test_oversized_line_drains_then_processes_next_request():
    proc = cli(b"x" * (300 * 1024) + b"\n" + json.dumps(request()).encode() + b"\n")
    results = [json.loads(line) for line in proc.stdout.splitlines()]
    assert proc.returncode == 1
    assert len(results) == 2
    assert results[0]["code"] == "request_limit_exceeded"
    assert results[1]["status"] == "ok"


def test_unknown_profile_fails_without_legacy_fallback():
    proc = cli(b"", GABRIEL_PROFILE="autonomous-production")
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["code"] == "unsupported_runtime_profile"


def test_metadata_result_cannot_mutate_the_catalog():
    result = execute(request())
    result["capabilities"][0]["name"] = "shell"
    assert "shell" not in {entry["name"] for entry in execute(request())["capabilities"]}
