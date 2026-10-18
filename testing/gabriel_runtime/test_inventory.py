"""Inventory uses committed Git objects and never imports discovered source."""
import importlib.util
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "tooling/scripts/gabriel_inventory.py"
spec = importlib.util.spec_from_file_location("gabriel_inventory", SCRIPT)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def test_static_registry_routes_and_dynamic_gaps():
    source = '''
TOOL_REGISTRY = {"read": {}, "shell": {}}
TOOL_REGISTRY[external_name] = value
@mcp.tool()
def execute_tool():
    raise RuntimeError("must never be imported")
server = MCPServer(id="test_server")
'''
    anchors, gaps = inventory.discover("agentic/tools.py", source)
    assert {item["name"] for item in anchors} == {"read", "shell", "execute_tool", "test_server"}
    assert any(gap["reason"] == "registry_mutation" for gap in gaps)
    assert all(item["review_status"] == "unreviewed" for item in anchors)


def test_compose_discovery_is_scoped_and_explicitly_qualified():
    anchors, gaps = inventory.discover("compose.test.yml", "services:\n  agent:\n    image: example\nvolumes:\n  data:\n")
    assert [anchor["name"] for anchor in anchors] == ["agent"]
    assert gaps[0]["reason"] == "compose_anchors_require_rendered_config_review"


def test_parse_failure_is_a_visible_gap():
    anchors, gaps = inventory.discover("broken.py", "def missing(")
    assert not anchors
    assert gaps[0]["reason"] == "python_parse_failed"


def test_explicit_tool_aliases_and_dynamic_names_are_not_hidden():
    source = '@tool("external_alias")\ndef internal():\n    pass\n@mcp.tool(name=compute_name())\ndef dynamic():\n    pass\n'
    anchors, gaps = inventory.discover("tools.py", source)
    assert "external_alias" in {a["name"] for a in anchors}
    assert any(g["reason"] == "dynamic_tool_name" for g in gaps)


def test_git_inventory_ignores_untracked_and_dirty_content(tmp_path):
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True,
                              capture_output=True).stdout
    git("init")
    git("config", "user.name", "Gabriel fixture")
    git("config", "user.email", "fixture@example.invalid")
    tracked = tmp_path / "tool.py"
    tracked.write_text('@tool\ndef committed_tool():\n    pass\n')
    git("add", "tool.py")
    git("commit", "-m", "fixture")
    tracked.write_text('@tool\ndef dirty_tool():\n    pass\n')
    (tmp_path / "secret.txt").write_text("fixture private content")
    report = inventory.build_inventory(tmp_path, "HEAD")
    assert report["tracked_file_count"] == 1
    assert report["files"][0]["path"] == "tool.py"
    assert [a["name"] for a in report["capability_anchors"]] == ["committed_tool"]
    assert report["status"] == "REVIEW_REQUIRED"
    assert report["files"][0]["proposed_disposition"] == "isolate"
