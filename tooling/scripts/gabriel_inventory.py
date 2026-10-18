#!/usr/bin/env python3
"""Index tracked source and discover static capability anchors without importing it."""
import argparse
import ast
import json
import re
import subprocess
from pathlib import Path

REGISTRIES = {"TOOL_REGISTRY", "TOOL_PHASE_MAP", "SYSTEM_MCP_SERVERS"}


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True)
    return result.stdout


def category(path):
    if path.startswith("gabriel/") or path in {"gabriel.sh", "compose.gabriel.yml"}:
        return "gabriel_runtime"
    if "/api/" in path and path.endswith("/route.ts"):
        return "api_route"
    if "Dockerfile" in Path(path).name or "compose" in Path(path).name:
        return "deployment"
    if path.startswith(("agentic/prompts/", "skills/")):
        return "prompt_or_skill"
    if path.startswith(("mcp/", "agentic/", "recon/", "recon_orchestrator/", "scanners/")):
        return "execution_or_security_component"
    if any(word in path.lower() for word in ("secret", "credential", "auth", "setting")):
        return "authority_or_configuration"
    return "supporting_source"


def discover(path, source):
    anchors = []
    gaps = []

    def add(kind, name, line):
        anchors.append({"path": path, "kind": kind, "name": name, "line": line,
                        "review_status": "unreviewed"})

    if path.endswith(".py"):
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return [], [{"path": path, "reason": "python_parse_failed"}]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    target = decorator.func if isinstance(decorator, ast.Call) else decorator
                    label = ast.unparse(target)
                    if label == "tool" or label.endswith(".tool"):
                        tool_name = node.name
                        if isinstance(decorator, ast.Call):
                            explicit = next((kw.value for kw in decorator.keywords if kw.arg == "name"), None)
                            if explicit is None and decorator.args:
                                explicit = decorator.args[0]
                            if isinstance(explicit, ast.Constant) and isinstance(explicit.value, str):
                                tool_name = explicit.value
                            elif explicit is not None:
                                gaps.append({"path": path, "line": node.lineno,
                                             "reason": "dynamic_tool_name"})
                        add("decorated_tool", tool_name, node.lineno)
                    if re.search(r"\.(get|post|put|patch|delete|websocket)$", label):
                        add("python_route", node.name, node.lineno)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in REGISTRIES:
                        if isinstance(node.value, ast.Dict):
                            for key in node.value.keys:
                                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                                    add("registry_entry", key.value, node.lineno)
                                else:
                                    gaps.append({"path": path, "line": node.lineno,
                                                 "reason": "dynamic_registry_key"})
                        else:
                            gaps.append({"path": path, "line": node.lineno,
                                         "reason": "dynamic_registry_value"})
                    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        if target.value.id in REGISTRIES:
                            gaps.append({"path": path, "line": node.lineno,
                                         "reason": "registry_mutation"})
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "MCPServer":
                for kw in node.keywords:
                    if kw.arg == "id" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        add("system_mcp_server", kw.value.value, node.lineno)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id in REGISTRIES:
                    gaps.append({"path": path, "line": node.lineno,
                                 "reason": "registry_method_requires_review"})
    if path.endswith("/route.ts"):
        add("webapp_api_route", path, 1)
    if Path(path).name.endswith((".yml", ".yaml")) and "compose" in Path(path).name:
        in_services = False
        for number, line in enumerate(source.splitlines(), 1):
            if line == "services:":
                in_services = True
            elif line and not line.startswith((" ", "#")):
                in_services = False
            match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*(?:#.*)?", line)
            if in_services and match:
                add("compose_service_anchor", match.group(1), number)
        gaps.append({"path": path, "reason": "compose_anchors_require_rendered_config_review"})
    return anchors, gaps


def build_inventory(root, ref):
    commit = git(root, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip()
    entries = git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
    files, candidates, anchors, gaps = [], [], [], []
    for entry in entries:
        if not entry:
            continue
        meta, name = entry.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        path = name.decode("utf-8", errors="surrogateescape")
        file_category = category(path)
        files.append({"path": path, "object_id": oid, "mode": mode,
                      "category": file_category,
                      "proposed_disposition": "retain" if file_category == "gabriel_runtime" else "isolate",
                      "review_status": "unreviewed"})
        if kind != "blob" or mode == "120000":
            gaps.append({"path": path, "reason": "gitlink_or_symlink_requires_review"})
        elif path.endswith((".py", "/route.ts")) or "compose" in Path(path).name:
            candidates.append((path, oid))

    # Object IDs bind discovery to the selected commit, never to a dirty worktree.
    batch = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"],
                           input="".join(oid + "\n" for _, oid in candidates).encode(),
                           capture_output=True, check=True).stdout
    offset = 0
    for path, oid in candidates:
        end = batch.index(b"\n", offset)
        header = batch[offset:end].decode().split()
        if header[0] != oid or header[1] != "blob":
            raise ValueError("unexpected git object response")
        size = int(header[2])
        content = batch[end + 1:end + 1 + size]
        offset = end + size + 2
        try:
            source = content.decode("utf-8")
        except UnicodeError:
            gaps.append({"path": path, "reason": "non_utf8_source_requires_review"})
            continue
        discovered, unresolved = discover(path, source)
        anchors.extend(discovered)
        gaps.extend(unresolved)
    return {"schema_version": 1, "source_commit": commit,
            "status": "REVIEW_REQUIRED", "tracked_file_count": len(files),
            "capability_anchor_count": len(anchors), "files": files,
            "capability_anchors": anchors, "unresolved": gaps,
            "limitations": [
                "Every disposition is a proposal; no inherited capability is accepted for Gabriel.",
                "Static anchors do not enumerate runtime plugins, data-derived dispatch or all listeners/jobs/secrets.",
                "File, capability, rendered deployment and execution-path reviews remain mandatory.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--ref", default="HEAD")
    args = parser.parse_args()
    try:
        report = build_inventory(args.repo, args.ref)
    except (subprocess.CalledProcessError, ValueError):
        parser.exit(2, "Inventory failed: a readable committed source reference is required.\n")
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
