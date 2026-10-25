#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo 'BLOCKED: Gabriel runtime checks require Docker; no host pytest fallback.' >&2
    exit 2
fi
report_root="${1:-$(mktemp -d)}"
mkdir -p "$report_root"
report_root="$(cd "$report_root" && pwd)"
report_dir="$(mktemp -d "$report_root/run.XXXXXX")"
printf 'Evidence directory: %s\n' "$report_dir"
git rev-parse HEAD > "$report_dir/source-sha.txt"
python3 tooling/scripts/gabriel_inventory.py --ref HEAD > "$report_dir/inventory.json"
compose=(docker compose --project-name gabriel-runtime-check --file compose.gabriel.yml)
"${compose[@]}" config --format json > "$report_dir/compose.json"
python3 - "$report_dir/compose.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
assert set(config['services']) == {'gabriel'}
service = config['services']['gabriel']
assert service['build']['target'] == 'production'
assert service['network_mode'] == 'none' and service['read_only']
assert service['user'] == '10001:10001'
assert service['cap_drop'] == ['ALL']
assert 'no-new-privileges:true' in service['security_opt']
assert not service.get('volumes') and not service.get('ports')
print('PASS: rendered defensive deployment boundary')
PY
"${compose[@]}" build gabriel
docker image inspect gabriel-defender:dev --format '{{.Id}}' > "$report_dir/runtime-image-id.txt"
test_image="gabriel-runtime-tests:$(git rev-parse --short=12 HEAD)"
docker build --target test -f gabriel/Dockerfile -t "$test_image" .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --read-only --tmpfs /tmp:rw,nosuid,nodev,size=256m \
    --user "$(id -u):$(id -g)" -v "$report_dir:/evidence" \
    "$test_image" --report /evidence/runtime-tests.json
"${compose[@]}" run --rm --no-deps -T gabriel --describe > "$report_dir/runtime-description.json"
python3 - "$report_dir/inventory.json" "$report_dir/denial-input.jsonl" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
names = sorted({a['name'] for a in report['capability_anchors']
                if a['kind'] in {'registry_entry', 'decorated_tool', 'system_mcp_server'}})
assert names, 'No inherited names discovered; refusing an empty denial check'
with open(sys.argv[2], 'w') as stream:
    for name in names:
        stream.write(json.dumps({'schema_version': 1, 'operation': name, 'arguments': {}}) + '\n')
print(f'Checking {len(names)} discovered names against the production runtime')
PY
rc=0
"${compose[@]}" run --rm --no-deps -T gabriel < "$report_dir/denial-input.jsonl" \
    > "$report_dir/denial-results.jsonl" || rc=$?
[[ "$rc" -eq 1 ]] || { echo 'FAIL: inherited-name denial returned an unexpected exit'; exit 1; }
python3 - "$report_dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
description = json.loads((root / 'runtime-description.json').read_text())['result']
assert description['external_access'] is False
assert description['response_execution'] is False
assert {c['name'] for c in description['capabilities']} == {'capabilities.list', 'evidence.hash'}
inputs = (root / 'denial-input.jsonl').read_text().splitlines()
outputs = (root / 'denial-results.jsonl').read_text().splitlines()
assert len(inputs) == len(outputs) > 0
assert all(json.loads(line) == {'status': 'denied', 'code': 'operation_not_allowed'} for line in outputs)
print(f'PASS: {len(outputs)} discovered inherited names denied by the packaged production runtime')
PY
# Check the shipped image itself, not the larger test stage.
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --read-only --entrypoint python gabriel-defender:dev -c \
    'import importlib.util, pathlib, shutil; assert not any(pathlib.Path("/app", p).exists() for p in ("agentic", "mcp", "scanners", "recon")); assert importlib.util.find_spec("pytest") is None; assert all(shutil.which(p) is None for p in ("nmap", "hydra", "msfconsole", "git")); print("PASS: shipped image excludes inherited code, scanners and test dependencies")'
