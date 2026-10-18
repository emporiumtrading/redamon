#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo 'BLOCKED: real PostgreSQL/image identity checks require Docker; no host pytest fallback.' >&2
    exit 2
fi
report_root="${1:-$(mktemp -d)}"
mkdir -p "$report_root"
report_root="$(cd "$report_root" && pwd)"
report_dir="$(mktemp -d "$report_root/run.XXXXXX")"
work_dir="$(mktemp -d)"
mkdir "$work_dir/checkpoint"
export GABRIEL_IDENTITY_SECRET_DIR="$work_dir/secrets"
python3 tooling/scripts/gabriel_identity_prepare.py "$GABRIEL_IDENTITY_SECRET_DIR"
project="gabriel-id-check-$$-${RANDOM}"
if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ]]; then
    echo 'BLOCKED: disposable project name already exists.' >&2
    exit 2
fi
compose=(docker compose --project-name "$project" --file compose.gabriel-identity.yml)
cleanup() {
    status=$?
    "${compose[@]}" --profile test --profile operator down --volumes --remove-orphans >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT
git rev-parse HEAD > "$report_dir/source-sha.txt"
"${compose[@]}" --profile test --profile operator config --format json > "$report_dir/identity-compose.json"
python3 - "$report_dir/identity-compose.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
assert all(not s.get('ports') for s in c['services'].values())
assert all(n['internal'] for n in c['networks'].values())
assert c['services']['identity']['read_only']
assert c['services']['identity']['user']=='10001:10001'
assert {s['source'] for s in c['services']['identity']['secrets']} == {'app_dsn'}
assert {s['source'] for s in c['services']['identity-admin']['secrets']} == {'owner_dsn'}
print('PASS: private identity network and separate runtime/migration secret mounts')
PY
"${compose[@]}" --profile test build identity identity-tests
docker image inspect gabriel-identity:dev --format '{{.Id}}' > "$report_dir/identity-image-id.txt"
"${compose[@]}" up -d --wait identity-db
"${compose[@]}" exec -T identity-db postgres --version > "$report_dir/postgres-version.txt"
"${compose[@]}" run --rm --no-deps -T identity-admin migrate
"${compose[@]}" run --rm --no-deps -T --user "$(id -u):$(id -g)" \
    -v "$report_dir:/evidence" identity-tests --report /evidence/identity-tests.json
for phase in before after; do
    if [[ "$phase" == after ]]; then
        "${compose[@]}" restart identity-db
        "${compose[@]}" up -d --wait identity-db
    fi
    "${compose[@]}" run --rm --no-deps -T --user "$(id -u):$(id -g)" \
        -v "$work_dir/checkpoint:/checkpoint" --entrypoint python identity-tests \
        testing/gabriel_identity/restart_probe.py "$phase"
done
printf '%s\n' 'PASS: identity integration and PostgreSQL restart checks complete; disposable database cleaned on exit.'
