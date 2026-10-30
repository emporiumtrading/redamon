#!/usr/bin/env bash
set -euo pipefail
umask 077
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
mkdir "$work_dir/checkpoint" "$work_dir/objects"
export GABRIEL_IDENTITY_SECRET_DIR="$work_dir/secrets"
python3 tooling/scripts/gabriel_identity_prepare.py "$GABRIEL_IDENTITY_SECRET_DIR"
export GABRIEL_PROVIDER_KEY_DIR="$work_dir/provider-keys"
python3 tooling/scripts/gabriel_provider_keys.py "$GABRIEL_PROVIDER_KEY_DIR"
export GABRIEL_EVIDENCE_KEY_DIR="$work_dir/evidence-keys"
python3 tooling/scripts/gabriel_evidence_keys.py "$GABRIEL_EVIDENCE_KEY_DIR"
project="gabriel-id-check-$$-${RANDOM}"
if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ]]; then
    echo 'BLOCKED: disposable project name already exists.' >&2
    exit 2
fi
compose=(docker compose --project-name "$project" --file compose.gabriel-identity.yml --file compose.gabriel-tool-tests.yml --file compose.gabriel-hermes-tests.yml)
cleanup() {
    status=$?
    "${compose[@]}" --profile test --profile operator down --volumes --remove-orphans >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT
git rev-parse HEAD > "$report_dir/source-sha.txt"
"${compose[@]}" --profile test --profile operator --profile vault --profile cases config --format json > "$report_dir/identity-compose.json"
python3 - "$report_dir/identity-compose.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
assert all(not s.get('ports') for s in c['services'].values())
assert all(n['internal'] for n in c['networks'].values())
assert c['services']['identity']['read_only']
assert c['services']['identity']['user']=='10001:10001'
assert {s['source'] for s in c['services']['identity']['secrets']} == {'app_dsn'}
assert {s['source'] for s in c['services']['identity-admin']['secrets']} == {'owner_dsn'}
assert {s['source'] for s in c['services']['provider-secrets']['secrets']} == {'app_dsn','provider_keyring'}
assert 'provider_keyring' not in {s['source'] for s in c['services']['identity-db']['secrets']}
assert {s['source'] for s in c['services']['case-data']['secrets']} == {'app_dsn','evidence_keyring'}
assert 'evidence_keyring' not in {s['source'] for s in c['services']['identity-db']['secrets']}
assert c['services']['case-data']['volumes'][0]['source']=='evidence_data'
print('PASS: private network; separate evidence/provider keys and encrypted evidence volume')
PY
"${compose[@]}" --profile test build identity identity-tests investigation-tools hermes
docker build --build-arg "IDENTITY_BASE=${GABRIEL_IDENTITY_BASE:-python@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211}" -f gabriel/identity/Dockerfile --target checkpoint-signer -t gabriel-checkpoint-signer:dev .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --entrypoint python gabriel-checkpoint-signer:dev -c \
    "import importlib.util; from gabriel.identity.checkpoints import new_keypair,seal,verify; assert importlib.util.find_spec('psycopg') is None; assert importlib.util.find_spec('gabriel.identity.service') is None; print('PASS: offline signer excludes database drivers and application services')"
docker image inspect gabriel-checkpoint-signer:dev --format '{{.Id}}' > "$report_dir/checkpoint-signer-image-id.txt"
docker image inspect gabriel-identity:dev --format '{{.Id}}' > "$report_dir/identity-image-id.txt"
"${compose[@]}" up -d --wait identity-db investigation-tools hermes
"${compose[@]}" exec -T identity-db postgres --version > "$report_dir/postgres-version.txt"
"${compose[@]}" run --rm --no-deps -T identity-admin migrate
"${compose[@]}" exec -T identity-db createdb -U postgres gabriel_checkpoint
for phase in before after; do
    if [[ "$phase" == after ]]; then
        "${compose[@]}" restart identity-db
        "${compose[@]}" up -d --wait identity-db
    fi
    "${compose[@]}" run --rm --no-deps -T --user "$(id -u):$(id -g)" \
        -v "$work_dir/checkpoint:/checkpoint" -v "$work_dir/objects:/objects" \
        -e GABRIEL_EVIDENCE_ROOT=/objects --entrypoint python identity-tests \
        testing/gabriel_identity/restart_probe.py "$phase"
    if [[ "$phase" == before ]]; then
        "${compose[@]}" exec -T identity-db pg_dump -U postgres -d gabriel_checkpoint --format=custom > "$work_dir/database-backup.dump"
        cp -a "$work_dir/objects" "$work_dir/object-backup"
    fi
done
"${compose[@]}" exec -T identity-db createdb -U postgres gabriel_vault_restore
"${compose[@]}" exec -T identity-db pg_restore -U postgres --dbname=gabriel_vault_restore \
    --exit-on-error --single-transaction < "$work_dir/database-backup.dump"
cp -a "$work_dir/object-backup" "$work_dir/restored-objects"
"${compose[@]}" run --rm --no-deps -T --user "$(id -u):$(id -g)" \
    -v "$work_dir/checkpoint:/checkpoint" -v "$work_dir/restored-objects:/objects" \
    -e GABRIEL_EVIDENCE_ROOT=/objects --entrypoint python identity-tests \
    testing/gabriel_identity/restart_probe.py restored
"${compose[@]}" run --rm --no-deps -T --user "$(id -u):$(id -g)" \
    -v "$report_dir:/evidence" --entrypoint python identity-tests \
    tooling/scripts/pytest_isolated.py all testing/gabriel_identity/test_specialist_agents_integration.py \
    testing/gabriel_identity/test_browser_ai_integration.py \
    testing/gabriel_identity/test_browser_monitoring_integration.py \
    testing/gabriel_identity/test_browser_navigation_integration.py \
    testing/gabriel_identity/test_attack_pattern_runs_integration.py \
    testing/gabriel_identity/test_browser_events_integration.py \
    testing/gabriel_identity/test_specialist_coordinator_integration.py \
    testing/gabriel_identity/test_browser_specialist_projection.py \
    testing/gabriel_identity/test_browser_specialists_integration.py \
    testing/gabriel_identity/test_environment_integration.py \
    --strict --parallel 1 --report /evidence/focused-identity-tests.json
"${compose[@]}" run --rm --no-deps -T --user "$(id -u):$(id -g)" \
    -v "$report_dir:/evidence" identity-tests --report /evidence/identity-tests.json
printf '%s\n' 'PASS: identity integration and PostgreSQL restart checks complete; disposable database cleaned on exit.'

