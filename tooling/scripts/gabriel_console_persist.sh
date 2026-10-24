#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ ${GITHUB_ACTIONS:-} == true ]] || { echo 'Dedicated CI runner required'; exit 2; }
output=$(realpath "$1")
work=$(mktemp -d "$RUNNER_TEMP/gabriel-persist.XXXXXX")
mkdir "$work/state" "$work/objects"
export GABRIEL_IDENTITY_SECRET_DIR="$work/secrets"
export GABRIEL_PROVIDER_KEY_DIR="$work/provider-keys"
export GABRIEL_EVIDENCE_KEY_DIR="$work/evidence-keys"
python3 tooling/scripts/gabriel_identity_prepare.py "$GABRIEL_IDENTITY_SECRET_DIR"
python3 tooling/scripts/gabriel_provider_keys.py "$GABRIEL_PROVIDER_KEY_DIR"
python3 tooling/scripts/gabriel_evidence_keys.py "$GABRIEL_EVIDENCE_KEY_DIR"
project="gabriel-persist-$$-$RANDOM"
[[ -z $(docker ps -aq --filter "label=com.docker.compose.project=$project") ]] || exit 2
compose=(docker compose --project-name "$project" --file compose.gabriel-identity.yml)
trap '"${compose[@]}" --profile operator down --volumes --remove-orphans >/dev/null 2>&1' EXIT
docker tag gabriel-specialist-demo gabriel-identity:dev
"${compose[@]}" up -d --wait identity-db
"${compose[@]}" run --rm --no-deps -T --user "$(id -u):$(id -g)" identity-admin migrate
for phase in before after; do
    if [[ $phase == after ]]; then
        "${compose[@]}" restart identity-db
        "${compose[@]}" up -d --wait identity-db
    fi
    "${compose[@]}" run --rm --no-deps -T --user "$(id -u):$(id -g)" --entrypoint python -e PYTHONPATH=/app \
        -v "$GITHUB_WORKSPACE/testing/gabriel_console/persist_demo.py:/persist.py:ro" \
        -v "$output:/output" -v "$work/state:/state" -v "$work/objects:/objects" \
        -v "$work/secrets/app_dsn:/run/demo/app_dsn:ro" \
        -v "$work/evidence-keys/keyring.json:/run/demo/evidence-keyring.json:ro" \
        identity-admin /persist.py "$phase"
done
