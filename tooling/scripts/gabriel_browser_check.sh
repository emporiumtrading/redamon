#!/usr/bin/env bash
set -euo pipefail
umask 077
report_root="${1:?Provide an evidence directory}"
mkdir -p "$report_root"
report_root="$(cd "$report_root" && pwd)"
work_dir="$(mktemp -d)"
export GABRIEL_IDENTITY_SECRET_DIR="$work_dir/secrets"
export GABRIEL_BROWSER_LAB_UID="$(id -u)"
python3 tooling/scripts/gabriel_identity_prepare.py "$GABRIEL_IDENTITY_SECRET_DIR"
project="gabriel-browser-check-$$-${RANDOM}"
compose=(docker compose --project-name "$project" -f compose.gabriel-identity.yml -f compose.gabriel-browser-lab.yml)
cleanup() {
    status=$?
    "${compose[@]}" --profile browser-lab down --volumes --remove-orphans >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT
git rev-parse HEAD > "$report_root/source-sha.txt"
"${compose[@]}" --profile browser-lab config --format json > "$report_root/browser-compose.json"
"${compose[@]}" --profile browser-lab build browser-lab
docker image inspect gabriel-browser-lab:dev --format '{{.Id}}' > "$report_root/browser-image-id.txt"
"${compose[@]}" up -d --wait identity-db
"${compose[@]}" --profile browser-lab run --rm --no-deps -T -v "$report_root:/evidence" browser-lab /evidence
