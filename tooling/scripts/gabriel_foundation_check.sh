#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo 'BLOCKED: foundation Python tests require Docker; no host pytest fallback.' >&2
    exit 2
fi

report_dir="${1:-$(mktemp -d)}"
mkdir -p "$report_dir"
report_dir="$(cd "$report_dir" && pwd)"
image="gabriel-foundation-tests:$(git rev-parse --short=12 HEAD)"
git rev-parse HEAD > "$report_dir/source-sha.txt"
docker build -f testing/gabriel_foundation/Dockerfile -t "$image" .
docker image inspect "$image" --format '{{.Id}}' > "$report_dir/image-id.txt"
# Match the caller for writable evidence without granting elevated container capabilities.
docker run --rm --network none --cap-drop ALL \
    --security-opt no-new-privileges --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m \
    --user "$(id -u):$(id -g)" \
    -v "$report_dir:/evidence" "$image" --report /evidence/foundation.json
