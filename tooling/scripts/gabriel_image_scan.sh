#!/usr/bin/env bash
set -euo pipefail
umask 077
image_id=${1:?Exact locally built image ID required}
[[ $image_id =~ ^sha256:[a-f0-9]{64}$ ]] || exit 2
report=${2:?New report directory required}
mkdir -m 700 "$report"
report=$(realpath "$report")
cache=$(mktemp -d)
trap 'rm -f "$report/core.tar"; rm -rf "$cache"' EXIT
git rev-parse HEAD > "$report/source-sha.txt"
docker image inspect "$image_id" --format '{{.Id}}' > "$report/image-id.txt"
docker save "$image_id" -o "$report/core.tar"
sha256sum "$report/core.tar" > "$report/image-archive.sha256"
for scanner in anchore/syft:v1.55.0 anchore/grype:v0.121.0 ghcr.io/gitleaks/gitleaks:v8.30.1; do
    docker pull "$scanner" >/dev/null
    docker image inspect "$scanner" --format '{{index .RepoDigests 0}}' >> "$report/scanners.txt"
done
scanner=$(sed -n '1p' "$report/scanners.txt")
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 128 --memory 2g --cpus 2 --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,nosuid,nodev,size=1g,mode=1777 -e XDG_CACHE_HOME=/tmp -e SYFT_CHECK_FOR_APP_UPDATE=false \
    -v "$report/core.tar:/image/core.tar:ro" \
    "$scanner" docker-archive:/image/core.tar -o syft-json > "$report/sbom.json"
scanner=$(sed -n '2p' "$report/scanners.txt")
vulnerabilities=0
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 128 --memory 2g --cpus 2 --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 -e XDG_CACHE_HOME=/cache -e GRYPE_CHECK_FOR_APP_UPDATE=false \
    -v "$cache:/cache" -v "$report/sbom.json:/image/sbom.json:ro" \
    "$scanner" sbom:/image/sbom.json -o json --fail-on high > "$report/vulnerabilities.json" || vulnerabilities=$?
scanner=$(sed -n '3p' "$report/scanners.txt")
secrets=0
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 128 --memory 512m --cpus 1 --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 -v "$PWD/gabriel:/source:ro" \
    -v "$report:/reports" "$scanner" dir /source --redact=100 \
    --report-format json --report-path /reports/secrets.json || secrets=$?
python3 - "$report" "$vulnerabilities" "$secrets" <<'PY'
from collections import Counter
from pathlib import Path
import json,sys
root=Path(sys.argv[1]);scan=json.loads((root/'vulnerabilities.json').read_text())
counts=dict(Counter(row['vulnerability']['severity'] for row in scan['matches']))
result=dict(scan_exit=int(sys.argv[2]),secret_exit=int(sys.argv[3]),severity_counts=counts,
    source_secret_matches=len(json.loads((root/'secrets.json').read_text())),
    production_admitted=False,independent_security_review='pending')
(root/'summary.json').write_text(json.dumps(result,sort_keys=True)+'\n')
print(json.dumps(result,sort_keys=True))
PY
[[ $vulnerabilities == 0 && $secrets == 0 ]]
