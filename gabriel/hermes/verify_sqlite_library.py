"""Prove the CLI-only SQLite advisory is inapplicable to the scanned image."""

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys


image_id, purl = sys.argv[1:]
if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
    raise SystemExit("An exact Docker image ID is required.")
if not re.fullmatch(r"pkg:apk/alpine/sqlite-libs@3\.54\.1-r0\?[^\s]+", purl):
    raise SystemExit("The SBOM does not identify the expected Alpine SQLite library.")
if sqlite3.sqlite_version != "3.54.1":
    raise SystemExit("The interpreter did not load SQLite 3.54.1.")
if subprocess.run(["apk", "info", "-e", "sqlite"], check=False).returncode != 1:
    raise SystemExit("Unable to establish that the SQLite CLI package is absent.")
if shutil.which("sqlite3") or any(
    candidate.is_file()
    for root in ("/usr", "/opt", "/bin", "/sbin")
    for candidate in Path(root).rglob("sqlite3")
):
    raise SystemExit("A SQLite shell is present in the candidate.")

print(json.dumps({
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": f"urn:gabriel:sqlite-library:{image_id}",
    "author": "Gabriel candidate verification",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "version": 1,
    "statements": [{
        "vulnerability": {"name": "CVE-2026-119586"},
        "products": [{"@id": purl}],
        "status": "not_affected",
        "justification": "vulnerable_code_not_present",
        "impact_statement": (
            f"The SQLite command-line shell and its .recover command are absent "
            f"from {image_id}. The interpreter links only the SQLite library."
        ),
    }],
}, indent=2))
