#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"
compose=(docker compose --project-name gabriel-defender --file compose.gabriel.yml)
case "${1:-help}" in
    build) "${compose[@]}" build gabriel ;;
    describe) "${compose[@]}" run --rm --no-deps -T gabriel --describe ;;
    run) "${compose[@]}" run --rm --no-deps -T gabriel ;;
    test) bash tooling/scripts/gabriel_runtime_check.sh "${2:-$(mktemp -d)}" ;;
    inventory) python3 tooling/scripts/gabriel_inventory.py --ref "${2:-HEAD}" ;;
    help|-h|--help) printf '%s\n' 'Gabriel: build | describe | run (JSON lines on stdin) | test [evidence dir] | inventory [git ref]' ;;
    *) printf '%s\n' 'Unknown Gabriel command.' >&2; exit 2 ;;
esac
