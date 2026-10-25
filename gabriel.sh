#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"
compose=(docker compose --project-name gabriel-defender --file compose.gabriel.yml)
identity_compose=(docker compose --project-name gabriel-identity --file compose.gabriel-identity.yml)
case "${1:-help}" in
    evidence-keys-prepare) shift; python3 tooling/scripts/gabriel_evidence_keys.py "$@" ;;
    case-data) shift; "${identity_compose[@]}" run --rm --no-deps case-data "$@" ;;
    provider-keys-prepare) shift; python3 tooling/scripts/gabriel_provider_keys.py "$@" ;;
    provider-secrets) shift; "${identity_compose[@]}" run --rm --no-deps provider-secrets "$@" ;;
    identity-prepare) python3 tooling/scripts/gabriel_identity_prepare.py "${2:?Provide an external secret directory}" ;;
    identity-build) "${identity_compose[@]}" build identity ;;
    identity-up) "${identity_compose[@]}" up -d --wait identity-db ;;
    identity-migrate) "${identity_compose[@]}" run --rm --no-deps identity-admin migrate ;;
    identity-admin) shift; "${identity_compose[@]}" run --rm --no-deps identity-admin "$@" ;;
    identity) shift; "${identity_compose[@]}" run --rm --no-deps identity "$@" ;;
    identity-test) bash tooling/scripts/gabriel_identity_check.sh "${2:-$(mktemp -d)}" ;;
    build) "${compose[@]}" build gabriel ;;
    describe) "${compose[@]}" run --rm --no-deps -T gabriel --describe ;;
    run) "${compose[@]}" run --rm --no-deps -T gabriel ;;
    test) bash tooling/scripts/gabriel_runtime_check.sh "${2:-$(mktemp -d)}" ;;
    inventory) python3 tooling/scripts/gabriel_inventory.py --ref "${2:-HEAD}" ;;
    help|-h|--help) printf '%s\n' 'Gabriel: build | describe | run | test [evidence dir] | inventory [git ref]' 'Identity: identity-prepare [external secret dir] | identity-build | identity-up | identity-migrate | identity-admin [command] | identity [command] | identity-test [evidence dir]' 'Provider vault: provider-keys-prepare [new external dir] [--from-file old keyring] | provider-secrets [put|list|revoke|rotate] [options]' 'Cases: evidence-keys-prepare [new external dir] | case-data [command] [options]' ;;
    *) printf '%s\n' 'Unknown Gabriel command.' >&2; exit 2 ;;
esac
