#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/redamon.sh"
export REDAMON_TEST_STRICT=1
export REDAMON_TEST_ALLOW_MISSING=all
checks=0

for tier in unit integration live all coverage; do
    if output="$(_test_missing_input fixture 'missing fixture image' 'build fixture' "$tier" 2>&1)"; then
        echo "FAIL: strict $tier admitted a missing prerequisite"
        exit 1
    fi
    [[ "$output" == *BLOCKED* ]] || exit 1
    checks=$((checks + 1))
done

# Exercise final reporting without a real runtime; these functions are test doubles.
_TEST_SECTIONS=()
_test_run_shell() { return 1; }
_test_run_webapp() { return 0; }
if output="$(cmd_test unit 2>&1)"; then
    echo 'FAIL: shell failure did not fail the overall command'
    exit 1
fi
[[ "$output" != *'ALL TEST SECTIONS GREEN'* ]] || exit 1
checks=$((checks + 1))

_test_run_shell() { return 0; }
_test_run_webapp() { return 1; }
if output="$(cmd_test unit 2>&1)"; then
    echo 'FAIL: webapp failure did not fail the overall command'
    exit 1
fi
[[ "$output" != *'ALL TEST SECTIONS GREEN'* ]] || exit 1
checks=$((checks + 1))

_test_run_webapp() { return 0; }
output="$(cmd_test unit 2>&1)"
[[ "$output" == *'ALL TEST SECTIONS GREEN'* ]] || exit 1
checks=$((checks + 1))
printf '%d shell contract scenarios passed; simulated dependencies, not product acceptance\n' "$checks"
