#!/bin/bash
set -eu
cd -- "$(dirname -- "$0")"
exec python3 tooling/scripts/gabriel_install.py setup "$HOME/gabriel-private-test"
