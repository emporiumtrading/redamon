#!/usr/bin/env bash
set -euo pipefail
umask 077
printf '%s\n' 'LAB: authenticated X server bootstrap'
lab_auth="$(mktemp /tmp/gabriel-xauth.XXXXXX)"
lab_cookie="$(openssl rand -hex 16)"
xauth -f "$lab_auth" add :99 . "$lab_cookie"
export DISPLAY=:99
export XAUTHORITY="$lab_auth"
Xvfb :99 -screen 0 1280x1024x24 -auth "$lab_auth" -nolisten tcp > /tmp/gabriel-xvfb.log 2>&1 &
lab_xvfb_pid=$!
cleanup() {
    kill "$lab_xvfb_pid" 2>/dev/null || true
    wait "$lab_xvfb_pid" 2>/dev/null || true
}
trap cleanup EXIT
lab_ready=false
for _ in {1..30}; do
    if xdotool getdisplaygeometry >/dev/null 2>&1; then lab_ready=true; break; fi
    if ! kill -0 "$lab_xvfb_pid" 2>/dev/null; then break; fi
    sleep 0.1
done
if [[ "$lab_ready" != true ]]; then
    printf '%s\n' 'FAIL: authenticated X display did not become ready'
    cat /tmp/gabriel-xvfb.log
    exit 1
fi
printf '%s\n' 'LAB: display ready; starting bounded browser test'
timeout --kill-after=10 360 python testing/gabriel_browser/lab.py "$@"
