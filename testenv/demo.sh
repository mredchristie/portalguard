#!/bin/sh
#
# A clean, one-command demo of the actual product flow, for recording -
# no test harness, no assertions, and nothing to type while it runs.
#
#   make testenv-up
#   sudo ./testenv/demo.sh
#
# Everything after that one command is automatic: the fixture resets to
# "intercepting", the login-page accept is simulated a few seconds after
# the gap opens (in the background, no output, so it never interrupts what
# the recording is showing), and the real run happens in the foreground
# exactly as a person watching would type it themselves - detect, lock
# down, gap open, wait, seal, report.
set -eu

BIN=${BIN:-./bin/portalguard}
PORTAL=${PORTAL:-http://127.0.0.1:8080}
PROBES=${PROBES:-testenv/probes.json}

[ -x "$BIN" ] || { echo "$BIN not built. run: make build"; exit 64; }

curl -s -o /dev/null -m 5 "$PORTAL/status" \
    || { echo "fake portal not answering at $PORTAL. run: make testenv-up"; exit 64; }

curl -s -o /dev/null "$PORTAL/reset"

# Simulates the human clicking Accept on the portal's login page. 8s is a
# generous guess at how long detection, lockdown and gap-open take before
# the "waiting for login" message appears - tune it if a recording ever
# shows the accept landing before that message does.
( sleep 8; curl -s -o /dev/null -X POST "$PORTAL/accept" ) &

exec "$BIN" run -probes-file "$PROBES" -wait 60s -poll 2s -redact
