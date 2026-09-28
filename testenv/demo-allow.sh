#!/bin/sh
#
# The two-process demo: `run` waiting in one place while a second, separate
# invocation of `allow` widens the gap underneath it. That is the thing worth
# recording, because it is the thing that used to fail outright with
# "cannot apply EXTEND_GAP in state IDLE".
#
#   make testenv-up
#   sudo ./testenv/demo-allow.sh
#
# Nothing to type while it runs. `run` holds the foreground exactly as a
# person would type it; the widen, the status read and the login are driven
# from the background on a timer. The privileged commands are run by this
# script, which is already root, so nothing here backgrounds a `sudo` - that
# is what put a password prompt over live output in an earlier take.
#
# Everything the background half prints is fenced with a banner naming which
# process is talking, since a single pane cannot show you two terminals. To
# record it as two genuine panes instead, see testenv/README.md, "Recording
# the two-process demo".
set -eu

BIN=${BIN:-./bin/portalguard}
PORTAL=${PORTAL:-http://127.0.0.1:8080}
PROBES=${PROBES:-testenv/probes.json}

# The hosts the second process opens. Addresses rather than names on purpose:
# the fixture answers DNS on port 5354, which is not this machine's resolver,
# so a made-up hostname would fail to resolve and the demo would be about
# that instead. On a real portal these are the names in the blank page's
# <script> tags - at BT Wi-Fi, cdn.btwifi.com and reg.btwifi.com.
WIDEN=${WIDEN:-127.0.0.2 127.0.0.3:8443}

# Seconds from launch. GAP_AT wants to land after "waiting for the login"
# appears; LOGIN_AT after the widen has printed.
WIDEN_AT=${WIDEN_AT:-9}
LOGIN_AT=${LOGIN_AT:-18}

[ -x "$BIN" ] || { echo "$BIN not built. run: make build"; exit 64; }

curl -s -o /dev/null -m 5 "$PORTAL/status" \
    || { echo "fake portal not answering at $PORTAL. run: make testenv-up"; exit 64; }

curl -s -o /dev/null "$PORTAL/reset"

banner() { printf '\n=== %s ===\n' "$1"; }

(
    sleep "$WIDEN_AT"

    banner "second terminal: the login page is blank, so widen the gap"
    echo "\$ sudo portalguard allow $WIDEN"
    # Word splitting is what we want here: WIDEN is a list of arguments.
    # shellcheck disable=SC2086
    "$BIN" allow $WIDEN

    banner "second terminal: what the kernel says the gap is now"
    echo "\$ sudo portalguard status"
    "$BIN" status

    banner "back to the first terminal, still waiting where it was"

    sleep $((LOGIN_AT - WIDEN_AT))
    curl -s -o /dev/null -X POST "$PORTAL/accept"
) &

exec "$BIN" run -no-handoff -probes-file "$PROBES" -wait 90s -poll 2s -redact
