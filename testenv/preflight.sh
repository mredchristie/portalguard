#!/bin/sh
#
# Everything the off-box hotspot can prove, back to back: the regression check
# before a field test. Unit tests first, then each hotspot run, then a verdict
# per suite. Cuts the network while the hotspot runs are going.
#
#   make preflight
#
# Needs the VPN disconnected, and mkcert -install done once (the known run
# checks real certificates).
set -u

cd "$(dirname "$0")/.."

SUMMARY=$(mktemp)
trap './testenv/hotspot.sh down >/dev/null 2>&1; rm -f "$SUMMARY" "${TRACE:-}"' EXIT
trap 'exit 130' INT TERM

suite() {
    name=$1
    shift
    printf '\n##### %s #####\n' "$name"
    if "$@"; then
        echo "pass  $name" >> "$SUMMARY"
    else
        echo "FAIL  $name" >> "$SUMMARY"
    fi
}

suite "unit tests" go test ./...
./testenv/hotspot.sh up || { echo "the hotspot did not come up"; exit 1; }
# One password prompt, up front, rather than one in the middle of a run.
sudo -v || exit 1
TRACE=$(mktemp -t portalguard-trace)
suite "auto-allow: page renders first time" sudo TRACE="$TRACE" ./testenv/hotspot-demo.sh auto
# The trace the field test will depend on: it has to hold the automatic
# opens as DNS verdicts, not just the printed lines.
suite "trace records the DNS verdicts" grep -q 'dns   auto .*cdn.guestwifi.test' "$TRACE"
suite "manual: blank page, allow, remember" sudo ./testenv/hotspot-demo.sh first
suite "known network: remembered hosts verified" sudo ./testenv/hotspot-demo.sh known

printf '\n##### preflight #####\n'
cat "$SUMMARY"
if grep -q '^FAIL' "$SUMMARY"; then
    echo "not ready for the field"
    exit 1
fi
echo "ready for the field"
