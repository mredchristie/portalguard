#!/bin/sh
#
# Portalguard against the off-box hotspot, start to finish, with nothing to
# type while it runs. It is the recording and the test at once: every step
# the "browser" takes is also a check, and the run ends with a verdict.
#
#   ./testenv/hotspot.sh up
#   sudo ./testenv/hotspot-demo.sh          # first visit: blank page, allow, remember, login
#   sudo ./testenv/hotspot-demo.sh known    # next visit: remembered hosts open themselves
#
# Add "human" (first human, known human) to click Accept in the real browser
# yourself instead of having curl log in, with time to reload and click. That
# is the take to screen-record.
#
# Needs the VPN disconnected: `run` refuses to start beside one, and NordVPN
# in particular drops DNS to anything but its own servers.
#
# While it runs, this Mac's DNS points at the hotspot, so the Mac is offline
# the way it would be at a real one. DNS and pf are both put back on exit,
# however it exits.
#
# The "browser" is curl, run in the background on a timer, over plain HTTP so
# it needs no certificate trust. `run` also opens the real login page in your
# browser, which is worth screen-recording alongside: it comes up blank, then
# renders once the gap is widened.
set -eu

cd "$(dirname "$0")/.."

ACT=${1:-first}
MODE=${2:-auto}
WAIT=60s
# DNS_FILTER=off runs without the v0.3 DNS filter: the control run, in which
# the DNS check below should fail, because every app's lookups reach the
# network during the gap.
RUN_FLAGS=""
[ "${DNS_FILTER:-on}" = off ] && RUN_FLAGS="-no-dns-filter"
[ "$MODE" = human ] && WAIT=180s
BIN=${BIN:-./bin/portalguard}
DOMAIN=${DOMAIN:-guestwifi.test}
DIR=${DIR:-$PWD/bin/hotspot}
RESULTS=$(mktemp)

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 64; }
[ -x "$BIN" ] || { echo "$BIN not built. run: make build"; exit 64; }
WWW=$(cat "$DIR/www.ip" 2>/dev/null) || { echo "hotspot not up. run: ./testenv/hotspot.sh up (without sudo)"; exit 64; }
curl -s -m 3 -o /dev/null "http://$WWW:8443/status" || { echo "hotspot not answering at $WWW. run: ./testenv/hotspot.sh up"; exit 64; }
# Without the anchor hook `run` rightly refuses to lock down, and every check
# below would be measuring an unfiltered network. macOS updates restore
# /etc/pf.conf and take the hook with them, so this is worth checking first.
/sbin/pfctl -s rules 2>/dev/null | grep -q 'anchor "portalguard"' \
    || { echo "pf has no portalguard anchor (a macOS update restores /etc/pf.conf). run: sudo $BIN install-anchor"; exit 64; }

cleanup() {
    "$BIN" release >/dev/null 2>&1 || true
    ./testenv/hotspot.sh dns-off >/dev/null 2>&1 || true
}
# An interrupt must exit: a trap that only cleans up lets the script carry on
# from wherever it was, against a machine it has just put back.
trap cleanup EXIT
trap 'exit 130' INT TERM

curl -s -m 3 -X POST -o /dev/null "http://$WWW:8443/reset"

# A first visit means a network this Mac does not know yet, so forget the
# hotspot's hosts from any earlier known-network run. Otherwise they open
# themselves and the blank page never happens.
if [ "$ACT" = first ] && [ -f /etc/portalguard/known-networks.json ]; then
    python3 - "$DOMAIN" <<'PY'
import json, sys
path = "/etc/portalguard/known-networks.json"
with open(path) as f:
    data = json.load(f)
if data.get("networks", {}).pop(sys.argv[1], None) is not None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
PY
fi
./testenv/hotspot.sh dns-on >/dev/null
grep -q "nameserver $WWW" /etc/resolv.conf || { echo "DNS did not take (is a VPN still connected?)"; exit 1; }

banner() { printf '\n=== %s ===\n' "$1"; }

# check records one expectation, so the background half can report a result
# the foreground reads at the end.
check() {
    if [ "$2" = "$3" ]; then
        echo "ok   $1" >> "$RESULTS"
    else
        echo "FAIL $1 (got $2, wanted $3)" >> "$RESULTS"
    fi
}

# fetch prints "loaded" or "blocked" for one URL, the way a page would
# experience it: either the resource arrives or it never does.
# wait_for_gap blocks until the kernel says the gap is open. Every check the
# browser makes is only meaningful against a real lockdown, so if the gap
# never opens it records that and stops, rather than grading an open network.
wait_for_gap() {
    i=0
    while [ $i -lt 30 ]; do
        if "$BIN" status 2>/dev/null | grep -q '^phase *: GAP'; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    echo "FAIL the gap never opened, so nothing else was checked" >> "$RESULTS"
    return 1
}

fetch() {
    if curl -s -f -m 4 -o /dev/null "$1"; then echo loaded; else echo blocked; fi
}

login() {
    # The form post to reg, then the redirect back to www that completes it.
    if curl -s -f -m 4 -L -o /dev/null \
        --data-urlencode "return=http://www.$DOMAIN:8443/complete" \
        "http://reg.$DOMAIN/login"; then
        echo "logged in"
    else
        echo "blocked"
    fi
}

first_visit() {
    wait_for_gap || return 0
    # From here on, every name the network's resolver hears was asked during
    # the gap. See the DNS check at the end.
    curl -s -m 2 -o /dev/null -X POST "http://$WWW:8443/dnsmark"
    sleep 3
    banner "browser: loading the login page"
    page=$(fetch "http://www.$DOMAIN:8443/login")
    echo "page:    $page"
    js=$(fetch "http://cdn.$DOMAIN/site.js")
    echo "site.js: $js  <- the script that reveals the page"
    # The page preconnects to reg, so reg is looked up now too, as on BT.
    fetch "http://reg.$DOMAIN/" >/dev/null
    [ "$js" = blocked ] && echo "The page is blank."
    check "login page reachable through the gap" "$page" loaded
    check "cdn blocked before allow (off-box, so pf is really filtering)" "$js" blocked

    if [ "$MODE" = human ]; then sleep 10; else sleep 6; fi
    banner "second terminal: open what it suggested"
    echo "\$ sudo portalguard allow cdn.$DOMAIN reg.$DOMAIN"
    "$BIN" allow "cdn.$DOMAIN" "reg.$DOMAIN"
    echo "\$ sudo portalguard remember"
    "$BIN" remember

    sleep 2
    if [ "$MODE" = human ]; then
        js=$(fetch "http://cdn.$DOMAIN/site.js")
        check "cdn reachable after allow" "$js" loaded
        banner "now reload the login page (Cmd+R) and click Accept and connect"
        return 0
    fi
    banner "browser: reload"
    js=$(fetch "http://cdn.$DOMAIN/site.js")
    echo "site.js: $js"
    check "cdn reachable after allow" "$js" loaded
    [ "$js" = loaded ] && echo "The page renders. Accept and connect..."
    result=$(login)
    echo "login:   $result"
    check "login completes through reg" "$result" "logged in"
    banner "back to the first terminal"
}

known_visit() {
    wait_for_gap || return 0
    # From here on, every name the network's resolver hears was asked during
    # the gap. See the DNS check at the end.
    curl -s -m 2 -o /dev/null -X POST "http://$WWW:8443/dnsmark"
    sleep 3
    banner "browser: loading the login page"
    js=$(fetch "http://cdn.$DOMAIN/site.js")
    echo "site.js: $js  <- no allow this time"
    check "remembered cdn opened without allow" "$js" loaded
    if [ "$MODE" = human ]; then
        banner "the page renders first time: click Accept and connect"
        return 0
    fi
    [ "$js" = loaded ] && echo "The page renders first time. Accept and connect..."
    result=$(login)
    echo "login:   $result"
    check "login completes through remembered reg" "$result" "logged in"
    banner "back to the first terminal"
}

case "$ACT" in
    first) first_visit & ;;
    known) known_visit & ;;
    *) echo "usage: $0 [first|known] [auto|human]"; exit 64 ;;
esac
BROWSER=$!

status=0
# shellcheck disable=SC2086
"$BIN" run -no-handoff $RUN_FLAGS -wait "$WAIT" -poll 2s -redact || status=$?
# If run gave up early the browser has nothing left to test against.
kill "$BROWSER" 2>/dev/null || true
wait "$BROWSER" 2>/dev/null || true
check "run noticed the login and sealed" "$status" 0

# What the network's resolver heard during the gap. The hotspot is the
# network, so a name it never heard never left this machine. Released first:
# the sealed lockdown would drop the request for the log itself.
"$BIN" release >/dev/null 2>&1
leaked=$(curl -s -m 3 "http://$WWW:8443/dnslog" | python3 -c '
import json, sys
login = {"www.guestwifi.test", "cdn.guestwifi.test", "reg.guestwifi.test",
         "captive.apple.com", "connectivitycheck.gstatic.com"}
names = json.load(sys.stdin)
print(" ".join(sorted(n for n in names if n not in login)) or "none")
' 2>/dev/null || echo "unreadable")
echo "DNS that reached the network during the gap, beyond the login's own names: $leaked"
check "no other app's DNS left the machine during the gap" "$leaked" none

banner "verdict"
cat "$RESULTS"
if grep -q '^FAIL' "$RESULTS"; then
    rm -f "$RESULTS"
    exit 1
fi
rm -f "$RESULTS"
echo "all checks passed"
