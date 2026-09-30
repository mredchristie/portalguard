#!/bin/sh
#
# Portalguard against the off-box hotspot, start to finish, with nothing to
# type while it runs. It is the recording and the test at once: every step
# the "browser" takes is also a check, and the run ends with a verdict.
#
#   ./testenv/hotspot.sh up
#   sudo ./testenv/hotspot-demo.sh auto     # auto-allow: the page renders first time, no allow
#   sudo ./testenv/hotspot-demo.sh          # without it: blank page, allow, remember, login
#   sudo ./testenv/hotspot-demo.sh known    # next visit: remembered hosts open themselves
#   sudo ./testenv/hotspot-demo.sh hostile        # a portal that attacks: malformed page,
#                                                 # too many hosts, a disguised DNS name
#   sudo ./testenv/hotspot-demo.sh hostile-known  # DNS lies about remembered hosts
#
# first and known run with -no-auto-allow: they prove the paths auto-allow
# falls back to, which it would otherwise hide.
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
case "$ACT" in
    auto | hostile) ;;
    *) RUN_FLAGS="$RUN_FLAGS -no-auto-allow" ;;
esac
# run always writes a trace: it is how the verdict knows the run really went
# from lockdown to SEALED. TRACE=file keeps it somewhere of your choosing.
RUNTRACE=${TRACE:-$(mktemp -t portalguard-demo-trace)}
RUN_FLAGS="$RUN_FLAGS -trace $RUNTRACE"
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
# `set skip on lo0` stops the DNS filter, and every filter check below would
# fail for that reason alone. Internet Sharing sets it when the hotspot's
# containers start (and NordVPN's kill switch leaves it behind), so clear it
# here, after the hotspot is up, rather than grade a filterless run.
skipping() {
    /sbin/pfctl -s Interfaces -v 2>/dev/null | grep -Eq '^[[:space:]]*lo0[[:space:]].*[(]skip[)]'
}
if [ "${DNS_FILTER:-on}" != off ] && skipping; then
    echo "pf is skipping loopback (Internet Sharing sets it for the hotspot); clearing it..."
    "$BIN" install-anchor >/dev/null || exit 64
    skipping && { echo "pf still skips loopback, so the DNS filter cannot run"; exit 64; }
fi

cleanup() {
    "$BIN" release >/dev/null 2>&1 || true
    [ -n "${TRACE:-}" ] || rm -f "$RUNTRACE"
    ./testenv/hotspot.sh dns-off >/dev/null 2>&1 || true
}
# An interrupt must exit: a trap that only cleans up lets the script carry on
# from wherever it was, against a machine it has just put back.
trap cleanup EXIT
trap 'exit 130' INT TERM

curl -s -m 3 -X POST -o /dev/null "http://$WWW:8443/reset"
# The DNS log file is this run's only once the gap's /dnsmark recreates it.
rm -f "$DIR/dnslog"
# The attack is on before run starts: detection is part of what it tests.
case "$ACT" in
    hostile) curl -s -m 3 -X POST -o /dev/null "http://$WWW:8443/hostile?mode=page" ;;
    hostile-known) curl -s -m 3 -X POST -o /dev/null "http://$WWW:8443/hostile?mode=dns" ;;
esac

# A first visit means a network this Mac does not know yet, so forget the
# hotspot's hosts from any earlier known-network run. Otherwise they open
# themselves and the blank page never happens.
case "$ACT" in known | hostile-known) forget=no ;; *) forget=yes ;; esac
if [ "$forget" = yes ] && [ -f /etc/portalguard/known-networks.json ]; then
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

# resolv.conf changing is not the resolver changing: macOS can take a moment
# to follow it, and a run that starts inside that moment sees the real
# internet, finds no portal, and has nothing to test. Wait until this Mac
# itself sees the hotspot's portal.
seen=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    rc=0
    "$BIN" detect >/dev/null 2>&1 || rc=$?
    if [ "$rc" = 10 ]; then
        seen=yes
        break
    fi
    sleep 1
done
[ -n "$seen" ] || { echo "this Mac does not see the hotspot's portal (detect exit $rc), so there is nothing to test"; exit 1; }

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

# lookup prints the resolver's status for a name, as the system resolver
# path sees it: dig asks the network's resolver, which pf sends to the filter.
lookup() {
    dig +time=3 +tries=1 +noall +comments "$1" 2>/dev/null |
        sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1
}

auto_visit() {
    wait_for_gap || return 0
    curl -s -m 2 -o /dev/null -X POST "http://$WWW:8443/dnsmark"
    sleep 3
    banner "browser: loading the login page"
    page=$(fetch "http://www.$DOMAIN:8443/login")
    echo "page:    $page"
    js=$(fetch "http://cdn.$DOMAIN/site.js")
    echo "site.js: $js  <- nobody ran allow"
    check "login page reachable through the gap" "$page" loaded
    check "cdn opened automatically on first sight" "$js" loaded
    # The same lookup for a name on another site is still refused, and
    # never reaches the network.
    other=$(lookup "cdn.not$DOMAIN")
    echo "cdn.not$DOMAIN: ${other:-no answer}  <- not the portal's site"
    check "a lookalike domain is still refused" "$other" REFUSED
    if [ "$MODE" = human ]; then
        banner "the page renders first time: click Accept and connect"
        return 0
    fi
    [ "$js" = loaded ] && echo "The page renders first time. Accept and connect..."
    result=$(login)
    echo "login:   $result"
    check "login completes through reg, also opened automatically" "$result" "logged in"
    banner "back to the first terminal"
}

hostile_visit() {
    wait_for_gap || return 0
    curl -s -m 2 -o /dev/null -X POST "http://$WWW:8443/dnsmark"
    sleep 3
    banner "browser: a portal that fights back"
    page=$(fetch "http://www.$DOMAIN:8443/login")
    js=$(fetch "http://cdn.$DOMAIN/site.js")
    echo "page: $page, site.js: $js  <- found behind a malformed interception page"
    check "login page reachable behind a malformed interception page" "$page" loaded
    check "auto-allow still opens the portal's own cdn under attack" "$js" loaded
    # The page preconnects to reg first, as the real one does; then asks
    # for fifteen more of its own hosts. Auto-allow stops at ten, cdn and reg
    # included, and refuses the rest outright: none of their lookups, of any
    # type, may reach the network.
    fetch "http://reg.$DOMAIN/" >/dev/null
    i=1
    while [ $i -le 15 ]; do
        fetch "http://h$i.$DOMAIN/" >/dev/null
        i=$((i + 1))
    done
    echo "asked for h1 to h15.$DOMAIN"
    # The disguised name: one DNS label spelling the allowed cdn name.
    dotted=$(lookup "cdn\\.$DOMAIN")
    echo "one label 'cdn.$DOMAIN': ${dotted:-no answer}  <- not the cdn, whatever it spells"
    check "a single label spelling an allowed name is refused" "$dotted" REFUSED
    result=$(login)
    check "login still completes under attack" "$result" "logged in"
    banner "back to the first terminal"
}

hostile_known_visit() {
    wait_for_gap || return 0
    curl -s -m 2 -o /dev/null -X POST "http://$WWW:8443/dnsmark"
    sleep 3
    banner "browser: remembered hosts, but the network lies about them"
    js=$(fetch "http://cdn.$DOMAIN/site.js")
    echo "site.js: $js  <- cdn now resolves to an impostor with a self-signed certificate"
    check "a remembered host with a lying address stays shut" "$js" blocked
    # Log in without cdn or reg, so the run can seal.
    curl -s -m 3 -X POST -o /dev/null "http://$WWW:8443/accept"
    banner "back to the first terminal"
}

case "$ACT" in
    first) first_visit & ;;
    known) known_visit & ;;
    auto) auto_visit & ;;
    hostile) hostile_visit & ;;
    hostile-known) hostile_known_visit & ;;
    *) echo "usage: $0 [first|known|auto|hostile|hostile-known] [auto|human]"; exit 64 ;;
esac
BROWSER=$!

status=0
# shellcheck disable=SC2086
"$BIN" run -no-handoff $RUN_FLAGS -wait "$WAIT" -poll 2s -redact || status=$?
# If run gave up early the browser has nothing left to test against.
kill "$BROWSER" 2>/dev/null || true
wait "$BROWSER" 2>/dev/null || true
check "run noticed the login and sealed" "$status" 0
# Exit 0 also means "no portal, nothing to do". Only the trace says the run
# went the whole way.
if grep -q -- '--SEAL--> SEALED' "$RUNTRACE" 2>/dev/null; then sealed=yes; else sealed=no; fi
check "run went from lockdown to SEALED" "$sealed" yes

# What the attacks should have left in the run's own record.
yn() { if "$@"; then echo yes; else echo no; fi; }
case "$ACT" in
    hostile)
        check "detection found the real login behind the malformed page" \
            "$(yn grep -q "PORTAL_FOUND (www.$DOMAIN)" "$RUNTRACE")" yes
        autos=$(grep 'dns   auto' "$RUNTRACE" | awk '{print $NF}' | sort -u | wc -l | tr -d ' ')
        echo "hosts opened automatically: $autos"
        check "auto-allow stopped at its cap of 10" "$(yn [ "$autos" -le 10 ])" yes
        check "and said so" "$(yn grep -q 'anything more has to be allowed by hand' "$RUNTRACE")" yes
        ;;
    hostile-known)
        check "the impostor's certificate was rejected" "$(yn grep -q 'did not verify' "$RUNTRACE")" yes
        check "no remembered host opened on a lying answer" \
            "$(yn grep -q 'known network, TLS verified)' "$RUNTRACE")" no
        ;;
esac

# What the network's resolver heard during the gap. The hotspot is the
# network, so a name it never heard never left this machine.
#
# Read now, while run has left the Mac sealed, from the file the hotspot
# writes into the folder it shares with this Mac. Asking over HTTP meant
# releasing first, and every app that looked something up in the seconds
# before the question arrived was counted as a gap leak (www.netflix.com and
# www.google.com, in the first preflight). An older hotspot without the file
# falls back to asking after the release.
if [ -f "$DIR/dnslog" ]; then
    dnslog=$(python3 -c 'import json, sys; print(json.dumps([l.strip() for l in open(sys.argv[1]) if l.strip()]))' "$DIR/dnslog")
    "$BIN" release >/dev/null 2>&1
else
    "$BIN" release >/dev/null 2>&1
    dnslog=""
    for _ in 1 2 3 4 5; do
        dnslog=$(curl -s -f -m 3 "http://$WWW:8443/dnslog") && break
        sleep 1
    done
fi
opened=$(grep 'dns   auto' "$RUNTRACE" 2>/dev/null | awk '{print $NF}' | sort -u | tr '\n' ' ')
leaked=$(printf '%s' "$dnslog" | python3 -c '
import json, sys
login = {"www.guestwifi.test", "cdn.guestwifi.test", "reg.guestwifi.test",
         "captive.apple.com", "connectivitycheck.gstatic.com"}
# Hosts auto-allow opened are the login too, and only those: the trace says
# which. A host it refused must not appear under any record type.
opened = set(sys.argv[1].split())
names = json.load(sys.stdin) or []  # an older hotspot says null for none
print(" ".join(sorted(n for n in names if n not in login and n not in opened)) or "none")
' "$opened" 2>/dev/null || echo "unreadable")
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
