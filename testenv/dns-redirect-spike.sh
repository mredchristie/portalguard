#!/bin/sh
#
# Can pf redirect this Mac's DNS to a local resolver? The v0.3 DNS filter
# depends on it, so it is proven here first, with nothing else involved.
#
#   sudo ./testenv/dns-redirect-spike.sh
#
# Loads only a redirect into the portalguard anchor (no lockdown, nothing
# else blocked), runs a fake resolver that answers every name with
# 203.0.113.99, then looks names up two ways: straight at the network's
# resolver, and through macOS's own resolver. An answer of 203.0.113.99 means
# the query was diverted. Everything is undone on exit.
#
# Needs the rdr hook in /etc/pf.conf: sudo ./bin/portalguard install-anchor.
# Disconnect any VPN first; its resolver would be the one tested.
set -u

cd "$(dirname "$0")/.."
MARK=203.0.113.99
SPIKE=${SPIKE:-./bin/dnsspike}
LOG=$(mktemp)

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 64; }
/sbin/pfctl -s nat 2>/dev/null | grep -q 'rdr-anchor "portalguard"' \
    || { echo "no rdr hook loaded. run: sudo ./bin/portalguard install-anchor"; exit 64; }
# A ruleset that skips loopback - a VPN kill switch's; NordVPN leaves one
# behind - means no redirect is ever applied on it.
/sbin/pfctl -s Interfaces -v 2>/dev/null | grep -q '^lo0 (skip)' \
    && { echo "pf is skipping loopback (a VPN kill switch's ruleset; NordVPN leaves one behind),"; \
         echo "so DNS cannot be redirected. disconnect the VPN, then: sudo ./bin/portalguard install-anchor"; exit 64; }
RESOLVER=$(awk '/^nameserver/ && $2 ~ /^[0-9.]+$/ {print $2; exit}' /etc/resolv.conf)
[ -n "$RESOLVER" ] || { echo "no IPv4 resolver in /etc/resolv.conf"; exit 1; }
# An IPv6 resolver too, if the network hands one out: macOS may send every
# lookup to it, so the redirect has to work for both families.
RESOLVER6=$(awk '/^nameserver/ && $2 ~ /:/ && $2 !~ /%/ {print $2; exit}' /etc/resolv.conf)

[ -x "$SPIKE" ] || { echo "$SPIKE not built. run: make dns-spike"; exit 64; }
"$SPIKE" -marker "$MARK" 2>"$LOG" &
SPIKE_PID=$!
TOKEN=$(/sbin/pfctl -E 2>&1 | awk -F': ' '/Token/ {print $2}')

cleanup() {
    /sbin/pfctl -a portalguard -F all >/dev/null 2>&1
    [ -n "$TOKEN" ] && /sbin/pfctl -X "$TOKEN" >/dev/null 2>&1
    kill "$SPIKE_PID" 2>/dev/null
    dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null
}
# An interrupt must exit: a trap that only cleans up lets the script carry on
# from wherever it was, against a machine it has just put back.
trap cleanup EXIT
trap 'exit 130' INT TERM

/sbin/pfctl -a portalguard -f - <<RULES 2>/dev/null || { echo "rules did not load"; exit 1; }
table <pg_dns> persist { $RESOLVER $RESOLVER6 }
rdr pass on lo0 inet  proto { udp, tcp } from any to <pg_dns> port 53 -> 127.0.0.1 port 5300
rdr pass on lo0 inet6 proto { udp, tcp } from any to <pg_dns> port 53 -> ::1 port 5300
pass out quick route-to (lo0 127.0.0.1) inet  proto { udp, tcp } from any to <pg_dns> port 53 keep state
pass out quick route-to (lo0 ::1) inet6 proto { udp, tcp } from any to <pg_dns> port 53 keep state
RULES
dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null
sleep 1

pass=0
check() {
    printf '  %-44s %-16s' "$1" "$2"
    if [ "$2" = "$MARK" ]; then echo "diverted"; pass=$((pass + 1)); else echo "NOT diverted"; fi
}

echo "resolver: $RESOLVER"
check "dig @$RESOLVER (udp)" "$(dig +short +time=2 +tries=1 @"$RESOLVER" spike-udp.example A | tail -1)"
check "dig @$RESOLVER (tcp)" "$(dig +short +tcp +time=2 +tries=1 @"$RESOLVER" spike-tcp.example A | tail -1)"
# dscacheutil can hang when nothing answers; give it five seconds.
sys_answer=$( (dscacheutil -q host -a name spike-system.example & p=$!; (sleep 5; kill $p 2>/dev/null) & wait $p) 2>/dev/null | awk '/ip_address/ {print $2; exit}')
check "macOS resolver (dscacheutil)" "$sys_answer"
want=3
if [ -n "$RESOLVER6" ]; then
    echo "IPv6 resolver: $RESOLVER6"
    check "dig @$RESOLVER6 (udp)" "$(dig +short +time=2 +tries=1 @"$RESOLVER6" spike-udp6.example A | tail -1)"
    check "dig @$RESOLVER6 (tcp)" "$(dig +short +tcp +time=2 +tries=1 @"$RESOLVER6" spike-tcp6.example A | tail -1)"
    want=5
fi

echo
echo "the fake resolver saw:"
sed 's/^/  /' "$LOG"
echo

# What pf was doing, for when a lookup is not diverted.
diag() { printf '\n--- %s\n' "$1"; shift; "$@" 2>&1 | sed 's/^/  /'; }
kill -0 "$SPIKE_PID" 2>/dev/null && echo "fake resolver: running" || echo "fake resolver: NOT running"
diag "pf status" sh -c "/sbin/pfctl -s info | head -2"
diag "main translation rules (pfctl -s nat)" /sbin/pfctl -s nat
diag "our anchor's translation rules" /sbin/pfctl -a portalguard -s nat
diag "our anchor's filter rules" /sbin/pfctl -a portalguard -s rules
diag "anchors" /sbin/pfctl -s Anchors
diag "states on port 53 / 5300" sh -c "/sbin/pfctl -ss | grep -E ':53[^0-9]|:5300|\\.53 |\\.5300 ' | head -20"
diag "who listens on 5300" sh -c "lsof -nP -i :5300"
echo
[ "$pass" -eq "$want" ] && echo "PASS: pf redirects this Mac's DNS" || { echo "FAIL: $pass of $want diverted"; exit 1; }
