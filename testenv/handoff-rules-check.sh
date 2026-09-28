#!/bin/sh
#
# Does the handover hole let VPN traffic out, and only VPN traffic?
#
#   sudo ./testenv/handoff-rules-check.sh
#
# No VPN needed, and none may be connected. It locks down, starts a handover
# with the default VPN ports, and sends one UDP packet to port 51820
# (WireGuard, in the hole) and one to port 9 (not in it), then another to
# 51820 after the handover has timed out and closed the hole. tcpdump on the
# outgoing interface shows which actually left the machine: pf drops a
# blocked packet before the interface ever sees it.
#
# The destination is 203.0.113.1, from TEST-NET-3 (RFC 5737): reserved for
# documentation, never routed to anyone, so nothing is sent to a real host.
#
# Why this exists: a live VPN cannot prove the hole. NordVPN's kill switch
# replaces pf's ruleset when it connects, and WireGuard takes the default
# route before its handshake, so the handover steps aside before the hole is
# ever used. See docs/pf-design.md, "The handover".
set -u

cd "$(dirname "$0")/.."
BIN=${BIN:-./bin/portalguard}
DST=203.0.113.1
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
CAP=$(mktemp)

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 64; }
[ -x "$BIN" ] || { echo "$BIN not built. run: make build"; exit 64; }
[ -n "$IFACE" ] || { echo "no default route"; exit 1; }

cleanup() {
    kill "$TCPDUMP" "$HANDOFF" 2>/dev/null
    "$BIN" release >/dev/null 2>&1
    rm -f "$CAP"
}
trap cleanup EXIT INT TERM

send() { printf 'portalguard-handover-test' | nc -u -w1 "$DST" "$1" >/dev/null 2>&1; }
seen() { grep -c "$DST\.$1:" "$CAP"; }

"$BIN" lockdown || exit 1

tcpdump -i "$IFACE" -n -l "udp and host $DST" >"$CAP" 2>/dev/null &
TCPDUMP=$!

"$BIN" handoff -wait 8s >/dev/null 2>&1 &
HANDOFF=$!
sleep 2

echo "during the handover (hole open for the default VPN ports):"
send 51820
send 9
sleep 1
during_vpn=$(seen 51820)
during_other=$(seen 9)
printf '  udp 51820 left the machine: %s packet(s)   want 1+\n' "$during_vpn"
printf '  udp 9     left the machine: %s packet(s)   want 0\n' "$during_other"
printf '  check: %s   want blocked\n' "$("$BIN" check 2>&1 | head -1)"

wait "$HANDOFF" 2>/dev/null
echo "after the handover timed out (hole closed again):"
send 51820
sleep 1
after_vpn=$(( $(seen 51820) - during_vpn ))
printf '  udp 51820 left the machine: %s packet(s)   want 0\n' "$after_vpn"

echo
if [ "$during_vpn" -ge 1 ] && [ "$during_other" -eq 0 ] && [ "$after_vpn" -eq 0 ]; then
    echo "PASS: the handover lets VPN traffic out, and nothing else, and closes again"
else
    echo "FAIL: see the counts above"
    exit 1
fi
