#!/bin/sh
#
# Does a VPN client get past the lockdown, and how?
#
#   sudo ./testenv/vpn-bypass-check.sh
#
# Locks down with no VPN hole at all, snapshots pf, waits while you connect
# the VPN, snapshots pf again, and releases. Compare the two snapshots:
#
#   - pf disabled after connecting          the client turned pf off
#   - anchor "portalguard" gone from main   the client reloaded pf's main
#                                           ruleset, dropping our hook
#   - both intact, VPN still connected      the client's traffic is not
#                                           filtered by pf at all
#
# Found by the handover control test: NordVPN connected with only UDP 9 let
# out. This script says which of the three it is.
set -u

cd "$(dirname "$0")/.."
BIN=${BIN:-./bin/portalguard}

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 64; }
[ -x "$BIN" ] || { echo "$BIN not built. run: make build"; exit 64; }

snapshot() {
    printf '\n===== %s =====\n' "$1"
    printf 'pf:            %s\n' "$(/sbin/pfctl -s info 2>/dev/null | grep -o 'Status: [A-Za-z]*')"
    printf 'default route: %s\n' "$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')"
    printf 'check:         %s\n' "$("$BIN" check 2>&1 | head -1)"
    printf 'our rules:     %s loaded in the portalguard anchor\n' "$(/sbin/pfctl -a portalguard -s rules 2>/dev/null | grep -c .)"
    echo 'main ruleset:'
    /sbin/pfctl -s rules 2>/dev/null | sed 's/^/  /'
    echo 'anchors:'
    /sbin/pfctl -s Anchors 2>/dev/null | sed 's/^/  /'
}

trap '"$BIN" release >/dev/null 2>&1' EXIT
trap 'exit 130' INT TERM

"$BIN" lockdown || exit 1
snapshot "locked down, VPN disconnected"

printf '\nConnect your VPN now. Press Enter once it says connected,\n'
printf 'or after about 30 seconds if it cannot connect.\n'
read -r _

snapshot "after connecting the VPN"
printf '\nreleasing the lockdown\n'
