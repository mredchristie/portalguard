#!/bin/sh
#
# End-to-end test: the real pf backend, a real portal, a real off-box target.
#
#   sudo ./testenv/e2e.sh
#
# THIS WILL CUT THIS MACHINE'S NETWORK, on purpose, several times. Every
# privileged command is echoed before it runs, and teardown is unconditional:
# the EXIT trap flushes the anchor whether the run passes, fails, or is
# interrupted. If all else fails: sudo pfctl -a portalguard -F all
#
# What this covers, and what it does not, is documented in testenv/README.md
# under "Which half of the test covers what". Read that before treating a green
# run as end-to-end proof.
set -u

BIN=${BIN:-./bin/portalguard}
PROBES=${PROBES:-testenv/probes.json}
PORTAL=${PORTAL:-http://127.0.0.1:8080}     # the fake portal, on loopback
GATEWAY=${GATEWAY:-}                         # the off-box target, on en0
CONTROL=${CONTROL:-1.1.1.1}                  # must stay blocked while the gap is open
WAIT=${WAIT:-90}

fail_count=0
run_pid=""
RUN_LOG=""

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
cmd()  { printf '   $ %s\n' "$*"; "$@"; }
pass() { printf '   \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '   \033[31mFAIL\033[0m %s\n' "$*"; fail_count=$((fail_count + 1)); }

# --- teardown, unconditional -------------------------------------------------
cleanup() {
    say "TEARDOWN (always runs)"
    if [ -n "$run_pid" ] && kill -0 "$run_pid" 2>/dev/null; then
        printf '   stopping backgrounded portalguard run (pid %s)\n' "$run_pid"
        kill "$run_pid" 2>/dev/null
        wait "$run_pid" 2>/dev/null
    fi
    [ -n "${RUN_LOG:-}" ] && rm -f "$RUN_LOG"
    cmd pfctl -a portalguard -F rules  >/dev/null 2>&1
    cmd pfctl -a portalguard -F Tables >/dev/null 2>&1
    ifconfig pflog1 >/dev/null 2>&1 && cmd ifconfig pflog1 destroy >/dev/null 2>&1
    printf '   anchor flushed. network should be back.\n'
}
trap cleanup EXIT INT TERM

# --- assertions --------------------------------------------------------------
# reachable/blocked deliberately use IP literals: DNS is blocked during
# lockdown, so a hostname here would test the wrong thing.
reachable() {
    if curl -s -o /dev/null -m 6 "$1" 2>/dev/null; then
        pass "$2"
    else
        bad "$2 (curl exit $?)"
    fi
}
blocked() {
    curl -s -o /dev/null -m 6 "$1" 2>/dev/null
    rc=$?
    if [ $rc -eq 0 ]; then
        bad "$2 -- it was REACHABLE, which means traffic is leaking"
    else
        pass "$2 (curl exit $rc)"
    fi
}
table_empty() {
    out=$(pfctl -a portalguard -t "$1" -T show 2>/dev/null | tr -d '[:space:]')
    if [ -z "$out" ]; then
        pass "$2"
    else
        bad "$2 -- table still holds: $out"
    fi
}
table_contains() {
    if pfctl -a portalguard -t "$1" -T show 2>/dev/null | grep -q "$2"; then
        pass "$3"
    else
        bad "$3 -- $2 is not in <$1>"
    fi
}

# --- preconditions -----------------------------------------------------------
say "PRECONDITIONS"

[ "$(id -u)" -eq 0 ] || { echo "must run as root: sudo $0"; exit 64; }
[ -x "$BIN" ] || { echo "$BIN not built. run: make build"; exit 64; }

# Refuse to test a stale binary.
#
# This is not fussiness: an e2e that silently validates an old build is worse
# than no e2e, because it reports green for code that was never run. It has
# happened - a whole leak-report feature was "tested" by a binary compiled
# before the feature existed, and every assertion about it failed for a reason
# that had nothing to do with the code.
#
# Refusing rather than rebuilding is deliberate: this script runs under sudo,
# so building here would leave root-owned artefacts in bin/ and break the next
# ordinary `make build`.
stale=$(find cmd internal -name '*.go' -newer "$BIN" 2>/dev/null | head -3)
if [ -n "$stale" ]; then
    echo "$BIN is older than the sources:"
    echo "$stale" | sed 's/^/    /'
    echo "run 'make build' first (as yourself, not root), then re-run this."
    exit 64
fi
printf '   binary is current\n'

if [ -z "$GATEWAY" ]; then
    GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')
fi
[ -n "$GATEWAY" ] || { echo "no default gateway; are you on a network?"; exit 64; }
printf '   off-box target (gateway): %s\n' "$GATEWAY"
printf '   fake portal (loopback):   %s\n' "$PORTAL"
printf '   control host:             %s\n' "$CONTROL"

grep -q 'portalguard' /etc/pf.conf 2>/dev/null \
    || { echo "anchor hook missing. run: sudo $BIN install-anchor"; exit 64; }

curl -s -o /dev/null -m 5 "$PORTAL/status" \
    || { echo "fake portal not answering at $PORTAL. run: make testenv-up"; exit 64; }

curl -s -o /dev/null -m 5 "http://$GATEWAY/" \
    || { echo "gateway $GATEWAY does not answer HTTP; set GATEWAY= to something that does"; exit 64; }

# Reset the fixture so a re-run starts from "not logged in".
curl -s -o /dev/null "$PORTAL/reset"
printf '   fake portal reset to intercepting\n'

# ==============================================================================
say "PHASE A -- LOCKED_DOWN blocks a genuinely off-box target"
# This is the half that actually exercises pf. The gateway is reached over en0,
# not lo0, so `pass quick on lo0 all` cannot make this pass vacuously.

cmd "$BIN" lockdown || bad "lockdown failed"

blocked   "http://$GATEWAY/"        "gateway blocked while locked down (over en0)"
reachable "$PORTAL/status"          "loopback still works while locked down"
table_empty pg_portal               "no gap open during a bare lockdown"

cmd "$BIN" release >/dev/null || bad "release failed"
reachable "http://$GATEWAY/"        "gateway reachable again after release"

# ==============================================================================
say "PHASE B -- the full cycle, driven by the real CLI"
# portalguard run holds the state machine in one process, which is its natural
# scope. We assert from outside while it waits in GAP_OPEN.

RUN_LOG=$(mktemp -t portalguard-e2e)
printf '   $ %s run -probes-file %s -wait %ss &   (output -> %s)\n' "$BIN" "$PROBES" "$WAIT" "$RUN_LOG"
"$BIN" run -probes-file "$PROBES" -wait "${WAIT}s" -poll 2s >"$RUN_LOG" 2>&1 &
run_pid=$!

# Wait for the gap to open, by watching the kernel rather than the log output.
printf '   waiting for GAP_OPEN'
i=0
while [ $i -lt 30 ]; do
    if pfctl -a portalguard -t pg_portal -T show 2>/dev/null | grep -q "$GATEWAY"; then
        break
    fi
    printf '.'
    sleep 1
    i=$((i + 1))
done
printf '\n'

say "PHASE B1 -- GAP_OPEN lets the portal through and nothing else"
table_contains pg_portal "$GATEWAY" "gap pinned to the gateway address"
reachable "http://$GATEWAY/"        "portal reachable through the gap (over en0)"
blocked   "http://$CONTROL/"        "control host still blocked -- the gap is narrow"
reachable "$PORTAL/status"          "loopback still works"

if ifconfig pflog1 >/dev/null 2>&1; then
    pass "pflog1 created for the leak log"
else
    bad  "pflog1 missing -- leak logging degraded (not fatal)"
fi

say "PHASE B2 -- AUTHENTICATED"
# Poking our own fixture's accept endpoint. This is not portalguard logging in:
# the tool never submits anything, and the fixture has no credential form.
printf '   simulating the human clicking Accept on the fake portal\n'
cmd curl -s -o /dev/null -X POST "$PORTAL/accept"

printf '   waiting for the re-probe to succeed and seal'
i=0
while [ $i -lt 30 ]; do
    kill -0 "$run_pid" 2>/dev/null || break
    printf '.'
    sleep 1
    i=$((i + 1))
done
printf '\n'
wait "$run_pid" 2>/dev/null
run_pid=""

say "PHASE B3 -- SEALED closes the gap again"
blocked   "http://$GATEWAY/"        "gateway blocked again after seal"
reachable "$PORTAL/status"          "loopback still works while sealed"
table_empty pg_portal               "pg_portal emptied by the seal"
table_empty pg_dns                  "pg_dns emptied by the seal"

# The invariant that matters for the UI: status must never report an address
# as open when no pass rule permits it.
phase=$("$BIN" status --json 2>/dev/null | sed -n 's/.*"phase"[^"]*"\([^"]*\)".*/\1/p')
if [ "$phase" = "GAP" ]; then
    bad "status reports GAP after seal -- nothing is permitted at this point"
else
    pass "status reports $phase after seal, not GAP"
fi
if "$BIN" status --json 2>/dev/null | grep -q '"allowed"'; then
    bad "status still lists allowed hosts after seal"
else
    pass "status lists nothing as allowed after seal"
fi

say "PHASE B4 -- the leak report is real"
# A silently broken counter read would otherwise pass as "nothing leaked",
# which is the most dangerous way for this to fail: a reassuring report is
# worse than no report.
if grep -q "what happened while portalguard was engaged" "$RUN_LOG"; then
    pass "report was printed at seal"
else
    bad "no report printed at seal"
    sed -n '1,40p' "$RUN_LOG" | sed 's/^/      | /'
fi

blocked_n=$(sed -n 's/^Held back \([0-9][0-9]*\) packets.*/\1/p' "$RUN_LOG" | head -1)
if [ -n "$blocked_n" ] && [ "$blocked_n" -gt 0 ] 2>/dev/null; then
    pass "report counted $blocked_n outbound packets held back (non-zero)"
else
    bad "report shows no packets held back -- counter read is broken, not a quiet network"
fi

if grep -q "packets, not lookups" "$RUN_LOG"; then
    pass "report does not let a packet count read as a query count"
else
    bad "report is missing the packets-vs-lookups caveat"
fi

if grep -q "gap was open for" "$RUN_LOG"; then
    pass "report states how long the gap was open"
else
    bad "report does not state the gap duration"
fi

# With no pflog enrichment yet, the report must say so rather than imply
# that an absent hostname list means nothing was asked for.
if grep -q "not known" "$RUN_LOG" || grep -q "Hostnames queried" "$RUN_LOG"; then
    pass "report is explicit about whether it knows the hostnames"
else
    bad "report neither lists hostnames nor says they are unknown"
fi

printf '\n   --- report as printed ---\n'
sed -n '/what happened while portalguard was engaged/,/^---$/p' "$RUN_LOG" | sed 's/^/   /'

say "PHASE C -- release restores the machine"
cmd "$BIN" release >/dev/null || bad "release failed"
reachable "http://$GATEWAY/"        "gateway reachable after release"
table_empty pg_portal               "pg_portal empty after release"
table_empty pg_dns                  "pg_dns empty after release"

if ifconfig pflog1 >/dev/null 2>&1; then
    bad  "pflog1 still present after release -- it should have been destroyed"
else
    pass "pflog1 destroyed"
fi

# ==============================================================================
say "RESULT"
if [ "$fail_count" -eq 0 ]; then
    printf '   \033[32mall assertions passed\033[0m\n'
    exit 0
fi
printf '   \033[31m%s assertion(s) failed\033[0m\n' "$fail_count"
exit 1
