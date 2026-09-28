#!/bin/sh
#
# End-to-end test: the real pf backend, a real portal, a real off-box target.
#
#   sudo ./testenv/e2e.sh
#   sudo ./testenv/e2e.sh --redact   # PHASE B also redacted; see below
#
# THIS WILL CUT THIS MACHINE'S NETWORK, on purpose, several times. Every
# privileged command is echoed before it runs, and teardown is unconditional:
# the EXIT trap flushes the anchor whether the run passes, fails, or is
# interrupted. If all else fails: sudo pfctl -a portalguard -F all
#
# What this covers, and what it does not, is documented in testenv/README.md
# under "Which half of the test covers what". Read that before treating a green
# run as end-to-end proof.
#
# --redact is a command-line argument, not an environment variable, and
# that is load-bearing, not a style choice: `sudo` resets the environment
# before exec'ing this script under its default policy (env_reset), so
# `REDACT=1 sudo ./testenv/e2e.sh` silently runs with REDACT unset inside
# the script - confirmed directly (`REDACT=1 sudo sh -c 'echo $REDACT'`
# prints nothing) after an earlier version of this script used exactly that
# env-var form and produced an apparently-redacted PHASE B that was
# actually printing real hostnames the whole time. Arguments are part of
# the exec'd command line, not the environment, so sudo cannot drop them.
set -u

BIN=${BIN:-./bin/portalguard}
PROBES=${PROBES:-testenv/probes.json}
PORTAL=${PORTAL:-http://127.0.0.1:8080}     # the fake portal, on loopback
GATEWAY=${GATEWAY:-}                         # the off-box target, on en0
CONTROL=${CONTROL:-1.1.1.1}                  # must stay blocked while the gap is open
WAIT=${WAIT:-90}

REDACT=0
for arg in "$@"; do
    case "$arg" in
        --redact) REDACT=1 ;;
        *)
            printf 'unknown argument: %s\n' "$arg" >&2
            printf 'usage: %s [--redact]\n' "$0" >&2
            exit 64
            ;;
    esac
done

fail_count=0
run_pid=""
RUN_LOG=""
RUN_LOG2=""
AUDIT_B=""
AUDIT_D=""

# Per-phase accounting, for the summary at the end and the JSON it writes
# ($SUMMARY). A phase is everything from one "PHASE ..." heading to the next.
SUMMARY=${SUMMARY:-/tmp/portalguard-e2e.json}
PHASES_TSV=$(mktemp -t portalguard-e2e-phases)
phase_name=""
phase_start=0
phase_pass=0
phase_fail=0

end_phase() {
    [ -n "$phase_name" ] || return 0
    printf '%s\t%s\t%s\t%s\n' "$phase_name" "$phase_pass" "$phase_fail" \
        "$(( $(date +%s) - phase_start ))" >>"$PHASES_TSV"
    phase_name=""
}

say() {
    printf '\n\033[1m== %s\033[0m\n' "$*"
    end_phase
    case "$1" in
        PHASE*)
            phase_name=$1
            phase_start=$(date +%s)
            phase_pass=0
            phase_fail=0
            ;;
    esac
}
cmd()  { printf '   $ %s\n' "$*"; "$@"; }
pass() { printf '   \033[32mPASS\033[0m %s\n' "$*"; phase_pass=$((phase_pass + 1)); }
bad()  { printf '   \033[31mFAIL\033[0m %s\n' "$*"; fail_count=$((fail_count + 1)); phase_fail=$((phase_fail + 1)); }

# refuse_unredacted is not "bad": a failed assertion still lets the script
# run to completion and report a failing exit code, but this specific
# failure means untrusted output may already be sitting in a log a
# recording could pick up next. --redact was requested; if this cycle
# cannot be shown to actually be running redacted, stop immediately rather
# than let anything else print, teardown still runs via the EXIT trap.
refuse_unredacted() {
    printf '\n   \033[1;31mREFUSING TO CONTINUE\033[0m %s\n' "$*"
    printf '   --redact was requested but this cycle is not verifiably running redacted.\n'
    printf '   Stopping now rather than produce a run that looks safe to record and is not.\n'
    exit 1
}

# --- teardown, unconditional -------------------------------------------------
cleanup() {
    say "TEARDOWN (always runs)"
    if [ -n "$run_pid" ] && kill -0 "$run_pid" 2>/dev/null; then
        printf '   stopping backgrounded portalguard run (pid %s)\n' "$run_pid"
        kill "$run_pid" 2>/dev/null
        wait "$run_pid" 2>/dev/null
    fi
    [ -n "${RUN_LOG:-}" ]  && rm -f "$RUN_LOG"
    [ -n "${RUN_LOG2:-}" ] && rm -f "$RUN_LOG2"
    # Audit files hold real hostnames even when everything displayed is
    # redacted - never left behind, on any exit path.
    [ -n "${AUDIT_B:-}" ] && rm -f "$AUDIT_B"
    [ -n "${AUDIT_D:-}" ] && rm -f "$AUDIT_D"
    cmd pfctl -a portalguard -F rules  >/dev/null 2>&1
    cmd pfctl -a portalguard -F nat    >/dev/null 2>&1
    cmd pfctl -a portalguard -F Tables >/dev/null 2>&1
    [ -n "${PHASES_TSV:-}" ] && rm -f "$PHASES_TSV"
    ifconfig pflog1 >/dev/null 2>&1 && cmd ifconfig pflog1 destroy >/dev/null 2>&1
    printf '   anchor flushed. network should be back.\n'
}
# An interrupt must exit: a trap that only cleans up lets the script carry on
# from wherever it was, against a machine it has just put back.
trap cleanup EXIT
trap 'exit 130' INT TERM

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

# A VPN owning the default route makes its tunnel the "gateway", and every
# phase would be testing the wrong thing - a live run did exactly that.
case "$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')" in
    utun*|ipsec*|ppp*) echo "a VPN owns the default route. disconnect it, then: sudo $BIN install-anchor"; exit 64 ;;
esac
if [ -z "$GATEWAY" ]; then
    GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')
fi
[ -n "$GATEWAY" ] || { echo "no default gateway; are you on a network?"; exit 64; }
printf '   off-box target (gateway): %s\n' "$GATEWAY"
printf '   fake portal (loopback):   %s\n' "$PORTAL"
printf '   control host:             %s\n' "$CONTROL"
if [ "$REDACT" = "1" ]; then
    printf '   \033[1mredaction: ON  - both PHASE B and PHASE D display categories only\033[0m\n'
else
    printf '   redaction: off - PHASE B shows real hostnames, PHASE D only (pass --redact for both)\n'
fi

grep -q 'portalguard' /etc/pf.conf 2>/dev/null \
    || { echo "anchor hook missing. run: sudo $BIN install-anchor"; exit 64; }
pfctl -s nat 2>/dev/null | grep -q 'rdr-anchor "portalguard"' \
    || { echo "rdr hook missing (PHASE F needs it). run: sudo $BIN install-anchor"; exit 64; }
# A ruleset that skips loopback - a VPN kill switch's; NordVPN leaves one
# behind - means no redirect is ever applied on it.
/sbin/pfctl -s Interfaces -v 2>/dev/null | grep -q '^lo0 (skip)' \
    && { echo "pf is skipping loopback (a VPN kill switch's ruleset; NordVPN leaves one behind),"; \
         echo "so DNS cannot be redirected. disconnect the VPN, then: sudo ./bin/portalguard install-anchor"; exit 64; }

curl -s -o /dev/null -m 5 "$PORTAL/status" \
    || { echo "fake portal not answering at $PORTAL. in another terminal run: make e2e-portal"; exit 64; }

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
if [ "$REDACT" = "1" ]; then
    AUDIT_B=$(mktemp -t portalguard-e2e-audit-b)
    printf '   $ %s run -probes-file %s -wait %ss -redact -audit-log <not printed> &   (output -> %s)\n' \
        "$BIN" "$PROBES" "$WAIT" "$RUN_LOG"
    "$BIN" run -no-handoff -no-dns-filter -probes-file "$PROBES" -wait "${WAIT}s" -poll 2s -redact -audit-log "$AUDIT_B" >"$RUN_LOG" 2>&1 &
else
    printf '   $ %s run -probes-file %s -wait %ss &   (output -> %s)\n' "$BIN" "$PROBES" "$WAIT" "$RUN_LOG"
    "$BIN" run -no-handoff -no-dns-filter -probes-file "$PROBES" -wait "${WAIT}s" -poll 2s >"$RUN_LOG" 2>&1 &
fi
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
    bad "status reports GAP after seal; nothing is permitted at this point"
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

# The enrichment check: a silently broken reader must not pass as "no DNS
# went out". pflog1 was already confirmed created above, and background
# traffic during the gap (mDNSResponder etc., same as the demo capture)
# is reliably enough to produce at least one logged query on this machine.
names_line=$(grep "Hostnames queried:" "$RUN_LOG" | head -1)
if [ -n "$names_line" ] && ! printf '%s' "$names_line" | grep -qE '^Hostnames queried: *$'; then
    pass "enriched report names at least one hostname ($names_line)"
else
    bad "report was not enriched with a hostname -- the reader is silently broken, not just quiet"
fi

if [ "$REDACT" = "1" ]; then
    # Everything from here to the "report as printed" dump below is a gate,
    # not an assertion: --redact was requested, so nothing raw may reach
    # that dump. refuse_unredacted exits immediately rather than letting a
    # failure here be merely "FAIL" while the script carries on to print
    # more.

    # Structural check, same reasoning as PHASE D's: a raw hostname could
    # never coincidentally match "category (N hostnames)".
    if printf '%s' "$names_line" | grep -qE '\([0-9]+ hostnames?\)'; then
        pass "PHASE B's displayed line has the category shape, not raw domains"
    else
        refuse_unredacted "PHASE B's displayed line does not look like categories: $names_line"
    fi

    # The actual privacy property, checked against real ground truth
    # ($AUDIT_B, written to disk but never printed by this script) rather
    # than assumed from the structural check above: none of what was
    # really captured may appear in what got displayed.
    audit_line=$(grep "Hostnames queried:" "$AUDIT_B" | head -1)
    if [ -z "$audit_line" ]; then
        refuse_unredacted "the audit log has no Hostnames queried line -- -audit-log itself is broken, so nothing here can be verified"
    fi
    leaked=0
    for h in $(printf '%s' "$audit_line" | sed 's/^Hostnames queried: *//' | tr ',' ' '); do
        h=$(printf '%s' "$h" | sed 's/^ *//;s/ *$//')
        [ -n "$h" ] || continue
        grep -qF "$h" "$RUN_LOG" && leaked=$((leaked + 1))
    done
    if [ "$leaked" -eq 0 ]; then
        pass "none of PHASE B's real hostnames (verified via the unprinted audit log) reached the displayed report"
    else
        # Deliberately not printing which hostname(s) leaked, or how many
        # made it into RESULT's summary either - refuse_unredacted exits
        # before that would ever be reached.
        refuse_unredacted "PHASE B's redacted display leaked real hostname(s) into the report -- see \$AUDIT_B locally, not reproduced here"
    fi
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
say "PHASE D -- -redact through the real binary, not just unit tests"
# Redact is a pure transform on data already collected the same way as
# PHASE B, so this is not re-testing the reader - it is checking that the
# flag is actually wired to it, end to end, the way this suite always
# insists on (a compiled-but-never-run path is not tested; see PHASE B4's
# comment). The real check: none of what -audit-log shows this run actually
# captured (never printed) may appear in what -redact actually displayed.

curl -s -o /dev/null "$PORTAL/reset"
printf '   fake portal reset to intercepting\n'

RUN_LOG2=$(mktemp -t portalguard-e2e-redact)
AUDIT_D=$(mktemp -t portalguard-e2e-audit-d)
printf '   $ %s run -probes-file %s -wait %ss -redact -audit-log <not printed> &   (output -> %s)\n' \
    "$BIN" "$PROBES" "$WAIT" "$RUN_LOG2"
"$BIN" run -no-handoff -no-dns-filter -probes-file "$PROBES" -wait "${WAIT}s" -poll 2s -redact -audit-log "$AUDIT_D" >"$RUN_LOG2" 2>&1 &
run_pid=$!

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

# PHASE D runs -redact unconditionally, so - same as PHASE B's gate above -
# every check from here to the release below is a hard gate, not a soft
# assertion: refuse_unredacted exits immediately on failure.

redacted_line=$(grep "Hostnames queried:" "$RUN_LOG2" | head -1)
if [ -n "$redacted_line" ] && ! printf '%s' "$redacted_line" | grep -qE '^Hostnames queried: *$'; then
    pass "redacted report still names at least one category ($redacted_line)"
else
    refuse_unredacted "redacted report has no Hostnames queried line -- -redact broke enrichment rather than just generalising it"
fi

# The structural check: every entry must have the "category (N hostnames)"
# shape Redact produces. A raw hostname could never coincidentally match
# this, so this alone proves the line is categories, not domains.
if printf '%s' "$redacted_line" | grep -qE '\([0-9]+ hostnames?\)'; then
    pass "redacted entries have the category (N hostnames) shape, not raw domains"
else
    refuse_unredacted "redacted line does not look like categories: $redacted_line"
fi

# The actual privacy property, checked against this run's own real ground
# truth ($AUDIT_D, written to disk but never printed by this script) rather
# than assumed from the structural check above: nothing this run really
# captured may appear in what got displayed. A self-check, not a comparison
# against PHASE B's data - it holds regardless of whether PHASE B itself
# ran redacted ($REDACT).
audit_line_d=$(grep "Hostnames queried:" "$AUDIT_D" | head -1)
if [ -z "$audit_line_d" ]; then
    refuse_unredacted "the audit log has no Hostnames queried line -- -audit-log itself is broken, so nothing here can be verified"
fi
leaked=0
for h in $(printf '%s' "$audit_line_d" | sed 's/^Hostnames queried: *//' | tr ',' ' '); do
    h=$(printf '%s' "$h" | sed 's/^ *//;s/ *$//')
    [ -n "$h" ] || continue
    grep -qF "$h" "$RUN_LOG2" && leaked=$((leaked + 1))
done
if [ "$leaked" -eq 0 ]; then
    pass "none of this run's real hostnames (verified via the unprinted audit log) reached the displayed report"
else
    refuse_unredacted "PHASE D's redacted display leaked real hostname(s) into the report -- see \$AUDIT_D locally, not reproduced here"
fi

cmd "$BIN" release >/dev/null || bad "release failed"
reachable "http://$GATEWAY/"        "gateway reachable after the redaction cycle's release"

# ==============================================================================
say "PHASE E -- the VPN handover lets VPN traffic out and nothing else"
# No VPN is involved: a live VPN cannot prove this (NordVPN's kill switch
# replaces pf's rules, WireGuard takes the route before its handshake). So one
# UDP packet goes to 51820 (WireGuard, in the hole) and one to port 9 (not),
# and tcpdump on the outgoing interface shows which left: pf drops a blocked
# packet before the interface sees it. 203.0.113.1 is TEST-NET-3, routed to
# no one.
HO_DST=203.0.113.1
HO_IF=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
HO_CAP=$(mktemp -t portalguard-e2e-handover)
ho_send() { printf 'portalguard-e2e' | nc -u -w1 "$HO_DST" "$1" >/dev/null 2>&1; }
ho_seen() { grep -c "$HO_DST\.$1:" "$HO_CAP"; }

cmd "$BIN" lockdown >/dev/null || bad "lockdown failed"
tcpdump -i "$HO_IF" -n -l "udp and host $HO_DST" >"$HO_CAP" 2>/dev/null &
ho_dump=$!
printf '   $ %s handoff -wait 8s &   (no VPN will connect, so it times out)\n' "$BIN"
"$BIN" handoff -wait 8s >/dev/null 2>&1 &
ho_pid=$!
sleep 2
ho_send 51820
ho_send 9
sleep 1
if [ "$(ho_seen 51820)" -ge 1 ]; then pass "udp 51820 left during the handover (the VPN hole)"; else bad "udp 51820 did not leave during the handover"; fi
if [ "$(ho_seen 9)" -eq 0 ]; then pass "udp 9 was dropped during the handover (not VPN traffic)"; else bad "udp 9 left during the handover -- the hole is too wide"; fi
blocked "http://$GATEWAY/" "everything else still blocked during the handover"
wait "$ho_pid" 2>/dev/null
before=$(ho_seen 51820)
ho_send 51820
sleep 1
if [ "$(ho_seen 51820)" -eq "$before" ]; then pass "the VPN hole closed again when the handover timed out"; else bad "udp 51820 still leaves after the handover timed out"; fi
blocked "http://$GATEWAY/" "the lockdown stays after a handover with no VPN"
kill "$ho_dump" 2>/dev/null
rm -f "$HO_CAP"
cmd "$BIN" release >/dev/null || bad "release failed"

# ==============================================================================
say "PHASE F -- the DNS filter keeps every other app's DNS on the machine"
# The same cycle as PHASE B, with the v0.3 DNS filter on (run's default).
# Here the portal and the probes are addresses, so the login needs no DNS at
# all: every lookup during the gap should be refused on the machine, and pf
# should count nothing leaving through the DNS hole. PHASE B, with the filter
# off, is the contrast.
curl -s -o /dev/null "$PORTAL/reset"
RUN_LOG3=$(mktemp -t portalguard-e2e-dns)
printf '   $ %s run -probes-file %s -wait %ss -redact &   (the DNS filter is on by default)\n' "$BIN" "$PROBES" "$WAIT"
"$BIN" run -no-handoff -probes-file "$PROBES" -wait "${WAIT}s" -poll 2s -redact >"$RUN_LOG3" 2>&1 &
run_pid=$!
i=0
while [ $i -lt 30 ]; do
    pfctl -a portalguard -t pg_portal -T show 2>/dev/null | grep -q "$GATEWAY" && break
    sleep 1
    i=$((i + 1))
done
if pfctl -s nat -a portalguard 2>/dev/null | grep -q "rdr"; then
    pass "the gap's DNS is redirected to the filter (rdr loaded)"
else
    bad "no rdr rule in the anchor -- the filter is not in the path"
fi
# Background apps get a few seconds to try their lookups.
sleep 6
cmd curl -s -o /dev/null -X POST "$PORTAL/accept"
printf '   waiting for the re-probe to succeed and seal'
i=0
while [ $i -lt 45 ]; do
    kill -0 "$run_pid" 2>/dev/null || break
    printf '.'
    sleep 1
    i=$((i + 1))
done
printf '\n'
kill -0 "$run_pid" 2>/dev/null && bad "run had not sealed 45s after the login"
wait "$run_pid" 2>/dev/null
run_pid=""
refused=$(sed -n 's/^The DNS filter refused \([0-9][0-9]*\) lookup.*/\1/p' "$RUN_LOG3" | head -1)
if [ -n "$refused" ] && [ "$refused" -gt 0 ] 2>/dev/null; then
    pass "the filter refused $refused lookup(s) on the machine"
else
    bad "the report shows no refusals -- the filter did not run, or saw nothing"
fi
if grep -q "No DNS went through the gap" "$RUN_LOG3"; then
    pass "pf counted no DNS leaving during the gap"
else
    bad "DNS left through the gap with the filter on: $(grep 'went out through the DNS hole' "$RUN_LOG3")"
fi
rm -f "$RUN_LOG3"
cmd "$BIN" release >/dev/null || bad "release failed"
reachable "http://$GATEWAY/" "gateway reachable after the DNS filter cycle"

# ==============================================================================
say "RESULT"
printf '   %-60s %6s %6s\n' "phase" "checks" "secs"
while IFS="$(printf '\t')" read -r name ok nok secs; do
    printf '   %-60s %3s/%-3s %4ss\n' "$name" "$ok" "$((ok + nok))" "$secs"
done <"$PHASES_TSV"

# The same, as JSON: what the portfolio's replay of this run is built from.
{
    printf '{\n  "version": "%s",\n  "date": "%s",\n  "failed": %s,\n  "phases": [\n' \
        "$("$BIN" version 2>/dev/null | awk '{print $NF}')" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$fail_count"
    first=1
    while IFS="$(printf '\t')" read -r name ok nok secs; do
        [ $first -eq 1 ] || printf ',\n'
        first=0
        printf '    {"name": "%s", "passed": %s, "failed": %s, "secs": %s}' "$name" "$ok" "$nok" "$secs"
    done <"$PHASES_TSV"
    printf '\n  ]\n}\n'
} >"$SUMMARY"
chmod 644 "$SUMMARY"
rm -f "$PHASES_TSV"
printf '   summary written to %s\n' "$SUMMARY"

if [ "$fail_count" -eq 0 ]; then
    printf '   \033[32mall assertions passed\033[0m\n'
    exit 0
fi
printf '   \033[31m%s assertion(s) failed\033[0m\n' "$fail_count"
exit 1
