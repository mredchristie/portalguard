# Architecture

How Portalguard is put together, and — the part that matters more — which of
its claims are actually demonstrated and which are still assertions.

For the firewall rules themselves, line by line, see
[`pf-design.md`](pf-design.md).

## The shape

```
cmd/portalguard/       CLI. One process per invocation.
internal/portal/       Detection: probes, classification, DNS hijack checks.
internal/state/        The state machine, and the session that wires it up.
internal/firewall/     Backend interface, host types, fail-safe teardown.
  pf/                  macOS, via pfctl
  nftables/            Linux (stub)
  wfp/                 Windows (stub)
  backend/             Build-tagged driver selection
internal/netinfo/      Default route and VPN tunnel detection.
testenv/               A fake captive portal, and the end-to-end test.
```

Detection knows nothing about firewalls. The firewall knows nothing about
portals. The state machine is the only place that knows both, and it is pure —
it validates transitions and records history without touching the network. That
is what lets the legal sequence be tested without root.

## The state machine

Eight states, one legal path, and one escape hatch from anywhere:

```
IDLE ──detect──> DETECTING ──portal found──> PORTAL_FOUND ──lockdown──> LOCKED_DOWN
                     │                                                        │
                no portal                                                 open gap
                     │                                                        v
                     v                                                    GAP_OPEN
                   IDLE                                            (portal host + DNS only;
                                                                    the human logs in here)
                                                                              │
                                                                       re-probe succeeds
                                                                              v
HANDED_OFF <──hand off── SEALED <──seal── AUTHENTICATED
```

It is table-driven, and **anything absent from the table is rejected**. That is
not stylistic: the transition it exists to forbid is `PORTAL_FOUND → GAP_OPEN`,
opening a hole before the lockdown is up. A hole punched in a firewall that is
not yet blocking is just an open network.

`RELEASE` is legal from every state and returns to `IDLE`. It is what the
signal handler, the panic handler, and `portalguard release` all call.

Two design choices worth stating:

**Authentication is only ever concluded from a successful re-probe.**
Portalguard never reads the portal's own "you are connected" page. A portal
that lies about that is not a hypothetical.

**The machine lives in one process.** `run` holds it for a whole cycle. The
separate commands (`lockdown`, `allow`, `seal`) each start a fresh machine, and
only the *firewall* state is recovered across invocations, by reading the
kernel. This is honest but limited, and it is why the end-to-end test drives
`run` rather than stepping through commands.

## The backend interface

```go
type Backend interface {
    Name() string
    Available(ctx) (bool, string)
    Lockdown(ctx) error
    AllowHost(ctx, Host) error
    Seal(ctx) error
    Release(ctx) error
    Status(ctx) (Status, error)
}
```

`Release` is not part of the four-verb story but is the most important method
on the interface: it is the single-operation teardown the fail-safe depends on,
it must succeed even if nothing was ever installed, and everything else is
built so that it can.

`Reporter` is deliberately **separate**:

```go
type Reporter interface { LeakReport() Report }
```

A backend that cannot account for its own traffic is simply not a `Reporter`,
rather than stubbing a method that returns zeros. Zeros from a backend that
did not measure are indistinguishable from zeros on a quiet network, and the
whole point of the leak report is not to make that mistake.

`Host` pins addresses, never names. A portal that controls DNS — which, per the
hijack check, it usually does — could otherwise repoint its own hostname after
the hole was opened.

## Why the anchor design

pf lets rules live in a named container. Portalguard uses exactly one, and
everything follows from that:

- **Teardown is one operation.** Emptying the container removes every rule
  Portalguard added and cannot affect anything else. Writing into the main
  ruleset would mean teardown had to reconstruct whatever was there before,
  which is not a thing to get right at 2am in a hotel.
- **Nothing is written to disk.** Rules are piped to the kernel, so a reboot
  clears them. The worst case recovers by turning it off and on again.
- **pf is shared, so it is claimed by reference count**, never switched off.

The cost is the one-line hook in `/etc/pf.conf`, because a stock Mac has
nowhere for third-party rules to hang. That is done once, deliberately, rather
than by rewriting the main ruleset on every lockdown — Apple's own comment in
that file warns that system services insert rules there dynamically, and
reloading it would drop them each time.

The failure this creates is severe enough to design against directly: **rules
loaded into an unhooked container load cleanly and filter nothing.** So
`Lockdown` verifies the hook every time and refuses without it. Protecting a
machine in name only is worse than not protecting it, because the user stops
looking.

## What is proven

Verified on real hardware, and re-verified by `testenv/e2e.sh`:

| Claim | How |
| --- | --- |
| Detection classifies open internet, portal, and no network | Unit tests plus live runs against the fake portal in all three interception styles |
| The portal host is extracted and pinned | Unit tests over redirect, meta-refresh, JS bounce, 511, and substituted-body cases |
| Both rulesets are valid pf | `pfctl -n -f` parse check, live |
| `LOCKED_DOWN` blocks a genuinely off-box target | e2e Phase A, over `en0` |
| **`GAP_OPEN` is narrow** — portal reachable, everything else still blocked | **e2e Phase B1**: gateway reachable through the gap while a control host stays blocked |
| `SEALED` closes it again | e2e Phase B3 |
| Teardown leaves nothing behind | e2e Phase C: both tables empty, log device destroyed, network restored |
| Counters survive rule reloads | Integration test against a fake pfctl, driving the whole sequence |
| The machine recovers from a crash | Signal and panic handlers release; `make rescue` proven against an empty container |

## What is not proven

This section is the reason the document exists.

**The end-to-end test uses a gateway split.** A container runtime on macOS
cannot give a portal that is off-box from the Mac: published ports are bound by
a helper process *on the host*, and BSD routes every local address through
`lo0`. Since the lockdown ruleset must pass loopback traffic unconditionally —
without it, local IPC breaks and the machine is unusable — any test aimed at
the container would pass **without the gap rules doing anything at all**.

So the test is split. The pf half aims at the LAN gateway over `en0`, which is
genuinely off-box and has a real portal's topology. The portal-semantics half
aims at the container over `lo0`, where pf is not involved. Each half is
meaningful; neither is the whole claim.

**`GAP_OPEN` narrowness is proven by the e2e test, not by the demo.** This is
worth being precise about, because the two get conflated. The e2e test does
demonstrate it: the gateway is reachable through the gap while a control host
stays blocked, both over `en0`. The **demo** does not — it shows lockdown
versus no lockdown, on a VPN toggle, with no portal involved at all. Anyone
presenting the demo should not claim it shows the gap working.

**Not covered by anything yet:**

- A genuinely hostile network. The gateway cooperates: it does not hijack DNS,
  intercept probes, or drop packets. The hijack detection is unit-tested but
  has never met a real portal.
- The handoff to the VPN. `HANDED_OFF` releases the rules and the user then
  starts the tunnel, leaving a brief unprotected window — a smaller version of
  the problem this tool exists to solve. Closing it means keeping the lockdown
  and permitting only the VPN's endpoint, which needs the endpoint address.
- The DNS hole in `GAP_OPEN` is machine-wide. Background daemons do leak
  hostnames through it. v0.1 counts them and says so; scoping the rules to the
  browser's user id is the fix and is not built.
- DHCP lease expiry mid-lockdown, IPv6-only networks, and roaming between
  networks while engaged.
- Linux and Windows. The packages exist with their designs recorded in the
  package docs. No rule has ever been programmed on either.

**One structural limitation:** the state machine does not persist across
invocations, only the firewall state does. Stepping through `lockdown`,
`allow`, `seal` as separate commands works at the firewall level but starts a
fresh machine each time. A menu bar app will hold one process and not hit this;
a shell script driving the individual commands will.
