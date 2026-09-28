# Architecture

How Portalguard is put together, and - the part that matters more - which of
its claims are actually demonstrated and which are still assertions.

For the firewall rules themselves, line by line, see
[`pf-design.md`](pf-design.md). For how wide the gap should be, and why that is
a harder question than it looks, see [`gap-scope.md`](gap-scope.md).

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
portals. The state machine is the only place that knows both, and it is pure -
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
     ^
     └──────────hand off── LOCKED_DOWN   (no portal: just waiting for the VPN)
```

`hand off` is not a release. Until a VPN tunnel carries the default route,
the lockdown stays, with only the VPN client's own connection allowed out;
the rules come down only once the tunnel is up. See "The handover" in
[`pf-design.md`](pf-design.md).

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

**The machine is recovered, not held.** `run` drives a whole cycle in one
process, but each command is its own process, so a second invocation rebuilds
the machine rather than inheriting it. See "Picking the machine back up" below.

## Picking the machine back up

Every command is a separate process, so `sudo portalguard allow cdn.example.net`
has to work out for itself what the `run` waiting in the other terminal already
did. Two sources, and the order between them is the whole safety argument.

**The kernel decides.** The loaded ruleset is read back at the start of any
command that acts on the firewall: which rules are loaded, and whether any of
them points at a gap table. That gives the phase - `OFF`, `LOCKED`, `GAP` - and
the addresses and ports currently permitted. It cannot be out of date, because
it *is* the thing doing the filtering.

**A session file enriches.** `/var/run/portalguard.session` holds what no packet
filter can: which state the machine had reached, and the hostnames and reasons
behind the addresses in the tables. `/var/run` for the same reason the pf enable
token lives there - root-only, and cleared on reboot, which matches the lifetime
of everything else Portalguard installs.

The file is only ever allowed to choose **between states that share a phase**.
A bare lockdown and a sealed gap are byte-for-byte the same ruleset, so the file
gets to say which one it is; nothing else. A file claiming `GAP_OPEN` over a
ruleset that permits nothing is ignored, and a file left behind by a process
that died is discarded the moment the kernel reports `OFF`.

That ordering is why nothing has to guarantee the file gets cleaned up. **The
worst a stale snapshot can do is be ignored.** It is written best-effort for the
same reason the pf token is: refusing to lock a machine down because a
bookkeeping file would not write is the tail wagging the dog. Losing it costs
the hostnames, not the gap.

Two things follow that are easy to miss:

- **Widening had to be fixed underneath the state machine as well.** pf loads a
  table declaration as a *replacement*. A second process rendering its ruleset
  from an empty allow-list plus one new host would have evicted the portal
  address and the resolvers the first process pinned - the gap would appear to
  widen while actually moving, and the login page would go dead at the moment
  the user added the host meant to fix it. Recovering the allow-list from the
  kernel is what makes `allow` additive rather than destructive.
- **`allow <host>` installs no safety net.** Everywhere else, the process that
  engages the firewall releases it on the way out. Here the firewall belongs to
  another process, and a Ctrl-C between two hostnames must not tear down a
  lockdown this one never installed and cannot put back. Widening is additive
  and leaves nothing to unwind, so exiting without touching anything is the
  correct failure.

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

`NameWatcher` is the second optional capability, on the same reasoning:

```go
type NameWatcher interface { NamesSeen() []string }
```

It answers a different question at a different time. A report accounts for a
window that has closed; this is evidence about one still open, and it is worth
having only because the user can still act on it - a portal host missing from
the gap can still be added to it. What it returns is raw: lookups rather than
blocks, from every process on the machine, because the DNS hole is machine-
wide. `state.SuggestAllow` does the filtering, and is the only place the
"is this the portal's host" heuristic lives.

`Host` pins addresses, never names. A portal that controls DNS - which, per the
hijack check, it usually does - could otherwise repoint its own hostname after
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
than by rewriting the main ruleset on every lockdown - Apple's own comment in
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
| **`GAP_OPEN` is narrow** - portal reachable, everything else still blocked | **e2e Phase B1**: gateway reachable through the gap while a control host stays blocked |
| `SEALED` closes it again | e2e Phase B3 |
| Teardown leaves nothing behind | e2e Phase C: both tables empty, log device destroyed, network restored |
| Counters survive rule reloads | Integration test against a fake pfctl, driving the whole sequence |
| The machine recovers from a crash | Signal and panic handlers release; `make rescue` proven against an empty container |
| A second process widens a gap rather than replacing it | Unit test driving two backends against one fake kernel; live at BT Wi-Fi; and `make hotspot-demo` |
| A blank page's missing hosts are named, and only those | `make hotspot-demo`: `cdn` and `reg` suggested against an off-box portal, nothing else |
| The re-probe sees the login finish once the probe names resolve outside the gap | `make hotspot-demo`, through `<pg_check>` |
| A remembered host opens only after a live TLS check | `make hotspot-known`, against certificates the system trusts |
| Hostnames opened by `allow` survive into a later `remember` | `make hotspot-demo`, three separate processes |
| The handover lets VPN traffic out, nothing else, and closes on timeout | `make handoff-check`: a UDP packet to 51820 leaves, one to 9 does not, and 51820 is dropped again once the hole closes, seen on the wire |
| A VPN kill switch taking over the firewall is noticed, not missed | Live with NordVPN: its ruleset replaced ours on connect, and the handover reported it and cleaned up |
| A stale session file cannot claim a gap the ruleset denies | Unit tests over every phase/snapshot pairing |
| Detection survives a real portal | BT Wi-Fi, live: portal found, host pinned, non-standard port carried through, clean release |

## What is not proven

This section is the reason the document exists.

**The end-to-end test uses a gateway split.** A container runtime on macOS
cannot give a portal that is off-box from the Mac: published ports are bound by
a helper process *on the host*, and BSD routes every local address through
`lo0`. Since the lockdown ruleset must pass loopback traffic unconditionally -
without it, local IPC breaks and the machine is unusable - any test aimed at
the container would pass **without the gap rules doing anything at all**.

So the test is split. The pf half aims at the LAN gateway over `en0`, which is
genuinely off-box and has a real portal's topology. The portal-semantics half
aims at the container over `lo0`, where pf is not involved. Each half is
meaningful; neither is the whole claim.

**The off-box hotspot joins the two halves.** `testenv/hotspot/` runs a
BT-shaped portal across four containers under Apple's `container` tool, each
with its own address reached over `bridge100`, which pf filters like any other
interface. It exercises the portal semantics and pf together, with the default
probe list and the network's own DNS, and its first live runs found three bugs
every earlier test had passed: the re-probe and the remembered-host
certificate check were both dropped by the lockdown, and `allow` lost the
names of what it opened. See `testenv/README.md`, "The off-box hotspot".

**`GAP_OPEN` narrowness is proven by the e2e test, not by the demo.** This is
worth being precise about, because the two get conflated. The e2e test does
demonstrate it: the gateway is reachable through the gap while a control host
stays blocked, both over `en0`. The **demo** does not - it shows lockdown
versus no lockdown, on a VPN toggle, with no portal involved at all. Anyone
presenting the demo should not claim it shows the gap working.

**Not covered by anything yet:**

- A genuinely hostile network. The gateway cooperates: it does not hijack DNS,
  intercept probes, or drop packets. The hijack detection is unit-tested but
  has never met a real portal.
- A VPN client that actually depends on the handover hole. The hole's rules
  are proven on the wire, but neither VPN on the test machine uses it:
  NordVPN's kill switch takes the firewall over on connect, and the WireGuard
  app takes the default route before its handshake, so the handover steps
  aside first. An OpenVPN or IKEv2 client, which handshakes before taking the
  route, is the case still to run. Some clients also call their provider's API
  before connecting, which the hole does not allow.
- The DNS hole in `GAP_OPEN` is machine-wide. Background daemons do leak
  hostnames through it; Portalguard counts them and says so. Scoping the rule
  to the browser's user id, once the plan, cannot work on macOS, because every
  lookup is sent by `mDNSResponder`. The fix is a filtering resolver, v0.3.
- DHCP lease expiry mid-lockdown, IPv6-only networks, and roaming between
  networks while engaged.
- Linux and Windows. The packages exist with their designs recorded in the
  package docs. No rule has ever been programmed on either.

**The gap is one host wide, and real portals are not.** BT Wi-Fi spans four
hostnames across three ports; the gap opened for the first of each, and the
login page rendered blank because the script that reveals it was blocked.
`allow` is the answer and now works across processes, and `run` now names the
hosts being looked up that the gap does not include, so the user is not left
diagnosing a blank page with no internet. A network dealt with once can now be
remembered - `portalguard remember` saves what `allow` widened the gap with,
and the next visit tries those hosts automatically, but only the ones that
complete a fresh TLS handshake with a certificate valid for their name; DNS on
a hostile network proves nothing, so nothing here is opened on DNS's word
alone. All of it is proven against real pf and the off-box hotspot, and none of it
has been back to BT Wi-Fi since. What a real rogue access point does when it
meets the TLS check is still untested: the rejection is proven against a
self-signed server in a unit test, not live. The options, and the ones taken, are in
[`gap-scope.md`](gap-scope.md).

**Cross-process resume is field-tested.** `allow` widened a live gap from a
second terminal at BT Wi-Fi, and does so on every `make hotspot-demo`. What
the hotspot added was the proof that the names survive as well as the
addresses: `remember` in a third process saves the hosts `allow` opened.
