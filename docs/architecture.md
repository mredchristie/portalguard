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
| The handover lets VPN traffic out, nothing else, and closes on timeout | e2e PHASE E (and `make handoff-check`): a UDP packet to 51820 leaves, one to 9 does not, and 51820 is dropped again once the hole closes, seen on the wire |
| A VPN kill switch taking over the firewall is noticed, not missed | Live with NordVPN: its ruleset replaced ours on connect, and the handover reported it and cleaned up |
| pf can redirect this Mac's DNS to a local resolver | `make dns-spike`: queries straight at the router (UDP and TCP) and through mDNSResponder all diverted |
| With the DNS filter, nothing but the login's names reaches the network's resolver | `make hotspot-demo`: the hotspot's resolver heard only the login's names; 65 other lookups refused on the machine. The control (`DNS_FILTER=off`) leaked 20 names |
| The DNS filter holds on a real LAN, not only the hotspot | e2e PHASE F: 68 lookups refused, and pf counted no DNS leaving during the gap. PHASE B, filter off, leaked names in the same setup, NordVPN's own telemetry among them |
| The portal's own hosts open as the page asks for them, and nothing else does | `make hotspot-auto`: `cdn` and `reg` opened with no `allow`, the page rendered first time, a lookalike domain was refused, and the resolver heard nothing beyond the login's names |
| Auto-allow cannot reopen a sealed gap | Unit test: the seal closes auto-allow first, and an answer arriving after it opens nothing |
| Without the filter, auto-allow falls back to pf's log | Live against the hotspot with loopback skipped: `cdn` and `reg` opened from the log and the login completed |
| A leftover `set skip on lo0` is cleared before the gap | Live: `install-anchor`, and now `run`, flush and reload pf; Internet Sharing (started by the hotspot's containers) was found to be one source, NordVPN's kill switch the other |
| A remembered host is not opened on a lying DNS answer | `hotspot-demo.sh hostile-known`: cdn and reg pointed at an impostor with a self-signed certificate; both failed the check, stayed shut, and the login still completed |
| A malformed portal page cannot stop detection | `hotspot-demo.sh hostile`: an interception page leading with the bytes that once crashed it, and an empty refresh, still yields the real login |
| Auto-allow stops at 10 hosts, and nothing past the cap reaches the network | `hotspot-demo.sh hostile`: 15 more hosts asked for, 10 opened, the rest refused under every record type (the first run found their AAAA and HTTPS lookups leaking, now fixed) |
| A DNS name disguised as an allowed one is refused | `hotspot-demo.sh hostile`: one label spelling `cdn.guestwifi.test` got REFUSED |
| The parsers of untrusted input do not crash | `make fuzz`: six fuzz targets over DNS queries and replies, portal pages, redirect URLs and the site matcher; the four bugs they found are saved as regression inputs |
| pf redirects IPv6 DNS as well as IPv4 | `make dns-spike` on a network listing an IPv6 resolver: direct lookups to it over UDP and TCP both diverted |
| Armed: nothing leaks while a network is joined | `hotspot-demo.sh armed`: locked down on the home network, then joined the hotspot; detection went through the lockdown, 524 packets of join burst were held back, and the hotspot's resolver heard only detection and the login |
| The handover can start the VPN itself, through a hole one server wide | Live: `vpn use` a WireGuard tunnel, then `lockdown` and `handoff`: the hole was pinned to its server (`203.0.113.10:51820/udp`, read from macOS's own VPN settings), the tunnel was started by portalguard, came up on utun4, and the rules were released |
| A stale session file cannot claim a gap the ruleset denies | Unit tests over every phase/snapshot pairing |
| Detection survives a real portal | BT Wi-Fi, live: portal found, host pinned, non-standard port carried through, clean release |

## Armed mode

`arm` reverses `run`'s order: lock down, then detect. Detection through the
lockdown runs the DNS filter in probe mode (the probe names, the hijack
check's made-up `.invalid` name, and the login host once the probes name it;
nothing else), opens each probe answer as a check hole on 80 and 443 so the
probe can connect, and pins the login host without opening it. The ruleset
then goes back to a bare lockdown before the login's own gap, so no
detection hole carries over. The state machine has one new state, `ARMED`,
engaged like a lockdown: from it, detection leads only to `LOCKED_DOWN`.

A lockdown while already engaged keeps the running account, so the report
counts what the join burst tried to send. What armed detection does not do
is follow the portal's redirect chain: that needs connections to the portal,
which the lockdown refuses until the gap. A chain on the portal's own site is
caught by auto-allow; one elsewhere falls back to the suggestion.

Trusted networks are recognised by the gateway's hardware address, and trust
is acted on only when detection also finds open internet: a trusted router
with a login page in front of it is treated as a stranger.

## What is not proven

This section is the reason the document exists.

**Auto-allow has not met a real portal.** Every run so far is the hotspot,
whose login hosts sit neatly under one domain. A real portal may send its
login through a CDN on another domain, a payment provider, or a host whose
site `siteOf` gets wrong. Each of those falls back to the suggestion rather
than failing open, which is proven by unit tests; how often it happens on
real networks is not known yet.

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
- The DNS filter against a real portal. It is proven against the off-box
  hotspot; a real network adds resolvers that behave differently, and portals
  whose pages load third-party names that will be refused until allowed. It
  also runs only inside `run`. Lookups sent to an IPv6 resolver are caught
  and filtered (proven by `make dns-spike`), but what it lets out goes over
  IPv4, so an IPv6-only network gets no filter.
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
