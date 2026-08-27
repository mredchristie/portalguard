# Portalguard

Hold the line while you log in to a captive portal.

## The problem

A full-tunnel VPN and a captive portal cannot both go first. The VPN cannot
connect because the portal blocks everything until you have logged in, and
the portal's login page cannot load because the VPN has already claimed the
default route. Everyone's workaround is the same: turn the VPN off, log in,
turn it back on.

That gap is the problem. While it's open, the machine is on an untrusted
network with nothing in front of it - DNS queries go out in plaintext, mail
clients reconnect, iCloud/Dropbox/etc. start syncing, and anyone on the
network can see which services you use and often who you are.

Portalguard manages that gap instead of leaving it open: it detects the
portal, blocks all traffic, allows exactly the portal's login page through,
watches for the login to succeed, seals back up, and hands a clean connection
to your VPN.

**It never submits your credentials and never bypasses a portal's payment or
terms screen.** You log in yourself. Portalguard only controls the firewall
around that moment.

### Not the same thing as a Wi-Fi password

A WPA password typed into Wi-Fi settings is checked before you join the
network at all. Once you're on, the internet just works and your VPN
connects normally - there's no gap to manage.

A captive portal is different: you're already on the network, but a web page
blocks everything until you log in or click through, often on a network with
no Wi-Fi password at all (most hotel, cafe and train Wi-Fi). That's the
deadlock this tool exists for. Run `detect` if you're not sure which one
you're looking at - `OPEN_INTERNET` means there's nothing for Portalguard to
do.

## Status

v0.1, working. Detection and the state machine work. The macOS pf backend is
implemented and verified on real hardware: both rulesets parse, `LOCKED_DOWN`
loads and genuinely blocks, and `make rescue` restores networking. The full
`LOCKED_DOWN -> GAP_OPEN -> AUTHENTICATED -> SEALED` cycle is e2e-tested
against a real portal and real pf.

The leak report's counter and hostname layers are real and e2e-tested.
Process attribution is implemented but confirmed not to work on this
platform for this rule shape (pf reports a fixed value instead of a real
pid), so the report says so rather than guessing - see "The leak report"
below.

Linux and Windows are stubs: designs recorded, no implementation.

## What it changes on your Mac

macOS ships with a firewall in the kernel called **pf**. It's off by
default, has no UI, and Portalguard drives it from the command line.

**Rules live in a named box.** pf lets a tool put its rules in a labelled
container of its own - an *anchor*. Portalguard's is called `portalguard`.
Emptying that box removes every rule Portalguard has ever added and touches
nothing else on the system - that's the whole basis of the recovery story
below.

**The box has to be plugged in once.** `install-anchor` adds a single line
to `/etc/pf.conf` pointing at Portalguard's box. That line does nothing
unless Portalguard is running. It backs up the original file first, and
`uninstall-anchor` restores it.

If that line is missing, rules load fine and filter *nothing* - Portalguard
would report the machine locked down while it's wide open. So it checks for
the line every time and refuses to start without it.

## Quick start

```fish
make build

# Read-only. Never touches the firewall.
./bin/portalguard detect -v
```

Before anything can program the packet filter, once per machine:

```fish
sudo ./bin/portalguard install-anchor
```

`sudo ./bin/portalguard uninstall-anchor` undoes it.

Exit codes make it scriptable:

| Code | Meaning         |
| ---- | --------------- |
| 0    | `OPEN_INTERNET` |
| 10   | `PORTAL`        |
| 20   | `NO_NETWORK`    |
| 1    | error           |

```fish
if ./bin/portalguard detect > /dev/null
    echo "clear to bring the VPN up"
end
```

Test it against a fake portal without leaving the house - see
[`testenv/README.md`](testenv/README.md).

## Commands

| Command                | Root | What it does                                                   |
| ---------------------- | ---- | -------------------------------------------------------------- |
| `detect`               | no   | Classify the network. Changes nothing.                          |
| `print-rules`          | no   | Show the firewall rules it would apply, without applying them.  |
| `status`               | no*  | Show what is currently being enforced. *Root, to read the rules.|
| `install-anchor`       | yes  | The one-line setup above. Once per machine.                     |
| `uninstall-anchor`     | yes  | Revert that.                                                    |
| `run`                  | yes  | The whole flow, blocking until you have logged in.              |
| `lockdown`             | yes  | Block everything.                                               |
| `allow [host]`         | yes  | Open the gap for the detected portal, or widen it for a host.   |
| `seal`                 | yes  | Close the gap, keep the lockdown.                               |
| `release`              | yes  | Tear everything down. The escape hatch.                         |

## How it decides

Detection probes plain-HTTP endpoints with known-good responses - Apple's
`hotspot-detect.html` and Google's `generate_204` by default, configurable
with `-probe` or `-probes-file`. Plain HTTP is deliberate: a portal has to
intercept the probe to be detected, which it can't do to HTTPS without a
certificate error.

Interception is recognised from a redirect, an RFC 6585 `511`, a
meta-refresh/JS bounce page, or a substituted body. Whichever probe carried
the portal's address becomes the host the gap is opened for, pinned to the
IPs it resolved to at that moment, so the portal can't widen its own hole
later by changing DNS.

Two independent checks look for a hijacked resolver: a random `.invalid`
name that must not resolve (and does, on a hijacking network), and probe
hostnames resolving to private/CGNAT/link-local addresses, which
`captive.apple.com` never legitimately does.

When probes disagree (some portals whitelist one well-known endpoint), the
verdict is `PORTAL`. Locking down unnecessarily is recoverable; the other way
round isn't.

## States

```
IDLE ──detect──> DETECTING ──portal found──> PORTAL_FOUND ──lockdown──> LOCKED_DOWN
                     │                                                        │
                no portal                                                 open gap
                     │                                                        v
                     v                                                    GAP_OPEN
                   IDLE                                            (portal host + DNS only;
                                                                    you log in here)
                                                                              │
                                                                       re-probe succeeds
                                                                              v
HANDED_OFF <──hand off── SEALED <──seal── AUTHENTICATED
```

`RELEASE` is legal from every state and returns to `IDLE`. Anything not in
the transition table is rejected, so the traffic-leaking move (opening a gap
before the lockdown) can't be reached.

Authentication is only ever concluded from a successful re-probe. Portalguard
doesn't believe the portal's own "you are connected" page.

## Layout

```
cmd/portalguard/       CLI
internal/portal/       detection: probes, classification, DNS hijack checks
internal/state/        the state machine, and the session that wires it up
internal/firewall/     backend interface, host types, fail-safe teardown
  pf/                  macOS, via pfctl anchors
  nftables/            Linux (stub)
  wfp/                 Windows (stub)
  backend/             build-tagged selection
testenv/               a fake captive portal to test against
docs/architecture.md   how the pieces fit, and what is proven
docs/pf-design.md      the firewall rules, explained line by line
docs/demo.md           reproducing the leak, and redacting the capture
```

## Running alongside a VPN

Portalguard is designed to run **before** your VPN, not beside it. A VPN
kill switch does the same job as the lockdown (block everything, permit the
tunnel), and two tools each asserting "block everything except my thing"
over one interface produce whatever the rule ordering happens to give.

So every command that engages the firewall refuses when a tunnel owns the
default route:

```
portalguard: utun7 (10.5.0.2) is up and carrying the default route (gateway 10.5.0.2).

A VPN kill switch and portalguard's lockdown will fight over pf rules.
portalguard is meant to run before the VPN, not beside it.

Disconnect the VPN first, then re-run.
To override anyway: --allow-active-vpn
```

Detection requires all three of: the default route leaves through the
interface, the name is tunnel-shaped, and the interface has an address. The
last rules out macOS's own permanently-up, addressless `utun` devices, of
which there are usually seven.

Two known limitations, detailed in [`docs/pf-design.md`](docs/pf-design.md):

- **The DNS hole in `GAP_OPEN` is machine-wide.** Background daemons' queued
  lookups fire at the portal's resolver the moment it opens. Connections
  stay blocked, but hostnames leak. v0.1 keeps the gap short and logs what
  went through; v0.2 will scope the rules to the browser's uid.
- **The handoff window isn't closed yet.** `HANDED_OFF` releases our rules
  before you bring the VPN up, leaving a brief unprotected moment - a
  smaller version of the problem this tool exists to solve.

## The leak report

When the gap closes, Portalguard says what went through it, in whichever of
three states it can actually back up:

- **Counters alone**, when pflog can't be read: packet/byte counts to the
  portal's IP, no hostnames.
- **Hostnames**, from a real run: `tcpdump`'s own DNS decode on a dedicated
  `pflog1` device, e.g. `Hostnames queried: ssl.gstatic.com,
  imap.mail.me.com`.
- **Hostnames and processes**, when pf attributes a query to a real pid -
  not the case on this machine today. `pf(4)`'s `log (user)` option doesn't
  populate a real per-packet pid for this rule shape (`pass ... keep state`);
  it reports a fixed value on every packet regardless of sender. Confirmed
  against ground truth, not inferred - see
  [`docs/pf-design.md`](docs/pf-design.md), "Resolved: pid 100000 is a
  kernel sentinel, not a misread".

The report never claims more than it can verify: it distinguishes "the
kernel didn't say" from "we couldn't tell", and it won't show a process name
it can't stand behind. If a future run hits a genuine parse problem or a
heuristic trips, `sudo portalguard run -verbose` says which.

`sudo portalguard run -redact` turns hostnames into broad categories
(`mail (1 hostname), other (1 hostname)`) so a report can be shared without
naming your providers or accounts. Full detail is the default for reading on
your own machine.

## Seeing it for yourself

You don't need a hotel to reproduce the leak - it's the VPN going down that
causes it, not the portal itself. The instant traffic stops going through
the tunnel, background apps notice and reconnect, and their DNS goes out in
the clear. A captive portal just holds you in that state longer.

Measured on the development machine, toggling the VPN off on ordinary Wi-Fi:

| | DNS packets captured on `en0` |
| --- | --- |
| VPN toggled off, no Portalguard | **178, in plaintext** |
| Portalguard locked down | **0** |

The zero isn't just an empty capture: tcpdump reported 128 packets reaching
the filter during the locked-down window (so the capture was live), and
pf's own block counters showed 1948 outbound / 187 inbound packets dropped
in the same window (so the firewall was actively stopping them, not just
absent from a quiet network):

```fish
sudo pfctl -a portalguard -s rules -v
```

That block counter is what actually proves it - a packet sniffer can't see
what the filter drops before the capture point, only what gets out.

Caveats: the 178 and 1948 numbers aren't the same measurement (DNS-only vs.
all protocols) and the two windows weren't equal length, so don't compare
them as a ratio. And this demonstrates lockdown, not the gap itself - that
`GAP_OPEN` lets only the login page through is what the end-to-end test
covers (see [`docs/architecture.md`](docs/architecture.md)).

**Handling a capture of your own:** the file contains real hostnames your
machine reaches for, so treat it as personal. `.gitignore` excludes
`*.pcap`, `*.pcapng` and `pg-demo/` so a stray capture can't be committed.
Before showing anyone, replace names with categories, not products
(`<mail provider>`, not the brand). Full procedure in
[`docs/demo.md`](docs/demo.md).

## A warning you can ignore

Every rule load prints this, and it's not an error:

```
Use of -f option, could result in flushing of rules
present in the main ruleset added by the program,
e.g. portmap or SecurityAgent
```

It prints on every rule load, including Portalguard's, which only ever
writes into its own box. Nothing has gone wrong.

pf also rewrites and reorders rules as it loads them, so to see what's
actually enforced, ask the kernel rather than reading the generated text:

```fish
sudo pfctl -a portalguard -s rules
```

## Failing safe

The rule that outranks everything else: **if Portalguard dies, your network
comes back.**

- Every rule lives inside Portalguard's own box. Emptying it is a complete
  undo that can't affect anything else on the system.
- No rule is ever written to disk, so nothing Portalguard enforces can
  survive a reboot. (The one-line setup in `/etc/pf.conf` does persist, but
  it only points at an empty box.)
- A signal handler releases the rules on SIGINT, SIGTERM, SIGHUP and SIGQUIT,
  and a panic while the firewall is engaged releases before it unwinds.
- pf is shared with the rest of the system. Portalguard switches it on
  through a reference count and only ever releases its own claim - it can
  never switch pf off underneath something else using it.

`SIGKILL` and a power cut are the cases no handler can catch. For those, one
command gets your network back, no portalguard binary needed:

```fish
make rescue
```

which is exactly `sudo pfctl -a portalguard -F all`. `sudo portalguard
release` does the same and also drops the pf enable reference. A reboot also
clears everything, since nothing is persisted.

Full detail - the anchor setup, every rule line by line, and how Portalguard
stays out of NordVPN's way - is in [`docs/pf-design.md`](docs/pf-design.md).
