# Portalguard

Hold the line while you log in to a captive portal.

## The problem

A full-tunnel VPN and a captive portal cannot both go first. The VPN cannot
connect because the hotel's portal blocks everything until you have logged in,
and the portal's login page cannot load because the VPN has already claimed the
default route and is sending every packet into a tunnel that has not come up.
The deadlock has one obvious way out, and everybody takes it: turn the VPN off,
log in, turn it back on.

That gap is the whole problem. In the seconds or minutes it is open, the
machine is on an untrusted network with nothing in front of it, and it does not
sit quietly. DNS queries go out in plaintext. Mail clients reconnect. iCloud,
Dropbox and a dozen background agents notice the new link and start syncing.
Anyone on that network — and on open Wi-Fi that is everyone — sees which
services you use, which hosts you resolve, and often enough who you are. The
irony is exact: you disabled the VPN in order to get to the network you needed
the VPN for.

Portalguard manages that gap instead of leaving it open. It detects the portal,
blocks all traffic, allows exactly the portal's login page through, watches for
the login to succeed, seals back up, and hands a clean connection to your VPN.

**It never submits your credentials and never bypasses a portal's payment or
terms screen.** You log in yourself. Portalguard only controls the firewall
around that moment.

### Not the same thing as a Wi-Fi password

A network that asks for a WPA password in your Wi-Fi settings has nothing to
do with Portalguard. That password is checked before you join the network at
all — once you're on, the internet just works and your VPN connects normally.
There is no gap to manage.

A captive portal is different: you're already on the network, but a web page
blocks everything until you log in or click through, often on a network with
no Wi-Fi password at all (most hotel, café and train Wi-Fi). That's the
deadlock this tool exists for. Run `detect` if you're not sure which one
you're looking at — `OPEN_INTERNET` means there's nothing for Portalguard to
do here.

## Status

v0.1, working. Detection and the state machine work. The macOS pf backend is
implemented and verified on real hardware: both rulesets parse, `LOCKED_DOWN`
loads and genuinely blocks, and `make rescue` restores networking. The full
`LOCKED_DOWN → GAP_OPEN → AUTHENTICATED → SEALED` cycle is e2e-tested against
a real portal and real pf. The leak report's counter and hostname layers are
real and e2e-tested; process attribution is implemented, and confirmed not
to work on this platform for this rule shape — pf reports a fixed value
instead of a real pid, verified against ground truth — so the report says
so rather than guessing. See "The leak report" below.
Linux and Windows are stubs with their designs recorded but no
implementation.

## What it changes on your Mac, in plain terms

macOS ships with a firewall in the kernel called **pf**. It is off by default,
it has no user interface, and most people never touch it. Portalguard drives it
from the command line.

Two ideas are worth knowing before you install anything, because everything
else follows from them:

**Rules live in a named box.** pf lets a tool put its rules in a labelled
container of its own — the term is an *anchor* — instead of mixing them in with
everyone else's. Portalguard's is called `portalguard`. Emptying that box
removes every rule Portalguard has ever added and touches nothing else on the
system. That is the whole basis of the recovery story further down: one
command, and your network is back.

**The box has to be plugged in once.** A stock Mac has nowhere for a third
party's rules to hang, so `install-anchor` adds a single line to
`/etc/pf.conf` — the file macOS reads at boot — pointing at Portalguard's box.
The box is empty unless Portalguard is running, so that line does nothing at
all the rest of the time. It backs up the original file first, and
`uninstall-anchor` puts it back.

This matters more than it sounds: if that line is missing, rules load fine and
filter *nothing*. Portalguard would report that your machine is locked down
while it is wide open. So it checks for the line every time and refuses to
start without it, rather than protecting you in name only.

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

That is the one-line change described above. You only ever do it once, and
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

Test it against a fake portal without leaving the house — see
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

Detection probes plain-HTTP endpoints whose untampered responses are known —
Apple's `hotspot-detect.html` and Google's `generate_204` by default,
configurable with `-probe` or `-probes-file`. Plain HTTP is deliberate: a
portal has to be able to intercept the probe, which it cannot do for HTTPS
without a certificate error.

Interception is recognised from a redirect, an RFC 6585 `511`, a meta-refresh
or JavaScript bounce page, or a substituted body where a known one was
required. Whichever of those carried the portal's address becomes the host the
gap is opened for, and it is pinned to the IPs it resolved to at that moment,
so a portal cannot widen its own hole later by changing its DNS answer.

Two independent checks look for a hijacked resolver: a random name under the
reserved `.invalid` TLD, which must not resolve and does on a hijacking
network, and probe hostnames resolving to private, CGNAT or link-local
addresses, which `captive.apple.com` never legitimately does.

When probes disagree — some portals whitelist one well-known endpoint — the
verdict is `PORTAL`. Locking down when you did not need to is the recoverable
mistake; the other way round is not.

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

`RELEASE` is legal from every state and returns to `IDLE`. Anything not in the
transition table is rejected, so the move that would leak traffic — opening a
gap before the lockdown — cannot be reached.

Authentication is only ever concluded from a successful re-probe. Portalguard
does not believe the portal's own "you are connected" page.

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

Portalguard is designed to run **before** your VPN, not beside it. A VPN kill
switch works the same way the lockdown does — block everything, permit the
tunnel — and two tools independently asserting "block everything except my
thing" over one interface produce whatever the rule ordering happens to give.

So every command that engages the firewall refuses when a tunnel owns the
default route:

```
portalguard: utun7 (10.5.0.2) is up and carrying the default route (gateway 10.5.0.2).

A VPN kill switch and portalguard's lockdown will fight over pf rules.
portalguard is meant to run before the VPN, not beside it.

Disconnect the VPN first, then re-run.
To override anyway: --allow-active-vpn
```

The detection needs all three of: the default route leaves through the
interface, the name is tunnel-shaped, and the interface has an address. Only
the third rules out macOS's own permanently-up `utun` devices — there are
usually seven of them, addressless, and a naive check would refuse to run on
every Mac.

Two honest limitations, both in [`docs/pf-design.md`](docs/pf-design.md):

- **The DNS hole in `GAP_OPEN` is machine-wide.** Every background daemon's
  queued lookups fire at the portal's resolver the moment it opens. Their
  connections stay blocked, but the hostnames leak. v0.1 keeps the gap short
  and logs what went through it; v0.2 scopes the rules to the browser's uid.
- **The handoff window is not closed yet.** `HANDED_OFF` releases our rules and
  then you bring the VPN up, which leaves a brief unprotected moment — a
  smaller version of the problem this tool exists to solve.

## The leak report

When the gap closes, Portalguard says what went through it. The report has
three honest states, and it only ever moves toward saying more once it has
actually verified that much:

**Counters alone**, when pflog can't be read at all:

```
46 packets (4.8 kB) went out through the DNS hole, to 192.168.0.1.
That is packets, not lookups: a query and its reply are counted separately.
Which hostnames were asked for, and by which processes, is not known:
that needs packet logging, which was not available for this run.
```

**Hostnames, from a real run** (`tcpdump`'s own DNS decode, reading a
dedicated `pflog1` device — no packet capture beyond that, and reading it
needs no root):

```
26 packets (2.8 kB) went out through the DNS hole, to 192.168.0.1.
That is packets, not lookups: a query and its reply are counted separately.
Hostnames queried: ssl.gstatic.com, imap.mail.me.com
The kernel did not attribute these queries to a process.
```

**Hostnames and processes**, when pf actually attributes a query to a real
pid. Not the case on this machine today — see below.

The numbers always come from pf's own per-rule counters — no packet capture,
nothing to install, nothing that can be unavailable. Hostnames are one layer
past that: real, working, e2e-tested against a real gap. Process attribution
(*which app* asked) is a third layer past hostnames, and **on this machine
it confirmed, rather than found a bug to fix**: `pf(4)`'s `log (user)`
option is real and documented, but on this rule shape (`pass ... keep
state`, matching the pf backend's DNS gap rules exactly) it does not
populate a real per-packet pid at all — it reports a fixed value
unconditionally, every packet, regardless of which process actually sent it.
That was confirmed against ground truth, not inferred: a capture fired three
DNS queries from processes whose real pids were captured via `$!` before pf
or `tcpdump` ever saw the packet, and none of those three real pids ever
appeared in what pf logged. See [`docs/pf-design.md`](docs/pf-design.md),
"Resolved: pid 100000 is a kernel sentinel, not a misread", for the full
capture.

The report distinguishes this from an actual read failure — *"the kernel
did not say"* is a different and more useful claim than *"we could not
tell"*, and collapsing them would hide which one is actually true. If a
future run instead hits a genuine parse problem (the reverse-engineered
struct offsets breaking on some future macOS) or the heuristic that catches
one process attributed to implausibly many hostnames, `sudo portalguard run
-verbose` prints which, tagged `[parse]` or `[heuristic]` — those two need
opposite fixes, and the report text itself stays free of that detail by
design either way.

**The report never claims to know more than it does**, in either direction.
The DNS hole in `GAP_OPEN` is machine-wide, so background daemons do fire
lookups through it, and every number and hostname above is real, not a
sample. What it does not do is show an empty list that reads like an
all-clear, and it does not show a process name it cannot stand behind either.

**`-redact` generalises hostnames for sharing.** `sudo portalguard run
-redact` turns `Hostnames queried: imap.mail.me.com, ssl.gstatic.com` into
`Hostnames queried: mail (1 hostname), other (1 hostname)` — broad categories
instead of the literal domains, so a report can be pasted into a bug report
or a chat without naming your mail provider or your accounts. The default
stays full detail, for reading on your own machine.

## Seeing it for yourself

You do not need a hotel to reproduce the leak. **It is not the portal that
causes it — it is the tunnel going down.** The instant your traffic stops going
through the VPN, every background app that was waiting notices and reconnects,
and its DNS goes out in the clear on whatever network you are on. A captive
portal only makes it worse, by holding you in that state for minutes instead of
seconds.

So you can demonstrate it on your own Wi-Fi with a VPN toggle. Measured on the
development machine:

| | DNS packets captured on `en0` |
| --- | --- |
| VPN toggled off, no Portalguard | **178, in plaintext** |
| Portalguard locked down | **0** |

Every one of those 178 packets carried the name of a service the machine uses,
handed to whoever runs the network.

### Why the zero is not the evidence

An empty capture proves nothing on its own. It looks exactly like a quiet
machine, or like a capture that was never running. Two other numbers are what
turn it into evidence.

**The capture was live.** tcpdump reported 128 packets reaching the filter
during the locked-down window and none of them matching. The interface was
carrying traffic; the zero is not an artefact of a dead capture.

**The firewall was actively dropping.** During the same window, the block rules
counted:

```
1948 outbound packets  (1,096,096 bytes)  dropped
 187 inbound packets   (   38,542 bytes)  dropped
```

Read the counters before releasing, because releasing clears them:

```fish
sudo pfctl -a portalguard -s rules -v
```

That third number is the one that matters. Blocked outbound packets never reach
the interface — the filter drops them before the capture point — so a packet
sniffer *cannot* see what was stopped. It can only see what got out. The
counter is the sole witness to the traffic that did not.

Absence of evidence and evidence of absence are different claims. The empty
capture, the live-filter count, and the block counter together support the
second one. Any of them alone does not.

### What these numbers are not

Two things to be straight about when showing this, because both are easy to
overstate:

**178 and 1948 are not the same measurement.** The 178 is DNS only — the
capture filter discards everything else in the kernel. The 1948 is every
outbound packet of every protocol the firewall stopped: DNS, but also TCP
retries, mDNS, NTP, sync traffic, and anything else that tried. It is not a
larger version of the 178, and presenting it as one would be a sleight of hand.

**The two windows were not recorded as equal length.** The counts above are
each true of their own window, and none of the reasoning here rests on
comparing their rates. Treat them as two observations, not a ratio.

### What it does not show

**This demonstrates lockdown, not the gap.** It compares "firewall engaged"
against "no firewall", on a VPN toggle, with no captive portal involved at any
point. It says nothing about the harder claim — that `GAP_OPEN` lets the login
page through and nothing else. That claim is demonstrated by the end-to-end
test, which reaches a real off-box host through the gap while a control host
stays blocked. See [`docs/architecture.md`](docs/architecture.md).

### Handling the capture

That file contains the hostnames *your* machine reaches for — mail, cloud
storage, messaging. Treat it as personal. The `'udp port 53'` filter is applied
by the kernel so nothing else is ever written to disk, and `.gitignore`
excludes `*.pcap`, `*.pcapng` and `pg-demo/` so a stray capture cannot be
committed.

Before showing anyone, replace every name with a **category, not a product** —
`<mail provider>`, not the brand; `<mail client>`, not the application. Only
the redacted summary belongs in the repo. Full procedure:
[`docs/demo.md`](docs/demo.md).

## A warning you can ignore

Every rule load prints this, and it is not an error:

```
Use of -f option, could result in flushing of rules
present in the main ruleset added by the program,
e.g. portmap or SecurityAgent
```

It is printed on every rule load, including Portalguard's — which only ever
write into their own box and cannot touch anything else. Nothing has gone
wrong.

One related thing worth knowing: **pf rewrites and reorders rules as it loads
them**, so if you want to know what is actually being enforced, ask the kernel
rather than reading the generated text:

```fish
sudo pfctl -a portalguard -s rules
```

## Failing safe

The rule that outranks everything else: **if Portalguard dies, your network
comes back.**

- Every rule lives inside Portalguard's own box. Emptying it is a complete
  undo, and it cannot affect anything else on the system.
- No rule is ever written to disk. Rules are handed to the kernel directly, so
  nothing Portalguard enforces can survive a reboot. (The one-line setup in
  `/etc/pf.conf` does persist — but it only points at an empty box, so it
  enforces nothing on its own.)
- A signal handler releases the rules on SIGINT, SIGTERM, SIGHUP and SIGQUIT,
  and a panic while the firewall is engaged releases before it unwinds.
- pf is shared with the rest of the system, so Portalguard switches it on
  through a reference count and only ever releases its own claim. It can never
  switch pf off underneath something else that is using it.

`SIGKILL` and a power cut are the cases no handler can catch. For those, one
line gets your network back:

```fish
make rescue
```

which is exactly:

```fish
sudo pfctl -a portalguard -F all
```

No portalguard binary needed, safe to run when nothing is installed, and it
touches nothing on the system but our own anchor. `sudo portalguard release`
does the same and also drops our pf enable reference.

A reboot also clears it, since nothing is persisted.

Full detail — the anchor setup, every rule line by line, and how Portalguard
stays out of NordVPN's way — is in [`docs/pf-design.md`](docs/pf-design.md).
