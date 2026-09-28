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

v0.2. Two additions over v0.1:

- **The handover to your VPN.** v0.1 released every rule and then asked you
  to start the VPN, so everything queued on the machine went out in the clear
  until the tunnel came up. `run` now seals and then holds the lockdown with
  only VPN traffic allowed out, and steps aside the moment the tunnel carries
  your traffic. `handoff` does the same after a plain `lockdown`, on any
  network. See "Handing over to your VPN" below.
- **The portal's redirect chain.** Detection follows the portal's own
  redirects to its login page and pins every host on the way into the gap,
  instead of only the first.

Detection and the state machine work. The macOS pf backend is
implemented and verified on real hardware: both rulesets parse, `LOCKED_DOWN`
loads and genuinely blocks, and `make rescue` restores networking. The full
`LOCKED_DOWN -> GAP_OPEN -> AUTHENTICATED -> SEALED` cycle is e2e-tested
against a real portal and real pf.

The leak report's counter and hostname layers are real and e2e-tested.
Process attribution is implemented but confirmed not to work on this
platform for this rule shape (pf reports a fixed value instead of a real
pid), so the report says so rather than guessing - see "The leak report"
below.

The separate commands (`lockdown`, `allow`, `seal`, `release`) work across
processes, so `allow` can widen a gap from a second terminal while `run` waits
in the first. The live ruleset is the authority for that; a session file in
`/var/run` supplies only what pf cannot hold.

The whole flow also runs against an off-box, BT-shaped test portal
(`make hotspot-demo`, see `testenv/README.md`): four hosts on their own
addresses, which pf genuinely filters, unlike the loopback fixtures before it.
Its first runs found three bugs every earlier test had passed, all now fixed:
`run` could not see a login finish, remembered hosts could never open
themselves, and `allow` lost the names of what it opened.

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

**Three bookkeeping files in `/var/run`.** `portalguard.pf-token` holds pf's
reference token so any invocation can drop it, `portalguard.session` records
what the running session knows, so `allow` and `seal` work as separate
commands, and `portalguard.counters` carries the running packet totals across
the rule loads that reset pf's own. `/var/run` is cleared on reboot, which is
the point: no file outlives the rules it describes, and none of them is
trusted over the live ruleset.

## Quick start

```fish
make build

# Read-only. Never touches the firewall.
./bin/portalguard detect -v
```

### Install

`make build` leaves the binary at `./bin/portalguard`, which is fine for
trying it out. To run it as plain `portalguard` from anywhere, put it on your
PATH:

```fish
sudo make install
```

This copies the binary to `/usr/local/bin/portalguard`. Sudo is needed
because `/usr/local/bin` is root-owned on a stock Mac; `make uninstall`
removes it again. Everything else in this README works either way - just
swap `./bin/portalguard` for `portalguard` once it's installed.

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
[`testenv/README.md`](testenv/README.md). `make demo` runs the whole flow
against that fixture with nothing to type, and `make demo-allow` runs the
two-process version, where a separate `allow` widens the gap while `run`
waits. Both are shaped for recording with asciinema.

## Commands

| Command                | Root | What it does                                                   |
| ---------------------- | ---- | -------------------------------------------------------------- |
| `detect`               | no   | Classify the network. Changes nothing.                          |
| `check`                | no   | One HTTP request. Prints `internet: reachable` or `blocked`.    |
| `print-rules`          | no   | Show the firewall rules it would apply, without applying them.  |
| `status`               | no*  | Show what is currently being enforced. *Root, to read the rules.|
| `install-anchor`       | yes  | The one-line setup above. Once per machine.                     |
| `uninstall-anchor`     | yes  | Revert that.                                                    |
| `run`                  | yes  | The whole flow, blocking until you have logged in. Names portal hosts the gap is missing while it waits.|
| `lockdown`             | yes  | Block everything.                                               |
| `allow [host:port...]` | yes  | Open the gap for the detected portal, or widen it for named hosts.|
| `remember`             | yes  | Save what `allow` widened the gap with, so the next visit to this domain can try it automatically once it verifies. See below.|
| `seal`                 | yes  | Close the gap, keep the lockdown.                               |
| `handoff`              | yes  | Keep the lockdown, let only your VPN out, step aside once its tunnel is up.|
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
docs/gap-scope.md      how wide the gap should be, and why that is hard
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

One known limitation, detailed in [`docs/pf-design.md`](docs/pf-design.md):

- **The DNS hole in `GAP_OPEN` is machine-wide.** Background daemons' queued
  lookups fire at the portal's resolver the moment it opens. Connections
  stay blocked, but hostnames leak. Portalguard keeps the gap short and logs
  what went through. The fix once planned for v0.2, scoping the DNS rule to
  the browser's user id, cannot work on macOS: apps do not send their own DNS
  queries, they ask `mDNSResponder`, which sends them all as one system user.
  The real fix is a filtering resolver of Portalguard's own, planned for
  v0.3; see "The DNS hole is machine-wide" in `docs/pf-design.md`.

## Handing over to your VPN

After the seal, `run` does not release the lockdown and leave you to start
your VPN in the open. It keeps blocking everything except the VPN client's
own connection, waits for the tunnel, and releases only once the tunnel
carries your traffic:

```
Authenticated and sealed. Traffic is still blocked.

Connect your VPN now. Until its tunnel is up, only VPN traffic can leave.
Waiting up to 3m0s for the tunnel...

Your VPN is up on utun4. Portalguard has stepped aside; the VPN owns the connection.
```

By default the VPN hole is the standard ports of the common protocols, to
any address, since most clients pick their server when they connect:
WireGuard (UDP 51820, which is also NordLynx), OpenVPN (UDP and TCP 1194)
and IKEv2 (UDP 500 and 4500). If your VPN uses something else, name it:

```fish
sudo portalguard run -vpn vpn.example.net:443/tcp
sudo portalguard handoff -vpn 203.0.113.5:51820
```

TCP 443 is not in the default on purpose: open to any address, it would be
ordinary HTTPS for every app on the machine. Name your server instead.

The same works without a portal. On a network where you just want nothing
out until the VPN is back:

```fish
sudo portalguard lockdown
sudo portalguard handoff      # then connect the VPN
```

Some VPNs bring their own firewall. NordVPN, for one, replaces pf's whole
ruleset with its kill switch when it connects, which switches Portalguard's
rules off. Portalguard notices, and tells you the VPN's kill switch held the
line while it connected instead of claiming it did. It also stops the login
wait if anything switches its rules off mid-login, and `status` says whether
the lockdown is actually being applied.

If no tunnel comes up within `-wait` (3 minutes by default), the VPN hole
closes again and the lockdown stays. `-no-handoff` stops `run` at `SEALED`,
as v0.1 did.

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

## Tested against

Real networks it has been pointed at, and what happened. The lab has a fake
portal in `testenv/`; this table is the part that isn't a lab.

### BT Wi-Fi (Waitrose)

| | |
| --- | --- |
| Detection | **worked** - found `www.btwifi.com` from the probe redirect |
| Pinning | **worked** - `192.168.23.21` |
| Ports | **worked** - opened 80, 443 and 8443, taking the non-standard port out of the redirect rather than assuming defaults |
| Lockdown and gap | **worked** |
| Ctrl-C | **worked** - released cleanly |
| Logging in | **failed on the first trip**, worked on the second once the gap was widened |
| `allow` | **failed on the first trip**, worked on the second from a second terminal |
| Seal and release | **worked** - `AUTHENTICATED`, then `SEALED`, then released |

Two trips, and everything below came out of the first one. Both findings are
worth reading as warnings about the shape of the problem rather than as bugs
in a feature.

**The login page came up blank, not unstyled.** The page loaded fine - HTTP
200, the full HTML - but it ships hidden behind `.btwf-site { display: none }`
and is revealed by JavaScript from `cdn.btwifi.com`, which the gap did not
include. A blocked stylesheet gives you an ugly page you can still use; a
blocked script that owns `display` gives you a white rectangle with nothing on
screen to say which host to unblock. The portal spans four hosts and three
ports: `www.btwifi.com:8443` for the page, `cdn.btwifi.com` for all JS and CSS,
`reg.btwifi.com` for the auth POST, `info.btwifi.com:442` for the terms.

That's the ordinary shape of a portal built by people who build websites, so
none of it gets special-cased. The options for handling it, and the one taken,
are in [`docs/gap-scope.md`](docs/gap-scope.md).

Since that trip, `run` says which host is missing. DNS stays open while the gap
is, so every lookup this machine makes goes past the leak reader, the portal's
own included. While it waits for the login it prints the names that were looked
up and are not in the gap, narrowed to the ones sharing a domain with the
portal so the machine-wide DNS noise stays out of it:

```
Waiting up to 10m0s for the login to go through...

  Looked up but not open: cdn.btwifi.com, reg.btwifi.com
  If the login page is blank or broken, these are what to open:
    sudo portalguard allow cdn.btwifi.com reg.btwifi.com
```

It opens nothing. Which hosts end up in the gap stays a decision a person
makes, for the same reason the tool never types your credentials: on a network
that answers its own DNS - which, per the hijack check, it usually does -
"widen automatically" means the portal picks what goes in the hole.

That decision only has to be made once per network, though. After widening the
gap by hand:

```
sudo portalguard remember
```

saves `cdn.btwifi.com` and `reg.btwifi.com` against BT Wi-Fi's domain. The next
time the gap opens for that domain, `run` and `allow` both try those hosts
automatically - but only the ones that complete a real TLS handshake with a
certificate valid for their name, checked fresh against this network, on this
connection. DNS on a hostile network proves nothing, since whoever runs the
network answers it; a certificate does, since forging one takes the real
private key rather than control of DNS. A host that doesn't pass falls back to
being suggested, same as before. See
[`docs/gap-scope.md`](docs/gap-scope.md), option E, for the reasoning and its
limits - it ships pre-seeded with BT Wi-Fi's hosts, since that's the one this
project has actually diagnosed by hand; everything else accrues the same way,
`allow` then `remember`, once.

**`allow` couldn't widen the gap** - the command that exists for exactly this
situation was the one that didn't work. It failed with `cannot apply EXTEND_GAP
in state IDLE`, because the state machine lived in the `run` process and a
second invocation started from scratch. Fixed: the phase is now read back from
the loaded ruleset and the rest from a session file, so `allow` works from a
second terminal while `run` waits in the first:

```fish
# terminal 1
sudo portalguard run

# terminal 2, once the login page comes up blank
sudo portalguard allow cdn.btwifi.com reg.btwifi.com info.btwifi.com:442
```

A bare host opens 80 and 443; `host:port` opens that port instead. Note that pf
holds one port set for the whole gap, so a port opened for one host is open for
every host in it.

**Second trip, same hotspot: the full cycle worked.** Detection, lockdown, gap,
then `allow cdn.btwifi.com reg.btwifi.com` from a second terminal widening the
live gap while `run` waited in the first, then the login itself, then
`AUTHENTICATED`, `SEALED`, release. Those two hosts were the whole difference
between a blank rectangle and a working login page; `info.btwifi.com:442` is
only needed if you want to read the terms. So the cross-process fix and the
table-replacement fix are both confirmed on a real portal, not just against
the fake kernel.

One thing the trip broke, which is worth recording because it was caused by
the fix: the leak report came back saying "No traffic was accounted for."
pf's per-rule counters belong to the kernel, and *any* rule load resets them
for every process, not just the one doing the loading. Sampling banked them
into memory before each of its own reloads, which was enough while one process
owned the whole run. Once `allow` could reload from a second terminal, that
process banked the machine's counts into its own memory and exited with them,
leaving the waiting `run` to report zero. The running totals now live in
`/var/run/portalguard.counters`, so whichever process is about to reload banks
them where the next one can find them.

That report also asserted a cause it had never checked - it said the counters
"could not be read" for any empty result, including a truthful zero. It now
tracks how many samples were attempted and how many failed, and only blames
the measurement when the measurement actually failed.

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
clears everything: no rule is ever written to disk, and the `/var/run`
bookkeeping files go with it.

Full detail - the anchor setup, every rule line by line, and how Portalguard
stays out of NordVPN's way - is in [`docs/pf-design.md`](docs/pf-design.md).
