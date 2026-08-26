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

## Status

v0.1, in progress. Detection and the state machine work. The macOS pf backend
is implemented and verified on real hardware: both rulesets parse, `LOCKED_DOWN`
loads and genuinely blocks, and `make rescue` restores networking. Still to
come in v0.1 — the full `LOCKED_DOWN → GAP_OPEN → AUTHENTICATED → SEALED` cycle
driven end to end against the test portal, and the `pflog0` reader behind the
DNS leak log. Linux and Windows are stubs with their designs recorded but no
implementation.

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

That adds one line to `/etc/pf.conf`. Stock macOS has no user anchor point, and
without it every rule Portalguard loads would be stored and silently ignored —
so lockdown checks for it and refuses rather than pretend. `sudo portalguard
uninstall-anchor` reverts it; the original is backed up to
`/etc/pf.conf.portalguard.bak`.

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
| `print-rules`          | no   | Print the pf ruleset without loading it.                        |
| `status`               | no*  | Show the backend and what it is enforcing. *Root to read pf.    |
| `install-anchor`       | yes  | Add the anchor point to `/etc/pf.conf`. Once per machine.       |
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
docs/pf-design.md      the pf ruleset, explained line by line
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

## A warning you can ignore

Every rule load prints this, and it is not an error:

```
Use of -f option, could result in flushing of rules
present in the main ruleset added by the program,
e.g. portmap or SecurityAgent
```

pfctl prints it on any `-f`, including the anchor-scoped loads Portalguard uses,
which cannot touch the main ruleset at all. Nothing has gone wrong.

One related thing worth knowing: **pf reorders rules as it loads them**, so
`sudo pfctl -a portalguard -s rules` is the authoritative account of what is
being enforced. The generated text is only the request.

## Failing safe

The rule that outranks everything else: **if Portalguard dies, your network
comes back.**

- Every rule lives inside one pf anchor. `pfctl -a portalguard -F all` is a
  complete undo, and it cannot affect anything else on the system.
- The main pf ruleset and `/etc/pf.conf` are never edited, so nothing survives
  a reboot.
- A signal handler releases the rules on SIGINT, SIGTERM, SIGHUP and SIGQUIT,
  and a panic while the firewall is engaged releases before it unwinds.
- pf is enabled through its reference-counted interface (`pfctl -E` / `-X`), so
  Portalguard never disables pf out from under another user of it.

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
