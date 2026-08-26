# The pf backend: anchor setup, rules, and how to get your network back

Read this before running `sudo portalguard lockdown`. A wrong rule here takes
your own machine off the network, and one of the failure modes below is worse
than that: rules that load successfully, do nothing, and leave you believing
you are protected when you are not.

Nothing in this document has been executed yet. The rule-programming calls in
`internal/firewall/pf` return `pending ruleset review` until this design is
signed off.

---

## 1. The anchor setup

### Why an anchor at all

Every rule Portalguard installs goes into a single pf anchor named
`portalguard`. An anchor is a named, nested ruleset: it can be loaded, listed
and flushed as a unit, and flushing it cannot affect anything else on the
system. That property is the whole basis of the fail-safe promise —
`pfctl -a portalguard -F all` is a complete, targeted undo.

The alternative, writing into the main ruleset, would mean our teardown had to
reconstruct whatever was there before. That is not a thing to get wrong at
2am in a hotel.

### The problem: stock pf.conf has no user anchor point

Your `/etc/pf.conf` is the macOS default, and it hooks exactly one anchor:

```
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
```

`pfctl(8)` puts it plainly: "Evaluation of anchor rules from the main ruleset
is described in `pf.conf(5)`." An anchor's rules are evaluated **only** where
the main ruleset references it. So this:

```fish
sudo pfctl -a portalguard -f my-rules.conf
```

succeeds, reports no error, stores the rules — and filters nothing at all,
because no `anchor "portalguard"` line exists for the kernel to reach them
through.

That is the dangerous failure mode. Rules that fail loudly are fine; rules
that load silently and never run would have Portalguard reporting
`LOCKED_DOWN` over an entirely open network. **Lockdown must verify the hook
exists and refuse to proceed without it**, rather than installing inert rules.
That check is `pfctl -sr` on the main ruleset, looking for our anchor line.

### The fix: one line in /etc/pf.conf, installed once

I recommend a deliberate one-time install rather than rewriting the main
ruleset at runtime. Two reasons:

- The risky operation happens once, when you are sitting at a working
  network and not depending on the tool. At runtime we only ever touch our
  own anchor.
- Apple's own comment in `pf.conf` warns: *"Care must be taken to ensure that
  the main ruleset does not get flushed, as the nested anchors rely on the
  anchor point defined here. In addition ... some system services would
  dynamically insert anchors into the main ruleset."* Reloading the main
  ruleset on every lockdown would drop those dynamically-inserted anchors
  each time. Doing it once is a much smaller blast radius.

An empty anchor filters nothing, so the hook is inert whenever Portalguard is
not running, including across reboots.

### The exact diff

```diff
--- /etc/pf.conf
+++ /etc/pf.conf
@@
 scrub-anchor "com.apple/*"
 nat-anchor "com.apple/*"
 rdr-anchor "com.apple/*"
 dummynet-anchor "com.apple/*"
+# BEGIN portalguard - anchor point, empty unless portalguard is running.
+# Remove this block, or run `sudo portalguard uninstall-anchor`, to revert.
+anchor "portalguard"
+# END portalguard
 anchor "com.apple/*"
 load anchor "com.apple" from "/etc/pf.anchors/com.apple"
```

Two things about the placement, both load-bearing:

- **It must come after the `nat-anchor` / `rdr-anchor` / `dummynet-anchor`
  lines.** pf requires rules in the order options, normalisation, queueing,
  translation, filtering. `anchor "portalguard"` is a filter anchor, so
  putting it any earlier is a parse error.
- **It comes before `anchor "com.apple/*"` on purpose.** Our lockdown rules
  use `quick`, so the first match wins and evaluation stops. Sitting first
  means our block genuinely blocks, and cannot be undercut by a `pass quick`
  inside the AirDrop or Application Firewall anchors that Apple populates
  dynamically underneath `com.apple`. When our anchor is empty this ordering
  changes nothing: evaluation falls straight through to `com.apple` exactly
  as it does today.

### Install and revert

`sudo portalguard install-anchor` will, in this order:

1. Copy `/etc/pf.conf` to `/etc/pf.conf.portalguard.bak` if that backup does
   not already exist.
2. Insert the marked block above.
3. Validate without loading: `pfctl -n -f /etc/pf.conf`. **If this fails,
   restore the backup and abort** — an invalid `pf.conf` is a bad thing to
   leave on disk for the next boot.
4. Load it: `pfctl -f /etc/pf.conf`.

`sudo portalguard uninstall-anchor` removes the marked block, validates, and
reloads.

To do it by hand, or to revert if the tool is not around:

```fish
sudo cp /etc/pf.conf.portalguard.bak /etc/pf.conf   # if the backup exists
sudo pfctl -n -f /etc/pf.conf                        # check it parses
sudo pfctl -f /etc/pf.conf                           # load it
```

Or edit `/etc/pf.conf` and delete the three lines between the `BEGIN
portalguard` and `END portalguard` markers.

A macOS update may replace `/etc/pf.conf` and take the hook with it. That is
harmless but means the next lockdown will refuse; re-run `install-anchor`.

### Enabling pf itself

pf is present but disabled by default on macOS, and it is shared. Portalguard
uses the reference-counted interface so it can never turn pf off underneath
something else that is using it:

```fish
sudo pfctl -E          # enable, prints "Token : <number>"
sudo pfctl -X <token>  # release *our* reference; pf stays on if others hold one
```

The token is parsed from `-E`'s output and released on teardown.

---

## 2. The rules

Two rulesets, one per phase. Each is generated in memory and loaded whole:

```fish
sudo pfctl -a portalguard -f -   # ruleset text on stdin
```

Loading a ruleset into an anchor is atomic — there is no moment where the old
rules are gone and the new ones have not arrived — so a phase change cannot
leak through a gap between rulesets. Nothing is ever written to disk.

One constraint that shapes both: **`set` statements are not legal inside an
anchor.** No `set block-policy drop`, no `set skip on lo0`. Everything has to
be expressed as ordinary rules, which is why loopback gets an explicit pass
and every block says `drop` for itself.

`quick` means first match wins and evaluation stops. Order matters, and it is
passes first, block last.

### LOCKED_DOWN

```pf
# 1. Loopback is never touched. Local IPC, the DNS resolver stub, anything
#    talking to 127.0.0.1 keeps working.
pass quick on lo0 all

# 2. DHCP, both directions. Without this the lease expires while we are
#    locked down and the network disappears underneath us - which looks
#    exactly like Portalguard having broken the machine. The inbound rule is
#    scoped to a single protocol and port pair the OS parses anyway.
#
#    Deliberately no DHCPv6 (udp 546/547). A stateful DHCPv6 lease could
#    expire mid-lockdown on an IPv6-heavy network, but captive portal networks
#    that use stateful DHCPv6 are close to nonexistent, and widening the hole
#    for a case nobody has hit is the wrong trade. If it ever bites, the fix
#    is two more lines here, mirroring these.
pass out quick inet proto udp from any port 68 to any port 67 no state
pass in  quick inet proto udp from any port 67 to any port 68 no state

# 3. IPv6 neighbour discovery and router advertisement, so the link stays
#    usable. Every other kind of IPv6 traffic falls through to the block
#    below, which is deliberate: IPv6 is where leaks like to hide, and a
#    portal that only speaks IPv6 does not exist in practice.
pass quick inet6 proto icmp6 all \
    icmp6-type { neighbrsol, neighbradv, routersol, routeradv } no state

# 4. Everything else, in and out, on every interface.
block drop out quick all
block drop in  quick all
```

What that permits, in full: loopback, DHCP renewal, IPv6 neighbour discovery.
Nothing else leaves the machine. No DNS, no NTP, no mail sync, no iCloud, no
mDNS/Bonjour, no AirDrop.

`block drop` rather than `block return`: a portal probing us learns nothing
from silence, and dropping is what a hostile network expects to see anyway.

Blocking inbound as well as outbound costs nothing here — we are on an
untrusted network for a few minutes — and stops the machine answering
anything on it. Return traffic for our own connections is unaffected, because
pf checks the state table before the ruleset, and the gap's pass rules keep
state.

### GAP_OPEN

The same ruleset with the portal's hole added. Addresses live in pf tables so
the rule text never changes shape, and so `pfctl -a portalguard -t pg_portal
-T show` answers "what exactly is open right now" directly from the kernel.

```pf
# Addresses pinned at detection time. Empty tables are legal and simply never
# match, so both families are always declared.
table <pg_portal> persist { 192.168.1.1 }
table <pg_dns>    persist { 192.168.1.1 }

pass quick on lo0 all

pass out quick inet proto udp from any port 68 to any port 67 no state
pass in  quick inet proto udp from any port 67 to any port 68 no state

pass quick inet6 proto icmp6 all \
    icmp6-type { neighbrsol, neighbradv, routersol, routeradv } no state

# 5. The gap itself: the portal's login page, on the portal's own addresses,
#    on web ports only. `keep state` so replies come back without needing an
#    inbound pass.
pass out quick inet  proto tcp to <pg_portal> port { 80, 443, 8080 } keep state
pass out quick inet6 proto tcp to <pg_portal> port { 80, 443, 8080 } keep state

# 6. DNS to the resolvers this network handed us, and only to them. The login
#    flow has to resolve the portal's own hostname, and on a locked-down
#    machine no other resolver is reachable. This is the widest part of the
#    gap - see "The DNS hole is machine-wide" below - and the reason GAP_OPEN
#    is meant to last a minute, not an hour. `log` sends matches to pflog0 so
#    every query made through the hole can be recorded and shown.
pass out log quick inet  proto { tcp, udp } to <pg_dns> port 53 keep state
pass out log quick inet6 proto { tcp, udp } to <pg_dns> port 53 keep state

block drop out quick all
block drop in  quick all
```

The portal port from detection is added to the port list when it is not
already 80 or 443 — the `8080` above is the test environment's.

Note what the gap does *not* include: no ICMP, no UDP except DNS to those
resolvers, no other host, no other port. A portal that needs more (a payment
provider on a second hostname is the usual case) gets it explicitly, via
`sudo portalguard allow <host>`, which adds to `<pg_portal>` and is visible in
`status`.

### The DNS hole is machine-wide

The DNS pass rule is the one part of the gap that deserves to be uncomfortable,
and the reason is not the exotic one.

The exotic risk is a DNS tunnel: an attacker exfiltrating data as query names
through the portal's resolver. Real, but it needs something already running on
the machine that wants to do that.

The ordinary risk is worse because it happens every single time. **The DNS hole
is machine-wide.** The moment it opens, every background process that has been
sitting on a failed lookup retries at once - Mail, iCloud, Dropbox, Calendar,
every app that noticed the new link. Their *connections* stay blocked by the
rules below, so no data leaves. But the *queries* go through, and the portal's
resolver learns the hostname of every service you use. Hostnames are metadata,
and metadata is most of what an observer on a hotel network wanted anyway.

Portalguard cannot honestly claim to prevent this in v0.1. What it will do is
make it visible:

- The DNS pass rules carry `log`, so pf copies matching packets to `pflog0`.
- A reader on `pflog0` records every query made while the gap is open and
  reports it when the gap closes: how many, to whom, and for what names.

So the seal message becomes something like *"gap open for 47 seconds; 23 DNS
queries leaked to 192.168.1.1 from 6 processes"* - concrete, honest, and the
best possible argument for keeping GAP_OPEN short. It also happens to be the
most persuasive thing this tool can put on a screen.

**Not yet implemented.** The `log` keyword is in the ruleset above; the
`pflog0` reader is the remaining piece of v0.1.

The real fix is v0.2 and it is narrow rather than visible. pf on macOS can
match on the uid owning an outbound socket:

```pf
pass out quick inet proto { tcp, udp } to <pg_dns> port 53 user 501 keep state
```

Scope the DNS and portal rules to the uid of the browser doing the login and
background daemons cannot reach the hole at all. That turns a machine-wide
hole into a one-process hole. It needs to know which process will do the
logging in, which is straightforward once there is a menu bar app that opens
the login page itself.

Addresses are **pinned at detection time**. The gap is written against the IPs
the portal resolved to when we probed, not against a hostname. Otherwise a
portal that controls DNS — which, per the hijack check, it usually does —
could point its own name anywhere it liked after we opened the hole.

### Seal

Seal reloads the LOCKED_DOWN ruleset, dropping the tables and the pass rules.
That closes the hole for new connections, but existing states created while
the gap was open would survive a rule change, so it also kills them:

```fish
sudo pfctl -k 0.0.0.0/0 -k <addr>   # once per address, see below
```

**"Once per pinned address" means the full contents of `<pg_portal>` and
`<pg_dns>` at seal time, not just the IP detection originally found.** If the
user ran `portalguard allow payments.example` because the portal bounced
through a payment provider, that address is in the table and must be killed
too - otherwise sealing leaves a live connection to a third party open, which
is precisely the leak the seal exists to close. The implementation reads the
tables back from the kernel rather than trusting its own bookkeeping.

Collateral is worth naming: on most home and hotel networks the portal *is*
the default gateway, so `-k 0.0.0.0/0 -k <gateway>` kills every state to the
gateway. That is fine here - while we are locked down nothing else should have
states to it - but it would not be fine if this ran outside a lockdown.

`-k` is documented as: "A network prefix length of 0 can be used as a
wildcard. To kill all states with the target host2: `pfctl -k 0.0.0.0/0 -k
host2`." It is not anchor-scoped, so it is aimed at single addresses rather
than used broadly.

### Release

```fish
sudo pfctl -a portalguard -F rules    # our filter rules
sudo pfctl -a portalguard -F Tables   # our address tables
sudo pfctl -X <token>                 # drop our pf enable reference
```

Deliberately **not** `-F states` in the programmatic path: flushing the state
table would drop every TCP connection on the machine, which is a rude
surprise when all you asked for was your network back. Stale states are
harmless once the rules are gone. The hand-typed rescue command below does use
`-F all`, because a human typing it at 2am wants maximum effect and does not
want to remember two flags.

### Still to verify, with sudo, before this is trusted

**Step 0, before anything else: have the exit plan in your hand.** Step 3 cuts
your network on purpose. The difference between a ten-second test and a
confused twenty minutes is whether the way out is already proven and already
typed.

```fish
make rescue    # against an empty anchor, right now, before step 1
```

It should print the flush and succeed against an anchor that has nothing in
it. That confirms the command, the sudo prompt and the anchor name are all
correct while you still have a working network to fix them on. Leave this
document or the terminal history open on your phone before step 3.

Then, in this order:

1. `sudo pfctl -sr` — confirm the anchor line appears in the main ruleset
   after install.
2. `sudo pfctl -a portalguard -n -f -` with each ruleset — parse only, loads
   nothing. Confirms in particular that an `inet6` rule referring to a table
   holding only IPv4 addresses is accepted rather than rejected at load.
3. `sudo pfctl -a portalguard -f -` with the LOCKED_DOWN ruleset, then
   immediately `sudo pfctl -a portalguard -s rules` to confirm it is really
   there, and `make rescue` to get back out.

Step 3 is the first command in this whole project that can take your network
away. Everything before it is inspection or parsing.

---

## 3. Living alongside NordVPN

### What Nord is doing on this machine

Right now: `NordVPN.app`, `com.nordvpn.macos.helper` (a privileged helper, so
it can program pf and the routing table), and `WireGuard.app` are all running,
and the default route points into `utun7` at `10.5.0.2`.

Nord's kill switch is the direct conflict. It works the same way Portalguard's
lockdown does — block everything, permit the tunnel — and two independent
tools both asserting "block everything except my thing" over the same
interface produce whichever result the rule ordering happens to give. That is
not something to reason about live on a hotel network.

### The v0.1 rule: don't fight it, refuse to run beside it

**v0.1 assumes Nord is fully disconnected during testing and use.** The
sequence Portalguard is built around puts it before the VPN, not beside it:
lock down, open the gap, log in, seal, *then* the VPN comes up, and at
`HANDED_OFF` our rules are gone entirely. There is no phase where both are
meant to be enforcing at once.

So lockdown will detect an active tunnel and refuse, rather than proceed and
produce an undiagnosable mess. The message should name the interface and say
what to do:

```
portalguard: utun7 is up and carrying the default route (10.5.0.2).
A VPN kill switch and portalguard's lockdown will fight over pf rules.
Disconnect the VPN first, then re-run. To override: --allow-active-vpn
```

`--allow-active-vpn` exists because refusing outright would make the tool
useless to anyone whose VPN is not Nord, but it is opt-in and loud.

### How to detect it, and how not to

Not by looking for an interface that is up. **Eight `utun` interfaces are UP
and RUNNING on this Mac right now** — `utun0` through `utun7`. Seven of them
are macOS's own: iCloud Private Relay, Back to My Mac, and friends. They are
up on every Mac, all the time, and a check for "any utun is UP" would refuse
to run on every machine in the world.

The test that actually distinguishes a VPN:

1. Read the default route's interface (`route -n get default`, or the routing
   table directly).
2. If it is a `utun`/`ipsec`/`ppp` interface **and** that interface has an IP
   address assigned, a tunnel owns this machine's traffic.

`utun7` passes both — it has `inet 10.5.0.2` and holds the default route.
`utun0`–`utun6` have no address at all and fail the first test.

Secondary signals worth logging but not deciding on: `com.nordvpn.macos.helper`
running, and any non-`com.apple` anchors in `pfctl -sa`.

### Two smaller interactions

**Nord's DNS looks like a hijack.** Your resolver is `100.64.0.2`, inside
`100.64.0.0/10` (CGNAT), which is exactly the range Portalguard's DNS check
treats as suspicious when a *probe hostname* resolves into it. The check only
flags the addresses public hostnames resolve *to*, not the resolver's own
address, so this does not misfire today. But if Nord's Threat Protection ever
answers `captive.apple.com` from CGNAT space, detection would report a hijack
that is really just the VPN. Another reason v0.1 tests with Nord off — and a
note for whoever adds "detect the portal from inside a half-up tunnel" later.

**Handoff is not leak-free yet.** `HANDED_OFF` releases our rules and then the
user brings the VPN up, which leaves a brief unprotected window — a smaller
version of the problem this tool exists to solve. The fix, for v0.2, is to
keep the lockdown in place and add a pass rule for the VPN's server endpoint,
so traffic goes from "blocked" to "blocked except the tunnel" to "the tunnel
handles it" with nothing open in between. That needs to know the VPN's
endpoint address, which for Nord means reading it from the live tunnel config.

---

## 4. Getting your network back

The one line, from any terminal, no Portalguard binary needed:

```fish
sudo pfctl -a portalguard -F all
```

That empties our anchor and nothing else. The anchor point stays in
`pf.conf`, inert.

Or, equivalently:

```fish
make rescue            # runs exactly that command
sudo portalguard release   # also drops our pf enable reference
```

`make rescue` exists so that recovery is one short thing you can type without
thinking, which is the state you will be in when you need it.

Where it is documented, so it can be found without this file:

- **README.md**, in the "Failing safe" section at the end — the last thing on
  the page.
- **`portalguard --help`**, as the closing line of the usage text.
- **The Makefile**, as `make rescue`, with a comment.
- Printed by `portalguard` itself whenever a release fails.

What catches what:

| How it dies                  | What happens                                     |
| ---------------------------- | ------------------------------------------------ |
| Normal exit, error, panic    | `firewall.Guard` releases before unwinding        |
| Ctrl-C, SIGTERM, SIGHUP, SIGQUIT | The safety net releases, then re-raises      |
| `kill -9`, kernel panic, power cut | Nothing automatic. `make rescue`, or reboot |
| Reboot                       | Rules are gone; nothing is persisted to disk      |

The last row is the point of never writing a ruleset to disk: the worst case
recovers by turning it off and on again.

A watchdog would close the `kill -9` gap — a detached helper, or a launchd
job, that flushes the anchor if the main process stops checking in. Worth
doing before this is something anyone else runs; not v0.1.

---

## 5. What needs sudo, and when

pf lives behind `/dev/pf`, which is root-only. There is no entitlement or
group that avoids it; that is the price of using pfctl instead of a Network
Extension for v0.1.

**Never needs sudo** — these are the ones you will run most:

| Command                     | Why it is safe                          |
| --------------------------- | --------------------------------------- |
| `portalguard detect`        | HTTP requests and DNS lookups only      |
| `portalguard version`       | —                                       |
| `make build`, `make test`   | —                                       |
| `go run ./testenv/portal-web` | Binds 8080, an unprivileged port      |

**Needs sudo, once, at install time:**

| Command                            | What it touches                          |
| ---------------------------------- | ---------------------------------------- |
| `sudo portalguard install-anchor`  | Backs up and edits `/etc/pf.conf`, reloads the main ruleset |
| `sudo portalguard uninstall-anchor`| Reverts that                             |

**Needs sudo, every time, because it programs pf:**

| Command                       | pfctl calls made                                    |
| ----------------------------- | --------------------------------------------------- |
| `sudo portalguard lockdown`   | `-sr` (verify hook), `-E`, `-a portalguard -f -`     |
| `sudo portalguard allow`      | `-a portalguard -f -`                                |
| `sudo portalguard seal`       | `-a portalguard -f -`, `-k`                          |
| `sudo portalguard release`    | `-a portalguard -F rules -F Tables`, `-X <token>`    |
| `sudo portalguard run`        | all of the above                                     |
| `sudo portalguard status`     | `-a portalguard -s rules` — read-only, but `/dev/pf` still needs root |
| `make rescue`                 | `-a portalguard -F all`                              |

`status` without sudo degrades honestly rather than failing: it reports the
backend and prints `pf requires root: re-run with sudo` instead of guessing.

A menu bar app cannot ask for sudo on every click, so v0.2 will need a
privileged helper installed via `SMAppService` — the same shape as
`com.nordvpn.macos.helper`. The CLI's `sudo` requirement is a v0.1 shortcut,
not the eventual design.

---

## Decisions, reviewed and settled

Four questions went to review. All four are settled; recording them here so
the reasoning survives the next person who wonders why.

1. **Anchor placed before `com.apple/*`.** Approved. While locked down you do
   not want AirDrop or the Application Firewall punching pass rules underneath
   you, and the empty-anchor case falls through unchanged, so there is no cost
   when the tool is idle.
2. **DHCP stays open during lockdown.** Approved as unavoidable and low risk:
   the inbound rule is scoped to one protocol and port pair the OS parses
   anyway. DHCPv6 is acknowledged in a comment rather than allowed for.
3. **DNS is the widest part of the gap.** Accepted, with the real leak named
   rather than the exotic one — see "The DNS hole is machine-wide". v0.1 ships
   the cheap mitigation: keep the gap short, log every query made through it,
   and report the count when the gap closes. The `user`-scoped rules that
   actually close it are v0.2.
4. **`--allow-active-vpn` as an opt-in escape hatch** rather than a hard
   refusal. Approved: a hard refusal punishes anyone whose VPN the detection
   misreads. Opt-in, loud, logged.

One framing to keep when this goes public: the handoff window in section 3 is
named rather than quietly ignored. An honest account of the leak that remains
is the thing that makes the account of the leaks we do close believable.
