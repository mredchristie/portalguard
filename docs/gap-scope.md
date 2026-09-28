# How wide should the gap be?

Portalguard opens a hole for one host. Real captive portals are often spread
across several, and a portal you cannot finish logging in to is a portal that
has beaten the tool.

This document records the case that raised the question, sets out the options,
and says which one was taken and why. Two of them are shipped - `allow` (A) and
the blocked-name suggestions (A+) - and the rest are unbuilt; each section says
which it is.

## The case: BT Wi-Fi

Tested against BT Wi-Fi at a Waitrose. Detection did its job:

- found `www.btwifi.com` from the probe redirect
- pinned it to `192.168.23.21`
- opened `80`, `443` and `8443`, picking up the non-standard port out of the
  redirect rather than assuming the defaults
- released cleanly on Ctrl-C

Then the login page came up **blank**. Not unstyled - blank.

The page itself loaded fine: HTTP 200, the full HTML. But the markup ships
hidden, `.btwf-site { display: none }`, and is revealed by JavaScript served
from `cdn.btwifi.com`, which the gap did not include. A blocked stylesheet
gives you an ugly page you can still use. A blocked script that owns the
`display` property gives you a white rectangle with no error, no failed
element, and nothing on screen to suggest which host to unblock.

The portal spans four hosts:

| Host | Port | What it serves |
| --- | --- | --- |
| `www.btwifi.com` | 8443 | the login page |
| `cdn.btwifi.com` | 443 | all JavaScript and CSS |
| `reg.btwifi.com` | 443 | the authentication POST |
| `info.btwifi.com` | 442 | terms and conditions |

One redirect, four hosts, three ports, and only the first of each was open.

**None of this is BT-specific and none of it should be special-cased.** A CDN
for static assets and a separate host for the credential POST is the ordinary
shape of a portal built by people who build websites for a living. BT is just
the first one this was pointed at.

## What is actually hard here

Widening the gap is easy. Widening it by the right amount is the problem, and
every option below trades the same two things against each other:

- **A wider gap is a bigger hole.** `GAP_OPEN` is the only state where anything
  leaves this machine unfiltered, and the whole tool exists to keep that window
  small and short. An option that solves every portal by opening more is not
  solving the problem, it is abandoning it.
- **A portal you cannot log in to is worse than useless.** It is worse because
  the user's fallback is to turn Portalguard off and log in unprotected, which
  is the exact outcome it was built to prevent.

There is also a constraint from the ruleset itself. The pf design holds **one
port set for the whole gap**, not per host - see `renderPorts` in
[`pf-design.md`](pf-design.md). Opening 442 for the terms page opens 442 for
every address in the gap. That is a real cost of the current rule shape and it
gets worse with every host added.

## The options

### A. The user names the hosts (`allow`)

What exists. `sudo portalguard allow cdn.btwifi.com` widens an open gap, and
since the state-persistence fix it works from a second terminal while `run`
waits in the first.

- **Gap size:** the smallest possible. Nothing opens that a human did not name.
- **Trust:** unchanged. Addresses are still pinned at the moment they are added.
- **Cost:** it asks the user to diagnose a blank page with no internet, which is
  the worst possible moment for it. On BT you would need devtools open, and the
  knowledge that a hidden `<body>` means a blocked script.

This is the right primitive and the wrong entire answer.

### A+. Portalguard says which hosts were blocked

**Built.** The extension worth building, because **the evidence was already
being collected**.

DNS is open during `GAP_OPEN`, so `cdn.btwifi.com` resolves fine and then the
TCP connection to it is dropped. The leak reader is already tailing `pflog1`
and already accumulating every name queried through the hole (`r.names` in
[`leakreader.go`](../internal/firewall/pf/leakreader.go)). Portalguard is
holding the answer to "which host is missing?" and not showing it to anybody
until the report at seal, by which point it is too late to be useful.

So: while the gap is open, print the names that were looked up and are not in
it, with the command to allow them.

```
Waiting up to 10m0s for the login to go through...

  Looked up but not open: cdn.btwifi.com, reg.btwifi.com
  If the login page is blank or broken, these are what to open:
    sudo portalguard allow cdn.btwifi.com reg.btwifi.com
```

Worded as what was observed rather than as what is wrong, because that is all
it knows: these are lookups, not blocks. Plenty of portals resolve a host they
never load, and whether the page actually needs one is something only the
person looking at the page can say.

- **Gap size:** unchanged. This opens nothing; it tells a human what to open.
- **Trust:** unchanged. The decision stays with the person, which is the same
  line the tool already holds over credentials - it never logs in for you, and
  it should not decide who to trust for you either.
- **Cost:** the reader only exposed its names at `Stop()`, so it needed a peek
  method. The DNS hole is machine-wide, so the raw name list includes every
  background daemon's lookups and has to be filtered before it is a suggestion
  rather than noise.

That filter is where the registrable domain earns its place: rank a name as
worth suggesting if it shares a registrable domain with the portal host. Note
what changed - the heuristic is being used to **order a suggestion**, not to
**open a hole**. Getting it wrong costs the user a glance at a line of text.

Which is also why `siteOf` gets away with approximating the registrable domain
from the last two labels, plus a short list of registry labels (`co`, `ac`,
`ne`...) so `portal.hotel.co.uk` reduces to `hotel.co.uk` rather than to a
country's entire registry. No public suffix list, because being wrong here
mentions a host or stays quiet about one, and nothing downstream of it writes
a rule. Option C is where that stops being true.

How it is put together, since it crosses three packages:

| Piece | Where |
| --- | --- |
| `logReader.Peek` | [`leakreader.go`](../internal/firewall/pf/leakreader.go) - the names so far, both tcpdumps still running |
| `Backend.NamesSeen` | [`counters.go`](../internal/firewall/pf/counters.go) - the reader while it lives, the collected list after a seal |
| `firewall.NameWatcher` | [`report.go`](../internal/firewall/report.go) - optional capability, like `Reporter`; a backend that cannot watch names simply is not one |
| `Session.SuggestAllow` | [`suggest.go`](../internal/state/suggest.go) - the filtering, and the only place the heuristic lives |
| `Session.OnSuggestion` | [`session.go`](../internal/state/session.go) - fires from `WaitForAuth`, and only on a name it has not passed on before |

One wrinkle worth knowing about: a gap widened from a second terminal is
widened by a *different process*, and the waiting one never hears about it. So
`SuggestAllow` reads the session file as well as its own state, or it spends
the rest of the wait recommending a host the user has already opened.

### B. Follow the portal's own redirect chain

**Built in v0.2.** Probes still stop at the first redirect, because that
`Location` is what detection is looking for. After detection,
`Prober.FollowChain` walks the rest: 3xx `Location`s and meta refreshes, up
to five hops, GET only, and pins every further host into the gap the same way
the portal host is. It runs once, while the network is still open, and never
as part of the re-probe during the gap, where a hop outside the gap would cost
a timeout on every poll. `portalguard detect` prints the hops it found.

- **Gap size:** bounded and small. Every hop is an address the portal itself
  just sent us to, so it is hard to argue we should not reach it.
- **Trust:** essentially unchanged, for the same reason.
- **Cost:** near zero.
- **Does it fix BT?** **No.** The chain ended at `www.btwifi.com:8443`, which
  returned 200. Every one of the three missing hosts was a subresource, and no
  amount of redirect following finds a `<script src>`.

Worth doing on its own merits. It is not the fix for this, and it is the option
most likely to be mistaken for one because it sounds the most principled.

### C. Allow the whole registrable domain

**Rejected.** `*.btwifi.com`, resolved on demand as names are queried. Fixes the BT case
outright: all four hosts sit under one registrable domain.

- **Gap size:** unbounded and unknowable in advance. You cannot say what is in
  the gap, only what is eligible for it.
- **Trust:** **this is the one that gives something away.** `Host` pins
  addresses and never names, specifically so a portal that controls DNS - which,
  per the hijack check, it usually does - cannot repoint its own hostname after
  the hole is open. Allowing a domain hands that back: the network operator
  chooses which addresses land in the table by answering their own queries.
  Point `x.btwifi.com` at an address you would rather this machine did not
  reach, and now a background daemon can reach it.
- **Cost:** needs a public suffix list to be safe at all. Taking the last two
  labels turns `portal.hotel.co.uk` into all of `co.uk`. A PSL is a few hundred
  KB of data that goes stale in a tool whose entire ruleset is generated and
  never written to disk. It also needs a DNS-answer-watching mechanism that
  does not exist.

**Rejected.** It solves the motivating case by giving up the invariant the
firewall design is built on.

### D. Read the login page and pin what it references

**Held.** Fetch the portal page through the gap once it is open, extract the hosts named
in `<script src>`, `<link href>` and `<img src>`, pin those, add them.

- **Gap size:** bounded by what the page actually references. On BT that is
  `cdn.btwifi.com`, which is the host that made the difference.
- **Trust:** the addresses are still pinned. But Portalguard would be fetching
  and parsing the portal's own page, which is a step towards acting on the
  portal's behalf. The line it must not cross - the human enters the
  credentials, the human accepts the terms - is still comfortably clear, but it
  is closer than it was.
- **Cost:** the page is hostile input and the parser has to be written that way.
  It misses anything named only inside JavaScript, and no JS is executed. On BT
  that probably means the page renders and `reg.btwifi.com` is *still* blocked
  when the login is submitted - so D on its own trades a blank page for a
  failed login button.

**Held.** Reconsider if A+ turns out not to be enough in practice.

### E. Known networks, opened automatically but TLS-verified

**Built.** A+ still leaves a human diagnosing a blank page, once, every single
time the same network is met again. That repetition is what E removes,
without reopening the argument that got C rejected.

The mechanism: `portalguard remember` saves whatever `allow` most recently
widened the gap with - hosts a human already looked at and decided to trust -
under the portal host's registrable domain (`internal/state/known.go`). On a
later visit, `OpenGap` calls `Session.OpenKnown`, which looks up that domain
and, for each remembered host, does **not** simply open it. It resolves the
host through whatever DNS this network hands out, same as ever, then makes
one TCP connection and requires a TLS handshake with a certificate that
validates for that exact hostname against the system trust store - no
`InsecureSkipVerify`, no custom root (`internal/state/verify.go`). Only a host
that passes is added to the gap. One that fails is not opened and is not
reported as an error: it simply falls through to A+, which will suggest it if
the portal turns out to need it.

Why this is not C with extra steps: C's objection was that DNS on a hostile
network is answered by whoever is hostile, so trusting a *name* hands the
network operator the choice of which address ends up in the gap. That
objection is still entirely correct, and E does not answer it by trusting DNS
more carefully - it answers it by not resting on DNS at all. A certificate
valid for `cdn.btwifi.com` is not something a network operator can produce by
controlling DNS; it requires either BT's private key or a compromised
certificate authority. A rogue access point broadcasting a known SSID, or
spoofing DNS for a known hostname, gets exactly as far as it did before E
existed: the connection completes, the handshake does not, and the host stays
closed.

- **Gap size:** every host still enters the gap as a pinned address, same as
  A+ and `allow`. What E changes is who decides *to try* a given hostname -
  a past human decision, replayed - not what stands between trying and
  opening.
- **Trust:** the human decision is not removed, it is amortised. The first
  encounter with a network still runs through `allow` and, now, `remember` -
  a human still names every host, at least once. What no longer repeats is
  the diagnosis: TLS verification is what is allowed to stand in for the
  human on every visit after the first, and it is a strictly stronger check
  than the thing being replaced, not a weaker one wearing its clothes.
- **Cost:** a real certificate check per remembered host per run - a few
  hundred milliseconds and one TCP connection, spent only against hosts a
  human already vetted once. Hosts that serve only plain HTTP, no TLS at all,
  cannot pass this and fall back to A+ - a live gap, worth knowing before
  relying on E for a plain-HTTP CDN.

**Proven live against an off-box portal, not yet at a real hotspot.** The
first live run found that E could never have worked: the certificate check
dialled the remembered host before it was in the gap, and the lockdown dropped
the connection every time. The unit tests had stubbed the verifier, so they
never saw it. The fix is the check hole (`pf-design.md`, "The check hole"):
the address goes into `<pg_check>` on the one port being checked, for exactly
as long as the handshake takes. The run after that found a second bug:
`remember` saved the kernel's placeholder label, `portal`, because `allow` had
never recorded the names it opened. Both are fixed, and `make hotspot-known`
now shows the whole path against real pf: `cdn` and `reg` opened on the next
visit only after a TLS handshake with a certificate valid for each name, the
page rendering first time, and the gap open for 4 seconds instead of 22.

What that does not prove is the rejection path on a live network. The gate
refusing a self-signed certificate and a plain TCP server is proven by
`internal/state/verify_test.go`, not by a rogue host answering a remembered
name. The seed data ships with
exactly one entry, BT Wi-Fi, because it is the only network this project has
actually diagnosed by hand - see the case above. Every other provider a user
encounters accrues the same way: `allow`, then `remember`, once.

## The decision

**A+ shipped, then E, then B in v0.2.** Keep the gap decided by a human
for anything E's certificate check cannot vouch for, and let Portalguard
shorten the human part of the loop everywhere it safely can - first by saying
what is missing (A+), then by remembering what was true last time in a form
that has to re-prove itself before it is acted on (E). Redirect-chain
following (B) was nearly free and catches portals E and A+ do not, and is
built.

A+ and E are both built, and both are proven against real pf with an off-box,
BT-shaped portal (`testenv/hotspot/`): the suggestion named exactly the two
blocked hosts, and the remembered hosts opened themselves only after a live
certificate check. B is built and unit-tested against chained local servers;
it has not yet met a real portal that chains. Neither has met a hostile network: the fixture
cooperates, and a real rogue access point meeting the TLS check is still
untested.

**C is rejected**, and E is not a rediscovery of it: E answers the same case
C was reaching for by proving identity cryptographically instead of trusting
DNS, which is exactly the property C was rejected for lacking. **D is held**
pending evidence that A+ and E together are not enough.

The general principle, which is worth stating because it decides the next case
too: *Portalguard should get better at telling you what is blocked, not at
guessing what to unblock.* Every option that widens the gap automatically has
to be argued against the possibility of a portal choosing what goes in it. An
option that only improves what the user is told does not.

## Related

- [`pf-design.md`](pf-design.md) - the rules, including the single shared port
  set that makes each added host cost more than it looks
- [`architecture.md`](architecture.md) - what is proven and what is not
