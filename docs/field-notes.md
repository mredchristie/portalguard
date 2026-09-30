# Field notes

What happened when Portalguard met real networks, and the measurement that
shows the leak it exists to stop. Moved out of the README to keep that short;
nothing here is out of date, it is just the long version.

## Reproducing the leak at home

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
covers (see [`docs/architecture.md`](architecture.md)).

**Handling a capture of your own:** the file contains real hostnames your
machine reaches for, so treat it as personal. `.gitignore` excludes
`*.pcap`, `*.pcapng` and `pg-demo/` so a stray capture can't be committed.
Before showing anyone, replace names with categories, not products
(`<mail provider>`, not the brand). Full procedure in
[`docs/demo.md`](demo.md).

## Tested against real networks

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
are in [`docs/gap-scope.md`](gap-scope.md).

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
[`docs/gap-scope.md`](gap-scope.md), option E, for the reasoning and its
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

### Next: EE WiFi (paid, by the hour)

The first real test of auto-allow, and of a portal that takes payment. Before
leaving: `make preflight` should end "ready for the field". On site:

0. At home: `sudo portalguard doctor` should say Ready.
1. Disconnect the VPN, and quit its app.
2. Join the network. Do not click anything in the popup macOS shows.
3. `sudo portalguard run -verbose -trace ~/ee-trace.log`
4. EE's own hosts should open by themselves. If the page stalls on a payment
   step, the refused names are listed as they happen: type the payment host's
   name into the same terminal and press Enter.
5. Pay, log in, wait for SEALED, then connect the VPN when it says so.

The trace keeps every line and every DNS verdict, timestamped, for writing
up here afterwards.

