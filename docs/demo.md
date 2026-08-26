# The before-and-after demo

Two captures of the same 30 seconds, taken on the same machine: what leaves
your Mac when a VPN drops, and what leaves it when Portalguard is holding the
line.

## The key point: you do not need a hotel

The leak this tool exists to stop is **not caused by the captive portal**. It is
caused by the tunnel going down. The moment the default route stops pointing
into `utun`, every background daemon that has been waiting notices the change
and reconnects — and their DNS goes out in plaintext over `en0`, on whatever
network you happen to be on.

A captive portal only makes it *worse*, by forcing you to hold that state for
minutes instead of seconds while you find the login page and read the terms.

So the "before" capture reproduces on any network, including your home Wi-Fi,
with nothing but a VPN toggle. That is what makes this demo runnable today
rather than on the next work trip.

## Before you start: this capture is personal data

The whole point is that it contains the hostnames your machine reaches for. On
a typical Mac that means your mail provider, your cloud storage, your
messaging apps, and whatever else is signed in. **Treat the file as personal.**

Three things keep it proportionate:

- **Filter at capture time, not afterwards.** `'udp port 53'` is applied by the
  kernel, so nothing else is ever written to disk. You are collecting query
  metadata, not traffic content.
- **Keep it out of the repo.** `~/pg-demo/` below, and `.gitignore` already
  excludes nothing there — do not move it into the working tree.
- **Sanitise before showing anyone.** The counts and the shape are the
  interesting part; the specific hostnames are yours. There is a redaction step
  at the end.

No `sudo` is needed for any of the capture commands: `/dev/bpf*` is group
`access_bpf` and you are a member.

## Before: the leak

```fish
mkdir -p ~/pg-demo
```

Start the capture and leave it running:

```fish
tcpdump -i en0 -n -w ~/pg-demo/before.pcap 'udp port 53'
```

In the NordVPN app: **disconnect**. Wait 30 seconds — that is roughly how long
it takes for the reconnect stampede to play out. Then reconnect, and stop the
capture with Ctrl-C.

Read what you caught:

```fish
tcpdump -r ~/pg-demo/before.pcap -n 2>/dev/null | head -40
```

Count it:

```fish
tcpdump -r ~/pg-demo/before.pcap -n 2>/dev/null | wc -l
tcpdump -r ~/pg-demo/before.pcap -n 2>/dev/null | grep -oE 'A\? [^ ]+' | sort -u | wc -l
```

The second number — distinct hostnames — is the one that lands. Every name on
that list is a service you use, disclosed in plaintext to whoever runs the
network.

## After: Portalguard holding the line

Disconnect the VPN and leave it disconnected. Portalguard refuses to engage
while a tunnel owns the default route, and this is why — it is meant to hold
the gap the VPN is absent from.

```fish
make build
sudo ./bin/portalguard lockdown
```

Your network is now down, on purpose. Capture the same window:

```fish
tcpdump -i en0 -n -w ~/pg-demo/after.pcap 'udp port 53'
```

Wait 30 seconds, Ctrl-C, then read the counters **before** you release, because
releasing flushes them:

```fish
sudo pfctl -a portalguard -s rules -v
```

Then restore:

```fish
sudo ./bin/portalguard release
```

Compare:

```fish
tcpdump -r ~/pg-demo/after.pcap -n 2>/dev/null | wc -l
```

Zero. The queries were still made — the same daemons still tried — but the
packets never reached the wire. The `block drop out` rule's `Packets:` counter
in the `pfctl` output above is how many were stopped.

## The two halves have to be shown together

An empty pcap on its own is weak evidence: it looks identical to a quiet
machine, or to a capture that was never running. It is only meaningful next to

- the **before** capture, showing the same 30 seconds is not quiet, and
- the **block rule counter**, showing pf actively dropping rather than nothing
  being sent.

That pairing is the demo. Either half alone proves less than it appears to.

## Sanitising before you show anyone

```fish
tcpdump -r ~/pg-demo/before.pcap -n 2>/dev/null | grep -oE 'A\? [^ ]+' | sort | uniq -c | sort -rn > ~/pg-demo/before-names.txt
```

Then edit `before-names.txt` by hand, keeping the counts and generalising the
names — `imap.mail.me.com` becomes `<mail provider>`, and so on. Show the
redacted list, not the pcap.

Delete the captures when you are done:

```fish
rm -rf ~/pg-demo
```

## What this demo does not show

Worth stating plainly wherever it is presented, because the gap between what it
shows and what the tool claims is where credibility goes.

- **It is not a captive portal.** It is a VPN toggle on an ordinary network.
  The leak is real and the mechanism is the one Portalguard addresses, but
  nobody is being redirected to a login page. The portal makes the exposure
  window longer; it does not create it.
- **The `GAP_OPEN` phase is not demonstrated.** This shows lockdown versus no
  lockdown. It does not show the harder claim — that the gap lets the login
  page through and nothing else — because that needs a real portal.
- **The test portal cannot stand in.** `testenv/` simulates a portal's
  *answers*, not its gating, and it sits on `lo0` where the loopback pass rule
  makes any firewall test vacuous. See `testenv/README.md`.

## What is missing to do better

Two things, neither of which is worth building speculatively:

1. **A second device on the LAN.** With a Pi or a spare laptop running
   `go run ./testenv/portal-web`, the portal becomes genuinely off-box, the
   gateway split in `testenv/README.md` disappears, and `GAP_OPEN` can be
   demonstrated properly — portal reachable, everything else blocked, in one
   capture.

2. **`portalguard release` does not print the leak report.** Only `run` does,
   at seal. So the lockdown-only demo above has to read raw counters with
   `pfctl -s rules -v` instead of getting the formatted report. That is a small
   change to `runRelease`, but it is a change, and this session is not for
   features — noting it rather than doing it.
