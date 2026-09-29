# Portalguard

Log in to public Wi-Fi without leaking everything else.

A full-tunnel VPN and a captive portal cannot both go first: the VPN can't
connect until you log in, and the login page can't load through the VPN. So
everyone turns the VPN off, logs in, and turns it back on, and for that whole
window every app on the machine talks to an untrusted network in the clear.

Portalguard closes that window on macOS, using the firewall built into the
kernel (pf):

1. **Detects** the portal and pins its addresses.
2. **Locks down** all traffic.
3. **Opens a gap** for the login page only. While it is open, DNS goes
   through a filter that lets out only the login's own names.
4. **Seals** the gap once a re-probe sees the real internet.
5. **Hands over** to your VPN: only VPN traffic may leave until the tunnel is
   up, then Portalguard steps aside.

It never types a password or clicks accept for you. You log in yourself;
Portalguard only controls the firewall around that moment.

## Quick start

```fish
make build
sudo ./bin/portalguard install-anchor    # once per machine; adds two lines to /etc/pf.conf
./bin/portalguard detect -v             # read-only: is there a portal?
sudo ./bin/portalguard run              # the whole flow
```

`run` opens the login page in your browser and waits. If the page comes up
blank, it names the hosts that are missing and the command to open them:

```
  Looked up but not open: cdn.btwifi.com, reg.btwifi.com
  If the login page is blank or broken, these are what to open:
    sudo portalguard allow cdn.btwifi.com reg.btwifi.com
```

Run that in a second terminal. `sudo portalguard remember` then saves those
hosts, and next time they open by themselves, but only after each passes a
fresh TLS certificate check.

`sudo make install` puts the binary on your PATH as `portalguard`.

## Commands

| Command | Root | What it does |
| --- | --- | --- |
| `detect` | | Classify the network. Changes nothing. Exit code 0 open, 10 portal, 20 no network. |
| `check` | | One request: prints `internet: reachable` or `blocked`. |
| `status` | yes | What pf is actually enforcing, and whether it is still in force. |
| `run` | yes | The whole flow, from detection to handover. |
| `lockdown` | yes | Block everything. |
| `allow [host[:port]...]` | yes | Open the gap, or widen it for named hosts. |
| `remember` | yes | Save the hosts you allowed, for next time. |
| `seal` | yes | Close the gap, keep the lockdown. |
| `handoff` | yes | Keep the lockdown, let only your VPN out, step aside when it is up. |
| `release` | yes | Remove every rule. The escape hatch. |
| `install-anchor` | yes | One-time setup, or put the hooks back if something replaced pf's rules. |
| `uninstall-anchor` | yes | Undo that. |

Useful `run` flags: `-vpn host:port/proto` (a VPN on unusual ports),
`-no-handoff`, `-no-dns-filter`, `-redact` (share a report without naming
your services).

## If something goes wrong

**If Portalguard dies, your network comes back.** Every rule lives in one pf
anchor, nothing is written to disk, and a crash, Ctrl+C or panic releases the
rules. For the cases no handler can catch (`kill -9`, a power cut):

```fish
sudo pfctl -a portalguard -F all    # or: make rescue
```

A reboot also clears everything.

## Using it with a VPN

Run Portalguard **before** your VPN, not beside it; it refuses to lock down
while a tunnel holds the default route. After the login it hands over by
itself: connect your VPN when it says so.

Some VPNs bring their own firewall. NordVPN's kill switch replaces pf's rules
when it connects and leaves some behind after it disconnects. Portalguard
detects that and says so rather than claim a lockdown it no longer controls;
`sudo portalguard install-anchor` puts its own rules back.

## What is proven

On real pf, with a portal that is genuinely off the machine:

- **The lockdown blocks, the gap is narrow, the seal closes it.** `make e2e`,
  38 checks, including the VPN handover on the wire and the DNS filter.
- **Only the login's names leave during the gap.** The test portal's own DNS
  server heard nothing else, where the same run without the filter leaked 20
  names.
- **A real portal.** BT Wi-Fi: blank page diagnosed, `allow` from a second
  terminal, logged in, sealed.

The full list, and what is not proven yet (a hostile network, a VPN that
depends on the handover hole, roaming), is in
[`docs/architecture.md`](docs/architecture.md).

## Development

```fish
make test          # unit tests, no root needed
make e2e           # real pf; cuts the network on purpose (see testenv/README.md)
make hotspot-demo  # a BT-shaped test portal in containers, off the machine
```

## Docs

| | |
| --- | --- |
| [`architecture.md`](docs/architecture.md) | How the pieces fit, what is proven and what is not |
| [`pf-design.md`](docs/pf-design.md) | Every firewall rule, the DNS filter, the handover, living with VPNs |
| [`gap-scope.md`](docs/gap-scope.md) | How wide the gap should be, and why that is the hard part |
| [`field-notes.md`](docs/field-notes.md) | The BT Wi-Fi trips, and reproducing the leak at home |
| [`demo.md`](docs/demo.md) | Capturing the leak yourself, and redacting it |
| [`testenv/README.md`](testenv/README.md) | The test portals and how each test works |

macOS only. Linux and Windows backends are designed but not built.
