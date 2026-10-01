# PortalGuard

Log in to public Wi-Fi without leaking everything else.

A captive portal blocks everything until you log in, and your VPN can't get
through that block. So you turn the VPN off to log in, and every app on the
Mac talks to the network in the clear. PortalGuard closes that window on
macOS, with the firewall built into the kernel (pf):

1. **Arm.** Everything is blocked, before the Mac even joins the network.
2. **Gap open.** Only the login page's addresses get out, and only its names
   in DNS. Hosts on the portal's own site open as the page asks for them.
3. **Sealed.** Once a re-probe sees the real internet, the gap closes.
4. **Handed off.** It starts your VPN; only the VPN may connect until its
   tunnel is up, then PortalGuard steps aside.

You log in yourself. It never types a password or clicks accept for you.

## Before you start

A Mac (Apple Silicon or Intel; tested on macOS 26) with:

```sh
xcode-select --install                                        # Apple's command line tools
brew install go                                               # Go 1.26.5 or newer (or go.dev/dl)
go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0     # builds the app
```

For the VPN to start by itself, it must appear in **System Settings > VPN**
(the WireGuard app's tunnels do, and so do macOS's built-in VPNs).

## Install

Run these once, in order. Only the `sudo` lines ask for your password.

```sh
git clone https://github.com/mredchristie/portalguard.git
cd portalguard
make build                                # build the command
sudo make install                         # put it on your PATH as `portalguard`
sudo portalguard install-anchor           # hook into the firewall (adds two lines to /etc/pf.conf)
sudo portalguard install-helper           # run as root in the background: no more passwords
make app                                  # build the app
cp -R gui/build/bin/PortalGuard.app /Applications/
portalguard doctor                        # should end with "Ready"
```

Then, optionally:

```sh
portalguard vpn list                      # the VPNs macOS knows
portalguard vpn use "My VPN"              # start this one after you sign in
portalguard trust Home                    # run on your home Wi-Fi: Arm stands down there
```

The first time the app opens, allow **Location** when macOS asks: without it,
macOS hides Wi-Fi network names. The first time Cancel takes you back to your
usual Wi-Fi, macOS asks to share its saved password: choose **Always Allow**.

**To update:** `git pull`, then `make build`, `sudo make install`,
`sudo portalguard install-helper` (the helper must match), `make app`, and copy
the app again.

**To remove:** `sudo portalguard uninstall-helper`,
`sudo portalguard uninstall-anchor`, `sudo make uninstall`, and delete the app.

## Use it

**The app:** open PortalGuard, pick the Wi-Fi network and press **Arm**. It
locks the Mac, joins the network, opens the login page in your browser, and
starts your VPN once you have signed in. Cancel stays locked until the Mac is
back on its usual Wi-Fi, then lets go.

**The terminal:**

```sh
portalguard arm -join "BTWi-fi"   # the same flow, talked through step by step
portalguard run                   # already joined: detect, then lock down
```

If the login page stalls on a host from another site (a card processor, say),
the app offers it to open; in the terminal, type its name, or run
`portalguard allow <host>` from a second one.

## Commands

| Command | What it does |
| --- | --- |
| `arm`, `run` | The whole flow. `arm` locks down first; `run` detects first |
| `detect`, `check`, `doctor`, `status` | Read-only: classify the network, test reachability, readiness, what pf enforces |
| `trust`, `untrust` | Mark the network you are on as yours: `arm` stands down there |
| `vpn list`, `vpn use <name>` | Choose the VPN the handover starts |
| `allow`, `remember` | Open more hosts; save them for next time (verified by TLS) |
| `lockdown`, `seal`, `handoff`, `release` | Each step by hand. `release` removes every rule |
| `install-helper`, `install-anchor` | One-time setup, with matching `uninstall-` commands |

Useful flags: `-verbose` (every refused name, live), `-trace file`, `-json`
(the [progress feed](docs/feed.md) the app reads).

## If something goes wrong

Every rule lives in one pf anchor. A crash, Ctrl+C, closing the app or a
reboot gives the network back. For anything else:

```sh
sudo pfctl -a portalguard -F all   # or: make rescue
```

Run it before your VPN, not beside it. NordVPN's kill switch replaces pf's
rules; quit NordVPN before arming, and `install-anchor` puts the hooks back.

## Proven

- **EE WiFi, paid (£5.99), end to end in the app.** Login page 13.5 s after
  Arm; EE's payment page opened by itself; 534 packets blocked and 341
  lookups refused during the login; VPN up 0.5 s after signing in.
- **BT Wi-Fi.** Found the blank login page that auto-allow now fixes.
- **The lab.** An off-machine test portal in containers, a hostile one, real
  pf end to end, and fuzzing of everything that reads the network.

Details in [`docs/field-notes.md`](docs/field-notes.md) and
[`docs/architecture.md`](docs/architecture.md).

## Development

```sh
make test        # unit tests, no root
make e2e         # real pf; cuts the network on purpose
make fuzz        # the parsers that read untrusted input
make preflight   # all ten suites, before a field test
```

| Doc | |
| --- | --- |
| [`architecture.md`](docs/architecture.md) | How the pieces fit, and what is and is not proven |
| [`pf-design.md`](docs/pf-design.md) | Every firewall rule, the DNS filter, the handover |
| [`gap-scope.md`](docs/gap-scope.md) | How wide the gap should be |
| [`field-notes.md`](docs/field-notes.md) | BT and EE, trip by trip |
| [`feed.md`](docs/feed.md) | The `-json` progress feed |
| [`testenv/README.md`](testenv/README.md) | The test portals |

macOS only. Linux and Windows are designed but not built.
