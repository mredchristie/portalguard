# Test captive portal

A fake hotel portal you can point Portalguard at, so detection can be tested
without going to a cafe and without a real network to break.

It has two parts:

- **`portal-web`** — an HTTP server that intercepts every request until
  somebody clicks **Accept**, then answers the well-known probe endpoints
  honestly. It serves `/hotspot-detect.html` and `/generate_204` on the same
  paths the real endpoints use, so a probe list can be aimed at it by changing
  only the host.
- **`dnsmasq`** — a resolver that answers *every* query with the portal's
  address, which is what hotel networks do and what Portalguard's DNS hijack
  check is written to catch.

## Which half of the test covers what

**Read this before treating a green `e2e.sh` run as end-to-end proof.** The
test is deliberately split, because on this Mac it cannot be otherwise.

### Why it is split

A container runtime on macOS cannot give you a portal that is genuinely off-box
from the Mac's point of view. podman (and Docker Desktop — same architecture)
publishes ports through a helper process running *on the Mac*, and BSD routes
every local address through `lo0`:

```
$ route -n get 192.168.0.56        # this Mac's own LAN address
  interface: lo0
      flags: <UP,HOST,DONE,LLINFO,WASCLONED,LOCAL,IFSCOPE,IFREF>
```

That `LOCAL` flag is the kernel's own forwarding decision, and it is what pf
matches `on lo0` against. So `pass quick on lo0 all` — a rule the lockdown
cannot do without — would let any test against the container pass **without the
gap rules doing anything at all**. A green run would prove nothing.

### The split

| Half | Target | Path | What it proves |
| --- | --- | --- | --- |
| **pf behaviour** | the LAN gateway | `en0` | The block really blocks, the gap really opens, the seal really closes |
| **portal semantics** | the container | `lo0` | Redirect is detected, host is extracted, accept flips detection to open |

The pf half uses the default gateway as a stand-in portal. It answers HTTP, it
is reached over `en0`, and it has exactly a real captive portal's topology —
on most hotel and home networks the portal *is* the gateway.

**The gateway is a read-only target.** The test sends it HTTP GETs and nothing
else. No device outside this Mac is configured, modified, or written to.

The two halves are joined by pointing the fake portal's redirect at the
gateway:

```fish
cd testenv
env PORTAL_URL=http://192.168.0.1/ podman compose up -d --force-recreate portal
```

Detection then probes the container over `lo0`, reads a redirect to
`192.168.0.1`, and pins the gap to that address — which is off-box. One flow,
both halves, each doing the part it can honestly do.

### What is still not covered

- **A portal that is genuinely remote.** The login page in the pf half is the
  gateway's own web UI, not the fake portal. Detection's parsing of a real
  portal response is exercised over `lo0` only.
- **A hostile network.** The gateway cooperates. It does not hijack DNS,
  intercept probes, or drop packets.
- **Roaming**, DHCP lease expiry mid-lockdown, and IPv6-only networks.

Closing these needs a second device on the LAN running the portal, at which
point the split disappears and `e2e.sh` can point at it with `GATEWAY=`.

## What it does and does not simulate

It simulates the portal's **answers**: the redirect, the interstitial, the 511,
the hijacked DNS, and the moment those stop after login. That is the entire
surface detection reads, so `portalguard detect` exercises its real code path
end to end.

It does **not** route traffic, so clicking Accept does not literally open a
gateway — it makes the probe endpoints stop lying. Testing that traffic is
genuinely blocked needs the pf backend and a real network; this environment
tests detection and the state transitions around it.

There is no credential form, only a terms-acceptance button. That is on
purpose: Portalguard never submits credentials, so the fixture does not model
anything it could be tempted to automate.

## Quickest test: no containers at all

The portal is plain Go in this repo, so you can skip the container runtime:

```fish
go run ./testenv/portal-web -addr 127.0.0.1:8080
```

In another shell:

```fish
# Before clicking Accept: PORTAL, exit code 10
./bin/portalguard detect -v -no-dns-check -probes-file testenv/probes.json

# Click Accept at http://127.0.0.1:8080/login (or: curl -X POST http://127.0.0.1:8080/accept)

# After: OPEN_INTERNET, exit code 0
./bin/portalguard detect -no-dns-check -probes-file testenv/probes.json

# Put it back to intercepting
curl -s http://127.0.0.1:8080/reset > /dev/null
```

`-no-dns-check` is used here because the DNS side is not running; leave it off
once you bring dnsmasq up.

Interception style is switchable, and all three are worth testing because they
take different paths through the detector:

```fish
go run ./testenv/portal-web -mode redirect      # 302 to the login page
go run ./testenv/portal-web -mode interstitial  # 200 with a meta-refresh bounce
go run ./testenv/portal-web -mode 511           # RFC 6585 Network Authentication Required
```

## With containers

This Mac has `podman` but no `docker` CLI, so the runtime has to be named:

```fish
podman machine start                     # the VM is currently stopped
cd testenv
podman compose up --build -d
```

With Docker Desktop instead, `docker compose up --build -d` works unchanged.
The Makefile targets take an override:

```fish
make COMPOSE="podman compose" testenv-up
make COMPOSE="podman compose" testenv-logs
make COMPOSE="podman compose" testenv-down
```

Configuration lives in `.env` (copy `.env.example`):

| Variable      | Meaning                                                        |
| ------------- | -------------------------------------------------------------- |
| `PORTAL_IP`   | Address dnsmasq answers every query with. Must be reachable *from the client*. |
| `PORTAL_URL`  | Where the portal redirects clients. Unset means "wherever you reached me", which is right for both localhost and LAN clients. Set it to aim the gap at a specific address. |
| `PORTAL_PORT` | Host port for the portal. Default 8080.                          |
| `DNS_PORT`    | Host port for dnsmasq. Default 5354 - not 5353, which is mDNS and already taken on macOS. |
| `MODE`        | `redirect`, `interstitial` or `511`.                             |

For a same-Mac test, `PORTAL_IP=127.0.0.1` is fine. To involve another device,
set it to the Mac's LAN address:

```fish
ipconfig getifaddr en0
```

## Pointing a client at it

### The Mac itself, probe list only

The least invasive test, and the one to use by default: leave system DNS alone
and just aim the probes at the portal.

```fish
./bin/portalguard detect -v -probes-file testenv/probes.json
```

### The Mac itself, with hijacked DNS

To exercise the DNS hijack check you need the resolver on port 53, because
macOS's DNS settings have no port field. Two options:

1. Run dnsmasq on port 53 — `DNS_PORT=53` in `.env`. Rootless podman cannot
   bind ports below 1024, so this needs Docker Desktop or a rootful podman
   machine.
2. Query it directly without changing system DNS, which is enough to confirm
   the wildcard behaviour by hand:

   ```fish
   dig @127.0.0.1 -p 5354 anything.example +short
   dig @127.0.0.1 -p 5354 pg-test.portalguard.invalid +short
   ```

   Both should return `PORTAL_IP`. The second is the exact query
   Portalguard's hijack check makes: a name under `.invalid` that must not
   resolve.

Then point macOS at it — **System Settings → Network → Wi-Fi → Details → DNS**,
set `127.0.0.1`, and note the previous values so you can put them back. This
does affect the whole machine, so undo it when you are finished:

```fish
networksetup -getdnsservers Wi-Fi          # note these first
networksetup -setdnsservers Wi-Fi 127.0.0.1
networksetup -setdnsservers Wi-Fi empty    # back to DHCP
```

### Another device on the LAN

The realistic test, and the one that needs no changes to the Mac's own
networking:

1. Set `PORTAL_IP` to the Mac's LAN address and `DNS_PORT=53`, then bring the
   stack up.
2. On the phone or laptop, set DNS manually to the Mac's LAN address.
3. Browse to anything. Every name resolves to the Mac, the portal intercepts,
   and the login page appears — the same experience as a hotel network.
4. Point Portalguard at it from that device, or from the Mac with
   `-probe no_content=http://<mac-ip>:8080/generate_204`.

macOS will likely prompt to allow incoming connections the first time.

## Running the end-to-end test

```fish
make testenv-up
make e2e
```

(`make e2e` depends on `build`, so it always tests the binary it just built,
not a stale one.) It cuts this machine's network several times, on purpose.
Every privileged command is echoed before it runs, and the `EXIT` trap
flushes the anchor whether the run passes, fails, or is interrupted. If
something goes wrong anyway:

```fish
make rescue
```

Overridable with environment variables: `GATEWAY` (the off-box target,
defaults to the default route's gateway), `CONTROL` (a host that must stay
blocked, default `1.1.1.1`), `PORTAL`, `PROBES`, `WAIT`.

**Recording a run somewhere other than your own reading (e.g. a public
page) needs `--redact`:** `make e2e-redact`, or `make e2e REDACT=1`. Either
makes both `PHASE B` and `PHASE D` show categories rather than real
domains, and every check that depends on redaction having actually taken
effect verifies it against a ground-truth copy of the report written to a
file but never printed - refusing to continue rather than let the run
finish looking safe when it is not.

This has to go through `make`'s own `REDACT=1` variable or the plain
`sudo ./testenv/e2e.sh --redact` form - never
`REDACT=1 sudo ./testenv/e2e.sh` by itself. `sudo` resets the environment by
default, so that form silently drops `REDACT` before the script ever runs -
confirmed directly (`REDACT=1 sudo sh -c 'echo $REDACT'` prints nothing) -
and it has already produced one recording that displayed real hostnames
while claiming to be redacted. `make e2e REDACT=1` is safe specifically
because `make` expands `REDACT` into a `--redact` **argument** on the
`sudo ./testenv/e2e.sh` line it runs, before `sudo` is ever invoked -
arguments survive `sudo`, environment variables generally do not.

## Recording a demo

`e2e.sh` is a test harness - PASS/FAIL lines, phase banners, assertions -
not what a person using the tool would see. For a recording of the actual
product flow instead:

```fish
make testenv-up
make demo
```

One command, and nothing to type while it runs: `testenv/demo.sh` resets
the fixture, schedules the login-page "Accept" click in the background
(silent - it never interrupts what the recording is showing), and runs
`portalguard run` in the foreground exactly as a person would type it
themselves - detect, lock down, gap open, wait, seal, redacted report.
Compare with `make e2e`: that command backgrounding `sudo` and driving the
accept step live from the same recorded shell is what caused a visible
glitch (typing a command over live output) in an earlier take - `demo.sh`
avoids the whole problem by never backgrounding the privileged command at
all, only the harmless `curl`.

## Endpoints

| Path                    | Behaviour                                                |
| ----------------------- | -------------------------------------------------------- |
| `/generate_204`         | 204 once accepted, intercepted before                     |
| `/hotspot-detect.html`  | Apple's success body once accepted, intercepted before    |
| `/login`                | The portal page with the Accept button                    |
| `/accept` (POST)        | Simulates a successful login                              |
| `/reset` (GET)          | Back to intercepting, for repeat runs                     |
| `/status`               | `{"authenticated": bool, "mode": string}` for scripting   |
| anything else           | Intercepted, like a real portal                           |
