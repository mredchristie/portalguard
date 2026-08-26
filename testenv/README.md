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
| `PORTAL_IP`   | Address clients are told to reach the portal on. Must be reachable *from the client*. |
| `PORTAL_PORT` | Host port for the portal. Default 8080.                          |
| `DNS_PORT`    | Host port for dnsmasq. Default 5353.                             |
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
   dig @127.0.0.1 -p 5353 anything.example +short
   dig @127.0.0.1 -p 5353 pg-test.portalguard.invalid +short
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
