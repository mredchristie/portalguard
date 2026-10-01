# The progress feed

`portalguard run -json` and `portalguard arm -json` report what they are doing
as one JSON object per line on stdout, for a GUI or any other program to read
as it happens. Nothing else is written to stdout in this mode; the technical
log goes to `-trace` if one is given, and errors also go to stderr.

The feed is the same calls as the plain-words narration a person sees in a
terminal, so the two cannot disagree about what happened.

## Every event

| Field | |
| --- | --- |
| `type` | What kind of event, below |
| `at` | When, RFC 3339 in UTC |

## Events

| `type` | Fields | When |
| --- | --- | --- |
| `start` | `command` (`run` or `arm`), `version` | First |
| `transition` | `from`, `event`, `to`, `note` | Every move of the state machine. `to` is the state to show; `note` names the portal host, an opened host, or why |
| `joining` | `ssid` | `arm -join`: locked down, and now joining that Wi-Fi network |
| `waiting` | `for`: `network`, `login`, `vpn` or `handoff`; `timeout_seconds`; `starting` (for `vpn`: the VPN being started, if any) | The user has something to do |
| `login_url` | `url` | The login page, once the gap is open. Show it as a link: the browser opens it too, but not always in front |
| `suggest` | `names` | Hosts the page asked for that were not opened by themselves (another site, say a payment page). Offer to open them: see Input |
| `refused` | `name`, `kind` (`payment` or `other`) | A name on another site was refused that may be what the page is waiting for: a card processor, or an unrecognised site. Background apps' names are left out. Offer to open it, as for `suggest` |
| `note` | `text` | Something worth telling the user: the DNS filter could not start, a host could not be opened |
| `trusted` | `label`, `gateway_mac` | Armed, on a trusted network with open internet: stood down |
| `summary` | `gap_seconds`, `blocked_out_packets`, `lookups_refused`, `lookups_forwarded`, `opened_automatically` | After the seal |
| `vpn` | `status` (`up`), `interface`, `taken_over` | The VPN's tunnel has the connection and portalguard has stepped aside |
| `done` | `state`; `cancelled` and `held` after a cancel | Finished without an error. `held`: everything is still blocked, for the app to release (see Input) |
| `error` | `text` | Finished with one. The rules are released unless the text says otherwise |

The states, in order: `IDLE`, `ARMED` (arm only), `DETECTING` (run only),
`PORTAL_FOUND` (run only), `LOCKED_DOWN`, `GAP_OPEN`, `AUTHENTICATED`,
`SEALED`, `HANDED_OFF`.

## Input

While the login is waiting, each line written to stdin is a host name to open,
exactly as `portalguard allow <host>` would. `y` opens the last `suggest`
event's names. An opened host arrives as a `transition` (event `EXTEND_GAP`);
one that could not be opened arrives as a `note`.

At any point, `cancel` ends the run and gives the network back, as stdin
ending does. `cancel-hold` ends it too, but leaves a bare lockdown in place
and says so with `held` on `done`: for an app that first puts the Mac back on
its usual network, then runs `portalguard release`. Released straight away,
the Mac is unprotected on the network being cancelled until it has left.

## Example

```json
{"type":"start","at":"2026-09-30T05:10:01Z","command":"arm","version":"v0.5"}
{"type":"transition","at":"...","from":"IDLE","event":"ARM","to":"ARMED","note":"pf"}
{"type":"waiting","at":"...","for":"network","timeout_seconds":1800}
{"type":"transition","at":"...","from":"ARMED","event":"PORTAL_FOUND","to":"LOCKED_DOWN","note":"www.btwifi.com"}
{"type":"transition","at":"...","from":"LOCKED_DOWN","event":"OPEN_GAP","to":"GAP_OPEN","note":"www.btwifi.com"}
{"type":"login_url","at":"...","url":"http://www.btwifi.com:8443/login"}
{"type":"transition","at":"...","from":"GAP_OPEN","event":"EXTEND_GAP","to":"GAP_OPEN","note":"cdn.btwifi.com (same site, automatic)"}
{"type":"transition","at":"...","from":"GAP_OPEN","event":"AUTHENTICATED","to":"AUTHENTICATED"}
{"type":"transition","at":"...","from":"AUTHENTICATED","event":"SEAL","to":"SEALED"}
{"type":"summary","at":"...","gap_seconds":6,"blocked_out_packets":524,"lookups_refused":91}
{"type":"waiting","at":"...","for":"vpn","starting":"My VPN","timeout_seconds":180}
{"type":"vpn","at":"...","status":"up","interface":"utun4","taken_over":false}
{"type":"done","at":"...","state":"HANDED_OFF"}
```
