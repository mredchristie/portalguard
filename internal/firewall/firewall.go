// Package firewall provides a small, OS-independent surface for the only
// thing Portalguard needs from a packet filter: hold every packet down,
// punch one narrow hole for a captive portal login, close it again.
//
// Every backend must satisfy one rule above all others: if Portalguard dies,
// the machine's network must come back. Backends therefore install their
// rules inside a named, self-contained container (a pf anchor, an nftables
// table, a WFP sublayer) that can be destroyed in a single operation, and
// callers must arrange for Release to run on exit. See safety.go.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrNotImplemented is returned by backends that are stubbed for an OS we do
// not support yet.
var ErrNotImplemented = errors.New("firewall: backend not implemented on this platform")

// ErrNeedsPrivileges is returned when the backend is present but the process
// lacks the rights to program it (on macOS: not root).
var ErrNeedsPrivileges = errors.New("firewall: root privileges required")

// ErrNotLocked is returned when a hole is requested before Lockdown.
var ErrNotLocked = errors.New("firewall: not locked down")

// ==== what the firewall is doing ==========================================
// Coarser than the state machine - the firewall knows rules, not portals.

// Phase describes what the backend believes it is currently enforcing. It is
// deliberately coarser than the application state machine in internal/state:
// the firewall only knows about rules, not about portals or VPNs.
type Phase string

const (
	// PhaseOff means Portalguard's rules are not installed at all and the
	// system's normal networking applies. This is the safe resting state.
	PhaseOff Phase = "OFF"
	// PhaseLocked means all traffic is blocked except the always-on
	// essentials (loopback, DHCP, neighbour discovery).
	PhaseLocked Phase = "LOCKED"
	// PhaseGap means PhaseLocked plus explicit passes for one or more
	// portal hosts.
	PhaseGap Phase = "GAP"
)

// ==== what we let through =================================================
// A hole in the firewall. Pinned to addresses, never to a hostname.

// Host is a destination Portalguard is willing to let through while the gap is
// open. Hosts are always pinned to concrete addresses before a rule is written
// so that a portal cannot widen the hole later by changing its DNS answer.
type Host struct {
	// Name is the hostname as it appeared in the portal redirect, kept for
	// display and logging. May be empty when only an IP is known.
	Name string `json:"name,omitempty"`
	// Addrs are the addresses traffic may be sent to. Must be non-empty.
	Addrs []net.IP `json:"addrs"`
	// Ports are the destination TCP ports to allow. Empty means {80, 443}.
	Ports []int `json:"ports,omitempty"`
	// AllowDNSTo, when true, also permits UDP/TCP 53 to these addresses.
	// Used for the resolver the portal hands out over DHCP.
	AllowDNSTo bool `json:"allow_dns_to,omitempty"`
	// Check marks a hole Portalguard needs for its own checks rather than for
	// the user's login: the post-login re-probe, or the certificate check on
	// a remembered host. Backends keep these apart from the portal's hole so
	// they neither widen its port set nor outlive the check. See Checker.
	Check bool `json:"check,omitempty"`
	// Reason records why this hole exists, for `portalguard status`.
	Reason string `json:"reason,omitempty"`
}

// TCPPorts returns the effective TCP port list for the host.
func (h Host) TCPPorts() []int {
	if len(h.Ports) == 0 {
		return []int{80, 443}
	}
	return h.Ports
}

// String renders the host for logs and status output.
func (h Host) String() string {
	name := h.Name
	if name == "" {
		name = "(ip-only)"
	}
	return fmt.Sprintf("%s %v ports=%v dns=%t", name, h.Addrs, h.TCPPorts(), h.AllowDNSTo)
}

// Status is a snapshot of what the backend is enforcing right now, read back
// from the OS rather than from in-process bookkeeping wherever possible.
type Status struct {
	Backend   string `json:"backend"`
	Phase     Phase  `json:"phase"`
	Available bool   `json:"available"`
	// Managed reports whether Portalguard's own rule container exists.
	Managed bool      `json:"managed"`
	Allowed []Host    `json:"allowed,omitempty"`
	Since   time.Time `json:"since,omitzero"`
	// Detail carries backend-specific text (e.g. the raw anchor dump).
	Detail string `json:"detail,omitempty"`
}

// ==== the driver interface ================================================
// What every OS backend provides. Release is the one that must not fail.

// Backend is the per-OS packet filter driver.
//
// Implementations must be safe for concurrent use and must be idempotent:
// calling Lockdown twice, or Release on an already-released filter, is not an
// error.
type Backend interface {
	// Name identifies the backend, e.g. "pf" or "nftables".
	Name() string

	// Available reports whether this backend can actually be used here. It
	// returns a human-readable reason when it cannot.
	Available(ctx context.Context) (bool, string)

	// Lockdown blocks all traffic except the always-on essentials. It is the
	// first rule-writing call and creates the rule container.
	Lockdown(ctx context.Context) error

	// AllowHost punches a hole for one host. It is additive and only legal
	// once Lockdown has been called.
	AllowHost(ctx context.Context, h Host) error

	// Seal removes every hole opened by AllowHost, returning to a bare
	// lockdown. Traffic is still blocked after Seal; this is the state we
	// hand to the VPN from.
	Seal(ctx context.Context) error

	// Release tears the rule container down completely and restores normal
	// networking. It must succeed even if the process never called Lockdown,
	// and it is what the crash/exit handler calls.
	Release(ctx context.Context) error

	// Status reads back the currently enforced configuration.
	Status(ctx context.Context) (Status, error)
}

// ==== is anything actually being enforced? ===============================
// Loading rules is not the same as enforcing them. Something else can turn
// the packet filter off, or swap its ruleset, underneath us.

// Enforcer is implemented by backends that can tell whether the rules they
// loaded are still being evaluated. It exists because a VPN kill switch was
// found replacing pf's whole main ruleset on connect: Portalguard's rules
// stayed loaded, nothing referenced them any more, and the machine was open
// while Portalguard reported it locked. Optional, like Reporter.
type Enforcer interface {
	// Enforced reports whether traffic is still passing through this
	// backend's rules. When it is not, why says what changed.
	Enforced(ctx context.Context) (ok bool, why string)
}

// ==== filtering the gap's DNS ==============================================

// DNSFilterer is implemented by backends that can send the gap's DNS through
// Portalguard's own resolver (internal/dnsfilter) instead of straight to the
// network's. Optional: a backend without it keeps the machine-wide DNS hole.
type DNSFilterer interface {
	// UseDNSFilter makes the gaps loaded from now on filter their DNS. The
	// resolver must already be listening. It fails, changing nothing, when
	// the backend cannot redirect DNS.
	UseDNSFilter(ctx context.Context) error
}

// SelfDNSFilterer is a DNSFilterer that can also filter DNS for Portalguard's
// own lookups alone, where catching other apps' is impossible (pf skipping
// loopback): the filter's upstream rule still lets its own questions out, and
// everything else sent to the resolvers still goes nowhere. Enough for
// detection, which needs only its own lookups; not for a login, whose browser
// needs its lookups answered.
type SelfDNSFilterer interface {
	UseDNSFilterForSelf(ctx context.Context) error
}

// ==== handing over to the VPN =============================================
// Between sealing and the tunnel coming up, only the VPN's own handshake may
// leave. Releasing first, as v0.1 did, leaks everything in between.

// Endpoint is somewhere a VPN client connects to. A nil Addr means any
// address, for clients whose server is chosen at connect time; the port and
// protocol then carry the whole restriction.
type Endpoint struct {
	Addr  net.IP `json:"addr,omitempty"`
	Port  int    `json:"port"`
	Proto string `json:"proto"` // "udp" or "tcp"
}

// String renders the endpoint the way the -vpn flag takes it.
func (e Endpoint) String() string {
	host := "any"
	if e.Addr != nil {
		host = e.Addr.String()
		if e.Addr.To4() == nil {
			host = "[" + host + "]"
		}
	}
	return fmt.Sprintf("%s:%d/%s", host, e.Port, e.Proto)
}

// VPNOpener is implemented by backends that can hold the lockdown while
// letting a VPN client's handshake out. Optional, like Reporter and Checker:
// a backend without it cannot hand over without a gap.
type VPNOpener interface {
	// AllowVPN replaces the lockdown with one that also passes traffic to
	// the given endpoints, and nothing else. An empty list is a bare
	// lockdown again. Legal only while locked down with no gap open.
	AllowVPN(ctx context.Context, endpoints []Endpoint) error
}

// ==== holes for Portalguard's own checks ==================================
// The re-probe and the certificate check have to reach addresses outside
// the gap. Without this they are dropped like everything else.

// Checker is implemented by backends that can let Portalguard's own checks
// out while the gap is open, separately from the gap itself.
//
// Two checks need it. The re-probe that notices a finished login goes to the
// probe endpoints, whose real addresses only appear once the portal stops
// hijacking DNS - never in the gap. And a remembered host has to be reached
// to have its certificate checked, before it is opened. Both were dropped by
// the lockdown in every real run; only tests against loopback, which is
// never filtered, ever saw them succeed.
//
// It is an optional capability, like Reporter: a backend without it simply
// cannot run those checks, and the session falls back to what it did before.
type Checker interface {
	// AllowCheck lets traffic reach h's addresses on h's ports, with h
	// treated as a check (h.Check is implied). Adding an address already
	// allowed for a check is a no-op. Legal only while the gap is open.
	AllowCheck(ctx context.Context, h Host) error
	// DropCheck withdraws h's addresses from the check hole and kills any
	// connection still open to them.
	DropCheck(ctx context.Context, h Host) error
}
