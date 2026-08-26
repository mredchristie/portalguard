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
