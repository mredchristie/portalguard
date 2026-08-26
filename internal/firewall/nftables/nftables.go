// Package nftables is the planned Linux backend for Portalguard.
//
// It is a stub: the shape is here so the cross-platform architecture is
// visible, but no rules are programmed yet.
//
// Design sketch (for when this is implemented):
//
//	nft add table inet portalguard
//	nft add chain inet portalguard output { type filter hook output priority -10 \; policy drop \; }
//	nft add rule  inet portalguard output oif lo accept
//	nft add rule  inet portalguard output udp dport 67-68 accept          # DHCP
//	nft add rule  inet portalguard output ct state established accept
//	nft add rule  inet portalguard output ip daddr @portal_hosts accept   # the gap
//
// The whole table is the rule container: `nft delete table inet portalguard`
// is the single-operation teardown that Release needs, and the gap is a named
// set (`portal_hosts`) so AllowHost/Seal are set updates rather than rule
// rewrites.
package nftables

import (
	"context"
	"runtime"

	"portalguard/internal/firewall"
)

// Backend is the Linux nftables backend.
type Backend struct{}

// New returns a not-yet-implemented Linux backend.
func New() *Backend { return &Backend{} }

func (b *Backend) Name() string { return "nftables" }

func (b *Backend) Available(context.Context) (bool, string) {
	return false, "the Linux nftables backend is not implemented yet (running on " + runtime.GOOS + ")"
}

func (b *Backend) Lockdown(context.Context) error                 { return firewall.ErrNotImplemented }
func (b *Backend) AllowHost(context.Context, firewall.Host) error { return firewall.ErrNotImplemented }
func (b *Backend) Seal(context.Context) error                     { return firewall.ErrNotImplemented }
func (b *Backend) Release(context.Context) error                  { return nil } // nothing installed, nothing to undo

func (b *Backend) Status(context.Context) (firewall.Status, error) {
	return firewall.Status{Backend: b.Name(), Phase: firewall.PhaseOff, Available: false}, nil
}

var _ firewall.Backend = (*Backend)(nil)
