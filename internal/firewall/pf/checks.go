//go:build darwin

package pf

import (
	"context"
	"fmt"
	"net"

	"portalguard/internal/firewall"
)

// ==== holes for Portalguard's own checks ==================================
// The re-probe and the certificate check, kept apart from the gap proper.
// See firewall.Checker for why they exist and rules.go for the rule.

// AllowCheck adds h's addresses to the check table and reloads, unless every
// one of them is already there on h's ports - the re-probe calls this on every
// poll, and a reload each time would be churn for nothing.
func (b *Backend) AllowCheck(ctx context.Context, h firewall.Host) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.syncFromKernel(ctx)
	if b.phase != firewall.PhaseGap {
		// A check hole with no gap would be a hole with no reason to exist:
		// the checks it serves only run while the user is logging in.
		return fmt.Errorf("pf: check hole for %q refused: the gap is not open", h.Name)
	}
	if len(h.Addrs) == 0 {
		return fmt.Errorf("pf: refusing a check hole for %q with no address", h.Name)
	}
	h.Check = true
	h.AllowDNSTo = false
	if checkCovers(b.allowed, h) {
		return nil
	}
	return b.reloadGapLocked(ctx, next(b.allowed, h))
}

// DropCheck removes h's addresses from the check table, reloads, and kills
// anything still connected to them. The kill matters as much as the reload:
// a rule change stops new connections, not ones the check already opened.
func (b *Backend) DropCheck(ctx context.Context, h firewall.Host) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.syncFromKernel(ctx)
	if b.phase != firewall.PhaseGap {
		// Seal or release got there first and took the check table with it.
		return nil
	}

	drop := map[string]bool{}
	for _, ip := range h.Addrs {
		drop[ip.String()] = true
	}
	var kept []firewall.Host
	var removed []net.IP
	for _, a := range b.allowed {
		if !a.Check {
			kept = append(kept, a)
			continue
		}
		var addrs []net.IP
		for _, ip := range a.Addrs {
			if drop[ip.String()] {
				removed = append(removed, ip)
				continue
			}
			addrs = append(addrs, ip)
		}
		if len(addrs) > 0 {
			a.Addrs = addrs
			kept = append(kept, a)
		}
	}
	if len(removed) == 0 {
		return nil
	}

	if err := b.reloadGapLocked(ctx, kept); err != nil {
		return err
	}
	// pf tables are `persist`, so an address the new ruleset no longer names
	// would linger in the table. Delete it rather than leave a residue that
	// `status` has to explain.
	for _, ip := range removed {
		_, _ = b.pfctl(ctx, "-a", AnchorName, "-t", checkTable, "-T", "delete", ip.String())
	}
	var failed []string
	for _, ip := range removed {
		if err := b.killStatesTo(ctx, ip); err != nil {
			failed = append(failed, ip.String())
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("pf: check hole closed, but could not kill existing states to %v", failed)
	}
	return nil
}

// reloadGapLocked loads the gap for hosts, keeping leak logging pointed where
// it already is. A reload that forgot the log device would quietly stop the
// hostname capture halfway through the gap.
//
// The caller must hold b.mu.
func (b *Backend) reloadGapLocked(ctx context.Context, hosts []firewall.Host) error {
	g := gapFromHosts(hosts)
	if b.logExists(ctx) {
		g.logTo = LogInterface
	}
	if err := b.loadLocked(ctx, g); err != nil {
		return err
	}
	b.allowed = hosts
	return nil
}

// checkCovers reports whether every address in h is already in the check
// table on every one of h's ports.
func checkCovers(allowed []firewall.Host, h firewall.Host) bool {
	have := map[string]bool{}
	ports := map[int]bool{}
	for _, a := range allowed {
		if !a.Check {
			continue
		}
		for _, ip := range a.Addrs {
			have[ip.String()] = true
		}
		for _, p := range a.TCPPorts() {
			ports[p] = true
		}
	}
	for _, ip := range h.Addrs {
		if !have[ip.String()] {
			return false
		}
	}
	for _, p := range h.TCPPorts() {
		if !ports[p] {
			return false
		}
	}
	return true
}

var _ firewall.Checker = (*Backend)(nil)
