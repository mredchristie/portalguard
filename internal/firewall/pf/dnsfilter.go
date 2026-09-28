//go:build darwin

package pf

import (
	"context"
	"errors"
	"strings"

	"portalguard/internal/firewall"
)

// ErrNoRdrHook means the main ruleset does not reach an rdr-anchor for us, so
// the DNS filter's redirect would never happen. `install-anchor` adds it.
var ErrNoRdrHook = errors.New(`pf: /etc/pf.conf has no rdr-anchor "portalguard" line, so DNS cannot be redirected to the filter; run: sudo portalguard install-anchor`)

// ErrLoopbackSkipped means pf's main ruleset says `set skip on lo0`, so no
// rule is ever applied on loopback - including the rdr the filter depends on.
// Stock macOS does not set it. NordVPN's kill switch does: confirmed live,
// connecting and disconnecting it left `lo0 (skip)` behind, along with a main
// ruleset that no longer reached Portalguard's anchors.
var ErrLoopbackSkipped = errors.New("pf: the loaded ruleset skips loopback (set skip on lo0), so DNS cannot be redirected to the filter; a VPN kill switch left it behind (NordVPN does); with the VPN disconnected, `sudo portalguard install-anchor` restores pf's own rules")

// UseDNSFilter makes every gap loaded from now on send its DNS through
// Portalguard's resolver. It refuses, changing nothing, when the rdr hook is
// not loaded: diverting DNS to a redirect that never happens would break the
// login outright, which is worse than the old machine-wide hole.
func (b *Backend) UseDNSFilter(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.rdrHookLoaded(ctx) {
		return ErrNoRdrHook
	}
	if b.loopbackSkipped(ctx) {
		return ErrLoopbackSkipped
	}
	b.dnsFilter = true
	return nil
}

var _ firewall.DNSFilterer = (*Backend)(nil)

// loopbackSkipped reports whether pf is set to skip lo0 entirely, which
// `pfctl -s Interfaces -v` marks as "lo0 (skip)".
//
// The caller must hold b.mu.
func (b *Backend) loopbackSkipped(ctx context.Context) bool {
	out, err := b.pfctl(ctx, "-s", "Interfaces", "-v")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "lo0" && strings.Contains(line, "(skip)") {
			return true
		}
	}
	return false
}
