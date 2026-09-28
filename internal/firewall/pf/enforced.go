//go:build darwin

package pf

import (
	"context"
	"strings"

	"portalguard/internal/firewall"
)

// ==== is the lockdown still in force? =====================================
//
// Our rules live in an anchor, and an anchor is only evaluated while the main
// ruleset references it. Anything that reloads the main ruleset - a VPN kill
// switch, `pfctl -f /etc/pf.conf` from some other tool, a macOS update - can
// drop that reference, and pf will go on holding our rules without ever
// consulting them. NordVPN does exactly this when it connects: its kill switch
// loads a ruleset of its own with no portalguard anchor in it. Found by the
// v0.2 handover control test; see docs/pf-design.md, section 3.

// Enforced reports whether pf is enabled and the main ruleset still reaches
// our anchor. A pfctl failure is not treated as proof either way: it returns
// true, because crying wolf on a transient error would teach people to ignore
// the warning that matters.
func (b *Backend) Enforced(ctx context.Context) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if info, err := b.pfctl(ctx, "-s", "info"); err == nil && strings.Contains(info, "Status: Disabled") {
		return false, "pf has been turned off by something else on this machine"
	}
	ok, err := b.hookInstalled(ctx)
	if err != nil || ok {
		return true, ""
	}
	return false, "pf's main ruleset was replaced and no longer includes portalguard's rules (a VPN kill switch loading its own firewall is the usual cause)"
}

var _ firewall.Enforcer = (*Backend)(nil)
