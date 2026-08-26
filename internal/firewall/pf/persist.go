//go:build darwin

package pf

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mredchristie/portalguard/internal/firewall"
)

// tokenPath holds the pf enable reference token between invocations.
//
// The CLI is many short-lived processes: `lockdown` in one, `allow` in
// another, `release` in a third. Without this, only the process that called
// `pfctl -E` could call `pfctl -X`, and every other invocation would leave our
// enable reference dangling until reboot.
//
// /var/run is the right home precisely because it is cleared on reboot, which
// matches the anchor's own lifetime: nothing portalguard does survives a
// restart.
const tokenPath = "/var/run/portalguard.pf-token"

// saveToken records the enable token for other invocations to release.
func saveToken(token string) error {
	if token == "" {
		return nil
	}
	// 0600: the token is not a secret, but nothing else should be editing it.
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("save pf token: %w", err)
	}
	return nil
}

// loadToken reads a token left by an earlier invocation, or "" if there is none.
func loadToken() string {
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// clearToken removes the token file once the reference has been released.
func clearToken() {
	_ = os.Remove(tokenPath)
}

// syncFromKernel recovers what this process does not know because it did not
// do it: the phase, and what is currently allowed.
//
// The kernel is the only honest source here. A second invocation has an empty
// Backend struct, and without this it would refuse to widen an already-open
// gap ("not locked down") or report OFF while the machine is fully blocked.
//
// The caller must hold b.mu.
func (b *Backend) syncFromKernel(ctx context.Context) {
	if b.enableToken == "" {
		b.enableToken = loadToken()
	}

	out, err := b.pfctl(ctx, "-a", AnchorName, "-s", "rules")
	if err != nil || strings.TrimSpace(out) == "" {
		if b.phase == "" {
			b.phase = firewall.PhaseOff
		}
		return
	}

	// Rules are loaded, so we are at least locked down. Whether the gap is
	// open is decided by the *rules*, never by the tables.
	//
	// Deciding it from table contents was a real bug: pf tables are declared
	// `persist`, so they outlive a ruleset that no longer mentions them. After
	// a seal the lockdown ruleset is loaded and permits nothing, but the table
	// still holds the addresses the gap had pinned - and inferring the phase
	// from that reported GAP over a machine that was fully blocked.
	//
	// Rules are the only thing that actually filters packets, so they are the
	// only honest source for "is anything permitted".
	b.phase = firewall.PhaseLocked
	if gapRulesLoaded(out) {
		b.phase = firewall.PhaseGap
	}
}

// gapRulesLoaded reports whether the loaded ruleset contains a pass rule
// referring to one of the gap tables. A table with addresses in it permits
// nothing unless a rule points at it.
func gapRulesLoaded(rules string) bool {
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pass") {
			continue
		}
		if strings.Contains(line, "<"+portalTable+">") || strings.Contains(line, "<"+dnsTable+">") {
			return true
		}
	}
	return false
}
