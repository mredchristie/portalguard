//go:build darwin

package pf

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// The anchor hook: one line in /etc/pf.conf, installed once.
//
// pfctl(8) is explicit that "Evaluation of anchor rules from the main ruleset
// is described in pf.conf(5)" - an anchor's rules run only where the main
// ruleset references it. Stock macOS pf.conf hooks only com.apple, so without
// this line every rule portalguard loads is stored, reported, and ignored.
//
// This is done once, deliberately, rather than by rewriting the main ruleset
// at each lockdown. Apple's own comment in pf.conf warns that some system
// services insert anchors into the main ruleset dynamically, and reloading it
// would drop them every time. An empty anchor filters nothing, so the hook is
// inert whenever portalguard is not running, including across reboots.
const (
	// PfConfPath is the main ruleset macOS loads at boot.
	PfConfPath = "/etc/pf.conf"
	// BackupPath is where the pristine pf.conf is kept.
	BackupPath = "/etc/pf.conf.portalguard.bak"

	beginMarker = "# BEGIN portalguard"
	endMarker   = "# END portalguard"

	// hookBlock is inserted verbatim. Placement matters twice over: it must
	// come after the nat/rdr/dummynet anchors, because pf demands options then
	// normalisation then translation then filtering and this is a filter
	// anchor; and it comes before com.apple so that our `quick` block cannot
	// be undercut by a `pass quick` inside the AirDrop or Application Firewall
	// anchors Apple populates dynamically.
	hookBlock = beginMarker + ` - anchor point, empty unless portalguard is running.
# Remove this block, or run ` + "`sudo portalguard uninstall-anchor`" + `, to revert.
anchor "portalguard"
` + endMarker

	// hookAnchorPoint is the line the block is inserted above.
	hookAnchorPoint = `anchor "com.apple/*"`
)

// ==== install and revert ==================================================
// The one-time edit to /etc/pf.conf. Backs up first, validates first.

// InstallAnchor adds the hook to /etc/pf.conf and reloads the main ruleset.
// It is idempotent. Requires root.
func InstallAnchor(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return firewallNeedsRoot("install-anchor")
	}

	original, err := os.ReadFile(PfConfPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", PfConfPath, err)
	}
	if strings.Contains(string(original), beginMarker) {
		return nil // already installed
	}

	updated, err := insertHook(string(original))
	if err != nil {
		return err
	}

	// Keep a pristine copy before the first edit, never overwriting an
	// existing one: a second install must not back up an already-edited file.
	if _, err := os.Stat(BackupPath); os.IsNotExist(err) {
		if err := os.WriteFile(BackupPath, original, 0o644); err != nil {
			return fmt.Errorf("back up %s: %w", PfConfPath, err)
		}
	}

	return writeAndReload(ctx, updated, original)
}

// UninstallAnchor removes the hook and reloads. Requires root.
func UninstallAnchor(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return firewallNeedsRoot("uninstall-anchor")
	}

	original, err := os.ReadFile(PfConfPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", PfConfPath, err)
	}
	if !strings.Contains(string(original), beginMarker) {
		return nil // nothing to remove
	}
	return writeAndReload(ctx, removeHook(string(original)), original)
}

// writeAndReload writes a candidate pf.conf, validates it without loading, and
// only then loads it. An invalid pf.conf is a bad thing to leave on disk for
// the next boot, so a failed validation restores what was there before.
func writeAndReload(ctx context.Context, candidate string, original []byte) error {
	if err := os.WriteFile(PfConfPath, []byte(candidate), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", PfConfPath, err)
	}

	b := New()
	if _, err := b.pfctl(ctx, "-n", "-f", PfConfPath); err != nil {
		// Put it back exactly as it was before failing.
		if rerr := os.WriteFile(PfConfPath, original, 0o644); rerr != nil {
			return fmt.Errorf("%s is INVALID and could not be restored (%v); restore from %s by hand: %w",
				PfConfPath, rerr, BackupPath, err)
		}
		return fmt.Errorf("candidate %s did not parse, original restored: %w", PfConfPath, err)
	}

	if _, err := b.pfctl(ctx, "-f", PfConfPath); err != nil {
		return fmt.Errorf("load %s: %w", PfConfPath, err)
	}
	return nil
}

// ==== editing pf.conf =====================================================
// Find the spot, insert our block, take it back out cleanly.

// insertHook places the anchor block above the com.apple filter anchor.
func insertHook(conf string) (string, error) {
	lines := strings.Split(conf, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != hookAnchorPoint {
			continue
		}
		out := make([]string, 0, len(lines)+5)
		out = append(out, lines[:i]...)
		out = append(out, strings.Split(hookBlock, "\n")...)
		out = append(out, lines[i:]...)
		return strings.Join(out, "\n"), nil
	}
	return "", fmt.Errorf(
		"could not find %s in %s, so there is no safe place to insert the anchor; add it by hand (see docs/pf-design.md)",
		hookAnchorPoint, PfConfPath)
}

// removeHook strips the block back out, markers included.
func removeHook(conf string) string {
	var out []string
	skipping := false
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, beginMarker):
			skipping = true
		case strings.HasPrefix(trimmed, endMarker):
			skipping = false
		case !skipping:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// AnchorInstalled reports whether the hook is present in pf.conf on disk. This
// is the on-disk view; Lockdown checks the loaded ruleset instead, because
// that is what actually filters packets.
func AnchorInstalled() (bool, error) {
	conf, err := os.ReadFile(PfConfPath)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", PfConfPath, err)
	}
	return strings.Contains(string(conf), beginMarker), nil
}

func firewallNeedsRoot(cmd string) error {
	return fmt.Errorf("pf: %s edits %s and needs root: try `sudo portalguard %s`", cmd, PfConfPath, cmd)
}
