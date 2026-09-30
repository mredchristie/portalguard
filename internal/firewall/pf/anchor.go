//go:build darwin

package pf

import (
	"context"
	"errors"
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

	// hookAnchorPoint is the line the block is inserted above.
	hookAnchorPoint = `anchor "com.apple/*"`

	// The second hook, added in v0.3: a translation anchor, so the DNS filter
	// can redirect the gap's DNS to Portalguard's own resolver. pf applies
	// rdr rules only from anchors the main ruleset reaches with rdr-anchor,
	// and translation anchors must sit in pf.conf's translation section,
	// which is why this is a separate block rather than a line in the first.
	rdrBeginMarker = "# BEGIN portalguard-rdr"
	rdrEndMarker   = "# END portalguard-rdr"
	// rdrAnchorPoint is the line the rdr block is inserted below.
	rdrAnchorPoint = `rdr-anchor "com.apple/*"`

	filterHookLine = `anchor "portalguard"`
	rdrHookLine    = `rdr-anchor "portalguard"`
)

// rdrHookBlock is the translation hook, inserted after Apple's own.
func rdrHookBlock() string {
	return rdrBeginMarker + " - redirect point for the DNS filter, empty unless portalguard is running.\n" +
		rdrHookLine + "\n" +
		rdrEndMarker
}

// hookBlock is inserted verbatim. Placement matters twice over: it must come
// after the nat/rdr/dummynet anchors, because pf demands options then
// normalisation then translation then filtering and this is a filter anchor;
// and it comes before com.apple so that our `quick` block cannot be undercut
// by a `pass quick` inside the AirDrop or Application Firewall anchors Apple
// populates dynamically.
//
// A function rather than a const so the revert instruction it writes into
// /etc/pf.conf names how this specific `install-anchor` invocation was
// actually run (os.Args[0]) instead of a bare "portalguard", which fails
// with "command not found" for the common case of a binary that was never
// `make install`'d onto PATH.
func hookBlock() string {
	return beginMarker + " - anchor point, empty unless portalguard is running.\n" +
		"# Remove this block, or run `sudo " + os.Args[0] + " uninstall-anchor`, to revert.\n" +
		`anchor "portalguard"` + "\n" +
		endMarker
}

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
	// Each hook is added only if missing, so an install from before v0.3
	// gains the rdr hook without its filter hook being touched.
	updated := string(original)
	if !hasLine(updated, filterHookLine) {
		if updated, err = insertHook(updated); err != nil {
			return err
		}
	}
	if !hasLine(updated, rdrHookLine) {
		if updated, err = insertRdrHook(updated); err != nil {
			return err
		}
	}
	if updated == string(original) {
		return nil // already installed
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
		out = append(out, strings.Split(hookBlock(), "\n")...)
		out = append(out, lines[i:]...)
		return strings.Join(out, "\n"), nil
	}
	return "", fmt.Errorf(
		"could not find %s in %s, so there is no safe place to insert the anchor; add it by hand (see docs/pf-design.md)",
		hookAnchorPoint, PfConfPath)
}

// insertRdrHook places the rdr block directly after Apple's rdr anchor, which
// keeps it in the translation section where pf requires it.
func insertRdrHook(conf string) (string, error) {
	lines := strings.Split(conf, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != rdrAnchorPoint {
			continue
		}
		out := make([]string, 0, len(lines)+3)
		out = append(out, lines[:i+1]...)
		out = append(out, strings.Split(rdrHookBlock(), "\n")...)
		out = append(out, lines[i+1:]...)
		return strings.Join(out, "\n"), nil
	}
	return "", fmt.Errorf(
		"could not find %s in %s, so there is no safe place for the rdr anchor; add %s by hand after the other rdr-anchor lines",
		rdrAnchorPoint, PfConfPath, rdrHookLine)
}

// hasLine reports whether conf has exactly this line, ignoring indentation.
func hasLine(conf, want string) bool {
	for _, line := range strings.Split(conf, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// removeHook strips the block back out, markers included. Both blocks go:
// the rdr markers start with the same "# BEGIN portalguard" prefix.
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
	return hasLine(string(conf), filterHookLine) && hasLine(string(conf), rdrHookLine), nil
}

// rdrHookLoaded reports whether the loaded main ruleset reaches our rdr
// anchor. The DNS filter depends on it, and falls back to unfiltered DNS
// without it rather than divert DNS to a redirect that never happens.
//
// The caller must hold b.mu.
func (b *Backend) rdrHookLoaded(ctx context.Context) bool {
	out, err := b.pfctl(ctx, "-s", "nat")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "rdr-anchor ") && strings.Contains(line, `"`+AnchorName+`"`) {
			return true
		}
	}
	return false
}

func firewallNeedsRoot(cmd string) error {
	return fmt.Errorf("pf: %s edits %s and needs root: try `sudo %s %s`", cmd, PfConfPath, os.Args[0], cmd)
}

// HooksLoaded reports whether pf's loaded main ruleset reaches both anchors.
// It can be false while pf.conf on disk has them: anything that loads a
// ruleset of its own (Internet Sharing, a VPN kill switch) replaces the
// loaded one, and our hooks with it.
func HooksLoaded(ctx context.Context) bool {
	b := New()
	b.mu.Lock()
	defer b.mu.Unlock()
	filter, err := b.hookInstalled(ctx)
	return err == nil && filter && b.rdrHookLoaded(ctx)
}

// ReloadPfConf loads /etc/pf.conf again, validating it first. It puts our
// hooks back after another tool replaced the loaded ruleset, and in doing so
// removes whatever that tool had loaded.
func ReloadPfConf(ctx context.Context) error {
	b := New()
	if _, err := b.pfctl(ctx, "-n", "-f", PfConfPath); err != nil {
		return fmt.Errorf("%s did not parse, so it was not loaded: %w", PfConfPath, err)
	}
	if _, err := b.pfctl(ctx, "-f", PfConfPath); err != nil {
		return fmt.Errorf("load %s: %w", PfConfPath, err)
	}
	return nil
}

// LoopbackSkipped reports whether pf is skipping lo0, which stops the DNS
// filter's redirect. See ErrLoopbackSkipped.
func LoopbackSkipped(ctx context.Context) bool {
	b := New()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.loopbackSkipped(ctx)
}

// ErrEngaged means portalguard's own rules are loaded, so a full flush would
// throw away a lockdown that is in use.
var ErrEngaged = errors.New("portalguard's rules are loaded; run `sudo portalguard release` first")

// ClearLoopbackSkip removes a `set skip on lo0` that another tool set at
// runtime, and loads /etc/pf.conf again.
//
// Reloading pf.conf alone does not do it: pf keeps an interface's skip flag
// across a reload that does not mention it, which is how NordVPN's survives
// long after it disconnects. Only a full flush clears interface flags, and it
// takes everything else loaded with it, which is why it refuses while
// portalguard itself is engaged. Established connections may need to
// reconnect afterwards.
func ClearLoopbackSkip(ctx context.Context) error {
	b := New()
	if _, err := b.pfctl(ctx, "-n", "-f", PfConfPath); err != nil {
		return fmt.Errorf("%s did not parse, so nothing was changed: %w", PfConfPath, err)
	}
	// Status, not a bare `-s rules`: pfctl's chatter on stderr would read as
	// rules and refuse forever.
	if st, err := b.Status(ctx); err != nil {
		return fmt.Errorf("could not tell whether portalguard is engaged, so nothing was changed: %w", err)
	} else if st.Managed {
		return ErrEngaged
	}
	if _, err := b.pfctl(ctx, "-F", "all"); err != nil {
		return fmt.Errorf("flush pf: %w", err)
	}
	if _, err := b.pfctl(ctx, "-f", PfConfPath); err != nil {
		return fmt.Errorf("load %s after the flush: %w", PfConfPath, err)
	}
	if LoopbackSkipped(ctx) {
		return errors.New("pf still skips lo0 after a flush and reload; something is setting it again (is the VPN app still running?). a reboot clears it")
	}
	return nil
}
