//go:build darwin

// Package pf is the macOS backend for Portalguard, built on pf(4) driven
// through pfctl(8).
//
// All of Portalguard's rules live inside a single named anchor
// ("portalguard"). Nothing else on the system is edited while we are running,
// and teardown is one command that empties that anchor, which is what makes
// the fail-safe guarantee in internal/firewall/safety.go achievable.
//
// v0.1 deliberately uses pfctl rather than a Network Extension: it needs no
// entitlement, no signed system extension and no user approval dialog, at the
// cost of needing root.
package pf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mredchristie/portalguard/internal/firewall"
)

// AnchorName is the pf anchor that holds every rule Portalguard installs.
// Keeping it to one anchor means `pfctl -a portalguard -F all` is a complete
// undo.
const AnchorName = "portalguard"

// pfctlPath is the absolute path to pfctl; we do not trust PATH for a
// privileged command.
const pfctlPath = "/sbin/pfctl"

// errPendingReview marks the rule-programming calls that are intentionally
// inert until the anchor ruleset has been reviewed. See docs/pf-design.md.
var errPendingReview = errors.New("pf: rule programming not enabled yet (pending ruleset review)")

// Backend programs pf via pfctl.
type Backend struct {
	mu      sync.Mutex
	phase   firewall.Phase
	allowed []firewall.Host
	since   time.Time

	// enableToken is the reference-counted token returned by `pfctl -E`. pf on
	// macOS is shared: we must release our reference with `pfctl -X <token>`
	// rather than disabling pf outright, or we break other users of pf.
	enableToken string
}

// New returns the macOS pf backend.
func New() *Backend {
	return &Backend{phase: firewall.PhaseOff}
}

func (b *Backend) Name() string { return "pf" }

// Available reports whether pf can be driven from this process.
func (b *Backend) Available(ctx context.Context) (bool, string) {
	if _, err := os.Stat(pfctlPath); err != nil {
		return false, pfctlPath + " not found; is this really macOS?"
	}
	if os.Geteuid() != 0 {
		return false, "pf requires root: re-run with sudo"
	}
	if _, err := b.pfctl(ctx, "-s", "info"); err != nil {
		return false, fmt.Sprintf("pfctl is not usable: %v", err)
	}
	return true, ""
}

func (b *Backend) Lockdown(context.Context) error                 { return errPendingReview }
func (b *Backend) AllowHost(context.Context, firewall.Host) error { return errPendingReview }
func (b *Backend) Seal(context.Context) error                     { return errPendingReview }

// Release empties the Portalguard anchor and drops our pf enable reference.
// It is safe to run at any time, including when nothing was ever installed,
// and it is the manual escape hatch behind `sudo portalguard release`.
func (b *Backend) Release(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var errs []error

	// -F all empties rules, states and tables belonging to the anchor only.
	if _, err := b.pfctl(ctx, "-a", AnchorName, "-F", "all"); err != nil {
		// A missing anchor is not a failure: there was nothing to undo.
		if !isMissingAnchor(err) {
			errs = append(errs, fmt.Errorf("flush anchor: %w", err))
		}
	}

	if b.enableToken != "" {
		if _, err := b.pfctl(ctx, "-X", b.enableToken); err != nil {
			errs = append(errs, fmt.Errorf("release pf enable token %s: %w", b.enableToken, err))
		}
		b.enableToken = ""
	}

	b.phase = firewall.PhaseOff
	b.allowed = nil
	b.since = time.Time{}
	return errors.Join(errs...)
}

// Status reads the anchor back from the kernel rather than reporting what we
// think we installed.
func (b *Backend) Status(ctx context.Context) (firewall.Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	st := firewall.Status{
		Backend: b.Name(),
		Phase:   b.phase,
		Allowed: append([]firewall.Host(nil), b.allowed...),
		Since:   b.since,
	}
	ok, why := b.availableLocked(ctx)
	st.Available = ok
	if !ok {
		st.Detail = why
		return st, nil
	}

	out, err := b.pfctl(ctx, "-a", AnchorName, "-s", "rules")
	if err != nil {
		if isMissingAnchor(err) {
			st.Managed = false
			st.Phase = firewall.PhaseOff
			return st, nil
		}
		return st, fmt.Errorf("read anchor rules: %w", err)
	}
	rules := strings.TrimSpace(out)
	st.Managed = rules != ""
	st.Detail = rules
	if !st.Managed {
		st.Phase = firewall.PhaseOff
	}
	return st, nil
}

// availableLocked is Available without re-taking the mutex.
func (b *Backend) availableLocked(ctx context.Context) (bool, string) {
	if _, err := os.Stat(pfctlPath); err != nil {
		return false, pfctlPath + " not found"
	}
	if os.Geteuid() != 0 {
		return false, "pf requires root: re-run with sudo"
	}
	return true, ""
}

// pfctl runs pfctl and returns its combined output. pfctl is chatty on stderr
// even when it succeeds, so callers should treat stderr as informational.
func (b *Backend) pfctl(ctx context.Context, args ...string) (string, error) {
	return b.pfctlStdin(ctx, nil, args...)
}

// pfctlStdin runs pfctl with the given stdin, used to load anchor rules with
// `-f -` so we never write a ruleset to disk.
func (b *Backend) pfctlStdin(ctx context.Context, stdin []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, pfctlPath, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	text := out.String()
	if err != nil {
		return text, fmt.Errorf("pfctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(text))
	}
	return text, nil
}

// isMissingAnchor reports whether a pfctl error just means "that anchor does
// not exist", which for our purposes is equivalent to "nothing installed".
func isMissingAnchor(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such file or directory") ||
		strings.Contains(s, "anchor") && strings.Contains(s, "not exist")
}

var _ firewall.Backend = (*Backend)(nil)
