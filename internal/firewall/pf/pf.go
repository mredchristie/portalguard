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
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"portalguard/internal/firewall"
)

// AnchorName is the pf anchor that holds every rule Portalguard installs.
// Keeping it to one anchor means `pfctl -a portalguard -F all` is a complete
// undo.
const AnchorName = "portalguard"

// pfctlPath is the absolute path to pfctl; we do not trust PATH for a
// privileged command.
const pfctlPath = "/sbin/pfctl"

// ErrNoAnchorHook means rules would load successfully and filter nothing,
// because the main ruleset has no `anchor "portalguard"` line to reach them
// through. This is the one failure that must never be papered over: it would
// leave portalguard reporting LOCKED_DOWN over a wide open network.
//
// The usual cause is not a botched install but a macOS update: updates restore
// the stock /etc/pf.conf and the hook goes with it. Seen after 26.7.1.
var ErrNoAnchorHook = errors.New(`pf: the loaded ruleset has no anchor "portalguard" line, so portalguard's rules would load but never be evaluated; run: sudo portalguard install-anchor (the usual causes: a macOS update restored /etc/pf.conf, or Internet Sharing or a VPN loaded a ruleset of its own)`)

// tokenRe extracts the reference token from `pfctl -E` output.
var tokenRe = regexp.MustCompile(`(?i)token\s*:\s*(\d+)`)

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

	// logCreated records whether *we* created the pflog device. One we found
	// already there belongs to somebody else and is never destroyed.
	logCreated bool

	// logNote carries a non-fatal problem with leak logging, surfaced in
	// Status rather than failing the operation that hit it.
	logNote string

	// counters accumulate across every ruleset loaded during this engagement,
	// by any invocation, because pf resets per-rule statistics on reload and
	// every phase change reloads. Persisted; see counterPath in persist.go.
	counters tally

	// counterNoteMade stops a persistent failure to record the counters from
	// being reported once per sample.
	counterNoteMade bool

	// gapOpened and gapClosed bound the window the report describes.
	gapOpened time.Time
	gapClosed time.Time

	// resolvers records who the DNS hole pointed at, for the report.
	resolvers []net.IP

	// reader tails pflog1 for hostnames and process attribution while the
	// gap is open. nil until AllowHost successfully wires up logging, and
	// nil again once Seal or Release has collected its results.
	reader *logReader

	// leakNames, leakProcesses and leakProcessesUnavailable are the
	// reader's results, collected once at Seal or Release. They live on the
	// backend rather than the reader so the report can still be read after
	// the reader itself has been torn down.
	leakNames                []string
	leakProcesses            []string
	leakProcessesUnavailable bool
	// leakProcessNote is the tagged diagnostic behind
	// leakProcessesUnavailable ("[parse] ...", "[heuristic] ..." or
	// "[kernel] ..."). Carried separately from logNote so it reaches the
	// Report itself, not only Status() - Status() dies with the process,
	// the report does not.
	leakProcessNote string
	// leakProcessesDeclinedByKernel is true when every attributable record
	// this run saw was the confirmed kernel "not attributed" sentinel, not
	// a read failure - see Report.ProcessesDeclinedByKernel.
	leakProcessesDeclinedByKernel bool

	// dnsFilter is set while the gap's DNS goes through Portalguard's own
	// resolver. Recovered from the kernel by a second process (the loaded
	// rules carry a route-to only when it is on), so an `allow` from another
	// terminal keeps it.
	dnsFilter bool

	// exec, when set, replaces the real pfctl and ifconfig invocations.
	//
	// It exists so the rule-programming sequence can be tested without root
	// and without touching the machine's networking. The counter accumulation
	// in particular is only correct across a whole Lockdown/AllowHost/Seal
	// sequence, which is not something a unit test of any single function can
	// establish.
	exec commandRunner
}

// commandRunner is the shape of a privileged command invocation.
type commandRunner func(ctx context.Context, path string, stdin []byte, args ...string) (string, error)

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

// Release empties the Portalguard anchor and drops our pf enable reference.
// It is safe to run at any time, including when nothing was ever installed,
// and it is the manual escape hatch behind `sudo portalguard release`.
func (b *Backend) Release(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var errs []error

	// Bank the counters before the flush destroys them. A run torn down
	// without a seal - an abort, a signal, a panic - still gets a report.
	b.sampleCountersLocked(ctx)
	if b.phase == firewall.PhaseGap && b.gapClosed.IsZero() {
		b.gapClosed = time.Now()
	}

	// Flush our rules and our tables, both scoped to the anchor. Deliberately
	// not -F all, which would take the state table with it and drop every TCP
	// connection on the machine - a rude surprise when all that was asked for
	// was the network back. Stale states are harmless once the rules are gone.
	//
	// The hand-typed rescue command (`make rescue`) does use -F all, because a
	// human typing it wants maximum effect and one flag to remember.
	// nat too: it holds the DNS filter's rdr rule, and flushing "rules"
	// covers only filter rules.
	for _, what := range []string{"rules", "nat", "Tables"} {
		if _, err := b.pfctl(ctx, "-a", AnchorName, "-F", what); err != nil {
			// A missing anchor is not a failure: there was nothing to undo.
			if !isMissingAnchor(err) {
				errs = append(errs, fmt.Errorf("flush anchor %s: %w", what, err))
			}
		}
	}

	// Collect whatever the reader found before the device goes: a run torn
	// down without a seal still gets a report. The log device goes with the
	// rules, and only if it was ours.
	b.stopReaderLocked()
	if err := b.destroyLogInterface(ctx); err != nil {
		errs = append(errs, err)
	}

	// The token may have been written by an earlier invocation: `lockdown` and
	// `release` are usually different processes.
	if b.enableToken == "" {
		b.enableToken = loadToken()
	}
	if b.enableToken != "" {
		if _, err := b.pfctl(ctx, "-X", b.enableToken); err != nil {
			errs = append(errs, fmt.Errorf("release pf enable token %s: %w", b.enableToken, err))
		}
		b.enableToken = ""
	}
	clearToken()

	// The engagement is over, so the account closes with it. The totals stay
	// in memory: a run torn down without a seal still has its report read
	// after this returns.
	clearTally()

	b.phase = firewall.PhaseOff
	b.allowed = nil
	b.since = time.Time{}
	b.dnsFilter = false
	return errors.Join(errs...)
}

// Status reads the anchor back from the kernel rather than reporting what we
// think we installed.
func (b *Backend) Status(ctx context.Context) (firewall.Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if ok, _ := b.availableLocked(ctx); ok {
		b.syncFromKernel(ctx)
	}

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
	rules := strings.TrimSpace(stripPfctlNoise(out))
	st.Managed = rules != ""
	st.Detail = rules
	if !st.Managed {
		st.Phase = firewall.PhaseOff
	}

	// The allow-list is read back from the kernel, and only when the rules
	// actually reference the tables.
	//
	// This is the invariant that matters for anything rendering a UI: an
	// address may only be shown as open if a pass rule permits it. Reporting
	// table contents unconditionally would show a sealed machine as still
	// letting the portal through, because `persist` tables outlive the rules
	// that referenced them.
	st.Allowed = nil
	if st.Phase == firewall.PhaseGap {
		// syncFromKernel, at the top of this method, has already rebuilt
		// b.allowed from the loaded rules and the tables they reference.
		st.Allowed = append([]firewall.Host(nil), b.allowed...)
	} else if residue := b.openAddrsLocked(ctx); len(residue) > 0 {
		// Not reachable through any rule, but worth saying out loud: it means
		// a teardown did not finish, and `pfctl -a portalguard -F Tables`
		// will clear it.
		st.Detail = fmt.Sprintf(
			"note: %d address(es) left in the gap tables with no rule permitting them (residue from an interrupted teardown; harmless, clear with `pfctl -a %s -F Tables`)\n%s",
			len(residue), AnchorName, st.Detail)
	}

	if b.logNote != "" {
		st.Detail = b.logNote + "\n" + st.Detail
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
	if b.exec != nil {
		return b.exec(ctx, pfctlPath, stdin, args...)
	}
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

// stripPfctlNoise drops the lines pfctl prints on stderr whatever it is asked,
// which the combined output would otherwise pass off as rules. On a Mac
// without ALTQ, every call can open with two of them.
func stripPfctlNoise(out string) string {
	var keep []string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "No ALTQ support in kernel") || strings.HasPrefix(t, "ALTQ related functions disabled") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

// appendNote adds a non-fatal problem to logNote, keeping any earlier one
// rather than overwriting it. More than one independent thing can go wrong
// in a single run - losing an earlier note to a later one would hide it
// from Status().
func (b *Backend) appendNote(s string) {
	if b.logNote == "" {
		b.logNote = s
		return
	}
	b.logNote += "\n" + s
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
