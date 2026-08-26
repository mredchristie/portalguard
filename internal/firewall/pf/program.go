//go:build darwin

package pf

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mredchristie/portalguard/internal/firewall"
)

// Lockdown blocks everything except what the machine needs to stay on the
// link. It is the first rule-writing call and the point of no return for the
// network, so it verifies the anchor hook before touching anything: rules
// loaded into an unreferenced anchor load cleanly and filter nothing, which
// would leave the caller believing the machine is protected when it is wide
// open.
func (b *Backend) Lockdown(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if ok, err := b.hookInstalled(ctx); err != nil {
		return fmt.Errorf("check anchor hook: %w", err)
	} else if !ok {
		return ErrNoAnchorHook
	}

	if err := b.enableLocked(ctx); err != nil {
		return err
	}

	if err := b.loadLocked(ctx, gap{}); err != nil {
		return err
	}

	b.phase = firewall.PhaseLocked
	b.allowed = nil
	b.since = time.Now()
	return nil
}

// AllowHost widens the gap by one host and reloads. Loading a ruleset into an
// anchor is atomic, so there is no instant where the old rules are gone and
// the new ones have not arrived.
func (b *Backend) AllowHost(ctx context.Context, h firewall.Host) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.syncFromKernel(ctx)
	if b.phase == firewall.PhaseOff {
		return firewall.ErrNotLocked
	}
	if len(h.Addrs) == 0 {
		return fmt.Errorf("pf: refusing to open a hole for %q with no address", h.Name)
	}

	// Set up the log device before the gap opens, so the first leaked query is
	// captured rather than missed. A failure here is reported and ignored:
	// losing the leak log is bad, but failing to open the gap over it would
	// leave the user unable to log in at all.
	g := gapFromHosts(next(b.allowed, h))
	if created, err := b.ensureLogInterface(ctx); err != nil {
		b.logNote = fmt.Sprintf("leak logging unavailable: %v", err)
	} else {
		b.logCreated = b.logCreated || created
		g.logTo = LogInterface
	}

	if err := b.loadLocked(ctx, g); err != nil {
		// The previous ruleset is still loaded, so the failure leaves the
		// filter no more permissive than it already was.
		return err
	}
	b.allowed = next(b.allowed, h)
	b.phase = firewall.PhaseGap
	return nil
}

// next returns the allow-list with one more host on it.
func next(current []firewall.Host, h firewall.Host) []firewall.Host {
	return append(append([]firewall.Host(nil), current...), h)
}

// Seal closes the gap and returns to a bare lockdown.
//
// Reloading the rules only stops *new* connections: states created while the
// gap was open survive a ruleset change. So it also kills those states, for
// every address in both tables rather than only the originally detected portal
// IP, because a host added by `portalguard allow` would otherwise survive the
// seal with a live connection open to a third party.
func (b *Backend) Seal(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.syncFromKernel(ctx)
	if b.phase == firewall.PhaseOff {
		return firewall.ErrNotLocked
	}

	// Read the addresses back from the kernel rather than trusting our own
	// bookkeeping about what we opened.
	addrs := b.openAddrsLocked(ctx)

	// Rules first, then states: the other order leaves a window where a
	// killed connection can immediately re-establish.
	if err := b.loadLocked(ctx, gap{}); err != nil {
		return err
	}
	b.phase = firewall.PhaseLocked
	b.allowed = nil

	// Empty the tables now that their addresses have been read out above.
	//
	// pf tables are declared `persist`, so they survive a ruleset that no
	// longer references them. Leaving them populated would mean the pinned
	// addresses outlive the permission they represented, which is exactly the
	// mismatch a UI reading the tables would render as "still open".
	if _, err := b.pfctl(ctx, "-a", AnchorName, "-F", "Tables"); err != nil {
		if !isMissingAnchor(err) {
			return fmt.Errorf("seal: flush tables: %w", err)
		}
	}

	if err := b.destroyLogInterface(ctx); err != nil {
		b.logNote = err.Error()
	}

	var failed []string
	for _, ip := range addrs {
		if err := b.killStatesTo(ctx, ip); err != nil {
			failed = append(failed, ip.String())
		}
	}
	if len(failed) > 0 {
		// The gap is closed either way; report rather than fail, since the
		// caller's next move should not be to unwind a good seal.
		return fmt.Errorf("pf: sealed, but could not kill existing states to %s",
			strings.Join(failed, ", "))
	}
	return nil
}

// openAddrsLocked reads both gap tables out of the kernel. Errors are
// swallowed: a missing table means nothing was open, and Seal must not fail
// because it could not enumerate what it is closing.
func (b *Backend) openAddrsLocked(ctx context.Context) []net.IP {
	var out []net.IP
	for _, table := range []string{portalTable, dnsTable} {
		out = append(out, b.tableAddrs(ctx, table)...)
	}
	return out
}

// tableAddrs returns the current contents of one of our pf tables.
func (b *Backend) tableAddrs(ctx context.Context, table string) []net.IP {
	out, err := b.pfctl(ctx, "-a", AnchorName, "-t", table, "-T", "show")
	if err != nil {
		return nil
	}
	var addrs []net.IP
	for _, line := range strings.Split(out, "\n") {
		field := strings.TrimSpace(line)
		if field == "" {
			continue
		}
		// Table entries can carry a /prefix; we only ever add host addresses.
		if host, _, ok := strings.Cut(field, "/"); ok {
			field = host
		}
		if ip := net.ParseIP(field); ip != nil {
			addrs = append(addrs, ip)
		}
	}
	return addrs
}

// killStatesTo drops every state whose target is the given address. The
// wildcard source has to match the address family, per pfctl(8): "A network
// prefix length of 0 can be used as a wildcard."
func (b *Backend) killStatesTo(ctx context.Context, ip net.IP) error {
	wildcard := "0.0.0.0/0"
	if ip.To4() == nil {
		wildcard = "::/0"
	}
	_, err := b.pfctl(ctx, "-k", wildcard, "-k", ip.String())
	return err
}

// loadLocked renders and loads an anchor ruleset from stdin, so no ruleset is
// ever written to disk and nothing survives a reboot.
func (b *Backend) loadLocked(ctx context.Context, g gap) error {
	rules := render(g)
	if _, err := b.pfctlStdin(ctx, []byte(rules), "-a", AnchorName, "-f", "-"); err != nil {
		return fmt.Errorf("load anchor ruleset: %w", err)
	}
	return nil
}

// enableLocked enables pf through its reference-counted interface and keeps
// the token, so releasing our reference can never turn pf off underneath
// something else that is using it.
func (b *Backend) enableLocked(ctx context.Context) error {
	if b.enableToken != "" {
		return nil
	}
	out, err := b.pfctl(ctx, "-E")
	if err != nil {
		return fmt.Errorf("enable pf: %w", err)
	}
	if m := tokenRe.FindStringSubmatch(out); m != nil {
		b.enableToken = m[1]
		// Persist it: the process that releases is usually not the one that
		// enabled, and an unreleased reference outlives us otherwise.
		if err := saveToken(b.enableToken); err != nil {
			return err
		}
		return nil
	}
	// pf is enabled but we have no token to release later. Say so rather than
	// silently leaving a reference behind forever.
	return fmt.Errorf("pf: enabled, but could not parse the reference token from: %q", strings.TrimSpace(out))
}

// hookInstalled reports whether the main ruleset references our anchor. See
// ErrNoAnchorHook for why this is checked before every lockdown.
func (b *Backend) hookInstalled(ctx context.Context) (bool, error) {
	out, err := b.pfctl(ctx, "-s", "rules")
	if err != nil {
		return false, err
	}
	return anchorReferenced(out, AnchorName), nil
}

// anchorReferenced looks for our anchor in a main-ruleset listing.
func anchorReferenced(rules, anchor string) bool {
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "anchor ") {
			continue
		}
		// pfctl prints `anchor "portalguard" all`; pf.conf writes
		// `anchor "portalguard"`. Match the quoted name either way.
		if strings.Contains(line, `"`+anchor+`"`) || strings.Contains(line, `"`+anchor+`/`) {
			return true
		}
	}
	return false
}

// PreviewRules renders the ruleset for a given allow-list without touching pf.
// It backs `portalguard print-rules`, which is how the rulesets get parse
// checked (`pfctl -a portalguard -n -f -`) before anything is loaded.
func PreviewRules(hosts []firewall.Host) string {
	if len(hosts) == 0 {
		return render(gap{})
	}
	return render(gapFromHosts(hosts))
}
