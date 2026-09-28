//go:build darwin

package pf

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"portalguard/internal/firewall"
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
// It is a var rather than a const so tests can redirect it; nothing else
// should reassign it.
var tokenPath = "/var/run/portalguard.pf-token"

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

// ==== the running account =================================================
// pf's counters belong to the kernel, so the total has to as well.

// counterPath holds the packet counts accumulated so far in this engagement.
//
// It is here for a reason that took a blank leak report at a hotspot to
// notice: **pf's per-rule counters belong to the kernel, not to a process, and
// any reload resets them for everybody.** Every invocation banks the live
// counters before it reloads, so as long as only one process ever reloaded,
// keeping the running total in that process's memory was correct.
//
// Making `allow` work from a second terminal broke that silently. The second
// process banks the machine's counters into its own memory, reloads - wiping
// pf's numbers for everyone - and exits. The `run` still waiting in the first
// terminal never sees them again, and its report is short by exactly the
// traffic that happened while the user was working out what to unblock, which
// is the most interesting part of the run.
//
// So the total lives where every invocation can reach it, next to the pf
// token, and for the same reasons: root-only, and cleared on reboot.
// It is a var rather than a const so tests can redirect it.
var counterPath = "/var/run/portalguard.counters"

// tallyFile is the on-disk shape of the running total. It is written out
// explicitly rather than by reflecting over `tally` so that renaming a field
// cannot silently change the file format under a half-finished engagement.
type tallyFile struct {
	Version           int    `json:"version"`
	BlockedOutPackets uint64 `json:"blocked_out_packets"`
	BlockedOutBytes   uint64 `json:"blocked_out_bytes"`
	BlockedInPackets  uint64 `json:"blocked_in_packets"`
	BlockedInBytes    uint64 `json:"blocked_in_bytes"`
	DNSPackets        uint64 `json:"dns_packets"`
	DNSBytes          uint64 `json:"dns_bytes"`
	PortalPackets     uint64 `json:"portal_packets"`
	PortalBytes       uint64 `json:"portal_bytes"`
	CheckPackets      uint64 `json:"check_packets,omitempty"`
	CheckBytes        uint64 `json:"check_bytes,omitempty"`
	// SampleAttempts and SampleFailures are what let an empty report say
	// which kind of empty it is. Without them "nothing was accounted for" has
	// to guess at its own cause, and a quiet network and a broken measurement
	// read identically - which is the one mistake the leak report exists not
	// to make.
	SampleAttempts int `json:"sample_attempts"`
	SampleFailures int `json:"sample_failures"`
}

const tallyVersion = 1

// loadTally reads the running total. The bool is false when there is nothing
// usable to read, which the caller must treat as "keep what you have" rather
// than "the total is zero".
func loadTally() (tally, bool) {
	data, err := os.ReadFile(counterPath)
	if err != nil {
		return tally{}, false
	}
	var f tallyFile
	if err := json.Unmarshal(data, &f); err != nil || f.Version != tallyVersion {
		return tally{}, false
	}
	return tally{
		blockedOutPkts:  f.BlockedOutPackets,
		blockedOutBytes: f.BlockedOutBytes,
		blockedInPkts:   f.BlockedInPackets,
		blockedInBytes:  f.BlockedInBytes,
		dnsPkts:         f.DNSPackets,
		dnsBytes:        f.DNSBytes,
		portalPkts:      f.PortalPackets,
		portalBytes:     f.PortalBytes,
		checkPkts:       f.CheckPackets,
		checkBytes:      f.CheckBytes,
		attempts:        f.SampleAttempts,
		failures:        f.SampleFailures,
	}, true
}

// saveTally records the running total for the next invocation.
func saveTally(t tally) error {
	data, err := json.Marshal(tallyFile{
		Version:           tallyVersion,
		BlockedOutPackets: t.blockedOutPkts,
		BlockedOutBytes:   t.blockedOutBytes,
		BlockedInPackets:  t.blockedInPkts,
		BlockedInBytes:    t.blockedInBytes,
		DNSPackets:        t.dnsPkts,
		DNSBytes:          t.dnsBytes,
		PortalPackets:     t.portalPkts,
		PortalBytes:       t.portalBytes,
		CheckPackets:      t.checkPkts,
		CheckBytes:        t.checkBytes,
		SampleAttempts:    t.attempts,
		SampleFailures:    t.failures,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(counterPath, append(data, '\n'), 0o600)
}

// clearTally forgets the running total. A fresh engagement gets a fresh
// account, and a released one leaves none behind.
func clearTally() {
	_ = os.Remove(counterPath)
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
	b.allowed = nil
	if gapRulesLoaded(out) {
		b.phase = firewall.PhaseGap
		b.allowed = b.allowedFromKernel(ctx, out)
	}
}

// allowedFromKernel rebuilds the allow-list from the loaded rules and the
// tables they reference. Called only when the gap rules are loaded, so
// everything it returns is genuinely permitted by a rule and not merely
// sitting in a `persist` table that nothing points at.
//
// Recovering this is what makes `allow` usable as a separate command. Without
// it a second invocation starts with an empty allow-list, and AllowHost
// renders the next ruleset from that list plus the one new host - which pf
// loads as a *replacement*, quietly evicting the portal address and the
// resolvers the first invocation pinned. The gap would appear to widen while
// actually moving, and the login page would go dead at the moment the user
// added the host that was supposed to fix it.
//
// The caller must hold b.mu.
func (b *Backend) allowedFromKernel(ctx context.Context, rules string) []firewall.Host {
	var out []firewall.Host

	if addrs := b.tableAddrs(ctx, portalTable); len(addrs) > 0 {
		ports := portsFromRules(rules, portalTable)
		if len(ports) == 0 {
			// The rules permit these addresses on ports we could not read, so
			// carrying on with the defaults would silently narrow the gap on
			// the next reload - dropping exactly the non-standard port a
			// portal needed us to open. Say so rather than let it pass.
			b.appendNote(fmt.Sprintf(
				"could not read the open ports back from the loaded ruleset; falling back to %v, so a gap on any other port will close on the next `allow`",
				defaultPortalPorts))
		}
		out = append(out, firewall.Host{
			Name:   "portal",
			Addrs:  addrs,
			Ports:  ports,
			Reason: "captive portal login page",
		})
	}

	if addrs := b.tableAddrs(ctx, dnsTable); len(addrs) > 0 {
		out = append(out, firewall.Host{
			Name:       "resolvers",
			Addrs:      addrs,
			Ports:      []int{53},
			AllowDNSTo: true,
			Reason:     "the portal login flow needs to resolve its own hostname",
		})
	}

	// The check hole is carried across processes the same way: an `allow`
	// from a second terminal that dropped it would silently stop the waiting
	// `run` from ever noticing the login had gone through.
	if addrs := b.tableAddrs(ctx, checkTable); len(addrs) > 0 {
		out = append(out, firewall.Host{
			Name:   "portalguard checks",
			Addrs:  addrs,
			Ports:  portsFromRules(rules, checkTable),
			Check:  true,
			Reason: "Portalguard's own re-probe and certificate checks",
		})
	}
	return out
}

// portRe pulls the numbers out of a pf port clause.
var portRe = regexp.MustCompile(`\d+`)

// portsFromRules reads the destination ports a loaded ruleset permits to a
// table.
//
// It has to cope with two spellings of the same thing. What we write is a list
// (`port { 80, 443, 8443 }`); what pfctl reads back is one rule per port with
// the list already expanded (`port = 8443`). Parsing both means the recovered
// ruleset is identical to the one it replaces, whichever source it came from,
// which is what the round-trip test checks.
func portsFromRules(rules, table string) []int {
	seen := map[int]bool{}
	var out []int
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pass") || !strings.Contains(line, "<"+table+">") {
			continue
		}
		// Everything after the table reference, so an address or an interface
		// number earlier in the line cannot be mistaken for a port.
		_, rest, ok := strings.Cut(line, "<"+table+">")
		if !ok {
			continue
		}
		i := strings.Index(rest, "port")
		if i < 0 {
			continue
		}
		clause := rest[i+len("port"):]
		// Stop at the rule's trailing keywords, which carry numbers of their
		// own on some pfctl versions (`keep state`, `(max 100)`).
		if j := strings.Index(clause, "keep"); j >= 0 {
			clause = clause[:j]
		}
		for _, m := range portRe.FindAllString(clause, -1) {
			n, err := strconv.Atoi(m)
			if err != nil || n < 1 || n > 65535 || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
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
