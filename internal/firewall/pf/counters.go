//go:build darwin

package pf

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"portalguard/internal/firewall"
)

// pf keeps per-rule statistics, and `pfctl -s rules -v` prints them:
//
//	block drop out quick all
//	  [ Evaluations: 1204      Packets: 412       Bytes: 38104      States: 0     ]
//
// That is the whole source of the counter-based report. It needs no pflog
// device, no BPF access and no packet capture - just the rules we already
// load - which is why it is the layer that ships first and the layer that
// still works when everything fancier is unavailable.
//
// Two properties of these counters drive the design:
//
//   - They are per-rule and reset when the ruleset is reloaded. Portalguard
//     reloads on every phase change, so lockdown's counts are destroyed the
//     instant the gap ruleset loads. Totals must therefore be sampled *before*
//     each reload and accumulated, never read once at the end.
//   - "Packets passed statefully are counted in the rule that created the
//     state" (pfctl(8)), so a DNS query and its reply both land on the DNS
//     pass rule. The number is packets, not lookups, and the report says so.

// ==== parsing pfctl output ================================================
// Pull packets and bytes out of the stats line under each rule.

// counterRe matches the statistics line pfctl prints under each rule.
var counterRe = regexp.MustCompile(
	`\[\s*Evaluations:\s*(\d+)\s+Packets:\s*(\d+)\s+Bytes:\s*(\d+)`)

// ruleCounters is one rule and what it matched.
type ruleCounters struct {
	rule    string
	packets uint64
	bytes   uint64
}

// parseRuleCounters reads `pfctl -s rules -v` output into per-rule counts.
func parseRuleCounters(out string) []ruleCounters {
	var (
		result  []ruleCounters
		pending string
	)
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "[") {
			// A statistics line belongs to the rule above it. pfctl prints a
			// second bracketed line (Inserted: uid ...) that carries no
			// counters; the regex simply will not match it.
			m := counterRe.FindStringSubmatch(trimmed)
			if m == nil || pending == "" {
				continue
			}
			pkts, _ := strconv.ParseUint(m[2], 10, 64)
			bytes, _ := strconv.ParseUint(m[3], 10, 64)
			result = append(result, ruleCounters{rule: pending, packets: pkts, bytes: bytes})
			pending = ""
			continue
		}

		// A rule line. `pfctl -vv` prefixes rule numbers as "@3 "; strip it so
		// classification only ever sees the rule itself.
		pending = stripRuleNumber(trimmed)
	}
	return result
}

// ruleNumRe matches the "@12 " prefix pfctl -vv adds.
var ruleNumRe = regexp.MustCompile(`^@\d+\s+`)

func stripRuleNumber(line string) string {
	return ruleNumRe.ReplaceAllString(line, "")
}

// ==== adding it up ========================================================
// pf resets counters on reload, so bank them before every reload.

// tally is the running total across every ruleset loaded during this
// engagement, by any invocation. It is persisted between processes; see
// counterPath in persist.go for why it has to be.
type tally struct {
	blockedOutPkts, blockedOutBytes uint64
	blockedInPkts, blockedInBytes   uint64
	dnsPkts, dnsBytes               uint64
	portalPkts, portalBytes         uint64
	checkPkts, checkBytes           uint64
	// attempts and failures count samples, not packets, so an empty report
	// can say whether the network was quiet or the measurement broke.
	attempts, failures int
}

// add folds one sample of the live counters into the running total.
func (t *tally) add(rules []ruleCounters) {
	for _, rc := range rules {
		switch classify(rc.rule) {
		case roleBlockOut:
			t.blockedOutPkts += rc.packets
			t.blockedOutBytes += rc.bytes
		case roleBlockIn:
			t.blockedInPkts += rc.packets
			t.blockedInBytes += rc.bytes
		case roleDNS:
			t.dnsPkts += rc.packets
			t.dnsBytes += rc.bytes
		case rolePortal:
			t.portalPkts += rc.packets
			t.portalBytes += rc.bytes
		case roleCheck:
			t.checkPkts += rc.packets
			t.checkBytes += rc.bytes
		}
	}
}

// role is what a rule is for, recovered from its text.
type role int

const (
	roleOther role = iota
	roleBlockOut
	roleBlockIn
	roleDNS
	rolePortal
	roleCheck
)

// classify recovers a rule's purpose from the text pfctl prints back, which is
// normalised and reordered relative to what we generated - so this matches on
// the parts pf preserves, not on our own formatting.
func classify(rule string) role {
	switch {
	case strings.HasPrefix(rule, "block"):
		if strings.Contains(rule, " out ") {
			return roleBlockOut
		}
		if strings.Contains(rule, " in ") {
			return roleBlockIn
		}
		return roleOther
	case strings.HasPrefix(rule, "pass"):
		// Checked first: the DNS filter's route-to rule names the resolvers
		// too, but what it matches is sent back to loopback, to the filter,
		// and never leaves. Counting it as DNS out would report every query
		// the filter refused as a leak - the first live filtered run did.
		if strings.Contains(rule, "route-to") {
			return roleOther
		}
		if strings.Contains(rule, "<"+dnsTable+">") {
			return roleDNS
		}
		if strings.Contains(rule, "<"+portalTable+">") {
			return rolePortal
		}
		if strings.Contains(rule, "<"+checkTable+">") {
			return roleCheck
		}
		return roleOther
	default:
		return roleOther
	}
}

// sampleCountersLocked reads the live counters and folds them into the total.
//
// It must be called immediately before any reload or flush, because that is
// what resets them. Failures are swallowed: losing an accounting sample must
// never stop the firewall operation it was attached to. They are counted
// though, so the report can tell a quiet network from a broken measurement.
//
// The running total is re-read from disk before every sample and written back
// after it, because pf's counters are shared by every process on the machine
// and so the account of them has to be too. See counterPath in persist.go.
//
// The caller must hold b.mu.
func (b *Backend) sampleCountersLocked(ctx context.Context) {
	if b.phase == firewall.PhaseOff {
		return
	}

	// Adopt the machine's total, but only if there genuinely is one. A failed
	// read must not be mistaken for a total of zero: on a machine where
	// /var/run cannot be written, this degrades to accumulating in memory,
	// which is exactly the behaviour it replaces rather than something worse.
	if disk, ok := loadTally(); ok {
		b.counters = disk
	}
	b.counters.attempts++

	out, err := b.pfctl(ctx, "-a", AnchorName, "-s", "rules", "-v")
	if err != nil {
		b.counters.failures++
	} else {
		b.counters.add(parseRuleCounters(out))
	}
	b.persistCountersLocked()
}

// persistCountersLocked writes the running total back out, reporting a
// persistent failure once rather than on every sample.
func (b *Backend) persistCountersLocked() {
	if err := saveTally(b.counters); err != nil && !b.counterNoteMade {
		b.counterNoteMade = true
		b.appendNote(fmt.Sprintf(
			"could not record the running packet counts (%v); a `%s` from another process will reset pf's counters without handing them back, so the leak report may undercount",
			err, AnchorName))
	}
}

// ==== the report ==========================================================
// Hand the totals out in the shape the CLI prints.

// LeakReport returns what this process has accounted for since Lockdown.
func (b *Backend) LeakReport() firewall.Report {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reportLocked()
}

func (b *Backend) reportLocked() firewall.Report {
	return firewall.Report{
		GapOpened:                 b.gapOpened,
		GapClosed:                 b.gapClosed,
		BlockedOutPackets:         b.counters.blockedOutPkts,
		BlockedOutBytes:           b.counters.blockedOutBytes,
		BlockedInPackets:          b.counters.blockedInPkts,
		BlockedInBytes:            b.counters.blockedInBytes,
		DNSPackets:                b.counters.dnsPkts,
		DNSBytes:                  b.counters.dnsBytes,
		PortalPackets:             b.counters.portalPkts,
		PortalBytes:               b.counters.portalBytes,
		CheckPackets:              b.counters.checkPkts,
		CheckBytes:                b.counters.checkBytes,
		Resolvers:                 b.resolvers,
		Names:                     b.leakNames,
		Processes:                 b.leakProcesses,
		ProcessesUnavailable:      b.leakProcessesUnavailable,
		ProcessesDeclinedByKernel: b.leakProcessesDeclinedByKernel,
		ProcessNote:               b.leakProcessNote,
		SampleAttempts:            b.counters.attempts,
		SampleFailures:            b.counters.failures,
		Source:                    "pf rule counters, pfctl -a portalguard -s rules -v",
	}
}

// NamesSeen returns the hostnames looked up through the gap so far, while it
// is still open.
//
// This is deliberately not part of the report: the report is the account
// rendered at seal, when nothing can be done about it any more, and this is
// the same evidence read early enough to act on. After a seal or a release
// the reader is gone and this returns what it finished with, which is the
// same list the report carries.
//
// Nothing here is filtered. These are lookups, not blocks, from every
// process on the machine - see logReader.Peek.
func (b *Backend) NamesSeen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reader != nil {
		return b.reader.Peek()
	}
	return append([]string(nil), b.leakNames...)
}

var _ firewall.Reporter = (*Backend)(nil)
var _ firewall.NameWatcher = (*Backend)(nil)
