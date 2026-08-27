//go:build darwin

package pf

import (
	"context"
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

// tally is the running total across every ruleset this process has loaded.
type tally struct {
	blockedOutPkts, blockedOutBytes uint64
	blockedInPkts, blockedInBytes   uint64
	dnsPkts, dnsBytes               uint64
	portalPkts, portalBytes         uint64
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
		if strings.Contains(rule, "<"+dnsTable+">") {
			return roleDNS
		}
		if strings.Contains(rule, "<"+portalTable+">") {
			return rolePortal
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
// never stop the firewall operation it was attached to.
//
// The caller must hold b.mu.
func (b *Backend) sampleCountersLocked(ctx context.Context) {
	if b.phase == firewall.PhaseOff {
		return
	}
	out, err := b.pfctl(ctx, "-a", AnchorName, "-s", "rules", "-v")
	if err != nil {
		return
	}
	b.counters.add(parseRuleCounters(out))
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
		Resolvers:                 b.resolvers,
		Names:                     b.leakNames,
		Processes:                 b.leakProcesses,
		ProcessesUnavailable:      b.leakProcessesUnavailable,
		ProcessesDeclinedByKernel: b.leakProcessesDeclinedByKernel,
		ProcessNote:               b.leakProcessNote,
		Source:                    "pf rule counters, pfctl -a portalguard -s rules -v",
	}
}

var _ firewall.Reporter = (*Backend)(nil)
