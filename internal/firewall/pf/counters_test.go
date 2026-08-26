//go:build darwin

package pf

import "testing"

// pfctlVerboseOutput is the shape `pfctl -a portalguard -s rules -v` prints:
// each rule followed by its statistics line, and a second bracketed line that
// carries no counters. Rule text is pf's own normalised rendering, not ours -
// pf reorders and rewrites on load, which is why classification matches on
// what pf preserves rather than on our formatting.
const pfctlVerboseOutput = `pass quick on lo0 all flags S/SA keep state
  [ Evaluations: 1523      Packets: 1200      Bytes: 148000     States: 2     ]
  [ Inserted: uid 0 pid 4210 State Creations: 2     ]
pass out quick inet proto udp from any port = 68 to any port = 67 no state
  [ Evaluations: 12        Packets: 4         Bytes: 1368       States: 0     ]
  [ Inserted: uid 0 pid 4210 State Creations: 0     ]
pass out log (all, user) quick inet proto { tcp udp } from any to <pg_dns> port = 53 keep state
  [ Evaluations: 340       Packets: 46        Bytes: 4922       States: 12    ]
  [ Inserted: uid 0 pid 4210 State Creations: 12    ]
pass out quick inet proto tcp from any to <pg_portal> port = 80 flags S/SA keep state
  [ Evaluations: 210       Packets: 88        Bytes: 21400      States: 3     ]
  [ Inserted: uid 0 pid 4210 State Creations: 3     ]
block drop out quick all
  [ Evaluations: 980       Packets: 412       Bytes: 38104      States: 0     ]
  [ Inserted: uid 0 pid 4210 State Creations: 0     ]
block drop in quick all
  [ Evaluations: 640       Packets: 133       Bytes: 9800       States: 0     ]
  [ Inserted: uid 0 pid 4210 State Creations: 0     ]
`

func TestParseRuleCounters(t *testing.T) {
	got := parseRuleCounters(pfctlVerboseOutput)
	if len(got) != 6 {
		t.Fatalf("parsed %d rules, want 6: %+v", len(got), got)
	}
	// The second bracketed line per rule must not be mistaken for a counter.
	last := got[len(got)-1]
	if last.packets != 133 || last.bytes != 9800 {
		t.Errorf("last rule = %+v, want packets 133 bytes 9800", last)
	}
}

func TestTallyClassifiesRoles(t *testing.T) {
	var tal tally
	tal.add(parseRuleCounters(pfctlVerboseOutput))

	cases := []struct {
		name      string
		got, want uint64
	}{
		{"blocked out packets", tal.blockedOutPkts, 412},
		{"blocked out bytes", tal.blockedOutBytes, 38104},
		{"blocked in packets", tal.blockedInPkts, 133},
		{"dns packets", tal.dnsPkts, 46},
		{"dns bytes", tal.dnsBytes, 4922},
		{"portal packets", tal.portalPkts, 88},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestTallyAccumulatesAcrossReloads is the property the whole design turns on.
// pf resets per-rule statistics when a ruleset is reloaded, and portalguard
// reloads at every phase change - so reading the counters once at the end
// would report only what happened since the last reload, losing every packet
// blocked during lockdown.
func TestTallyAccumulatesAcrossReloads(t *testing.T) {
	var tal tally
	tal.add(parseRuleCounters(pfctlVerboseOutput)) // sampled before the gap opened
	tal.add(parseRuleCounters(pfctlVerboseOutput)) // sampled before the seal

	if tal.blockedOutPkts != 824 {
		t.Errorf("blocked out packets = %d, want 824 (two samples of 412)", tal.blockedOutPkts)
	}
	if tal.dnsPkts != 92 {
		t.Errorf("dns packets = %d, want 92 (two samples of 46)", tal.dnsPkts)
	}
}

func TestClassifyRuleRoles(t *testing.T) {
	cases := []struct {
		rule string
		want role
	}{
		{"block drop out quick all", roleBlockOut},
		{"block drop in quick all", roleBlockIn},
		{"pass out log (all, user) quick inet proto udp from any to <pg_dns> port = 53 keep state", roleDNS},
		{"pass out quick inet proto tcp from any to <pg_portal> port = 80 keep state", rolePortal},
		{"pass quick on lo0 all", roleOther},
		{"pass out quick inet proto udp from any port = 68 to any port = 67 no state", roleOther},
		// A block rule naming a table is not permission and not a leak count.
		{"block drop out quick inet from any to <pg_portal>", roleBlockOut},
	}
	for _, c := range cases {
		if got := classify(c.rule); got != c.want {
			t.Errorf("classify(%q) = %v, want %v", c.rule, got, c.want)
		}
	}
}

func TestStripRuleNumber(t *testing.T) {
	// pfctl -vv prefixes rule numbers; classification must not see them.
	if got := stripRuleNumber("@3 block drop out quick all"); got != "block drop out quick all" {
		t.Errorf("stripRuleNumber = %q", got)
	}
	if got := stripRuleNumber("block drop out quick all"); got != "block drop out quick all" {
		t.Errorf("stripRuleNumber changed an unnumbered rule: %q", got)
	}
}

func TestParseRuleCountersHandlesEmptyOutput(t *testing.T) {
	if got := parseRuleCounters(""); len(got) != 0 {
		t.Errorf("empty output should parse to nothing, got %+v", got)
	}
}
