//go:build darwin

package pf

import (
	"net"
	"strings"
	"testing"

	"github.com/mredchristie/portalguard/internal/firewall"
)

func ips(ss ...string) []net.IP {
	out := make([]net.IP, 0, len(ss))
	for _, s := range ss {
		out = append(out, net.ParseIP(s))
	}
	return out
}

// lineIndex returns the position of the first line containing sub, or -1.
func lineIndex(rules, sub string) int {
	for i, line := range strings.Split(rules, "\n") {
		if strings.Contains(line, sub) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			return i
		}
	}
	return -1
}

func TestLockdownRulesetShape(t *testing.T) {
	rules := render(gap{})

	// The block must exist, and it must be last: quick means first match
	// wins, so a block above the passes would take the machine off the air.
	blockOut := lineIndex(rules, "block drop out quick all")
	blockIn := lineIndex(rules, "block drop in  quick all")
	if blockOut < 0 || blockIn < 0 {
		t.Fatalf("lockdown must block both directions:\n%s", rules)
	}

	for _, must := range []string{
		"pass quick on lo0 all",
		"port 68 to any port 67",
		"port 67 to any port 68",
		"icmp6-type { neighbrsol, neighbradv, routersol, routeradv }",
	} {
		i := lineIndex(rules, must)
		if i < 0 {
			t.Errorf("missing essential rule %q", must)
			continue
		}
		if i > blockOut {
			t.Errorf("rule %q comes after the catch-all block; quick would never reach it", must)
		}
	}

	// A bare lockdown must not let anything else through.
	if strings.Contains(rules, "pg_portal") || strings.Contains(rules, "pg_dns") {
		t.Errorf("lockdown must not declare gap tables:\n%s", rules)
	}
	if lineIndex(rules, "port 53") >= 0 {
		t.Error("lockdown must not allow DNS")
	}
}

func TestNoSetStatements(t *testing.T) {
	// `set` is illegal inside an anchor; pfctl rejects the whole ruleset.
	for _, rules := range []string{render(gap{}), render(gapFromHosts(sampleHosts()))} {
		for _, line := range strings.Split(rules, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "set ") {
				t.Errorf("set statement is not legal in an anchor: %q", line)
			}
		}
	}
}

func sampleHosts() []firewall.Host {
	return []firewall.Host{
		{Name: "login.hotel.example", Addrs: ips("192.168.1.1"), Ports: []int{80, 443, 8080}},
		{Name: "resolvers", Addrs: ips("192.168.1.1", "192.168.1.2"), AllowDNSTo: true, Ports: []int{53}},
	}
}

func TestGapRulesetShape(t *testing.T) {
	rules := render(gapFromHosts(sampleHosts()))

	blockOut := lineIndex(rules, "block drop out quick all")
	if blockOut < 0 {
		t.Fatalf("gap ruleset still has to block everything else:\n%s", rules)
	}

	for _, must := range []string{
		"table <pg_portal> persist { 192.168.1.1 }",
		"table <pg_dns> persist { 192.168.1.1 192.168.1.2 }",
		"pass out quick inet  proto tcp to <pg_portal> port { 80, 443, 8080 } keep state",
		"pass out quick inet6 proto tcp to <pg_portal> port { 80, 443, 8080 } keep state",
		"pass out log (all, user) quick inet  proto { tcp, udp } to <pg_dns> port 53 keep state",
		"pass out log (all, user) quick inet6 proto { tcp, udp } to <pg_dns> port 53 keep state",
	} {
		i := lineIndex(rules, must)
		if i < 0 {
			t.Errorf("missing %q from:\n%s", must, rules)
			continue
		}
		if i > blockOut {
			t.Errorf("%q comes after the catch-all block", must)
		}
	}
}

func TestGapDNSRulesAreLogged(t *testing.T) {
	// The leak report depends on pf copying these to the pflog device.
	rules := render(gapFromHosts(sampleHosts()))
	for _, line := range dnsRuleLines(rules) {
		// `all` because pf otherwise logs only the state-establishing packet,
		// and mDNSResponder multiplexes queries over one long-lived socket -
		// the case where the report would say "1 query" for a gap that leaked
		// fifty. `user` because it is what names the processes responsible.
		if !strings.Contains(line, "log (all, user") {
			t.Errorf("DNS pass rule must log (all, user): %q", line)
		}
	}
}

// dnsRuleLines returns the non-comment rule lines touching port 53.
func dnsRuleLines(rules string) []string {
	var out []string
	for _, line := range strings.Split(rules, "\n") {
		if strings.Contains(line, "port 53") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			out = append(out, line)
		}
	}
	return out
}

func TestGapLogsToDedicatedDevice(t *testing.T) {
	g := gapFromHosts(sampleHosts())
	g.logTo = LogInterface
	for _, line := range dnsRuleLines(render(g)) {
		if !strings.Contains(line, "to "+LogInterface) {
			t.Errorf("DNS rule should log to the dedicated device: %q", line)
		}
	}
}

// TestGapWithoutLogDeviceOmitsTheInterface is the degradation path that
// matters: if the pflog device could not be created, the ruleset must not name
// it. A rule referring to an interface that is not there risks failing to
// load, and failing to open the gap because logging is unavailable would leave
// the user unable to log in at all.
func TestGapWithoutLogDeviceOmitsTheInterface(t *testing.T) {
	g := gapFromHosts(sampleHosts())
	g.logTo = ""
	rules := render(g)
	if strings.Contains(rules, "to pflog") {
		t.Errorf("no log device means no interface may be named:\n%s", rules)
	}
	// Logging is still requested, so it lands on the default and is discarded
	// harmlessly if that does not exist either.
	for _, line := range dnsRuleLines(rules) {
		if !strings.Contains(line, "log (all, user)") {
			t.Errorf("should still request logging: %q", line)
		}
	}
}

func TestLogClause(t *testing.T) {
	if got := (gap{}).logClause(); got != "log (all, user)" {
		t.Errorf("logClause() = %q", got)
	}
	if got := (gap{logTo: "pflog1"}).logClause(); got != "log (all, user, to pflog1)" {
		t.Errorf("logClause(pflog1) = %q", got)
	}
}

func TestAddressesAreSortedAndDeduplicated(t *testing.T) {
	// Same inputs, same ruleset: makes the output diffable and the tests
	// meaningful.
	hosts := []firewall.Host{
		{Name: "p", Addrs: ips("10.0.0.2", "10.0.0.1", "10.0.0.2")},
	}
	rules := render(gapFromHosts(hosts))
	if !strings.Contains(rules, "table <pg_portal> persist { 10.0.0.1 10.0.0.2 }") {
		t.Errorf("expected sorted, deduplicated table:\n%s", rules)
	}
}

func TestEmptyTableRendersWithoutBody(t *testing.T) {
	// `table <x> persist { }` is not valid pf; a bare persist declaration is.
	g := gap{dnsAddrs: ips("192.168.1.1")}
	rules := render(g)
	if !strings.Contains(rules, "table <pg_portal> persist\n") {
		t.Errorf("empty table must be declared without a body:\n%s", rules)
	}
}

func TestPortalPortsDefaultToWeb(t *testing.T) {
	g := gapFromHosts([]firewall.Host{{Name: "p", Addrs: ips("10.0.0.1")}})
	rules := render(g)
	if !strings.Contains(rules, "port { 80, 443 }") {
		t.Errorf("expected the default web ports:\n%s", rules)
	}
}

func TestSinglePortNeedsNoBraces(t *testing.T) {
	if got := renderPorts([]int{8080}); got != "port 8080" {
		t.Errorf("renderPorts([8080]) = %q", got)
	}
}

func TestGapAllAddrsCoversEverythingOpened(t *testing.T) {
	// Seal kills states for every address in both tables, not just the
	// originally detected portal IP: a host added by `allow` would otherwise
	// survive the seal with a live connection.
	g := gapFromHosts(sampleHosts())
	got := map[string]bool{}
	for _, ip := range g.allAddrs() {
		got[ip.String()] = true
	}
	for _, want := range []string{"192.168.1.1", "192.168.1.2"} {
		if !got[want] {
			t.Errorf("%s is open but would not have its states killed at seal", want)
		}
	}
}

func TestGapFromHostsSeparatesResolvers(t *testing.T) {
	g := gapFromHosts(sampleHosts())
	if len(g.portalAddrs) != 1 {
		t.Errorf("portal addrs = %v, want just the portal", g.portalAddrs)
	}
	if len(g.dnsAddrs) != 2 {
		t.Errorf("dns addrs = %v, want both resolvers", g.dnsAddrs)
	}
	// A resolver's port must not leak into the portal's port list.
	for _, p := range g.portalPorts {
		if p == 53 {
			t.Error("port 53 must not be opened to the portal host")
		}
	}
}

// TestGapRulesLoadedIsDecidedByRulesNotTables guards the invariant that a
// sealed machine can never report an open address.
//
// pf tables are declared `persist`, so they outlive a ruleset that no longer
// references them. Inferring the phase from table contents therefore reported
// GAP over a machine that was fully blocked - and a UI reading that would have
// shown the portal as still permitted after the seal closed it.
func TestGapRulesLoadedIsDecidedByRulesNotTables(t *testing.T) {
	// What `pfctl -s rules` prints for a bare lockdown: no reference to the
	// gap tables, whatever the tables happen to still contain.
	lockdown := `pass quick on lo0 all
pass out quick inet proto udp from any port = 68 to any port = 67 no state
block drop out quick all
block drop in quick all`

	if gapRulesLoaded(lockdown) {
		t.Error("a lockdown ruleset must never be read as an open gap, even with populated tables")
	}

	gapLoaded := lockdown + `
pass out quick inet proto tcp from any to <pg_portal> port = 80 keep state
pass out log (all, user) quick inet proto { tcp udp } from any to <pg_dns> port = 53 keep state`

	if !gapRulesLoaded(gapLoaded) {
		t.Error("a ruleset with gap pass rules must be read as an open gap")
	}
}

func TestGapRulesLoadedIgnoresNonPassLines(t *testing.T) {
	// A comment or a block rule mentioning a table must not count as
	// permission.
	for _, rules := range []string{
		"# the gap: <pg_portal> is empty here",
		"block drop out quick inet proto tcp from any to <pg_portal>",
	} {
		if gapRulesLoaded(rules) {
			t.Errorf("must not read permission from %q", rules)
		}
	}
}
