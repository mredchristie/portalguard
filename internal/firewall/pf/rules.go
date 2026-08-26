//go:build darwin

package pf

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/mredchristie/portalguard/internal/firewall"
)

// The rulesets below are the ones reviewed in docs/pf-design.md. Change them
// and that document is wrong; change them without reading it and you will
// probably remove something load-bearing.
//
// Two constraints shape everything here:
//
//   - `set` statements are not legal inside an anchor, so there is no
//     `set skip on lo0` and no `set block-policy`. Loopback gets an explicit
//     pass rule and every block says `drop` for itself.
//   - `quick` means first match wins and evaluation stops, so the order is
//     passes first, block last. Reversing that would block everything.
const (
	// portalTable holds the addresses the login flow may talk to.
	portalTable = "pg_portal"
	// dnsTable holds the resolvers this network handed us.
	dnsTable = "pg_dns"
)

// defaultPortalPorts is the port set opened for the portal when detection
// found nothing more specific.
var defaultPortalPorts = []int{80, 443}

// gap describes the hole to punch. The zero value renders a bare lockdown.
type gap struct {
	portalAddrs []net.IP
	portalPorts []int
	dnsAddrs    []net.IP
}

// isOpen reports whether there is anything to let through.
func (g gap) isOpen() bool {
	return len(g.portalAddrs) > 0 || len(g.dnsAddrs) > 0
}

// gapFromHosts folds the allow-list into the two tables the ruleset uses.
// Hosts flagged AllowDNSTo become resolvers; everything else is portal.
func gapFromHosts(hosts []firewall.Host) gap {
	var g gap
	ports := map[int]bool{}
	for _, h := range hosts {
		if h.AllowDNSTo {
			g.dnsAddrs = append(g.dnsAddrs, h.Addrs...)
			continue
		}
		g.portalAddrs = append(g.portalAddrs, h.Addrs...)
		for _, p := range h.TCPPorts() {
			ports[p] = true
		}
	}
	for p := range ports {
		g.portalPorts = append(g.portalPorts, p)
	}
	sort.Ints(g.portalPorts)
	if len(g.portalPorts) == 0 {
		g.portalPorts = defaultPortalPorts
	}
	return g
}

// preamble is the part both phases share: what the machine needs to stay on
// the link, and nothing else.
const preamble = `# Loopback is never touched. Local IPC, the resolver stub, anything talking to
# 127.0.0.1 keeps working.
pass quick on lo0 all

# DHCP, both directions. Without this the lease expires while we are locked
# down and the network vanishes underneath us, which looks exactly like
# portalguard having broken the machine.
#
# Deliberately no DHCPv6 (udp 546/547): a stateful lease could expire
# mid-lockdown on an IPv6-heavy network, but captive portals using stateful
# DHCPv6 are close to nonexistent. If it ever bites, mirror these two lines.
pass out quick inet proto udp from any port 68 to any port 67 no state
pass in  quick inet proto udp from any port 67 to any port 68 no state

# IPv6 neighbour discovery and router advertisement, so the link stays usable.
# Every other kind of IPv6 falls through to the block below, deliberately:
# IPv6 is where leaks like to hide.
pass quick inet6 proto icmp6 all icmp6-type { neighbrsol, neighbradv, routersol, routeradv } no state
`

// blocks is the catch-all, and must always be last.
const blocks = `# Everything else, in and out, on every interface. block drop rather than
# block return: a hostile network learns nothing from silence.
block drop out quick all
block drop in  quick all
`

// render produces the anchor ruleset for a phase. An open gap renders the
// tables and pass rules; a closed one renders a bare lockdown.
func render(g gap) string {
	var b strings.Builder

	b.WriteString("# portalguard anchor ruleset. Generated, never written to disk.\n")
	b.WriteString("# See docs/pf-design.md. To remove: pfctl -a portalguard -F all\n\n")

	if g.isOpen() {
		// Tables are declared even when empty so the rule text keeps the same
		// shape, and so `pfctl -a portalguard -t pg_portal -T show` answers
		// "what is open right now" straight from the kernel.
		b.WriteString("# Addresses pinned at detection time, so a portal that controls DNS cannot\n")
		b.WriteString("# widen its own hole afterwards by changing what its name resolves to.\n")
		b.WriteString(renderTable(portalTable, g.portalAddrs))
		b.WriteString(renderTable(dnsTable, g.dnsAddrs))
		b.WriteString("\n")
	}

	b.WriteString(preamble)

	if g.isOpen() {
		b.WriteString("\n")
		if len(g.portalAddrs) > 0 {
			b.WriteString("# The gap: the portal's login page, on its own addresses, web ports only.\n")
			b.WriteString("# keep state so replies return without needing an inbound pass.\n")
			for _, af := range []string{"inet ", "inet6"} {
				fmt.Fprintf(&b, "pass out quick %s proto tcp to <%s> %s keep state\n",
					af, portalTable, renderPorts(g.portalPorts))
			}
		}
		if len(g.dnsAddrs) > 0 {
			b.WriteString("\n# DNS to this network's resolvers and only them. This hole is machine-wide:\n")
			b.WriteString("# every background daemon's queued lookups fire through it the moment it\n")
			b.WriteString("# opens. Connections stay blocked, hostnames do not. `log` copies matches\n")
			b.WriteString("# to pflog0 so what leaked can be counted and reported.\n")
			for _, af := range []string{"inet ", "inet6"} {
				fmt.Fprintf(&b, "pass out log quick %s proto { tcp, udp } to <%s> port 53 keep state\n",
					af, dnsTable)
			}
		}
	}

	b.WriteString("\n")
	b.WriteString(blocks)
	return b.String()
}

// renderTable emits a pf table declaration. An empty table is declared without
// a body: `persist` keeps it alive with no addresses, and a rule referring to
// it simply never matches.
func renderTable(name string, addrs []net.IP) string {
	if len(addrs) == 0 {
		return fmt.Sprintf("table <%s> persist\n", name)
	}
	return fmt.Sprintf("table <%s> persist { %s }\n", name, strings.Join(sortedAddrs(addrs), " "))
}

// sortedAddrs deduplicates and orders addresses so the same inputs always
// render the same ruleset, which makes the output diffable and testable.
func sortedAddrs(addrs []net.IP) []string {
	seen := map[string]bool{}
	var out []string
	for _, ip := range addrs {
		if ip == nil {
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// renderPorts formats a pf port clause. A single port needs no braces.
func renderPorts(ports []int) string {
	switch len(ports) {
	case 0:
		return renderPorts(defaultPortalPorts)
	case 1:
		return "port " + strconv.Itoa(ports[0])
	default:
		strs := make([]string, len(ports))
		for i, p := range ports {
			strs[i] = strconv.Itoa(p)
		}
		return "port { " + strings.Join(strs, ", ") + " }"
	}
}

// allAddrs returns every address the gap currently allows, which is what Seal
// must kill states for: not just the originally detected portal IP, but
// anything added by `portalguard allow` since.
func (g gap) allAddrs() []net.IP {
	return append(append([]net.IP(nil), g.portalAddrs...), g.dnsAddrs...)
}
