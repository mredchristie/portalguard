//go:build darwin

package pf

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"portalguard/internal/dnsfilter"
	"portalguard/internal/firewall"
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
	// checkTable holds addresses Portalguard's own checks may reach: the
	// post-login re-probe and the certificate check on a remembered host.
	// Kept apart from portalTable so a check never widens the portal's ports.
	checkTable = "pg_check"
	// LogInterface is the pflog pseudo-device our rules log to. A dedicated
	// device rather than the default pflog0, for the same reason the rules
	// live in a dedicated anchor: nothing else on the system owns it, so
	// creating and destroying it cannot disturb another tool.
	LogInterface = "pflog1"
)

// defaultPortalPorts is the port set opened for the portal when detection
// found nothing more specific.
var defaultPortalPorts = []int{80, 443}

// ==== describing the hole =================================================
// What to open, as addresses and ports. Zero value means a bare lockdown.

// gap describes the hole to punch. The zero value renders a bare lockdown.
type gap struct {
	portalAddrs []net.IP
	portalPorts []int
	dnsAddrs    []net.IP
	checkAddrs  []net.IP
	checkPorts  []int
	// vpn is the handover hole: a VPN client's handshake, and nothing else,
	// while the lockdown otherwise stands. Never set alongside a gap.
	vpn []firewall.Endpoint
	// dnsFilter sends the gap's DNS through Portalguard's own resolver
	// (internal/dnsfilter) instead of straight to the network's: pf redirects
	// it to 127.0.0.1, and only the filter's upstream port may leave.
	dnsFilter bool
	// logTo names the pflog interface the DNS rules log to. Empty means log
	// without naming a device, which pf sends to pflog0 and discards harmlessly
	// if that does not exist either. It is empty whenever we could not create
	// our own log device: a ruleset naming an interface that is not there may
	// fail to load, and failing to open the gap because we could not set up
	// logging would be the tail wagging the dog.
	logTo string
}

// isOpen reports whether there is anything to let through.
func (g gap) isOpen() bool {
	return len(g.portalAddrs) > 0 || len(g.dnsAddrs) > 0 || len(g.checkAddrs) > 0
}

// gapFromHosts folds the allow-list into the tables the ruleset uses.
// Hosts flagged AllowDNSTo become resolvers, hosts flagged Check go to the
// check table with their own port set, and everything else is portal.
func gapFromHosts(hosts []firewall.Host) gap {
	var g gap
	ports := map[int]bool{}
	checkPorts := map[int]bool{}
	for _, h := range hosts {
		switch {
		case h.AllowDNSTo:
			g.dnsAddrs = append(g.dnsAddrs, h.Addrs...)
		case h.Check:
			g.checkAddrs = append(g.checkAddrs, h.Addrs...)
			for _, p := range h.TCPPorts() {
				checkPorts[p] = true
			}
		default:
			g.portalAddrs = append(g.portalAddrs, h.Addrs...)
			for _, p := range h.TCPPorts() {
				ports[p] = true
			}
		}
	}
	g.portalPorts = sortedPorts(ports)
	if len(g.portalPorts) == 0 {
		g.portalPorts = defaultPortalPorts
	}
	g.checkPorts = sortedPorts(checkPorts)
	return g
}

// sortedPorts turns a port set into an ordered list, so the same inputs
// always render the same ruleset.
func sortedPorts(set map[int]bool) []int {
	var out []int
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// ==== the rules themselves ================================================
// Loopback, DHCP, IPv6 neighbour discovery. The bare minimum to stay on
// the network.

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

// ==== building the ruleset ================================================
// Assembles the text pf is given. Passes first, block last.

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
		b.WriteString(renderTable(checkTable, g.checkAddrs))
		b.WriteString("\n")
	}

	if g.isOpen() && g.dnsFilter && len(g.dnsAddrs) > 0 {
		// Translation before filtering, as pf requires. rdr pass hands the
		// redirected query straight to the filter on loopback.
		b.WriteString("# The DNS filter: every query for this network's resolvers comes back in on\n")
		b.WriteString("# loopback (see route-to below) and is redirected to Portalguard's resolver,\n")
		b.WriteString("# which forwards only the names the login needs. Needs the rdr-anchor hook.\n")
		// Both families: a dual-stack network hands out an IPv6 resolver too,
		// and macOS may send every lookup to it.
		fmt.Fprintf(&b, "rdr pass on lo0 inet  proto { udp, tcp } from any to <%s> port 53 -> 127.0.0.1 port %d\n",
			dnsTable, dnsfilter.ListenPort)
		fmt.Fprintf(&b, "rdr pass on lo0 inet6 proto { udp, tcp } from any to <%s> port 53 -> ::1 port %d\n\n",
			dnsTable, dnsfilter.ListenPort)
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
		if len(g.checkAddrs) > 0 {
			b.WriteString("\n# Portalguard's own checks: the re-probe that notices a finished login, and\n")
			b.WriteString("# the certificate check on a remembered host. Their addresses are outside\n")
			b.WriteString("# the gap by nature - a probe endpoint's real address only appears once the\n")
			b.WriteString("# portal stops hijacking DNS - so they get their own table and ports, and\n")
			b.WriteString("# leave with the gap.\n")
			for _, af := range []string{"inet ", "inet6"} {
				fmt.Fprintf(&b, "pass out quick %s proto tcp to <%s> %s keep state\n",
					af, checkTable, renderPorts(g.checkPorts))
			}
		}
		if len(g.dnsAddrs) > 0 && g.dnsFilter {
			b.WriteString("\n# DNS, filtered. Only Portalguard's resolver, from its one fixed source port,\n")
			b.WriteString("# may reach this network's resolvers; it forwards only the names the login\n")
			b.WriteString("# needs. Every other query is sent back to loopback, where the rdr above\n")
			b.WriteString("# hands it to that resolver. The hole is one socket wide, not machine-wide.\n")
			for _, af := range []string{"inet ", "inet6"} {
				fmt.Fprintf(&b, "pass out %s quick %s proto udp from any port %d to <%s> port 53 keep state\n",
					g.logClause(), af, dnsfilter.UpstreamPort, dnsTable)
			}
			fmt.Fprintf(&b, "pass out quick route-to (lo0 127.0.0.1) inet  proto { udp, tcp } from any to <%s> port 53 keep state\n",
				dnsTable)
			fmt.Fprintf(&b, "pass out quick route-to (lo0 ::1) inet6 proto { udp, tcp } from any to <%s> port 53 keep state\n",
				dnsTable)
		} else if len(g.dnsAddrs) > 0 {
			b.WriteString("\n# DNS to this network's resolvers and only them. This hole is machine-wide:\n")
			b.WriteString("# every background daemon's queued lookups fire through it the moment it\n")
			b.WriteString("# opens. Connections stay blocked, hostnames do not.\n")
			b.WriteString("#\n")
			b.WriteString("# log (all) rather than bare log: pf logs only the packet that establishes\n")
			b.WriteString("# a state, and mDNSResponder multiplexes queries over long-lived sockets,\n")
			b.WriteString("# so bare log would report one query for a gap that leaked fifty.\n")
			b.WriteString("# log (user) adds the uid and pid owning the socket, which is what lets\n")
			b.WriteString("# the leak report name the processes responsible.\n")
			for _, af := range []string{"inet ", "inet6"} {
				fmt.Fprintf(&b, "pass out %s quick %s proto { tcp, udp } to <%s> port 53 keep state\n",
					g.logClause(), af, dnsTable)
			}
		}
	}

	if len(g.vpn) > 0 {
		b.WriteString("\n# The handover: only the VPN client's own connection may leave, so nothing\n")
		b.WriteString("# goes out in the clear between sealing and the tunnel coming up. Portalguard\n")
		b.WriteString("# releases everything the moment the tunnel carries the default route.\n")
		for _, e := range g.vpn {
			b.WriteString(renderVPN(e))
		}
	}

	b.WriteString("\n")
	b.WriteString(blocks)
	return b.String()
}

// renderVPN emits the pass rules for one VPN endpoint: one family for a
// pinned address, both for "any".
func renderVPN(e firewall.Endpoint) string {
	proto := e.Proto
	if proto != "tcp" {
		proto = "udp"
	}
	if e.Addr != nil {
		af := "inet "
		if e.Addr.To4() == nil {
			af = "inet6"
		}
		return fmt.Sprintf("pass out quick %s proto %s to %s port %d keep state\n", af, proto, e.Addr, e.Port)
	}
	var b strings.Builder
	for _, af := range []string{"inet ", "inet6"} {
		fmt.Fprintf(&b, "pass out quick %s proto %s to any port %d keep state\n", af, proto, e.Port)
	}
	return b.String()
}

// logClause renders the log keyword and its options. The device is named only
// when we have one, so a missing pflog interface can never stop the gap from
// opening.
func (g gap) logClause() string {
	if g.logTo == "" {
		return "log (all, user)"
	}
	return fmt.Sprintf("log (all, user, to %s)", g.logTo)
}

// ==== formatting bits =====================================================
// Turning addresses and ports into pf syntax.

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
	out := append(append([]net.IP(nil), g.portalAddrs...), g.dnsAddrs...)
	return append(out, g.checkAddrs...)
}
