package firewall

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Report is what Portalguard can say about the traffic that happened while it
// was engaged.
//
// It is deliberately built to be honest about its own resolution. The packet
// filter's rule counters answer "how much", cheaply and always. They cannot
// answer "which hostnames" or "which processes" - that needs packet logging,
// which is a separate and more fragile mechanism. A Report therefore carries
// counts unconditionally and detail only when something was able to supply it,
// and its rendering never implies knowledge it does not have.
type Report struct {
	// GapOpened and GapClosed bound the window where the portal hole existed.
	GapOpened time.Time `json:"gap_opened,omitzero"`
	GapClosed time.Time `json:"gap_closed,omitzero"`

	// BlockedOutPackets is what this machine tried to send and was stopped
	// from sending. It is the number the whole tool exists to make non-zero.
	BlockedOutPackets uint64 `json:"blocked_out_packets"`
	BlockedOutBytes   uint64 `json:"blocked_out_bytes"`

	// BlockedInPackets is what the network tried to send us. On an open
	// network this is mostly broadcast noise and scanning, and it says
	// nothing about leaks.
	BlockedInPackets uint64 `json:"blocked_in_packets"`
	BlockedInBytes   uint64 `json:"blocked_in_bytes"`

	// DNSPackets went through the gap's resolver hole. Packets, not queries:
	// a query and its reply both count against the rule that created the
	// state, so this is roughly twice the query count and must never be
	// reported as a number of lookups.
	DNSPackets uint64 `json:"dns_packets"`
	DNSBytes   uint64 `json:"dns_bytes"`

	// PortalPackets went to the login page itself. This is the traffic the
	// gap exists for, so a healthy run has plenty of it.
	PortalPackets uint64 `json:"portal_packets"`
	PortalBytes   uint64 `json:"portal_bytes"`

	// Resolvers is who the DNS hole pointed at.
	Resolvers []net.IP `json:"resolvers,omitempty"`

	// Names, when non-empty, lists the hostnames actually queried. Supplying
	// this needs packet logging; counters alone cannot.
	Names []string `json:"names,omitempty"`
	// Processes, when non-empty, names what made those queries.
	Processes []string `json:"processes,omitempty"`

	// Source records where the numbers came from, so the rendering can be
	// precise about its own limits.
	Source string `json:"source,omitempty"`
}

// ==== reading the report ==================================================
// Helpers for the numbers. Enriched() says whether we know hostnames
// or only counts.

// GapDuration is how long the hole was open.
func (r Report) GapDuration() time.Duration {
	if r.GapOpened.IsZero() || r.GapClosed.IsZero() {
		return 0
	}
	return r.GapClosed.Sub(r.GapOpened)
}

// Enriched reports whether anything supplied per-query detail.
func (r Report) Enriched() bool { return len(r.Names) > 0 || len(r.Processes) > 0 }

// Empty reports whether nothing at all was counted, which usually means the
// counters could not be read rather than that nothing happened.
func (r Report) Empty() bool {
	return r.BlockedOutPackets == 0 && r.BlockedInPackets == 0 &&
		r.DNSPackets == 0 && r.PortalPackets == 0
}

// ==== wording =============================================================
// The phrasing is deliberate. It must never read as 'nothing leaked'
// when we did not look.

// String renders the report for a human at the end of a run.
//
// The wording is load-bearing. With counters alone this says how much went
// through the DNS hole and states plainly that what was asked for is unknown.
// It must never read as "nothing leaked" when the truth is "we did not look".
func (r Report) String() string {
	var b strings.Builder

	if d := r.GapDuration(); d > 0 {
		fmt.Fprintf(&b, "The gap was open for %s.\n", d.Round(time.Second))
	}

	fmt.Fprintf(&b, "Held back %s your machine tried to send while locked down.\n",
		packets(r.BlockedOutPackets, r.BlockedOutBytes))
	if r.BlockedInPackets > 0 {
		fmt.Fprintf(&b, "Dropped %s the network tried to send you.\n",
			packets(r.BlockedInPackets, r.BlockedInBytes))
	}

	if r.PortalPackets > 0 {
		fmt.Fprintf(&b, "The login page itself accounted for %s.\n",
			packets(r.PortalPackets, r.PortalBytes))
	}

	switch {
	case r.DNSPackets == 0:
		b.WriteString("No DNS went through the gap.\n")
	default:
		fmt.Fprintf(&b, "\n%s went out through the DNS hole", packets(r.DNSPackets, r.DNSBytes))
		if len(r.Resolvers) > 0 {
			fmt.Fprintf(&b, ", to %s", joinIPs(r.Resolvers))
		}
		b.WriteString(".\n")
		// The honesty clause. A query and its reply are both counted, so this
		// is not a lookup count, and without packet logging we do not know
		// what was asked for.
		b.WriteString("That is packets, not lookups: a query and its reply are counted separately.\n")

		if r.Enriched() {
			if len(r.Names) > 0 {
				fmt.Fprintf(&b, "Hostnames queried: %s\n", strings.Join(r.Names, ", "))
			}
			if len(r.Processes) > 0 {
				fmt.Fprintf(&b, "Asked by: %s\n", strings.Join(r.Processes, ", "))
			}
		} else {
			b.WriteString("Which hostnames were asked for, and by which processes, is not known:\n")
			b.WriteString("that needs packet logging, which was not available for this run.\n")
		}
	}

	if r.Source != "" {
		fmt.Fprintf(&b, "\nSource: %s\n", r.Source)
	}
	return b.String()
}

// packets renders a count with its byte size.
func packets(n, bytes uint64) string {
	unit := "packets"
	if n == 1 {
		unit = "packet"
	}
	return fmt.Sprintf("%d %s (%s)", n, unit, humanBytes(bytes))
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f kB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func joinIPs(ips []net.IP) string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return strings.Join(out, ", ")
}

// ==== optional capability =================================================
// Separate from Backend on purpose: a backend that cannot measure is
// not a Reporter.

// Reporter is implemented by backends that can account for the traffic they
// filtered. It is separate from Backend so a backend that cannot do this is
// simply not a Reporter, rather than having to stub a method that lies.
type Reporter interface {
	// LeakReport returns what the backend observed since Lockdown.
	LeakReport() Report
}
