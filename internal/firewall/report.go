package firewall

import (
	"fmt"
	"net"
	"sort"
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

	// CheckPackets went to Portalguard's own checks: the re-probe that
	// notices a finished login, and certificate checks on remembered hosts.
	CheckPackets uint64 `json:"check_packets,omitempty"`
	CheckBytes   uint64 `json:"check_bytes,omitempty"`

	// Resolvers is who the DNS hole pointed at.
	Resolvers []net.IP `json:"resolvers,omitempty"`

	// Names, when non-empty, lists the hostnames actually queried. Supplying
	// this needs packet logging; counters alone cannot.
	Names []string `json:"names,omitempty"`
	// Processes, when non-empty, names what made those queries.
	//
	// Names and Processes come from two different mechanisms and degrade
	// independently. Names comes from tcpdump's own DNS decoder, a stable
	// public interface. Processes comes from parsing the pflog record's
	// uid/pid fields by hand, since neither tcpdump nor the macOS SDK
	// exposes them - an undocumented layout that a future macOS could
	// silently change. A report can therefore have hostnames with no
	// process attribution; the reverse should not happen.
	Processes []string `json:"processes,omitempty"`
	// ProcessesUnavailable records that process attribution was attempted
	// and failed, as distinct from it never being attempted (which
	// Enriched() being false already covers). It only matters when Names
	// is non-empty: that is the one state where the rendering must say
	// "hostnames yes, processes no" rather than fall back to the disclaimer
	// that nothing is known, which would now be false.
	ProcessesUnavailable bool `json:"processes_unavailable,omitempty"`
	// ProcessesDeclinedByKernel is a more specific true than
	// ProcessesUnavailable: it means every record this run saw carried
	// pf's own "not attributed to a process" signal, confirmed against
	// real ground truth (see internal/firewall/pf/leakreader.go's
	// pidSentinel), rather than this package failing to read or trust the
	// data. It is a different and more useful statement - "the kernel did
	// not say" is not the same claim as "we could not tell" - so it gets
	// its own line in String() instead of collapsing into the generic
	// wording. Only meaningful when ProcessesUnavailable is also true.
	ProcessesDeclinedByKernel bool `json:"processes_declined_by_kernel,omitempty"`
	// ProcessNote is the diagnostic behind ProcessesUnavailable, tagged
	// with which kind: "[parse] ..." means a record's own bytes looked
	// wrong, most likely the reverse-engineered struct offsets themselves;
	// "[heuristic] ..." means every record parsed cleanly but the aggregate
	// looked implausible, most likely the heuristic being too eager rather
	// than the parse being wrong; "[kernel] ..." means
	// ProcessesDeclinedByKernel - not a failure of this package's reading
	// at all. The first two need opposite fixes and the third needs no fix,
	// which is why the tag exists rather than one bucket of prose.
	//
	// Diagnostic, not for a normal user: String() never includes it. It
	// lives on the Report, not only in the backend's Status(), because a
	// Status() note dies with the process that set it - gone the moment
	// that run exits, sometimes before anyone thought to check. A report
	// gets printed and can be kept.
	ProcessNote string `json:"process_note,omitempty"`

	// SampleAttempts and SampleFailures count readings of the counters, not
	// packets. They exist so an all-zero report can say which kind of zero it
	// is: a quiet network, or a measurement that never worked. Without them
	// the two are indistinguishable, and the report has to guess at its own
	// cause - which it did, wrongly, on a real run.
	SampleAttempts int `json:"sample_attempts,omitempty"`
	SampleFailures int `json:"sample_failures,omitempty"`

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

// Empty reports whether nothing at all was counted. On its own that says
// nothing about why: ask CountersUnavailable for that.
func (r Report) Empty() bool {
	return r.BlockedOutPackets == 0 && r.BlockedInPackets == 0 &&
		r.DNSPackets == 0 && r.PortalPackets == 0 && r.CheckPackets == 0
}

// CountersUnavailable reports whether the numbers are missing because the
// measurement failed, rather than because there was nothing to count.
//
// Zero attempts means nothing was ever read - there was no reload between
// engaging and reporting - and every attempt failing means the counters could
// not be read at all. Anything in between produced at least one real reading,
// so a zero from it is a genuine zero and must not be dressed up as a broken
// measurement: that would be the same error in the opposite direction, and
// the whole point of this report is to keep "we did not look" and "nothing
// happened" apart.
func (r Report) CountersUnavailable() bool {
	return r.SampleAttempts == 0 || r.SampleFailures == r.SampleAttempts
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
	if r.CheckPackets > 0 {
		fmt.Fprintf(&b, "Portalguard's own checks accounted for %s.\n",
			packets(r.CheckPackets, r.CheckBytes))
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
			switch {
			case len(r.Processes) > 0:
				fmt.Fprintf(&b, "Asked by: %s\n", strings.Join(r.Processes, ", "))
			case r.ProcessesDeclinedByKernel:
				// A different and more useful claim than the generic line
				// below: the kernel itself did not attribute these packets
				// to a process, confirmed against real ground truth - this
				// is not a failure of this package's reading.
				b.WriteString("The kernel did not attribute these queries to a process.\n")
			case r.ProcessesUnavailable:
				// Hostnames are known; which process asked for them is not.
				// This must not read as the full disclaimer below - that
				// would understate what the report actually knows.
				b.WriteString("Which process made these queries could not be determined.\n")
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

// ==== redaction ============================================================
// The hostname list is the most identifying part of a report - it names
// which mail provider, which extensions, which accounts a machine talks to.
// Redact exists for the moment someone wants to post or attach a report
// rather than just read it themselves.

// Redact returns a copy of r with hostnames generalised to broad categories
// instead of named, and resolver addresses removed outright. It is opt-in:
// the default (calling String directly on an unredacted Report) stays full
// detail, for reading on your own machine. Call Redact first for anything
// meant to be shared.
//
// Resolvers is cleared unconditionally, not generalised like Names - an
// IPv6 resolver address commonly encodes a real MAC address in its
// interface identifier (the modified-EUI-64 form, "...ff:fe..." at a fixed
// offset), and even the private-network IPv4 case adds nothing a shared
// report needs. This was found by inspection of a real recording rather
// than assumed: a router's IPv6 address with a derivable MAC address ended
// up plainly visible in an already-redacted demo before this existed.
//
// Process names are the one thing left as-is. A process name
// (mDNSResponder) says what kind of thing made a query; a hostname says who
// it talked to and often who you are, and a resolver address can say
// exactly which piece of hardware you are - that is the part this exists to
// generalise or remove.
func (r Report) Redact() Report {
	r.Resolvers = nil

	if len(r.Names) == 0 {
		return r
	}
	counts := make(map[string]int, len(r.Names))
	for _, name := range r.Names {
		counts[hostnameCategory(name)]++
	}
	cats := make([]string, 0, len(counts))
	for c := range counts {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	out := make([]string, 0, len(cats))
	for _, c := range cats {
		n := counts[c]
		unit := "hostname"
		if n != 1 {
			unit = "hostnames"
		}
		out = append(out, fmt.Sprintf("%s (%d %s)", c, n, unit))
	}
	r.Names = out
	return r
}

// hostnameCategory buckets a hostname into a broad, non-identifying category
// by keyword. This is a heuristic aimed at common cases, not a directory -
// an unmatched hostname always falls back to "other" rather than guessing
// further, so an unrecognised provider degrades to a vaguer bucket instead
// of leaking its name.
//
// Ordered most-specific first: a hostname is matched against the narrowest
// category it fits (icloud.com is "cloud sync/storage", not the broader
// "Apple services" catch-all further down) rather than whichever case
// happens to run first, so the two general Apple/Google buckets stay last -
// they exist so a real provider still reads as identifiable-but-vague
// ("Apple services") rather than falling all the way to "other", which is
// where most of a real capture ends up if the specific buckets above them
// only ever match a handful of textbook domains.
// HostnameCategory is hostnameCategory, for callers outside the report.
func HostnameCategory(host string) string { return hostnameCategory(host) }

func hostnameCategory(host string) string {
	h := strings.ToLower(host)
	switch {
	case containsAny(h, "imap", "smtp", "pop3", "mail.", "outlook.", "exchange."):
		return "mail"
	case containsAny(h, "icloud", "apple-cloudkit", "drive.google", "docs.google", "dropbox", "onedrive", "box.com"):
		return "cloud sync/storage"
	case containsAny(h, "push.apple", "courier.push", "gcm-http.googleapis", "fcm.googleapis", "push.services"):
		return "push notifications"
	case containsAny(h, "grammarly", "notion.so", "evernote"):
		return "writing/productivity tools"
	case containsAny(h, "spotify", "scdn.co", "netflix", "youtube", "music.apple", "music.", "video", "stream"):
		return "streaming/media"
	case containsAny(h, "swcdn.apple", "mzstatic", "gvt1.com", "gvt2.com", "update", "cdn", "akamai", "cloudfront", "fastly"):
		return "software update/delivery"
	case containsAny(h, "analytics", "telemetry", "metrics", "doubleclick", "googlesyndication", "googleadservices", "sentry", "crashlytics"):
		return "analytics/telemetry"
	case containsAny(h, "apple.com", "apple-dns", "aaplimg.com"):
		return "Apple services"
	case containsAny(h, "google.com", "googleapis", "gstatic.com", "googleusercontent"):
		return "Google services"
	default:
		return "other"
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
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

// NameWatcher is implemented by backends that can say, while the gap is still
// open, which hostnames have been looked up through it.
//
// Separate from Reporter because it answers a different question at a
// different time. A report is an account of a window that has closed; this is
// evidence about a window still open, and the only reason it is worth having
// is that the user can still act on it - a portal host that is missing from
// the gap can still be added to it.
//
// The names are raw: lookups rather than blocks, and machine-wide rather than
// the portal's. A caller that shows them to a person has to filter them
// first.
type NameWatcher interface {
	NamesSeen() []string
}
