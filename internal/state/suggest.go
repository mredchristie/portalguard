package state

import (
	"net"
	"sort"
	"strings"

	"portalguard/internal/firewall"
)

// ==== which host is missing ===============================================
// The gap stays decided by a human. This is how the human finds out what
// there is to decide about.

// SuggestAllow returns hostnames that were looked up while the gap was open,
// are not in the gap, and look like they belong to the portal.
//
// It exists because of the failure it fixes. A portal whose stylesheets and
// scripts come from a CDN host that is not in the gap does not report an
// error: the page loads, the markup arrives hidden, the script that would
// reveal it is dropped, and the user gets a blank rectangle with nothing on
// screen naming the host to open. Meanwhile the evidence is already in hand,
// because DNS is open through the gap and the leak reader has been watching
// every lookup go past. This hands that evidence over while it is still
// useful. See docs/gap-scope.md.
//
// It opens nothing. The suggestion is text, and every host still enters the
// gap only because a person named it in `portalguard allow` - which is the
// same line the tool holds over credentials. That is also what makes the
// heuristic below acceptable: it decides what to *mention*, not what to let
// through, so getting it wrong costs the reader a glance at a line of text.
//
// Returns nil for a backend that cannot watch names, which is not
// distinguishable from "nothing worth suggesting" and does not need to be:
// both mean there is nothing to print.
func (s *Session) SuggestAllow() []string {
	// Two sources of "looked up": the names the DNS filter refused, when it
	// is running, and the names pf's log saw go through the DNS hole. With
	// the filter on, the log only ever sees names the filter let out, so the
	// refusals are where a blank page's missing hosts show up.
	var seen []string
	if w, ok := s.fw.(firewall.NameWatcher); ok {
		seen = w.NamesSeen()
	}
	s.mu.Lock()
	if s.dns != nil {
		seen = append(seen, s.dns.Refused()...)
	}
	s.mu.Unlock()
	if len(seen) == 0 {
		return nil
	}

	s.mu.Lock()
	portalHost := s.last.PortalHost
	open := make(map[string]bool, len(s.allowed)+1)
	open[normalizeHost(portalHost)] = true
	for _, h := range s.allowed {
		open[normalizeHost(h.Name)] = true
	}
	path := s.store
	s.mu.Unlock()

	// A gap widened from a second terminal was widened by a different
	// process, and this one will never hear about it: `allow` writes to the
	// session file and returns, and nothing here transitions afterwards to
	// re-read it. That file is the only place those host names exist, so
	// read it, or every later suggestion repeats hosts the user has already
	// opened.
	if path != "" {
		if snap, err := LoadSnapshot(path); err == nil {
			for _, h := range snap.Allowed {
				open[normalizeHost(h.Name)] = true
			}
		}
	}

	return relatedNames(seen, portalHost, open)
}

// relatedNames picks the names worth showing out of every lookup the machine
// made while the gap was open.
//
// Two filters, in order: drop what is already open, then keep what shares a
// site with the portal. The second is the one doing the work, because the DNS
// hole is machine-wide and the raw list is mostly the background noise of a
// laptop that has just noticed it has a network - Apple push, browser
// telemetry, whatever was mid-sync when the lockdown landed. None of that is
// a portal host, and a suggestion list that includes it is one nobody reads.
func relatedNames(seen []string, portalHost string, open map[string]bool) []string {
	site := siteOf(portalHost)
	if site == "" {
		// No portal host means no way to tell a portal's CDN from a
		// telemetry endpoint. Suggesting everything would be worse than
		// suggesting nothing: it is the list the filter exists to avoid.
		return nil
	}

	found := map[string]bool{}
	var out []string
	for _, raw := range seen {
		name := normalizeHost(raw)
		if name == "" || open[name] || found[name] {
			continue
		}
		if siteOf(name) != site {
			continue
		}
		found[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// normalizeHost puts a hostname in the one form the comparisons here use:
// lower case, no trailing root dot (which DNS decodes carry and redirects do
// not), no port.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	// A port may be attached where a name came from a URL rather than from a
	// DNS decode. One colon is a "host:port"; several are an IPv6 literal,
	// which keeps every colon it has.
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.Index(h, ":"); i > 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return h
}

// siteOf reduces a hostname to the domain two names have to share to be
// called relatives: the registrable domain, near enough.
//
// Near enough, because doing this exactly needs the public suffix list, and a
// few hundred KB of data that goes stale is a poor trade for a tool whose
// entire ruleset is generated fresh and never written to disk. What it costs
// to be approximate is bounded by what this is used for: an over-broad answer
// mentions a hostname that was not worth mentioning, and an over-narrow one
// stays quiet about a host the user can still name themselves. Nothing here
// reaches a firewall rule. Were this ever used to *open* something, the
// public suffix list would stop being optional - see docs/gap-scope.md, where
// that is exactly why allowing a whole domain was rejected.
func siteOf(host string) string {
	h := normalizeHost(host)
	if net.ParseIP(h) != nil {
		// An address is not a relative of anything. Left to the label rule
		// below it would be: "10.0.0.5" and "1.2.0.5" would both reduce to
		// "0.5" and be called the same site.
		return ""
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 || labels[len(labels)-1] == "" {
		// A bare name has no domain to share.
		return ""
	}
	n := 2
	// "hotel.co.uk" is one site; "co.uk" is a country's entire registry.
	// The two-label rule gets this wrong in exactly the shape below - a
	// short registry label under a two-letter country code - and that shape
	// is common enough in hotels and airports to be worth the special case.
	last, penult := labels[len(labels)-1], labels[len(labels)-2]
	if len(labels) >= 3 && len(last) == 2 && registryLabels[penult] {
		n = 3
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// registryLabels are the second-level labels that are registries rather than
// somebody's domain, under a two-letter country code: the "co" of "co.uk".
// Not the public suffix list and not trying to be - just the handful whose
// absence would make siteOf answer "co.uk" to "which site is this".
var registryLabels = map[string]bool{
	"co": true, "com": true, "net": true, "org": true,
	"ac": true, "gov": true, "edu": true, "or": true, "ne": true,
}
