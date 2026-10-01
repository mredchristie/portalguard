// Package portal detects whether the current network is behind a captive
// portal, and if so, where that portal lives.
//
// Detection is deliberately done over plain HTTP. A captive portal has to be
// able to intercept and answer the probe, which it cannot do for HTTPS without
// a certificate error, so the well-known probe endpoints are all http://. We
// never send anything sensitive to them: the request carries no cookies, no
// credentials and no identifying headers beyond a user agent.
package portal

import (
	"time"
)

// Classification is the verdict for a network.
type Classification string

const (
	// OpenInternet means a probe reached the real internet unmodified.
	OpenInternet Classification = "OPEN_INTERNET"
	// Portal means something intercepted a probe: a redirect, a 511, or an
	// unexpected body where a known one was required.
	Portal Classification = "PORTAL"
	// NoNetwork means no probe got an answer at all: no link, no DHCP lease,
	// or traffic being dropped rather than intercepted.
	NoNetwork Classification = "NO_NETWORK"
	// Skipped is a probe stopped before it answered, because another had
	// already found the login page (Prober.FirstPortal). Never a verdict.
	Skipped Classification = "SKIPPED"
)

// Result is the outcome of one detection run.
type Result struct {
	Class Classification `json:"class"`

	// PortalURL is the login page we believe the user must visit. Set only
	// when Class is Portal and we could work it out.
	PortalURL string `json:"portal_url,omitempty"`
	// PortalHost is the hostname (no port) from PortalURL. This is the host
	// the gap will be opened for.
	PortalHost string `json:"portal_host,omitempty"`
	// PortalPort is the TCP port from PortalURL, defaulted by scheme.
	PortalPort int `json:"portal_port,omitempty"`
	// PortalAddrs are the addresses PortalHost resolved to at detection time.
	// Firewall rules are pinned to these so the portal cannot widen its own
	// hole by changing DNS answers later.
	PortalAddrs []string `json:"portal_addrs,omitempty"`

	// Hops are the further hosts the portal redirected through on its way
	// to the login page, each pinned at detection time like the portal host.
	// Filled in by FollowChain, not by Detect. See docs/gap-scope.md, option B.
	Hops []Hop `json:"hops,omitempty"`

	// Ambiguous is set when probes disagreed - typically a portal that
	// whitelists one of the probe endpoints. We report Portal in that case
	// because locking down is the safe reading.
	Ambiguous bool `json:"ambiguous,omitempty"`

	// DNSFailure is set when probes failed at name resolution rather than at
	// connect time, which usually means the network drops DNS to anything but
	// its own resolver.
	DNSFailure bool `json:"dns_failure,omitempty"`

	// DNS carries the result of the resolver-integrity checks.
	DNS DNSCheck `json:"dns"`

	Probes []ProbeResult `json:"probes"`
	// Stopped is set when detection ended at the first probe to find the
	// login page (Prober.FirstPortal): the DNS check is then empty.
	Stopped bool          `json:"stopped,omitempty"`
	At      time.Time     `json:"at"`
	Took    time.Duration `json:"took"`
}

// Summary renders a one-line human explanation of the verdict.
func (r Result) Summary() string {
	switch r.Class {
	case OpenInternet:
		return "open internet: probes reached the real endpoints unmodified"
	case Portal:
		s := "captive portal detected"
		if r.PortalHost != "" {
			s += " at " + r.PortalHost
		}
		if r.Ambiguous {
			s += " (probes disagreed; treating as portal)"
		}
		if r.DNS.Hijacked {
			s += "; DNS is being hijacked"
		}
		return s
	case NoNetwork:
		if r.DNSFailure {
			return "no network: name resolution failed for every probe"
		}
		return "no network: no probe got a response"
	default:
		return string(r.Class)
	}
}
