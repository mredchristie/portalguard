package portal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"time"
)

// DNSCheck records what we learned about the resolver on this network.
//
// Captive portals routinely hijack DNS: they answer every query with their own
// address so that any hostname the client tries lands on the login page. That
// matters to Portalguard for two reasons. It is a strong portal signal in its
// own right, and it means a firewall rule written against a hostname is
// meaningless here - the portal controls the mapping. Rules must be pinned to
// the addresses observed at detection time.
type DNSCheck struct {
	// Checked is false when the check was skipped.
	Checked bool `json:"checked"`
	// Hijacked is true when we have positive evidence of interception.
	Hijacked bool `json:"hijacked"`
	// Reasons lists the evidence, for display.
	Reasons []string `json:"reasons,omitempty"`
	// WildcardName is the guaranteed-nonexistent name we queried.
	WildcardName string `json:"wildcard_name,omitempty"`
	// WildcardAddrs are the addresses it wrongly resolved to, if any.
	WildcardAddrs []string `json:"wildcard_addrs,omitempty"`
	// ProbeAddrs maps each probe hostname to what it resolved to.
	ProbeAddrs map[string][]string `json:"probe_addrs,omitempty"`
}

// checkDNS looks for two independent signs of a hijacked resolver:
//
//  1. A name that cannot exist resolves anyway. Anything under .invalid is
//     reserved by RFC 2606 and must return NXDOMAIN, so an answer means the
//     resolver is synthesising records.
//  2. A probe hostname resolves to a private, loopback or link-local address.
//     captive.apple.com is never on 192.168.0.0/16.
func (p *Prober) checkDNS(ctx context.Context, probes []Probe) DNSCheck {
	out := DNSCheck{Checked: true, ProbeAddrs: map[string][]string{}}

	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	// 1. The wildcard test.
	out.WildcardName = randomInvalidName()
	if addrs, err := p.resolver().LookupIPAddr(ctx, out.WildcardName); err == nil && len(addrs) > 0 {
		for _, a := range addrs {
			out.WildcardAddrs = append(out.WildcardAddrs, a.IP.String())
		}
		out.Hijacked = true
		out.Reasons = append(out.Reasons,
			"a name that cannot exist ("+out.WildcardName+") resolved to "+
				strings.Join(out.WildcardAddrs, ", ")+"; the resolver is synthesising answers")
	}

	// 2. Probe hostnames landing on local addresses.
	for _, probe := range probes {
		host, _, ok := splitURL(probe.URL)
		if !ok || host == "" || net.ParseIP(host) != nil {
			continue
		}
		if _, seen := out.ProbeAddrs[host]; seen {
			continue
		}
		addrs, err := p.resolver().LookupIPAddr(ctx, host)
		if err != nil {
			continue
		}
		var strs []string
		var local []string
		for _, a := range addrs {
			strs = append(strs, a.IP.String())
			if isLocalAddr(a.IP) {
				local = append(local, a.IP.String())
			}
		}
		out.ProbeAddrs[host] = strs
		if len(local) > 0 {
			out.Hijacked = true
			out.Reasons = append(out.Reasons,
				host+" resolved to the local address "+strings.Join(local, ", ")+
					"; a public endpoint cannot legitimately live there")
		}
	}

	return out
}

// isLocalAddr reports whether an address is one a public hostname should never
// resolve to.
func isLocalAddr(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() ||
		isCGNAT(ip)
}

// isCGNAT reports membership of 100.64.0.0/10, which portals and some VPNs use
// for their own infrastructure.
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 100 && v4[1]&0xc0 == 64
}

// randomInvalidName builds a fresh name under the reserved .invalid TLD. It is
// randomised per run so that a previous answer cannot be served from cache.
func randomInvalidName() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Not security-critical: a timestamp is a fine fallback for cache busting.
		return "pg-" + time.Now().Format("20060102150405.000000000") + ".portalguard.invalid"
	}
	return "pg-" + hex.EncodeToString(b[:]) + ".portalguard.invalid"
}
