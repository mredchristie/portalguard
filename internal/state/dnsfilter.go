package state

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"portalguard/internal/dnsfilter"
	"portalguard/internal/firewall"
	"portalguard/internal/netinfo"
)

// ==== filtering the gap's DNS =============================================
//
// While the gap is open, the network's resolver would otherwise hear every
// name every background daemon on the machine asks for. The filter lets out
// only the names the login needs. See internal/dnsfilter and docs/pf-design.md,
// "The DNS hole is machine-wide".

// DNSAllowPath is where names passed to `allow` are handed to a DNS filter
// running in another process. Written by AllowExtra, read by the filter.
var DNSAllowPath = "/var/run/portalguard.dnsallow"

// ErrNoDNSFilter means this backend cannot redirect DNS, so the gap keeps the
// machine-wide DNS hole.
var ErrNoDNSFilter = errors.New("state: this firewall backend cannot filter DNS")

// DNSFilterStats is what the filter did, for the report.
type DNSFilterStats struct {
	// RefusedNames and Refused are the names, and queries, that never left.
	RefusedNames []string
	Refused      int
	// ForwardedNames and Forwarded are what went to the network's resolver.
	ForwardedNames []string
	Forwarded      int
}

// StartDNSFilter starts the filtering resolver and tells the firewall to send
// the gap's DNS through it. Call it after Lockdown and before OpenGap: the
// allowlist is built from the detection result, and the gap's rules are
// rendered with the filter from the start.
//
// Its allowlist is exact names only: the portal host, the hosts the portal
// redirected through, the probe endpoints (the re-probe resolves them),
// remembered hosts for this site, and anything passed to `allow` later.
func (s *Session) StartDNSFilter(ctx context.Context) error {
	if s.machine.State() != LockedDown {
		return fmt.Errorf("dns filter: start it after the lockdown and before the gap, not in %s", s.machine.State())
	}
	filterer, ok := s.fw.(firewall.DNSFilterer)
	if !ok {
		return ErrNoDNSFilter
	}
	var upstreams []net.IP
	for _, ip := range systemResolvers() {
		if ip.To4() != nil {
			upstreams = append(upstreams, ip)
		}
	}
	if len(upstreams) == 0 {
		return errors.New("dns filter: this network has no IPv4 resolver to filter towards")
	}

	s.mu.Lock()
	res := s.last
	knownPath := s.knownPath
	autoOn := s.autoOn
	verbose := s.dnsVerbose
	trace := s.dnsTrace
	s.mu.Unlock()

	names := []string{res.PortalHost}
	for _, h := range res.Hops {
		names = append(names, h.Host)
	}
	for _, pr := range s.probes() {
		if host, _, ok := probeTarget(pr); ok {
			names = append(names, host)
		}
	}
	names = append(names, osCheckNames...)
	if knownPath != "" {
		if kn, ok := LoadKnownNetworks(knownPath)[siteOf(res.PortalHost)]; ok {
			for _, spec := range kn.Hosts {
				host, _ := splitHostPort(spec)
				names = append(names, host)
			}
		}
	}

	// A fresh allow file: names allowed in an earlier run belong to that run.
	_ = os.Remove(DNSAllowPath)
	srv := &dnsfilter.Server{
		Upstreams: upstreams,
		Policy:    dnsfilter.NewPolicy(DNSAllowPath, names...),
	}
	// Still no default route (see scopedInterface): the filter's questions
	// go out of the Wi-Fi interface itself.
	if iface := s.boundInterface(); iface != "" {
		srv.UpstreamControl = netinfo.BindTo(iface)
	}
	if verbose {
		srv.Logf = s.logf
	}
	srv.Trace = trace
	s.mu.Lock()
	onOther := s.otherSite
	s.mu.Unlock()
	if onOther != nil {
		site := siteOf(res.PortalHost)
		srv.OnRefused = func(name string) {
			// The portal's own site is auto-allow's, or the suggestion's.
			if site != "" && sameSite(name, site) {
				return
			}
			if kind := OtherSiteKind(name); kind != "" {
				onOther(name, kind)
			}
		}
	}
	var auto *autoAllow
	site := autoAllowSite(res.PortalHost)
	if autoOn && site != "" {
		auto = newAutoAllow(s, site)
		srv.Auto = auto
	}
	if err := srv.Start(); err != nil {
		return err
	}
	if err := filterer.UseDNSFilter(ctx); err != nil {
		srv.Stop()
		return err
	}
	s.mu.Lock()
	s.dns = srv
	s.auto = auto
	s.mu.Unlock()
	s.logf("dns filter: only the login's names will leave; everything else is refused")
	switch {
	case auto != nil:
		s.logf("auto-allow: hosts on %s open as the login page asks for them", site)
	case autoOn:
		s.logf("auto-allow: off for this portal (no site of its own to trust); missing hosts will be suggested")
	}
	return nil
}

// UseVerboseDNS has the filter log each name the first time it is refused.
// Takes effect at StartDNSFilter.
func (s *Session) UseVerboseDNS(on bool) {
	s.mu.Lock()
	s.dnsVerbose = on
	s.mu.Unlock()
}

// UseOtherSiteHook has the login's filter report refused names on other
// sites that may be what the page is waiting for (a card processor, say), and
// not background noise. Takes effect at StartDNSFilter. See OtherSiteKind.
func (s *Session) UseOtherSiteHook(f func(name, kind string)) {
	s.mu.Lock()
	s.otherSite = f
	s.mu.Unlock()
}

// UseDNSTrace has the filter report every query and its verdict to f.
// Takes effect at StartDNSFilter.
func (s *Session) UseDNSTrace(f func(name, qtype, verdict string)) {
	s.mu.Lock()
	s.dnsTrace = f
	s.mu.Unlock()
}

// stopDNSFilter stops the resolver, if one is running, and returns what it
// did. The firewall's rules for it go with the seal or the release.
func (s *Session) stopDNSFilter() {
	s.mu.Lock()
	srv := s.dns
	s.mu.Unlock()
	if srv == nil {
		return
	}
	srv.Stop()
	_ = os.Remove(DNSAllowPath)
}

// DNSFilterStats reports what the filter did, and false if none ran.
func (s *Session) DNSFilterStats() (DNSFilterStats, bool) {
	s.mu.Lock()
	srv := s.dns
	s.mu.Unlock()
	if srv == nil {
		return DNSFilterStats{}, false
	}
	var st DNSFilterStats
	st.Refused, st.Forwarded = srv.Counts()
	st.RefusedNames, st.ForwardedNames = srv.Refused(), srv.Forwarded()
	return st, true
}

// allowDNSName hands a name to the filter: directly when this process runs
// it, and through the allow file for one running elsewhere. It must happen
// before the name is resolved, or the lookup itself is refused.
func (s *Session) allowDNSName(host string) {
	if net.ParseIP(host) != nil {
		return
	}
	s.mu.Lock()
	srv := s.dns
	s.mu.Unlock()
	if srv != nil {
		srv.Policy.Allow(host)
	}
	// Written whether or not a filter is running: with none, nothing reads
	// it, and the next StartDNSFilter clears it.
	_ = dnsfilter.AppendAllowFile(DNSAllowPath, host)
}

// filterResolver asks the DNS filter directly, on loopback, rather than
// through the system resolver.
func filterResolver() *net.Resolver {
	d := net.Dialer{Timeout: time.Second}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", dnsfilter.ListenPort))
		},
	}
}

// resolveViaFilter resolves host by asking the DNS filter directly, and falls
// back to the system resolver when no filter is listening.
//
// Directly, because the system resolver caches: the browser asked for this
// name moments ago, the filter refused it, and mDNSResponder will hand that
// refusal straight back without asking again. Found in the first live run of
// the filter, where `allow` failed with "no such host" for exactly that reason.
func resolveViaFilter(ctx context.Context, host string, ports []int, reason string) (firewall.Host, error) {
	if net.ParseIP(host) == nil {
		d := net.Dialer{Timeout: time.Second}
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", dnsfilter.ListenPort))
			},
		}
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := r.LookupIPAddr(lctx, host)
		cancel()
		if err == nil && len(addrs) > 0 {
			h := firewall.Host{Name: host, Ports: ports, Reason: reason}
			for _, a := range addrs {
				h.Addrs = append(h.Addrs, a.IP)
			}
			return h, nil
		}
	}
	return resolveHost(ctx, host, ports, reason)
}

// flushSystemDNSCache empties macOS's resolver cache, best effort.
var flushSystemDNSCache = func() {
	if runtime.GOOS != "darwin" {
		return
	}
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}
