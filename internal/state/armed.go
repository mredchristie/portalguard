package state

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"portalguard/internal/dnsfilter"
	"portalguard/internal/firewall"
	"portalguard/internal/portal"
)

// ==== armed: lock first, detect through the lockdown =======================
//
// run detects the portal and then locks down, so everything between joining
// a network and typing the command goes out unprotected, and that is exactly
// when every app on the machine fires off its backlog. Armed mode reverses the
// order: Arm blocks everything before a network is even known, and
// DetectArmed finds out what the network is through the lockdown.
//
// Only Portalguard's own detection gets out while it does. The DNS filter
// runs in probe mode: it forwards the probe names, the hijack check's made-up
// name, and the login host once the probes name it, and nothing else. Each
// probe name's answer is opened as a check hole on 80 and 443, so the probe
// can connect; the login host is resolved and pinned, not opened. When
// detection is done the ruleset goes back to a bare lockdown before anything
// else happens, so none of those holes carries over into the login.

// ErrNoNetworkYet means there is nothing to detect through: no DNS server has
// been handed out. The caller waits for a network and tries again.
var ErrNoNetworkYet = errors.New("state: no network yet")

// hijackCheckSuffix is where the DNS hijack check's made-up names live. .invalid
// is reserved (RFC 2606): no answer for it is real, so forwarding it gives
// nothing away and an answer is itself the evidence.
const hijackCheckSuffix = ".portalguard.invalid"

// Arm locks everything down with no portal known yet.
func (s *Session) Arm(ctx context.Context) error {
	if !s.machine.Can(EventArm) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventArm}
	}
	if err := s.fw.Lockdown(ctx); err != nil {
		return fmt.Errorf("arm: %w", err)
	}
	_, err := s.machine.Apply(EventArm, s.fw.Name())
	return err
}

// DetectArmed classifies the network from inside the armed lockdown, and
// leaves the machine LockedDown with a bare lockdown loaded, whatever the
// answer. The caller goes on to the gap (a portal) or the VPN handover.
//
// It returns ErrNoNetworkYet, and leaves the machine Armed, when the network
// has handed out no IPv4 DNS server to detect through.
func (s *Session) DetectArmed(ctx context.Context) (portal.Result, error) {
	if s.machine.State() != Armed {
		return portal.Result{}, fmt.Errorf("detect armed: not armed (%s)", s.machine.State())
	}
	filterer, ok := s.fw.(firewall.DNSFilterer)
	if !ok {
		return portal.Result{}, ErrNoDNSFilter
	}
	var upstreams []net.IP
	for _, ip := range systemResolvers() {
		if ip.To4() != nil {
			upstreams = append(upstreams, ip)
		}
	}
	if len(upstreams) == 0 {
		return portal.Result{}, ErrNoNetworkYet
	}

	opener := &probeOpener{s: s, probes: map[string]bool{}, resolve: map[string]bool{}}
	for _, pr := range s.probes() {
		if host, _, ok := probeTarget(pr); ok {
			opener.probes[normalizeHost(host)] = true
		}
	}
	_ = os.Remove(DNSAllowPath)
	srv := &dnsfilter.Server{Upstreams: upstreams, Policy: dnsfilter.NewPolicy(""), Auto: opener}
	if err := srv.Start(); err != nil {
		return portal.Result{}, fmt.Errorf("detect armed: dns filter: %w", err)
	}
	// Whatever happens from here, detection ends in a bare lockdown with the
	// probe filter gone.
	relock := func() error {
		srv.Stop()
		return s.fw.Lockdown(ctx)
	}
	if err := filterer.UseDNSFilter(ctx); err != nil {
		_ = relock()
		return portal.Result{}, fmt.Errorf("detect armed: %w", err)
	}
	resolvers := firewall.Host{
		Name:       "network resolvers",
		Addrs:      systemResolvers(),
		AllowDNSTo: true,
		Ports:      []int{53},
		Reason:     "detection through the lockdown: probe names only",
	}
	if err := s.fw.AllowHost(ctx, resolvers); err != nil {
		_ = relock()
		return portal.Result{}, fmt.Errorf("detect armed: %w", err)
	}
	s.logf("detecting through the lockdown: only the probes' own lookups may leave")

	prev := s.prober.OnPortal
	s.prober.OnPortal = opener.resolveOnly
	res := s.prober.Detect(ctx)
	s.prober.OnPortal = prev

	if err := relock(); err != nil {
		return res, fmt.Errorf("detect armed: back to a bare lockdown: %w", err)
	}
	s.mu.Lock()
	s.last = res
	s.mu.Unlock()
	if res.Class == portal.Portal {
		_, err := s.machine.Apply(EventPortalFound, res.PortalHost)
		return res, err
	}
	_, err := s.machine.Apply(EventNoPortal, string(res.Class))
	return res, err
}

// probeOpener is the DNS filter's AutoAllower during armed detection.
type probeOpener struct {
	s *Session

	mu sync.Mutex
	// probes are the probe hostnames: forwarded, and opened as check holes.
	probes map[string]bool
	// resolve are names forwarded but never opened: the login host, once
	// the probes have named it.
	resolve map[string]bool
}

func (o *probeOpener) resolveOnly(host string) {
	o.mu.Lock()
	o.resolve[normalizeHost(host)] = true
	o.mu.Unlock()
}

func (o *probeOpener) Wants(name string) bool {
	n := normalizeHost(name)
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.probes[n] || o.resolve[n] || strings.HasSuffix(n, hijackCheckSuffix)
}

// Open lets a probe connect to what its name resolved to. On a portal that is
// the portal's own address, which is the point: the probe has to reach it to
// be redirected.
func (o *probeOpener) Open(name string, addrs []net.IP) error {
	n := normalizeHost(name)
	o.mu.Lock()
	probe := o.probes[n]
	o.mu.Unlock()
	if !probe {
		return nil
	}
	checker, ok := o.s.fw.(firewall.Checker)
	if !ok {
		return errors.New("this firewall backend has no check holes")
	}
	return checker.AllowCheck(context.Background(), firewall.Host{
		Name:   n,
		Addrs:  addrs,
		Ports:  []int{80, 443},
		Check:  true,
		Reason: "connectivity probe, during detection through the lockdown",
	})
}
