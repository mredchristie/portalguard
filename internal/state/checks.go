package state

import (
	"context"
	"net"
	"net/url"
	"strconv"

	"portalguard/internal/firewall"
	"portalguard/internal/portal"
)

// ==== reaching past the gap for our own checks ============================
//
// Two things Portalguard does while the gap is open have to reach addresses
// the gap does not include: the re-probe that notices the login went through,
// and the certificate check on a remembered host. Under a real lockdown both
// were dropped. Every test that passed did so against loopback, which the
// lockdown never filters, so nothing noticed. See firewall.Checker.

// checker returns the backend's check capability, if it has one.
func (s *Session) checker() (firewall.Checker, bool) {
	c, ok := s.fw.(firewall.Checker)
	return c, ok
}

// openProbeChecks lets the re-probe reach wherever the probe endpoints
// resolve to right now, ahead of each poll.
//
// Before the login the portal usually answers the probe names with its own
// address, which is already in the gap. After it, they resolve to the real
// endpoints, which never are - and without this the probe that should notice
// the login is dropped by the lockdown, and the wait runs out on a network
// the user has already logged in to.
//
// What this trusts is DNS, which on this network belongs to the operator. The
// cost is bounded: the probes' own ports, only while the gap is open, and the
// worst a lying answer buys is a probe response Portalguard reads as "logged
// in" - which seals the gap, the safe direction.
func (s *Session) openProbeChecks(ctx context.Context) {
	c, ok := s.checker()
	if !ok {
		return
	}
	open := s.openAddrs()
	for _, pr := range s.probes() {
		host, port, ok := probeTarget(pr)
		if !ok {
			continue
		}
		h, err := resolveHost(ctx, host, []int{port}, "re-probe to notice the login finishing")
		if err != nil {
			// Not resolving yet is ordinary mid-login. The poll carries on
			// and the next one tries again.
			continue
		}
		var addrs []net.IP
		for _, ip := range h.Addrs {
			// Loopback is never filtered, and an address already in the gap
			// needs no second hole.
			if ip.IsLoopback() || open[ip.String()] {
				continue
			}
			addrs = append(addrs, ip)
		}
		if len(addrs) == 0 {
			continue
		}
		h.Addrs, h.Check = addrs, true
		if err := c.AllowCheck(ctx, h); err != nil {
			s.logf("could not open the re-probe to %s: %v", host, err)
			continue
		}
	}
}

// verifyThroughCheck runs the certificate check on one address of a
// remembered host, with a check hole open to that address and port for
// exactly as long as the handshake takes.
//
// The hole is dropped whatever the outcome. A host that verifies is then
// opened properly by the caller; one that does not leaves nothing behind.
func (s *Session) verifyThroughCheck(ctx context.Context, addr net.IP, port int, name string) error {
	c, ok := s.checker()
	if !ok || addr.IsLoopback() {
		return verifyKnownHost(ctx, addr, port, name)
	}
	h := firewall.Host{
		Name:   name,
		Addrs:  []net.IP{addr},
		Ports:  []int{port},
		Check:  true,
		Reason: "certificate check on a remembered host",
	}
	if err := c.AllowCheck(ctx, h); err != nil {
		return err
	}
	defer func() {
		// Background, not ctx: a cancelled run must still close the hole.
		if err := c.DropCheck(context.Background(), h); err != nil {
			s.logf("could not close the certificate check to %s: %v", name, err)
		}
	}()
	return verifyKnownHost(ctx, addr, port, name)
}

// probes returns the prober's endpoint list, or the defaults it would use.
func (s *Session) probes() []portal.Probe {
	if len(s.prober.Probes) > 0 {
		return s.prober.Probes
	}
	return portal.DefaultProbes()
}

// openAddrs is every address the session has put in the gap proper.
func (s *Session) openAddrs() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	open := map[string]bool{}
	for _, h := range s.allowed {
		for _, ip := range h.Addrs {
			open[ip.String()] = true
		}
	}
	return open
}

// probeTarget is the host and port a probe connects to.
func probeTarget(pr portal.Probe) (host string, port int, ok bool) {
	u, err := url.Parse(pr.URL)
	if err != nil || u.Hostname() == "" {
		return "", 0, false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return "", 0, false
		}
		return u.Hostname(), n, true
	}
	if u.Scheme == "https" {
		return u.Hostname(), 443, true
	}
	return u.Hostname(), 80, true
}

// ==== is the lockdown still in force? =====================================

// NotEnforcedError means the firewall's rules are loaded but no longer being
// applied: something else turned the filter off or replaced its ruleset.
type NotEnforcedError struct{ Why string }

func (e *NotEnforcedError) Error() string {
	return "the lockdown is no longer in force: " + e.Why
}

// enforced asks the backend whether its rules are still being applied. A
// backend that cannot tell is taken at its word.
func (s *Session) enforced(ctx context.Context) (bool, string) {
	e, ok := s.fw.(firewall.Enforcer)
	if !ok {
		return true, ""
	}
	return e.Enforced(ctx)
}
