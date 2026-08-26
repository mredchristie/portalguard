package state

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"portalguard/internal/firewall"
	"portalguard/internal/portal"
)

// ErrNoPortal is returned when an action needs a known portal and detection
// has not found one.
var ErrNoPortal = errors.New("state: no captive portal detected yet")

// ==== the session =========================================================
// Ties detection and the firewall to the state machine.

// Session drives one pass through the state machine, wiring detection and the
// packet filter to the transitions.
//
// The invariant it exists to maintain: the firewall is only ever loosened
// while the machine says it should be, and any error on the way in leaves the
// machine no less locked down than it was.
type Session struct {
	machine *Machine
	fw      firewall.Backend
	prober  *portal.Prober
	logf    firewall.Logf

	mu      sync.Mutex
	last    portal.Result
	allowed []firewall.Host
}

// NewSession wires a session. A nil prober gets the default probe list.
func NewSession(fw firewall.Backend, prober *portal.Prober, logf firewall.Logf) *Session {
	if prober == nil {
		prober = portal.NewProber()
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Session{machine: NewMachine(), fw: fw, prober: prober, logf: logf}
}

// Machine exposes the state machine for observers and status output.
func (s *Session) Machine() *Machine { return s.machine }

// Result returns the most recent detection result.
func (s *Session) Result() portal.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// ==== the flow, in order ==================================================
// Detect, lock down, open the gap, wait for login, seal, hand off.

// Detect runs the probes and moves the machine to PortalFound or back to Idle.
func (s *Session) Detect(ctx context.Context) (portal.Result, error) {
	if _, err := s.machine.Apply(EventDetect, ""); err != nil {
		return portal.Result{}, err
	}

	res := s.prober.Detect(ctx)

	s.mu.Lock()
	s.last = res
	s.mu.Unlock()

	if res.Class == portal.Portal {
		note := res.PortalHost
		if note == "" {
			note = "portal host unknown"
		}
		if _, err := s.machine.Apply(EventPortalFound, note); err != nil {
			return res, err
		}
		return res, nil
	}
	if _, err := s.machine.Apply(EventNoPortal, string(res.Class)); err != nil {
		return res, err
	}
	return res, nil
}

// Lockdown blocks all traffic. From here nothing leaks while the user works
// out what the portal wants.
func (s *Session) Lockdown(ctx context.Context) error {
	if !s.machine.Can(EventLockdown) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventLockdown}
	}
	if err := s.fw.Lockdown(ctx); err != nil {
		return fmt.Errorf("lockdown: %w", err)
	}
	_, err := s.machine.Apply(EventLockdown, s.fw.Name())
	return err
}

// OpenGap punches the single hole the human needs: the portal host on its own
// port plus 80/443, and DNS to the resolvers this network handed us.
//
// DNS is included because a portal's login flow almost always needs to resolve
// its own hostname, and because the portal's resolver is the only one reachable
// while we are locked down. It is the widest part of the gap and the reason
// this state is meant to be short-lived.
func (s *Session) OpenGap(ctx context.Context) error {
	if !s.machine.Can(EventOpenGap) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventOpenGap}
	}

	s.mu.Lock()
	res := s.last
	s.mu.Unlock()

	if res.Class != portal.Portal {
		return ErrNoPortal
	}

	hosts, err := gapHosts(res)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if err := s.fw.AllowHost(ctx, h); err != nil {
			// Leave the lockdown in place: a half-open gap is still closed
			// enough to be safe, and Release is always available.
			return fmt.Errorf("allow %s: %w", h.Name, err)
		}
		s.mu.Lock()
		s.allowed = append(s.allowed, h)
		s.mu.Unlock()
		s.logf("gap opened for %s", h)
	}

	_, err = s.machine.Apply(EventOpenGap, res.PortalHost)
	return err
}

// AllowExtra widens the gap for one more host. Portals routinely bounce
// through a second hostname (a payment provider, a CDN for their CSS), and the
// user has to be able to add it without dropping the lockdown.
func (s *Session) AllowExtra(ctx context.Context, host string, ports ...int) error {
	if !s.machine.Can(EventExtendGap) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventExtendGap}
	}
	h, err := resolveHost(ctx, host, ports, "manually added by the user")
	if err != nil {
		return err
	}
	if err := s.fw.AllowHost(ctx, h); err != nil {
		return fmt.Errorf("allow %s: %w", host, err)
	}
	s.mu.Lock()
	s.allowed = append(s.allowed, h)
	s.mu.Unlock()
	s.logf("gap widened for %s", h)

	_, err = s.machine.Apply(EventExtendGap, host)
	return err
}

// CheckAuth re-probes through the open gap. A success means the portal has let
// the user on, which is the only signal we trust: we never read the portal's
// own "you are logged in" page.
func (s *Session) CheckAuth(ctx context.Context) (bool, error) {
	res := s.prober.Detect(ctx)
	s.mu.Lock()
	s.last = res
	s.mu.Unlock()

	if res.Class != portal.OpenInternet {
		return false, nil
	}
	if !s.machine.Can(EventAuthenticated) {
		return true, &InvalidTransitionError{From: s.machine.State(), Event: EventAuthenticated}
	}
	_, err := s.machine.Apply(EventAuthenticated, "re-probe reached the real internet")
	return true, err
}

// WaitForAuth polls until the re-probe succeeds, the context is cancelled, or
// the deadline passes.
func (s *Session) WaitForAuth(ctx context.Context, every time.Duration) error {
	if every <= 0 {
		every = 3 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		ok, err := s.CheckAuth(ctx)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Seal closes the gap again, leaving a bare lockdown. Traffic is still
// blocked; this is the state we hand to the VPN from.
func (s *Session) Seal(ctx context.Context) error {
	if !s.machine.Can(EventSeal) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventSeal}
	}
	if err := s.fw.Seal(ctx); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	s.mu.Lock()
	s.allowed = nil
	s.mu.Unlock()

	_, err := s.machine.Apply(EventSeal, "gap closed")
	return err
}

// Report returns the backend's account of what it filtered, and whether the
// backend could supply one at all.
//
// Not every backend can account for its own traffic, so this is an optional
// capability rather than part of the Backend interface: a backend that cannot
// is simply not a firewall.Reporter, instead of stubbing a method that would
// have to return zeros indistinguishable from "nothing happened".
func (s *Session) Report() (firewall.Report, bool) {
	r, ok := s.fw.(firewall.Reporter)
	if !ok {
		return firewall.Report{}, false
	}
	return r.LeakReport(), true
}

// HandOff releases our rules so the user's VPN owns the connection.
//
// v0.1 does not start or verify the VPN: the user does that, and this call
// records the handover and gets our rules out of the way. Verifying that the
// tunnel is actually up before releasing is the obvious next step and is what
// makes the handover leak-free rather than merely brief.
func (s *Session) HandOff(ctx context.Context) error {
	if !s.machine.Can(EventHandOff) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventHandOff}
	}
	if err := s.fw.Release(ctx); err != nil {
		return fmt.Errorf("hand off: %w", err)
	}
	_, err := s.machine.Apply(EventHandOff, "rules released to the VPN")
	return err
}

// Release tears everything down and returns to Idle. It is legal from any
// state and is what the crash handler and `portalguard release` call.
func (s *Session) Release(ctx context.Context) error {
	err := s.fw.Release(ctx)
	s.mu.Lock()
	s.allowed = nil
	s.mu.Unlock()
	if _, aerr := s.machine.Apply(EventRelease, ""); err == nil {
		err = aerr
	}
	return err
}

// Allowed returns the holes currently open.
func (s *Session) Allowed() []firewall.Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]firewall.Host(nil), s.allowed...)
}

// ==== working out what to allow ===========================================
// Turns a detection result into the smallest allowed-host list.

// gapHosts turns a detection result into the minimal host list for the gap.
func gapHosts(res portal.Result) ([]firewall.Host, error) {
	if len(res.PortalAddrs) == 0 {
		return nil, fmt.Errorf("%w: no address for portal host %q", ErrNoPortal, res.PortalHost)
	}

	ports := []int{80, 443}
	if res.PortalPort != 0 && res.PortalPort != 80 && res.PortalPort != 443 {
		ports = append(ports, res.PortalPort)
	}

	hosts := []firewall.Host{{
		Name:   res.PortalHost,
		Addrs:  parseIPs(res.PortalAddrs),
		Ports:  ports,
		Reason: "captive portal login page",
	}}

	if dns := systemResolvers(); len(dns) > 0 {
		hosts = append(hosts, firewall.Host{
			Name:       "network resolvers",
			Addrs:      dns,
			AllowDNSTo: true,
			Ports:      []int{53},
			Reason:     "the portal login flow needs to resolve its own hostname",
		})
	}
	return hosts, nil
}

// resolveHost pins a hostname to addresses for a firewall rule.
func resolveHost(ctx context.Context, host string, ports []int, reason string) (firewall.Host, error) {
	h := firewall.Host{Name: host, Ports: ports, Reason: reason}
	if ip := net.ParseIP(host); ip != nil {
		h.Addrs = []net.IP{ip}
		return h, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return h, fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, a := range addrs {
		h.Addrs = append(h.Addrs, a.IP)
	}
	if len(h.Addrs) == 0 {
		return h, fmt.Errorf("resolve %s: no addresses", host)
	}
	return h, nil
}

func parseIPs(ss []string) []net.IP {
	var out []net.IP
	for _, s := range ss {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// systemResolvers reads the resolvers currently configured for the machine.
//
// On macOS and Linux /etc/resolv.conf is the portable-enough answer: macOS
// keeps it in step with the primary service's DNS. It misses per-interface
// resolvers that only scutil knows about, which is a gap worth closing before
// v1 - a split-DNS setup could leave the portal's resolver out of the gap.
func systemResolvers() []net.IP {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
