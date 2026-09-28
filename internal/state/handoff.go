package state

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"portalguard/internal/firewall"
	"portalguard/internal/netinfo"
)

// ==== handing over to the VPN =============================================
//
// v0.1 released every rule and then asked the user to start their VPN, so
// everything queued on the machine went out in the clear until the tunnel
// came up: a smaller copy of the very leak Portalguard exists to stop.
//
// The handover holds the lockdown instead, lets out only the VPN client's own
// handshake, and steps aside the moment a tunnel carries the default route.
// From then on the VPN owns the connection, and nothing went out unprotected
// in between. See docs/pf-design.md, "The handover".

// ErrNoTunnel means the wait ran out, or was cancelled, before a VPN tunnel
// took the default route. The lockdown is left exactly as it was before the
// handover began.
var ErrNoTunnel = errors.New("state: no VPN tunnel came up")

// ErrNoHandover means the firewall backend cannot hold the lockdown open for a
// VPN, so a handover could only be done the v0.1 way, by releasing first.
var ErrNoHandover = errors.New("state: this firewall backend cannot hand over to a VPN without releasing first")

// DefaultVPNEndpoints is what the handover lets out when the user names no
// server: the standard ports of the common VPN protocols, to any address,
// because most clients pick their server at connect time.
//
// Deliberately missing: TCP 443, which several providers use as a fallback.
// Opening it to any address would open ordinary HTTPS for every app on the
// machine, which is most of what the lockdown is there to hold back. A user
// whose VPN needs it names the server with -vpn instead.
func DefaultVPNEndpoints() []firewall.Endpoint {
	return []firewall.Endpoint{
		{Port: 51820, Proto: "udp"}, // WireGuard, and NordLynx, Mullvad, Proton on it
		{Port: 1194, Proto: "udp"},  // OpenVPN
		{Port: 1194, Proto: "tcp"},  // OpenVPN over TCP
		{Port: 500, Proto: "udp"},   // IKEv2 / IPsec key exchange
		{Port: 4500, Proto: "udp"},  // IKEv2 / IPsec NAT traversal
	}
}

// tunnelUp reports the tunnel carrying the default route, if any. A variable
// so tests can bring a tunnel up without a VPN.
var tunnelUp = netinfo.ActiveTunnel

// handOffPoll is how often the handover looks for the tunnel. Short, because
// every moment between the tunnel taking the route and the release is a
// moment the user's traffic is being dropped rather than tunnelled.
var handOffPoll = 250 * time.Millisecond

// HandOffResult is how a handover ended.
type HandOffResult struct {
	// Interface is the tunnel that took the default route.
	Interface string
	// TakenOver is set when, while the VPN connected, its own firewall
	// replaced Portalguard's (NordVPN's kill switch does). The VPN's kill
	// switch, not Portalguard's lockdown, then held traffic back until the
	// tunnel was up, and Why says what was seen.
	TakenOver bool
	Why       string
}

// HandOff holds the lockdown with only the given VPN endpoints open, waits up
// to wait for a VPN tunnel to take the default route, and then releases every
// rule.
//
// A VPN client with a kill switch of its own may replace the firewall's
// ruleset while it connects. That is noticed and reported in the result, not
// fought: two tools each asserting "block everything but mine" is the fight
// docs/pf-design.md section 3 decided not to have.
//
// Legal from SEALED, and from a bare LOCKED_DOWN, which is how it serves a
// network with no portal at all: lock down, then hand over to the VPN.
//
// If no tunnel comes up it closes the VPN hole again and returns ErrNoTunnel,
// leaving the machine locked down, not open.
func (s *Session) HandOff(ctx context.Context, endpoints []firewall.Endpoint, wait time.Duration) (HandOffResult, error) {
	var res HandOffResult
	if !s.machine.Can(EventHandOff) {
		return res, &InvalidTransitionError{From: s.machine.State(), Event: EventHandOff}
	}
	opener, ok := s.fw.(firewall.VPNOpener)
	if !ok {
		return res, ErrNoHandover
	}
	if len(endpoints) == 0 {
		return res, fmt.Errorf("hand off: no VPN endpoints to let through")
	}
	if ok, why := s.enforced(ctx); !ok {
		// Nothing to hold open: the lockdown was already gone.
		return res, &NotEnforcedError{Why: why}
	}
	if err := opener.AllowVPN(ctx, endpoints); err != nil {
		return res, fmt.Errorf("hand off: %w", err)
	}
	s.logf("waiting for a VPN tunnel; only %s may leave", describeEndpoints(endpoints))

	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	t := time.NewTicker(handOffPoll)
	defer t.Stop()
	for {
		if !res.TakenOver {
			if ok, why := s.enforced(waitCtx); !ok {
				res.TakenOver, res.Why = true, why
				s.logf("the VPN has taken over the firewall: %s", why)
			}
		}
		tun, _ := tunnelUp(waitCtx)
		if tun != nil {
			// Released either way: with a takeover this only clears our
			// inert anchor, which is ours to tidy up.
			if err := s.fw.Release(ctx); err != nil {
				return res, fmt.Errorf("hand off: the tunnel is up on %s, but releasing failed: %w", tun.Interface, err)
			}
			s.mu.Lock()
			s.allowed = nil
			s.mu.Unlock()
			res.Interface = tun.Interface
			_, err := s.machine.Apply(EventHandOff, "VPN tunnel "+tun.Interface+" carries the default route")
			return res, err
		}
		select {
		case <-waitCtx.Done():
			if res.TakenOver {
				// Our rules are loaded and inert; reloading them changes
				// nothing, and claiming the lockdown still stands would be
				// the exact false comfort this check exists to prevent.
				return res, &NotEnforcedError{Why: res.Why}
			}
			// Close the hole again. Background, not ctx: a cancelled wait
			// must still leave the machine as locked as it found it.
			if err := opener.AllowVPN(context.Background(), nil); err != nil {
				return res, fmt.Errorf("%w, and closing the VPN hole failed: %v", ErrNoTunnel, err)
			}
			return res, ErrNoTunnel
		case <-t.C:
		}
	}
}

// describeEndpoints renders an endpoint list for a log line.
func describeEndpoints(es []firewall.Endpoint) string {
	parts := make([]string, len(es))
	for i, e := range es {
		parts[i] = e.String()
	}
	return strings.Join(parts, ", ")
}

// ParseEndpoint reads one -vpn value: host:port/proto, where host is an IP
// address, a hostname, or "any", and /proto defaults to udp.
//
// A hostname is resolved with resolve, and every address it returns becomes
// an endpoint. Resolution has to happen while DNS is still reachable, which
// is while the gap is open, not after the seal.
func ParseEndpoint(spec string, resolve func(host string) ([]net.IP, error)) ([]firewall.Endpoint, error) {
	proto := "udp"
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		proto = strings.ToLower(spec[i+1:])
		spec = spec[:i]
	}
	if proto != "udp" && proto != "tcp" {
		return nil, fmt.Errorf("vpn endpoint %q: protocol must be udp or tcp", spec)
	}
	host, portStr, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, fmt.Errorf("vpn endpoint %q: want host:port, e.g. 203.0.113.5:51820/udp", spec)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("vpn endpoint %q: bad port", spec)
	}
	switch {
	case host == "any" || host == "*":
		return []firewall.Endpoint{{Port: port, Proto: proto}}, nil
	case net.ParseIP(host) != nil:
		return []firewall.Endpoint{{Addr: net.ParseIP(host), Port: port, Proto: proto}}, nil
	}
	if resolve == nil {
		return nil, fmt.Errorf("vpn endpoint %q: a hostname needs DNS, which the lockdown blocks; use the server's IP address", spec)
	}
	addrs, err := resolve(host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("vpn endpoint %q: could not resolve %s: %v", spec, host, err)
	}
	out := make([]firewall.Endpoint, len(addrs))
	for i, a := range addrs {
		out[i] = firewall.Endpoint{Addr: a, Port: port, Proto: proto}
	}
	return out, nil
}

// SystemResolve resolves a hostname through the machine's resolver, for
// ParseEndpoint.
func SystemResolve(ctx context.Context) func(string) ([]net.IP, error) {
	return func(host string) ([]net.IP, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		out := make([]net.IP, len(addrs))
		for i, a := range addrs {
			out[i] = a.IP
		}
		return out, nil
	}
}
