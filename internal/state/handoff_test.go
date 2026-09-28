package state

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"portalguard/internal/firewall"
	"portalguard/internal/netinfo"
	"portalguard/internal/portal"
)

// stubTunnel makes tunnelUp report tun (nil for "no tunnel yet") and polls
// fast, for the length of the test.
func stubTunnel(t *testing.T, tun *netinfo.Tunnel) {
	t.Helper()
	origUp, origPoll := tunnelUp, handOffPoll
	tunnelUp = func(context.Context) (*netinfo.Tunnel, error) { return tun, nil }
	handOffPoll = 5 * time.Millisecond
	t.Cleanup(func() { tunnelUp, handOffPoll = origUp, origPoll })
}

// sealedSession is a session that has been through a whole login and sealed.
func sealedSession(t *testing.T, fw *fakeBackend) *Session {
	t.Helper()
	m, err := NewMachineAt(Sealed, "test")
	if err != nil {
		t.Fatal(err)
	}
	return newSession(m, fw, nil, nil)
}

// TestHandOffHoldsTheLockdownUntilTheTunnel is the point of the handover:
// the VPN hole opens first, and the rules are released only once a tunnel
// has the default route - never before, which is what v0.1 did.
func TestHandOffHoldsTheLockdownUntilTheTunnel(t *testing.T) {
	fw := &fakeBackend{}
	s := sealedSession(t, fw)

	// The tunnel comes up on the third look.
	looks := 0
	stubTunnel(t, nil)
	tunnelUp = func(context.Context) (*netinfo.Tunnel, error) {
		looks++
		if looks < 3 {
			return nil, nil
		}
		return &netinfo.Tunnel{Interface: "utun4"}, nil
	}

	res, err := s.HandOff(context.Background(), DefaultVPNEndpoints(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Interface != "utun4" || res.TakenOver {
		t.Errorf("result = %+v, want utun4 with no takeover", res)
	}
	calls := strings.Join(fw.callsMade(), " ")
	if calls != "vpn:5 release" {
		t.Errorf("firewall calls = %q, want the VPN hole and then a release, in that order", calls)
	}
	if s.Machine().State() != HandedOff {
		t.Errorf("state = %s, want %s", s.Machine().State(), HandedOff)
	}
}

// TestHandOffWithNoTunnelStaysLocked: if the VPN never comes up, the machine
// must end as locked as it started, with the VPN hole closed again.
func TestHandOffWithNoTunnelStaysLocked(t *testing.T) {
	fw := &fakeBackend{}
	s := sealedSession(t, fw)
	stubTunnel(t, nil)

	_, err := s.HandOff(context.Background(), DefaultVPNEndpoints(), 40*time.Millisecond)
	if !errors.Is(err, ErrNoTunnel) {
		t.Fatalf("err = %v, want ErrNoTunnel", err)
	}
	calls := fw.callsMade()
	if strings.Join(calls, " ") != "vpn:5 vpn:0" {
		t.Errorf("firewall calls = %v, want the hole opened and closed again with nothing released", calls)
	}
	if s.Machine().State() != Sealed {
		t.Errorf("state = %s, want %s", s.Machine().State(), Sealed)
	}
}

// TestHandOffFromABareLockdown: no portal, just a VPN reconnecting.
func TestHandOffFromABareLockdown(t *testing.T) {
	fw := &fakeBackend{}
	m, _ := NewMachineAt(LockedDown, "test")
	s := newSession(m, fw, nil, nil)
	stubTunnel(t, &netinfo.Tunnel{Interface: "utun4"})
	if _, err := s.HandOff(context.Background(), DefaultVPNEndpoints(), time.Second); err != nil {
		t.Fatal(err)
	}
	if s.Machine().State() != HandedOff {
		t.Errorf("state = %s, want %s", s.Machine().State(), HandedOff)
	}
}

// TestHandOffNeverDuringTheGap: the gap is sealed first, always.
func TestHandOffNeverDuringTheGap(t *testing.T) {
	fw := &fakeBackend{}
	m, _ := NewMachineAt(GapOpen, "test")
	s := newSession(m, fw, nil, nil)
	stubTunnel(t, &netinfo.Tunnel{Interface: "utun4"})
	if _, err := s.HandOff(context.Background(), DefaultVPNEndpoints(), time.Second); err == nil {
		t.Fatal("handed off with the portal gap still open")
	}
	if len(fw.callsMade()) != 0 {
		t.Errorf("the firewall was touched: %v", fw.callsMade())
	}
}

func TestParseEndpoint(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) {
		if host == "vpn.example.net" {
			return []net.IP{net.ParseIP("198.51.100.1"), net.ParseIP("198.51.100.2")}, nil
		}
		return nil, errors.New("no such host")
	}
	cases := []struct {
		spec string
		want []string
	}{
		{"203.0.113.5:51820", []string{"203.0.113.5:51820/udp"}},
		{"203.0.113.5:443/tcp", []string{"203.0.113.5:443/tcp"}},
		{"any:1194/udp", []string{"any:1194/udp"}},
		{"[2001:db8::1]:51820/udp", []string{"[2001:db8::1]:51820/udp"}},
		{"vpn.example.net:51820", []string{"198.51.100.1:51820/udp", "198.51.100.2:51820/udp"}},
	}
	for _, c := range cases {
		got, err := ParseEndpoint(c.spec, resolve)
		if err != nil {
			t.Errorf("%s: %v", c.spec, err)
			continue
		}
		var s []string
		for _, e := range got {
			s = append(s, e.String())
		}
		if strings.Join(s, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s = %v, want %v", c.spec, s, c.want)
		}
	}
	for _, bad := range []string{"203.0.113.5", "203.0.113.5:0", "203.0.113.5:51820/icmp", "nosuch.example:51820"} {
		if _, err := ParseEndpoint(bad, resolve); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	// With the lockdown up there is no DNS, and a hostname has to say so.
	if _, err := ParseEndpoint("vpn.example.net:51820", nil); err == nil || !strings.Contains(err.Error(), "IP address") {
		t.Errorf("hostname with no resolver: err = %v", err)
	}
}

var _ firewall.VPNOpener = (*fakeBackend)(nil)

// TestGapIncludesTheRedirectChain: a host the portal redirected through is
// in the gap from the start, on its own port, not left to be discovered as a
// blank page.
func TestGapIncludesTheRedirectChain(t *testing.T) {
	res := portal.Result{
		Class:       portal.Portal,
		PortalHost:  "portal.example.net",
		PortalPort:  80,
		PortalAddrs: []string{"203.0.113.9"},
		Hops: []portal.Hop{
			{Host: "auth.example.net", Port: 8443, Addrs: []string{"203.0.113.10"}},
		},
	}
	hosts, err := gapHosts(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if h.Name == "auth.example.net" {
			if len(h.Addrs) != 1 || !h.Addrs[0].Equal(net.ParseIP("203.0.113.10")) {
				t.Errorf("hop pinned to %v, want 203.0.113.10", h.Addrs)
			}
			ports := h.TCPPorts()
			if ports[len(ports)-1] != 8443 {
				t.Errorf("hop ports = %v, want its own 8443 included", ports)
			}
			return
		}
	}
	t.Fatalf("the redirect hop is not in the gap: %+v", hosts)
}

// TestHandOffNoticesAVPNTakingOverTheFirewall is the NordVPN finding: its kill
// switch replaces the firewall's ruleset while it connects. The handover must
// say so rather than take the credit, and still step aside cleanly.
func TestHandOffNoticesAVPNTakingOverTheFirewall(t *testing.T) {
	fw := &fakeBackend{}
	s := sealedSession(t, fw)
	looks := 0
	stubTunnel(t, nil)
	tunnelUp = func(context.Context) (*netinfo.Tunnel, error) {
		looks++
		if looks == 2 {
			// The VPN's kill switch replaces our ruleset mid-connect.
			fw.mu.Lock()
			fw.notEnforced = "pf's main ruleset was replaced"
			fw.mu.Unlock()
		}
		if looks < 4 {
			return nil, nil
		}
		return &netinfo.Tunnel{Interface: "utun4"}, nil
	}
	res, err := s.HandOff(context.Background(), DefaultVPNEndpoints(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TakenOver || res.Why == "" {
		t.Errorf("result = %+v, want the takeover reported", res)
	}
	if s.Machine().State() != HandedOff {
		t.Errorf("state = %s, want %s", s.Machine().State(), HandedOff)
	}
}

// TestHandOffTimeoutAfterATakeoverDoesNotClaimALockdown: if the VPN replaced
// our rules and then never came up, "the lockdown is still in place" would be
// false. It has to say the lockdown is not in force.
func TestHandOffTimeoutAfterATakeoverDoesNotClaimALockdown(t *testing.T) {
	fw := &fakeBackend{}
	s := sealedSession(t, fw)
	stubTunnel(t, nil)
	tunnelUp = func(context.Context) (*netinfo.Tunnel, error) {
		fw.mu.Lock()
		fw.notEnforced = "pf's main ruleset was replaced"
		fw.mu.Unlock()
		return nil, nil
	}
	_, err := s.HandOff(context.Background(), DefaultVPNEndpoints(), 40*time.Millisecond)
	var ne *NotEnforcedError
	if !errors.As(err, &ne) {
		t.Fatalf("err = %v, want a NotEnforcedError", err)
	}
}

// TestWaitForAuthStopsWhenTheLockdownStopsApplying: the login wait must not
// carry on over a machine whose lockdown has silently gone.
func TestWaitForAuthStopsWhenTheLockdownStopsApplying(t *testing.T) {
	fw := &fakeBackend{notEnforced: "pf has been turned off"}
	m, _ := NewMachineAt(GapOpen, "test")
	s := newSession(m, fw, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.WaitForAuth(ctx, 10*time.Millisecond)
	var ne *NotEnforcedError
	if !errors.As(err, &ne) {
		t.Fatalf("err = %v, want a NotEnforcedError", err)
	}
}
