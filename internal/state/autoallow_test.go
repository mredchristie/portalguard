package state

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"portalguard/internal/firewall"
	"portalguard/internal/portal"
)

func TestAutoAllowSite(t *testing.T) {
	cases := map[string]string{
		"www.btwifi.com":             "btwifi.com",
		"portal.hotel.co.uk":         "hotel.co.uk",
		"www.guestwifi.test":         "guestwifi.test",
		"login.wifi.ee.co.uk":        "ee.co.uk",
		"192.168.23.21":              "", // an address has no site
		"router":                     "", // nor does a bare name
		"d1234.cloudfront.net":       "", // shared hosting: no site of its own
		"portal-x.azurewebsites.net": "",
		"myhotel.github.io":          "",
	}
	for host, want := range cases {
		if got := autoAllowSite(host); got != want {
			t.Errorf("autoAllowSite(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestSameSite(t *testing.T) {
	yes := []string{"cdn.btwifi.com", "reg.btwifi.com", "btwifi.com", "a.b.btwifi.com", "CDN.BTWIFI.COM."}
	no := []string{"evilbtwifi.com", "btwifi.com.evil.net", "secure.worldpay.com", "imap.mail.me.com", ""}
	for _, n := range yes {
		if !sameSite(n, "btwifi.com") {
			t.Errorf("%q should be on btwifi.com", n)
		}
	}
	for _, n := range no {
		if sameSite(n, "btwifi.com") {
			t.Errorf("%q must not count as btwifi.com", n)
		}
	}
	if sameSite("anything.com", "") {
		t.Error("no site must match nothing")
	}
}

func autoSession(t *testing.T, st State) (*Session, *fakeBackend, *autoAllow) {
	t.Helper()
	m, _ := NewMachineAt(st, "test")
	fw := &fakeBackend{}
	s := newSession(m, fw, nil, nil)
	s.last = portal.Result{Class: portal.Portal, PortalHost: "www.btwifi.com"}
	a := newAutoAllow(s, "btwifi.com")
	s.auto = a
	return s, fw, a
}

func allowCalls(fw *fakeBackend) int {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	n := 0
	for _, c := range fw.calls {
		if strings.HasPrefix(c, "allow:") {
			n++
		}
	}
	return n
}

// TestAutoAllowWantsOnlyItsSiteWhileTheGapIsOpen.
func TestAutoAllowWantsOnlyItsSiteWhileTheGapIsOpen(t *testing.T) {
	_, _, a := autoSession(t, GapOpen)
	if !a.Wants("cdn.btwifi.com") {
		t.Error("the portal's own CDN should be wanted")
	}
	if a.Wants("secure.worldpay.com") {
		t.Error("another site must be left to the user")
	}
	for _, st := range []State{LockedDown, Authenticated, Sealed} {
		_, _, a := autoSession(t, st)
		if a.Wants("cdn.btwifi.com") {
			t.Errorf("wanted a host in %s, where there is no gap to widen", st)
		}
	}
}

// TestAutoAllowOpensPinnedOnWebPortsOnly: the hole is the answer's addresses
// on 80 and 443, recorded like any other host.
func TestAutoAllowOpensPinnedOnWebPortsOnly(t *testing.T) {
	s, fw, a := autoSession(t, GapOpen)
	ip := net.IPv4(203, 0, 113, 9)
	if err := a.Open("CDN.btwifi.com.", []net.IP{ip}); err != nil {
		t.Fatal(err)
	}
	fw.mu.Lock()
	h := fw.allowed[len(fw.allowed)-1]
	fw.mu.Unlock()
	if h.Name != "cdn.btwifi.com" || len(h.Addrs) != 1 || !h.Addrs[0].Equal(ip) {
		t.Errorf("opened %+v", h)
	}
	if p := h.TCPPorts(); len(p) != 2 || p[0] != 80 || p[1] != 443 {
		t.Errorf("ports %v, want 80 and 443", p)
	}
	if got := s.AutoAllowed(); len(got) != 1 || got[0] != "cdn.btwifi.com" {
		t.Errorf("AutoAllowed = %v", got)
	}
	if got := s.Allowed(); len(got) != 1 {
		t.Errorf("session allowed = %v", got)
	}

	// The browser asking again for the same answer changes nothing.
	_ = a.Open("cdn.btwifi.com", []net.IP{ip})
	if n := allowCalls(fw); n != 1 {
		t.Errorf("%d firewall reloads for one answer asked twice, want 1", n)
	}
	// A new address for it (its AAAA) is opened, without a second announcement.
	_ = a.Open("cdn.btwifi.com", []net.IP{net.ParseIP("2001:db8::9")})
	if n := allowCalls(fw); n != 2 {
		t.Errorf("%d reloads, want 2 after a new address", n)
	}
	if got := s.AutoAllowed(); len(got) != 1 {
		t.Errorf("AutoAllowed = %v, want the one host", got)
	}
}

// TestAutoAllowStopsAtTheCap: past maxAutoAllow hosts, the rest are asked
// for by hand, though hosts already open can still gain addresses.
func TestAutoAllowStopsAtTheCap(t *testing.T) {
	_, fw, a := autoSession(t, GapOpen)
	for i := 0; i < maxAutoAllow; i++ {
		if err := a.Open(fmt.Sprintf("h%d.btwifi.com", i), []net.IP{net.IPv4(203, 0, 113, byte(i))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Open("one-too-many.btwifi.com", []net.IP{net.IPv4(203, 0, 113, 200)}); err != errAutoCap {
		t.Fatalf("err = %v, want the cap", err)
	}
	if err := a.Open("h0.btwifi.com", []net.IP{net.IPv4(203, 0, 113, 201)}); err != nil {
		t.Fatalf("an open host could not gain an address at the cap: %v", err)
	}
	if n := allowCalls(fw); n != maxAutoAllow+1 {
		t.Errorf("%d reloads, want %d", n, maxAutoAllow+1)
	}
}

// TestAutoAllowNeverOpensAfterTheSeal: the seal closes auto-allow first, so a
// lookup answered just after cannot put a gap back on a sealed machine.
func TestAutoAllowNeverOpensAfterTheSeal(t *testing.T) {
	s, fw, a := autoSession(t, Authenticated)
	if err := s.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.Open("cdn.btwifi.com", []net.IP{net.IPv4(203, 0, 113, 9)}); err != errAutoClosed {
		t.Fatalf("err = %v, want closed", err)
	}
	if n := allowCalls(fw); n != 0 {
		t.Errorf("%d opens after the seal", n)
	}

	// And a release does the same, from the gap itself.
	s, fw, a = autoSession(t, GapOpen)
	_ = s.Release(context.Background())
	if err := a.Open("cdn.btwifi.com", []net.IP{net.IPv4(203, 0, 113, 9)}); err == nil || allowCalls(fw) != 0 {
		t.Fatalf("opened after a release (err %v)", err)
	}
}

// TestAutoAllowFirewallFailureIsReported: the filter turns the error into a
// refusal, so the host falls back to being suggested.
func TestAutoAllowFirewallFailureIsReported(t *testing.T) {
	s, fw, a := autoSession(t, GapOpen)
	fw.failOn = "allow:cdn.btwifi.com"
	if err := a.Open("cdn.btwifi.com", []net.IP{net.IPv4(203, 0, 113, 9)}); err == nil {
		t.Fatal("a firewall failure was swallowed")
	}
	if len(s.AutoAllowed()) != 0 || len(s.Allowed()) != 0 {
		t.Error("a failed open was recorded as open")
	}
	if s.machine.State() != GapOpen {
		t.Errorf("state %s after a failed open", s.machine.State())
	}
}

// TestAutoAllowFromTheLogWithoutAFilter: with no DNS filter, the portal's
// own hosts pf's log saw are opened on the next poll, and only those.
func TestAutoAllowFromTheLogWithoutAFilter(t *testing.T) {
	orig := autoResolve
	autoResolve = func(_ context.Context, host string, ports []int, reason string) (firewall.Host, error) {
		return firewall.Host{Name: host, Ports: ports, Addrs: []net.IP{net.IPv4(203, 0, 113, 9)}}, nil
	}
	t.Cleanup(func() { autoResolve = orig })

	fw := &watchingBackend{}
	s := gapSession(t, fw)
	s.UseAutoAllow(true)
	s.startAutoFromLog("www.btwifi.com")
	fw.sees("cdn.btwifi.com", "gateway.icloud.com", "secure.worldpay.com")

	s.autoFromLog(context.Background())
	if got := s.AutoAllowed(); len(got) != 1 || got[0] != "cdn.btwifi.com" {
		t.Fatalf("AutoAllowed = %v, want just the portal's own CDN", got)
	}
	if got := s.SuggestAllow(); len(got) != 0 {
		t.Errorf("still suggesting %v after opening it", got)
	}
}

// TestAutoAllowOffIsV03: without UseAutoAllow nothing is ever opened, and the
// same names are suggested exactly as before.
func TestAutoAllowOffIsV03(t *testing.T) {
	fw := &watchingBackend{}
	s := gapSession(t, fw)
	s.startAutoFromLog("www.btwifi.com")
	fw.sees("cdn.btwifi.com")
	s.autoFromLog(context.Background())
	if s.auto != nil || allowCalls(&fw.fakeBackend) != 0 {
		t.Fatal("auto-allow ran without being asked for")
	}
	if got := s.SuggestAllow(); len(got) != 1 || got[0] != "cdn.btwifi.com" {
		t.Errorf("suggestions = %v", got)
	}
}

// TestAutoAllowNeedsASiteOfItsOwn: a portal on shared hosting gets none.
func TestAutoAllowNeedsASiteOfItsOwn(t *testing.T) {
	s := gapSession(t, &watchingBackend{})
	s.UseAutoAllow(true)
	s.startAutoFromLog("d1234.cloudfront.net")
	if s.auto != nil {
		t.Fatal("auto-allow trusted a shared hosting domain")
	}
}

// TestAutoAllowWantsNothingNewPastTheCap: a yes from Wants sends the query to
// the network, so past the cap only hosts already open may be asked about.
// Otherwise their AAAA and HTTPS lookups leak though their A answer never
// opens. Found by the hostile hotspot.
func TestAutoAllowWantsNothingNewPastTheCap(t *testing.T) {
	_, _, a := autoSession(t, GapOpen)
	for i := 0; i < maxAutoAllow; i++ {
		if err := a.Open(fmt.Sprintf("h%d.btwifi.com", i), []net.IP{net.IPv4(203, 0, 113, byte(i))}); err != nil {
			t.Fatal(err)
		}
	}
	var said []string
	a.s.logf = func(f string, args ...any) { said = append(said, fmt.Sprintf(f, args...)) }
	if a.Wants("h99.btwifi.com") {
		t.Error("a host past the cap was wanted, so its lookups would reach the network")
	}
	_ = a.Wants("h98.btwifi.com")
	if n := len(said); n != 1 || !strings.Contains(said[0], "allowed by hand") {
		t.Errorf("past the cap, said %q; want the cap explained once", said)
	}
	if !a.Wants("H0.btwifi.com.") {
		t.Error("a host already open must still be wanted, for its AAAA and HTTPS answers")
	}
	a.close()
	if a.Wants("h0.btwifi.com") {
		t.Error("wanted after the seal closed auto-allow")
	}
}
