package state

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"portalguard/internal/firewall"
	"portalguard/internal/netinfo"
	"portalguard/internal/portal"
)

// fakeBackend records calls so tests can assert on the order the firewall was
// driven in, without needing root or a real packet filter.
type fakeBackend struct {
	mu      sync.Mutex
	calls   []string
	allowed []firewall.Host
	failOn  string
	// phase is what Status reports, standing in for the loaded ruleset that a
	// second invocation would read back from the kernel.
	phase    firewall.Phase
	released int
	// notEnforced, when set, is what Enforced reports as the reason the
	// rules are no longer being applied.
	notEnforced string
}

func (f *fakeBackend) Enforced(context.Context) (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.notEnforced == "", f.notEnforced
}

func (f *fakeBackend) record(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	if f.failOn == name {
		return errors.New("injected failure")
	}
	return nil
}

func (f *fakeBackend) Name() string { return "fake" }

func (f *fakeBackend) Available(context.Context) (bool, string) { return true, "" }

func (f *fakeBackend) Lockdown(context.Context) error { return f.record("lockdown") }

func (f *fakeBackend) AllowHost(_ context.Context, h firewall.Host) error {
	if err := f.record("allow:" + h.Name); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed = append(f.allowed, h)
	return nil
}

func (f *fakeBackend) Seal(context.Context) error { return f.record("seal") }

func (f *fakeBackend) AllowVPN(_ context.Context, es []firewall.Endpoint) error {
	return f.record(fmt.Sprintf("vpn:%d", len(es)))
}

func (f *fakeBackend) Release(context.Context) error {
	f.mu.Lock()
	f.released++
	f.mu.Unlock()
	return f.record("release")
}

func (f *fakeBackend) Status(context.Context) (firewall.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return firewall.Status{
		Backend: "fake",
		Phase:   f.phase,
		Allowed: append([]firewall.Host(nil), f.allowed...),
	}, nil
}

func (f *fakeBackend) callsMade() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// portalServer stands in for a captive portal: it redirects until it is told
// the user has logged in, then answers the probe honestly.
type portalServer struct {
	mu            sync.Mutex
	authenticated bool
	loginURL      string
	*httptest.Server
}

func newPortalServer(loginURL string) *portalServer {
	ps := &portalServer{loginURL: loginURL}
	ps.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps.mu.Lock()
		authed := ps.authenticated
		ps.mu.Unlock()
		if authed {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, ps.loginURL, http.StatusFound)
	}))
	return ps
}

func (ps *portalServer) login() {
	ps.mu.Lock()
	ps.authenticated = true
	ps.mu.Unlock()
}

func newTestSession(fw firewall.Backend, probeURL string) *Session {
	return NewSession(fw, testProber(probeURL), nil)
}

// testProber probes one local endpoint and nothing else: no DNS hijack check,
// no default probe list reaching the real internet from a unit test.
func testProber(probeURL string) *portal.Prober {
	p := portal.NewProber()
	p.SkipDNSCheck = true
	p.Timeout = 2 * time.Second
	p.Probes = []portal.Probe{{Name: "test", URL: probeURL, Expect: portal.ExpectNoContent}}
	return p
}

func TestSessionFullFlow(t *testing.T) {
	// The portal login page lives on a loopback address so the gap can be
	// pinned to a real, resolvable host.
	ps := newPortalServer("http://127.0.0.1:8080/login")
	defer ps.Close()

	fw := &fakeBackend{}
	s := newTestSession(fw, ps.URL+"/generate_204")
	ctx := context.Background()

	res, err := s.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Class != portal.Portal {
		t.Fatalf("class = %s, want %s", res.Class, portal.Portal)
	}
	if s.Machine().State() != PortalFound {
		t.Fatalf("state = %s, want %s", s.Machine().State(), PortalFound)
	}

	if err := s.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.OpenGap(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Machine().State() != GapOpen {
		t.Fatalf("state = %s, want %s", s.Machine().State(), GapOpen)
	}

	// Before login, the re-probe must not claim success.
	if ok, err := s.CheckAuth(ctx); err != nil || ok {
		t.Fatalf("CheckAuth before login = %t, %v; want false, nil", ok, err)
	}

	ps.login()
	if ok, err := s.CheckAuth(ctx); err != nil || !ok {
		t.Fatalf("CheckAuth after login = %t, %v; want true, nil", ok, err)
	}
	if s.Machine().State() != Authenticated {
		t.Fatalf("state = %s, want %s", s.Machine().State(), Authenticated)
	}

	if err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	stubTunnel(t, &netinfo.Tunnel{Interface: "utun9"})
	if _, err := s.HandOff(ctx, DefaultVPNEndpoints(), time.Second); err != nil {
		t.Fatal(err)
	}
	if s.Machine().State() != HandedOff {
		t.Fatalf("state = %s, want %s", s.Machine().State(), HandedOff)
	}

	calls := fw.callsMade()
	if calls[0] != "lockdown" {
		t.Errorf("first firewall call was %q, want lockdown", calls[0])
	}
	// Every allow must come after the lockdown, or traffic leaks in between.
	for i, c := range calls {
		if len(c) > 6 && c[:6] == "allow:" && i == 0 {
			t.Errorf("allow at position 0: gap opened before lockdown")
		}
	}
}

func TestSessionOpenGapRequiresLockdown(t *testing.T) {
	ps := newPortalServer("http://127.0.0.1:8080/login")
	defer ps.Close()

	fw := &fakeBackend{}
	s := newTestSession(fw, ps.URL+"/generate_204")
	ctx := context.Background()

	if _, err := s.Detect(ctx); err != nil {
		t.Fatal(err)
	}
	err := s.OpenGap(ctx)
	var ite *InvalidTransitionError
	if !errors.As(err, &ite) {
		t.Fatalf("err = %v, want InvalidTransitionError", err)
	}
	if calls := fw.callsMade(); len(calls) != 0 {
		t.Errorf("firewall was touched before lockdown: %v", calls)
	}
}

func TestSessionFailedAllowLeavesLockdownInPlace(t *testing.T) {
	ps := newPortalServer("http://127.0.0.1:8080/login")
	defer ps.Close()

	fw := &fakeBackend{failOn: "allow:127.0.0.1"}
	s := newTestSession(fw, ps.URL+"/generate_204")
	ctx := context.Background()

	if _, err := s.Detect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.OpenGap(ctx); err == nil {
		t.Fatal("expected the injected allow failure to surface")
	}
	// The machine must not claim the gap is open when it is not.
	if got := s.Machine().State(); got != LockedDown {
		t.Fatalf("state = %s, want %s", got, LockedDown)
	}
}

func TestSessionDetectOpenInternetStaysIdle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	fw := &fakeBackend{}
	s := newTestSession(fw, srv.URL+"/generate_204")

	res, err := s.Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Class != portal.OpenInternet {
		t.Fatalf("class = %s, want %s", res.Class, portal.OpenInternet)
	}
	if s.Machine().State() != Idle {
		t.Fatalf("state = %s, want %s", s.Machine().State(), Idle)
	}
	if calls := fw.callsMade(); len(calls) != 0 {
		t.Errorf("an open network must not touch the firewall, got %v", calls)
	}
}

func TestSessionReleaseFromGapOpen(t *testing.T) {
	ps := newPortalServer("http://127.0.0.1:8080/login")
	defer ps.Close()

	fw := &fakeBackend{}
	s := newTestSession(fw, ps.URL+"/generate_204")
	ctx := context.Background()

	_, _ = s.Detect(ctx)
	_ = s.Lockdown(ctx)
	_ = s.OpenGap(ctx)

	if err := s.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Machine().State() != Idle {
		t.Fatalf("state = %s, want %s", s.Machine().State(), Idle)
	}
	if fw.released != 1 {
		t.Errorf("release called %d times, want 1", fw.released)
	}
	if got := s.Allowed(); len(got) != 0 {
		t.Errorf("allowed list should be empty after release, got %v", got)
	}
}

func TestGapHostsPinsAddressesAndPorts(t *testing.T) {
	res := portal.Result{
		Class:       portal.Portal,
		PortalHost:  "login.hotel.example",
		PortalPort:  8080,
		PortalAddrs: []string{"192.168.1.1"},
	}
	hosts, err := gapHosts(res)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) == 0 {
		t.Fatal("expected at least the portal host")
	}
	h := hosts[0]
	if h.Name != "login.hotel.example" {
		t.Errorf("name = %q", h.Name)
	}
	if len(h.Addrs) != 1 || h.Addrs[0].String() != "192.168.1.1" {
		t.Errorf("addrs = %v, want the pinned address", h.Addrs)
	}
	want := map[int]bool{80: true, 443: true, 8080: true}
	for _, p := range h.TCPPorts() {
		if !want[p] {
			t.Errorf("unexpected port %d in the gap", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing ports in the gap: %v", want)
	}
}

func TestGapHostsRefusesUnpinnedPortal(t *testing.T) {
	// Without an address there is nothing safe to write a rule against.
	_, err := gapHosts(portal.Result{Class: portal.Portal, PortalHost: "login.example"})
	if !errors.Is(err, ErrNoPortal) {
		t.Fatalf("err = %v, want ErrNoPortal", err)
	}
}
