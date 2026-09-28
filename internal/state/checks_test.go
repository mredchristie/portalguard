package state

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"portalguard/internal/firewall"
	"portalguard/internal/portal"
)

// checkingBackend is a fakeBackend that also has the check capability, and
// records what the check hole held at every moment that matters.
type checkingBackend struct {
	*fakeBackend
	checks  map[string]int // address -> port
	history []string
}

func newCheckingBackend(fw *fakeBackend) *checkingBackend {
	return &checkingBackend{fakeBackend: fw, checks: map[string]int{}}
}

func (c *checkingBackend) AllowCheck(_ context.Context, h firewall.Host) error {
	for _, ip := range h.Addrs {
		c.checks[ip.String()] = h.TCPPorts()[0]
		c.history = append(c.history, "open:"+ip.String())
	}
	return nil
}

func (c *checkingBackend) DropCheck(_ context.Context, h firewall.Host) error {
	for _, ip := range h.Addrs {
		delete(c.checks, ip.String())
		c.history = append(c.history, "drop:"+ip.String())
	}
	return nil
}

// TestOpenKnownVerifiesThroughACheckHole is the regression test for the
// certificate check that could never succeed: it dialled the remembered host
// before the host was in the gap, and the lockdown dropped the connection.
// The check must happen with a hole open to exactly that address and port,
// and the hole must be gone afterwards.
func TestOpenKnownVerifiesThroughACheckHole(t *testing.T) {
	fw := newCheckingBackend(knownGapBackend())
	s := resumeAtGapWith(t, fw)

	var sawHole bool
	orig := verifyKnownHost
	verifyKnownHost = func(_ context.Context, addr net.IP, port int, _ string) error {
		sawHole = fw.checks[addr.String()] == port
		return nil
	}
	t.Cleanup(func() { verifyKnownHost = orig })

	s.UseKnownNetworks(knownFile(t, "203.0.113.5:9443"))
	if opened := s.OpenKnown(context.Background()); len(opened) != 1 {
		t.Fatalf("opened = %v, want the one host", opened)
	}
	if !sawHole {
		t.Errorf("the certificate check ran with no hole to 203.0.113.5:9443, so a real lockdown would have dropped it; history %v", fw.history)
	}
	if len(fw.checks) != 0 {
		t.Errorf("check hole left open after verifying: %v", fw.checks)
	}
}

// TestOpenKnownClosesTheCheckHoleWhenVerificationFails: an address that did
// not prove itself must leave nothing behind, not even the hole it was
// checked through.
func TestOpenKnownClosesTheCheckHoleWhenVerificationFails(t *testing.T) {
	stubVerify(t, errors.New("certificate signed by unknown authority"))
	fw := newCheckingBackend(knownGapBackend())
	s := resumeAtGapWith(t, fw)

	s.UseKnownNetworks(knownFile(t, "203.0.113.5:9443"))
	if opened := s.OpenKnown(context.Background()); len(opened) != 0 {
		t.Fatalf("opened = %v, want none", opened)
	}
	if len(fw.checks) != 0 {
		t.Errorf("check hole left open after a failed verification: %v", fw.checks)
	}
	if len(fw.history) != 2 {
		t.Errorf("history = %v, want one open and one drop", fw.history)
	}
}

// TestProbeChecksOpenTheProbesRealAddress is the regression test for the
// re-probe that could not see a login finish: once the portal stops
// hijacking DNS the probe endpoint resolves outside the gap, and the probe
// must be let through to it.
func TestProbeChecksOpenTheProbesRealAddress(t *testing.T) {
	fw := newCheckingBackend(knownGapBackend())
	prober := portal.NewProber()
	prober.Probes = []portal.Probe{
		// The endpoint's real address, outside the gap.
		{Name: "real", URL: "http://198.51.100.7/hotspot-detect.html", Expect: portal.ExpectAppleSuccess},
		// Answered by the portal, whose address is already open.
		{Name: "hijacked", URL: "http://203.0.113.9/generate_204", Expect: portal.ExpectNoContent},
		// Loopback, which the lockdown never filters.
		{Name: "local", URL: "http://127.0.0.1:8080/generate_204", Expect: portal.ExpectNoContent},
		// An HTTPS probe, whose port is implied by the scheme.
		{Name: "tls", URL: "https://198.51.100.8/", Expect: ""},
	}
	s := newSession(NewMachine(), fw, prober, nil)
	s.allowed = fw.allowed

	s.openProbeChecks(context.Background())

	want := map[string]int{"198.51.100.7": 80, "198.51.100.8": 443}
	if len(fw.checks) != len(want) {
		t.Fatalf("check hole = %v, want %v", fw.checks, want)
	}
	for addr, port := range want {
		if fw.checks[addr] != port {
			t.Errorf("check hole for %s = port %d, want %d (all: %v)", addr, fw.checks[addr], port, fw.checks)
		}
	}
}

// TestProbeChecksAreSkippedWithoutTheCapability: a backend that cannot open
// a check hole gets the old behaviour, not a panic.
func TestProbeChecksAreSkippedWithoutTheCapability(t *testing.T) {
	fw := knownGapBackend()
	prober := portal.NewProber()
	prober.Probes = []portal.Probe{{Name: "real", URL: "http://198.51.100.7/", Expect: portal.ExpectAppleSuccess}}
	s := newSession(NewMachine(), fw, prober, nil)
	s.openProbeChecks(context.Background())
	for _, c := range fw.callsMade() {
		if c != "" {
			t.Errorf("unexpected firewall call %q from a backend with no check capability", c)
		}
	}
}

// resumeAtGapWith is resumeAtGap for a backend that wraps the fake.
func resumeAtGapWith(t *testing.T, fw *checkingBackend) *Session {
	t.Helper()
	path := tempSession(t)
	if err := SaveSnapshot(path, Snapshot{
		State:   GapOpen,
		Portal:  PortalRef{Host: "portal.example.test", Addrs: []string{"203.0.113.9"}},
		Allowed: fw.allowed,
	}); err != nil {
		t.Fatal(err)
	}
	s, err := Resume(context.Background(), fw, nil, nil, path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// knownFile writes a known-networks file remembering hosts for example.test.
func knownFile(t *testing.T, hosts ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known-networks.json")
	if err := SaveKnownNetworks(path, map[string]KnownNetwork{
		"example.test": {Site: "example.test", Hosts: hosts},
	}); err != nil {
		t.Fatal(err)
	}
	return path
}
