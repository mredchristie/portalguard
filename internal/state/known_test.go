package state

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"portalguard/internal/firewall"
)

func TestLoadKnownNetworksFallsBackToSeedWhenNoFileExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	got := LoadKnownNetworks(path)
	if _, ok := got["btwifi.com"]; !ok {
		t.Fatalf("expected the built-in BT Wi-Fi seed, got %v", got)
	}
}

func TestSaveAndLoadKnownNetworksRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-networks.json")
	want := map[string]KnownNetwork{
		"example.test": {Site: "example.test", Hosts: []string{"cdn.example.test", "reg.example.test:8443"}},
	}
	if err := SaveKnownNetworks(path, want); err != nil {
		t.Fatal(err)
	}
	got := LoadKnownNetworks(path)
	kn, ok := got["example.test"]
	if !ok {
		t.Fatalf("got %v, want an entry for example.test", got)
	}
	if len(kn.Hosts) != 2 || kn.Hosts[0] != "cdn.example.test" || kn.Hosts[1] != "reg.example.test:8443" {
		t.Fatalf("hosts = %v, want [cdn.example.test reg.example.test:8443]", kn.Hosts)
	}
	// The seed must not leak into a file that already exists and simply
	// does not mention it.
	if _, ok := got["btwifi.com"]; ok {
		t.Fatalf("seed entry leaked into a loaded file that never had one")
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		spec     string
		wantHost string
		wantPort int
	}{
		{"cdn.example.net", "cdn.example.net", 0},
		{"info.example.net:442", "info.example.net", 442},
		{"not:a:port", "not:a:port", 0},
	}
	for _, c := range cases {
		host, port := splitHostPort(c.spec)
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("splitHostPort(%q) = %q, %d; want %q, %d", c.spec, host, port, c.wantHost, c.wantPort)
		}
	}
}

// ==== OpenKnown =============================================================

// knownGapBackend is a gap already open for a portal at "portal.example.test",
// the shape OpenKnown expects to be called into.
func knownGapBackend() *fakeBackend {
	return &fakeBackend{
		phase: firewall.PhaseGap,
		allowed: []firewall.Host{
			{Name: "portal.example.test", Addrs: []net.IP{net.ParseIP("203.0.113.9")}, Ports: []int{80, 443}},
		},
	}
}

func resumeAtGap(t *testing.T, fw *fakeBackend) *Session {
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

func stubVerify(t *testing.T, err error) {
	t.Helper()
	orig := verifyKnownHost
	verifyKnownHost = func(context.Context, net.IP, int, string) error { return err }
	t.Cleanup(func() { verifyKnownHost = orig })
}

func TestOpenKnownOpensAHostThatVerifies(t *testing.T) {
	stubVerify(t, nil)
	fw := knownGapBackend()
	s := resumeAtGap(t, fw)

	knownPath := filepath.Join(t.TempDir(), "known-networks.json")
	if err := SaveKnownNetworks(knownPath, map[string]KnownNetwork{
		"example.test": {Site: "example.test", Hosts: []string{"203.0.113.5:9443"}},
	}); err != nil {
		t.Fatal(err)
	}
	s.UseKnownNetworks(knownPath)

	opened := s.OpenKnown(context.Background())
	if len(opened) != 1 || opened[0] != "203.0.113.5" {
		t.Fatalf("opened = %v, want [203.0.113.5]", opened)
	}
	found := false
	for _, h := range fw.allowed {
		if h.Name == "203.0.113.5" {
			found = true
			if len(h.Ports) != 1 || h.Ports[0] != 9443 {
				t.Errorf("ports = %v, want [9443]", h.Ports)
			}
		}
	}
	if !found {
		t.Fatalf("firewall never saw the known host allowed: %v", fw.allowed)
	}
}

func TestOpenKnownSkipsAHostThatDoesNotVerify(t *testing.T) {
	stubVerify(t, errors.New("certificate does not validate"))
	fw := knownGapBackend()
	s := resumeAtGap(t, fw)

	knownPath := filepath.Join(t.TempDir(), "known-networks.json")
	if err := SaveKnownNetworks(knownPath, map[string]KnownNetwork{
		"example.test": {Site: "example.test", Hosts: []string{"203.0.113.5:9443"}},
	}); err != nil {
		t.Fatal(err)
	}
	s.UseKnownNetworks(knownPath)

	if opened := s.OpenKnown(context.Background()); len(opened) != 0 {
		t.Fatalf("opened = %v, want none: a host that fails verification must not be opened", opened)
	}
	for _, h := range fw.allowed {
		if h.Name == "203.0.113.5" {
			t.Fatalf("firewall was told to allow a host that never verified: %v", fw.allowed)
		}
	}
}

func TestOpenKnownIsANoOpWithoutAPath(t *testing.T) {
	stubVerify(t, nil)
	fw := knownGapBackend()
	s := resumeAtGap(t, fw)
	// UseKnownNetworks deliberately not called.

	if opened := s.OpenKnown(context.Background()); opened != nil {
		t.Fatalf("opened = %v, want nil when no known-networks path is set", opened)
	}
}

func TestOpenKnownSkipsAHostAlreadyOpen(t *testing.T) {
	stubVerify(t, nil)
	fw := knownGapBackend()
	fw.allowed = append(fw.allowed, firewall.Host{Name: "cdn.example.test", Addrs: []net.IP{net.ParseIP("203.0.113.5")}, Ports: []int{443}})
	s := resumeAtGap(t, fw)

	knownPath := filepath.Join(t.TempDir(), "known-networks.json")
	if err := SaveKnownNetworks(knownPath, map[string]KnownNetwork{
		"example.test": {Site: "example.test", Hosts: []string{"cdn.example.test"}},
	}); err != nil {
		t.Fatal(err)
	}
	s.UseKnownNetworks(knownPath)

	if opened := s.OpenKnown(context.Background()); len(opened) != 0 {
		t.Fatalf("opened = %v, want none: the host was already open", opened)
	}
}

// ==== Remember ===============================================================

func TestRememberSavesExtraHostsUnderThePortalSite(t *testing.T) {
	fw := knownGapBackend()
	fw.allowed = append(fw.allowed,
		firewall.Host{Name: "resolvers", Addrs: []net.IP{net.ParseIP("203.0.113.1")}, Ports: []int{53}, AllowDNSTo: true},
		firewall.Host{Name: "cdn.example.test", Addrs: []net.IP{net.ParseIP("203.0.113.5")}, Ports: []int{443}},
	)
	s := resumeAtGap(t, fw)

	knownPath := filepath.Join(t.TempDir(), "known-networks.json")
	site, added, err := s.Remember(knownPath)
	if err != nil {
		t.Fatal(err)
	}
	if site != "example.test" {
		t.Fatalf("site = %q, want example.test", site)
	}
	if len(added) != 1 || added[0] != "cdn.example.test" {
		t.Fatalf("added = %v, want [cdn.example.test]", added)
	}

	saved := LoadKnownNetworks(knownPath)
	kn, ok := saved["example.test"]
	if !ok || len(kn.Hosts) != 1 || kn.Hosts[0] != "cdn.example.test" {
		t.Fatalf("saved entry = %+v, want one host cdn.example.test", kn)
	}
	// Neither the portal host itself nor the DNS-only resolver entry belong
	// in a remembered network: the portal host is re-pinned fresh every
	// visit, and the resolver is the network's, not the site's.
	for _, h := range kn.Hosts {
		if h == "portal.example.test" || h == "resolvers" {
			t.Fatalf("Remember saved a host it should have excluded: %v", kn.Hosts)
		}
	}

	// A second call with nothing new open adds nothing.
	_, added2, err := s.Remember(knownPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(added2) != 0 {
		t.Fatalf("second Remember added = %v, want none", added2)
	}
}

func TestRememberRequiresSomethingExtraOpen(t *testing.T) {
	fw := knownGapBackend() // only the portal host itself is open
	s := resumeAtGap(t, fw)

	if _, _, err := s.Remember(filepath.Join(t.TempDir(), "known-networks.json")); err == nil {
		t.Fatal("want an error when there is nothing extra to remember")
	}
}

// ==== names, not table labels ===============================================

// TestRememberRefusesAHostWithNoName is the regression test for the second
// hotspot run: `remember` saved "portal" - the kernel's label for the portal
// table - instead of the hosts `allow` had opened, because nothing had
// recorded their names. A later visit then resolved "portal" through the
// network's own DNS and tried to certificate-check whatever came back.
func TestRememberRefusesAHostWithNoName(t *testing.T) {
	fw := knownGapBackend()
	fw.allowed = append(fw.allowed,
		// What reconcileAllowed hands back for open addresses no snapshot
		// accounts for: the table's label, not a hostname.
		firewall.Host{Name: "portal", Addrs: []net.IP{net.ParseIP("203.0.113.5")}, Ports: []int{80, 443}},
		firewall.Host{Name: "portalguard checks", Addrs: []net.IP{net.ParseIP("198.51.100.7")}, Ports: []int{80}, Check: true},
	)
	s := resumeAtGap(t, fw)

	path := filepath.Join(t.TempDir(), "known-networks.json")
	if _, added, err := s.Remember(path); err == nil {
		t.Fatalf("remembered %v; want a refusal, since no open host has a name", added)
	}
	if kn, ok := LoadKnownNetworks(path)["example.test"]; ok {
		t.Fatalf("saved %+v for a network with nothing nameable open", kn)
	}
}

// TestLoadKnownNetworksDropsTableLabels: a file written before Remember
// checked names must not keep feeding "portal" to OpenKnown.
func TestLoadKnownNetworksDropsTableLabels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-networks.json")
	if err := SaveKnownNetworks(path, map[string]KnownNetwork{
		"example.test": {Site: "example.test", Hosts: []string{"portal", "cdn.example.test", "portalguard checks", "203.0.113.5:9443"}},
	}); err != nil {
		t.Fatal(err)
	}
	got := LoadKnownNetworks(path)["example.test"].Hosts
	if len(got) != 2 || got[0] != "cdn.example.test" || got[1] != "203.0.113.5:9443" {
		t.Fatalf("hosts = %v, want [cdn.example.test 203.0.113.5:9443]", got)
	}
}

// TestAllowFromASecondProcessRecordsTheName: a resumed session that persists
// writes the hosts it adds to the session file, so the next process knows
// them by name and not only by address.
func TestAllowFromASecondProcessRecordsTheName(t *testing.T) {
	fw := knownGapBackend()
	s := resumeAtGap(t, fw)
	path := tempSession(t)
	s.PersistTo(path)

	if err := s.AllowExtra(context.Background(), "203.0.113.5", 443); err != nil {
		t.Fatal(err)
	}
	snap, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range snap.Allowed {
		if h.Name == "203.0.113.5" {
			return
		}
	}
	t.Fatalf("the session file does not name the host just allowed: %+v", snap.Allowed)
}
