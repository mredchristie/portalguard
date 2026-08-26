package portal

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP %q", s)
	}
	return ip
}

// fakeResolver answers every query with the given address, which is exactly
// what a captive portal's resolver does.
func fakeResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "test resolver", Name: addr}
		},
	}
}

func TestRandomInvalidNameIsUnique(t *testing.T) {
	a, b := randomInvalidName(), randomInvalidName()
	if a == b {
		t.Error("wildcard probe names must differ between runs to defeat caching")
	}
	if !strings.HasSuffix(a, ".invalid") {
		t.Errorf("wildcard name %q must sit under the reserved .invalid TLD", a)
	}
}

func TestCheckDNSCleanResolverIsNotHijacked(t *testing.T) {
	p := NewProber()
	p.Timeout = 2 * time.Second
	// A resolver that fails everything cannot produce hijack evidence: the
	// check must stay quiet rather than guess.
	p.Resolver = fakeResolver("127.0.0.1")

	got := p.checkDNS(context.Background(), []Probe{{URL: "http://captive.apple.com/x"}})
	if !got.Checked {
		t.Fatal("check should be marked as performed")
	}
	if got.Hijacked {
		t.Errorf("resolution failure must not be reported as hijacking: %v", got.Reasons)
	}
}

func TestCheckDNSSkipsIPLiteralProbes(t *testing.T) {
	p := NewProber()
	p.Timeout = time.Second
	p.Resolver = fakeResolver("127.0.0.1")

	got := p.checkDNS(context.Background(), []Probe{{URL: "http://10.0.0.1/x"}})
	if len(got.ProbeAddrs) != 0 {
		t.Errorf("IP-literal probes need no lookup, got %v", got.ProbeAddrs)
	}
}

func TestClassifyHijackedDNSWithDeadProbesIsPortal(t *testing.T) {
	// The network answers DNS but drops our packets: still a portal.
	res := Result{
		Probes: []ProbeResult{{Class: NoNetwork, Reason: "timed out"}},
		DNS:    DNSCheck{Checked: true, Hijacked: true},
	}
	NewProber().classify(&res)
	if res.Class != Portal {
		t.Fatalf("class = %s, want %s", res.Class, Portal)
	}
	if !res.Ambiguous {
		t.Error("this inference should be flagged as ambiguous")
	}
}
