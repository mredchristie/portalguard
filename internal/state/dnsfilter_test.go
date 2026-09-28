package state

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"portalguard/internal/dnsfilter"
	"portalguard/internal/portal"
)

// Tests must never flush the real machine's DNS cache.
func init() { flushSystemDNSCache = func() {} }

func tempAllowFile(t *testing.T) string {
	t.Helper()
	orig := DNSAllowPath
	DNSAllowPath = filepath.Join(t.TempDir(), "dnsallow")
	t.Cleanup(func() { DNSAllowPath = orig })
	return DNSAllowPath
}

// dnsQuery is the packet a stub resolver sends for one A lookup.
func dnsQuery(name string) []byte {
	q := []byte{0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

// TestAllowHandsTheNameToTheFilterFirst: `allow` from a second process has
// to reach the filter running inside `run` before it resolves the name, or
// its own lookup is the one the filter refuses.
func TestAllowHandsTheNameToTheFilterFirst(t *testing.T) {
	file := tempAllowFile(t)
	m, _ := NewMachineAt(GapOpen, "test")
	s := newSession(m, &fakeBackend{}, nil, nil)

	// The name does not resolve, so AllowExtra fails; the hand-off must
	// already have happened by then.
	_ = s.AllowExtra(context.Background(), "cdn.guestwifi.invalid")
	data, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(data), "cdn.guestwifi.invalid") {
		t.Fatalf("allow file = %q, %v; want the name in it", data, err)
	}
}

// TestSuggestionsComeFromTheFiltersRefusals: with the filter on, pf's log
// only sees names the filter let out, so a blank page's missing host has to
// come from the refusals.
func TestSuggestionsComeFromTheFiltersRefusals(t *testing.T) {
	srv := &dnsfilter.Server{
		Upstreams:          []net.IP{net.IPv4(127, 0, 0, 1)},
		Policy:             dnsfilter.NewPolicy("", "www.guestwifi.test"),
		ListenAddr:         "127.0.0.1:0",
		UpstreamSourcePort: -1,
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	for _, name := range []string{"cdn.guestwifi.test", "imap.mail.me.com"} {
		c, err := net.Dial("udp4", srv.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(dnsQuery(name))
		_, _ = c.Read(make([]byte, 512))
		c.Close()
	}

	m, _ := NewMachineAt(GapOpen, "test")
	s := newSession(m, &fakeBackend{}, nil, nil)
	s.last = portal.Result{Class: portal.Portal, PortalHost: "www.guestwifi.test"}
	s.dns = srv

	got := s.SuggestAllow()
	if len(got) != 1 || got[0] != "cdn.guestwifi.test" {
		t.Errorf("suggestions = %v, want just cdn.guestwifi.test (the unrelated refusal filtered out)", got)
	}
}

// TestDNSFilterStartsOnlyBetweenLockdownAndGap: before the lockdown there is
// nothing to redirect into, and once the gap is open its rules are written.
func TestDNSFilterStartsOnlyBetweenLockdownAndGap(t *testing.T) {
	for _, st := range []State{Idle, PortalFound, GapOpen, Sealed} {
		m, _ := NewMachineAt(st, "test")
		s := newSession(m, &fakeBackend{}, nil, nil)
		if err := s.StartDNSFilter(context.Background()); err == nil {
			t.Errorf("started the DNS filter in %s", st)
		}
	}
}
