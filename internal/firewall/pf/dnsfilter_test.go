//go:build darwin

package pf

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"portalguard/internal/firewall"
)

// filteredGap locks down, turns the filter on and opens a portal gap.
func filteredGap(t *testing.T, kernel *fakePfctl, b *Backend) {
	t.Helper()
	ctx := context.Background()
	if err := b.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.UseDNSFilter(ctx); err != nil {
		t.Fatal(err)
	}
	for _, h := range []firewall.Host{
		{Name: "www.guestwifi.test", Addrs: []net.IP{net.ParseIP("192.168.64.7")}, Ports: []int{80, 443, 8443}},
		{Name: "resolvers", Addrs: []net.IP{net.ParseIP("192.168.64.7"), net.ParseIP("fd12:3456:789a::1")}, Ports: []int{53}, AllowDNSTo: true},
	} {
		if err := b.AllowHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
}

// TestFilteredGapLetsOnlyTheFilterOut: with the filter on, the only DNS pass
// is the filter's own port, everything else is rerouted, and there is no
// machine-wide DNS rule left.
func TestFilteredGapLetsOnlyTheFilterOut(t *testing.T) {
	kernel := newFakePfctl(t)
	kernel.rdrHookPresent = true
	b := newTestBackend(t, kernel)
	filteredGap(t, kernel, b)

	rules := kernel.loaded
	for _, want := range []string{
		"rdr pass on lo0 inet  proto { udp, tcp } from any to <pg_dns> port 53 -> 127.0.0.1 port 53530",
		"rdr pass on lo0 inet6 proto { udp, tcp } from any to <pg_dns> port 53 -> ::1 port 53530",
		"quick inet  proto udp from any port 41053 to <pg_dns> port 53 keep state",
		"quick inet6 proto udp from any port 41053 to <pg_dns> port 53 keep state",
		"pass out quick route-to (lo0 127.0.0.1) inet  proto { udp, tcp } from any to <pg_dns> port 53 keep state",
		"pass out quick route-to (lo0 ::1) inet6 proto { udp, tcp } from any to <pg_dns> port 53 keep state",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("filtered gap is missing %q:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "proto { tcp, udp } to <pg_dns> port 53") {
		t.Errorf("the machine-wide DNS rule is still there:\n%s", rules)
	}
	if strings.Index(rules, "rdr pass") > strings.Index(rules, "pass quick on lo0") {
		t.Errorf("the rdr comes after a filter rule; pf requires translation first:\n%s", rules)
	}
	requirePfctlParse(t, rules)
}

// TestNoFilterWithoutTheRdrHook: diverting DNS to a redirect that never
// happens would break the login, so the filter is refused and nothing changes.
func TestNoFilterWithoutTheRdrHook(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	if err := b.Lockdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.UseDNSFilter(context.Background()); !errors.Is(err, ErrNoRdrHook) {
		t.Fatalf("err = %v, want ErrNoRdrHook", err)
	}
}

// TestSecondProcessKeepsTheFilter: `allow` from another terminal reloads the
// ruleset, and must not quietly put the machine-wide DNS hole back.
func TestSecondProcessKeepsTheFilter(t *testing.T) {
	kernel := newFakePfctl(t)
	kernel.rdrHookPresent = true
	filteredGap(t, kernel, newTestBackend(t, kernel))

	second := newTestBackend(t, kernel)
	if err := second.AllowHost(context.Background(), firewall.Host{Name: "cdn.guestwifi.test", Addrs: []net.IP{net.ParseIP("192.168.64.4")}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(kernel.loaded, "route-to") || !strings.Contains(kernel.loaded, "rdr pass") {
		t.Errorf("a second process's allow dropped the DNS filter:\n%s", kernel.loaded)
	}
}

// TestSealDropsTheFilter: the filter belongs to the gap.
func TestSealDropsTheFilter(t *testing.T) {
	kernel := newFakePfctl(t)
	kernel.rdrHookPresent = true
	b := newTestBackend(t, kernel)
	filteredGap(t, kernel, b)
	if err := b.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(kernel.loaded, "rdr") || strings.Contains(kernel.loaded, "route-to") {
		t.Errorf("the sealed ruleset still redirects DNS:\n%s", kernel.loaded)
	}
}

// TestDivertedDNSIsNotCountedAsLeaving: the route-to rule sends queries back
// to the filter on loopback, so its packets must not be reported as DNS that
// went out. Only the filter's upstream rule counts.
func TestDivertedDNSIsNotCountedAsLeaving(t *testing.T) {
	rules := []ruleCounters{
		{rule: "pass out quick route-to (lo0 127.0.0.1) inet proto udp from any to <pg_dns> port = 53 keep state", packets: 200},
		{rule: "pass out log (all, user, to pflog1) quick inet proto udp from any port = 41053 to <pg_dns> port = 53 keep state", packets: 30},
	}
	var tl tally
	tl.add(rules)
	if tl.dnsPkts != 30 {
		t.Errorf("DNS out = %d packets, want 30: the diverted 200 never left", tl.dnsPkts)
	}
}

// TestNoFilterWhenLoopbackIsSkipped: Internet Sharing's ruleset sets
// `skip on lo0`, and no rdr is applied on a skipped interface. The filter must
// be refused rather than divert DNS into a redirect that never happens.
func TestNoFilterWhenLoopbackIsSkipped(t *testing.T) {
	kernel := newFakePfctl(t)
	kernel.rdrHookPresent = true
	kernel.skipLoopback = true
	b := newTestBackend(t, kernel)
	if err := b.Lockdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.UseDNSFilter(context.Background()); !errors.Is(err, ErrLoopbackSkipped) {
		t.Fatalf("err = %v, want ErrLoopbackSkipped", err)
	}
}
