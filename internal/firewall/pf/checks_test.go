//go:build darwin

package pf

import (
	"context"
	"net"
	"strings"
	"testing"

	"portalguard/internal/firewall"
)

// openTestGap locks down and opens a BT-shaped gap: the portal on its odd
// port, plus the network's resolver.
func openTestGap(t *testing.T, b *Backend) {
	t.Helper()
	ctx := context.Background()
	if err := b.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	for _, h := range []firewall.Host{
		{Name: "www.example.net", Addrs: []net.IP{net.ParseIP("192.168.23.21")}, Ports: []int{80, 443, 8443}},
		{Name: "resolvers", Addrs: []net.IP{net.ParseIP("192.168.23.1")}, Ports: []int{53}, AllowDNSTo: true},
	} {
		if err := b.AllowHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCheckHoleIsSeparateFromThePortal: a check must reach its address
// without the address joining the portal's table, and without its port
// joining the portal's port set.
func TestCheckHoleIsSeparateFromThePortal(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	openTestGap(t, b)

	probe := firewall.Host{Name: "captive.apple.com", Addrs: []net.IP{net.ParseIP("17.253.1.2")}, Ports: []int{80}}
	if err := b.AllowCheck(context.Background(), probe); err != nil {
		t.Fatalf("allow check: %v", err)
	}

	if got := kernel.tables[checkTable]; len(got) != 1 || got[0] != "17.253.1.2" {
		t.Errorf("check table = %v, want the probe address", got)
	}
	for _, ip := range kernel.tables[portalTable] {
		if ip == "17.253.1.2" {
			t.Errorf("the probe address leaked into the portal table: %v", kernel.tables[portalTable])
		}
	}
	if !strings.Contains(kernel.loaded, "to <"+checkTable+"> port 80 keep state") {
		t.Errorf("no check rule on port 80:\n%s", kernel.loaded)
	}
	// The portal and the resolvers are still exactly where they were.
	for _, want := range []string{"192.168.23.21", "192.168.23.1", "8443"} {
		if !strings.Contains(kernel.loaded, want) {
			t.Errorf("adding a check dropped %s:\n%s", want, kernel.loaded)
		}
	}
}

// TestCheckHoleSurvivesASecondProcess is the cross-process case that makes
// the check table necessary rather than a local rule: `allow` from another
// terminal reloads the ruleset, and if the reload forgot the re-probe's hole
// the waiting `run` would never see the login finish.
func TestCheckHoleSurvivesASecondProcess(t *testing.T) {
	kernel := newFakePfctl(t)
	ctx := context.Background()

	first := newTestBackend(t, kernel)
	openTestGap(t, first)
	if err := first.AllowCheck(ctx, firewall.Host{Name: "probe", Addrs: []net.IP{net.ParseIP("17.253.1.2")}, Ports: []int{80}}); err != nil {
		t.Fatal(err)
	}

	second := newTestBackend(t, kernel)
	if err := second.AllowHost(ctx, firewall.Host{Name: "cdn.example.net", Addrs: []net.IP{net.ParseIP("104.16.0.1")}}); err != nil {
		t.Fatal(err)
	}

	if got := kernel.tables[checkTable]; len(got) != 1 || got[0] != "17.253.1.2" {
		t.Errorf("a second process's allow dropped the check hole: check table = %v", got)
	}
	if !strings.Contains(kernel.loaded, "to <"+checkTable+"> port 80 keep state") {
		t.Errorf("a second process's allow dropped the check rule:\n%s", kernel.loaded)
	}
}

// TestAllowCheckDoesNotReloadForNothing: the re-probe asks on every poll, so
// asking again for an address already open must not reload the ruleset.
func TestAllowCheckDoesNotReloadForNothing(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	openTestGap(t, b)
	ctx := context.Background()

	probe := firewall.Host{Name: "probe", Addrs: []net.IP{net.ParseIP("17.253.1.2")}, Ports: []int{80}}
	if err := b.AllowCheck(ctx, probe); err != nil {
		t.Fatal(err)
	}
	loads := countLoads(kernel)
	if err := b.AllowCheck(ctx, probe); err != nil {
		t.Fatal(err)
	}
	if got := countLoads(kernel); got != loads {
		t.Errorf("an unchanged check reloaded the ruleset (%d loads, want %d)", got, loads)
	}
}

// TestDropCheckClosesItAndKillsItsStates: a certificate check that failed
// must leave nothing behind - not the rule, and not the connection it made.
func TestDropCheckClosesItAndKillsItsStates(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	openTestGap(t, b)
	ctx := context.Background()

	cdn := firewall.Host{Name: "cdn.example.net", Addrs: []net.IP{net.ParseIP("104.16.0.1")}, Ports: []int{443}}
	if err := b.AllowCheck(ctx, cdn); err != nil {
		t.Fatal(err)
	}
	if err := b.DropCheck(ctx, cdn); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(kernel.loaded, "<"+checkTable+"> port") {
		t.Errorf("the check rule survived the drop:\n%s", kernel.loaded)
	}
	if got := kernel.tables[checkTable]; len(got) != 0 {
		t.Errorf("check table after drop = %v, want empty", got)
	}
	killed := false
	for _, c := range kernel.calls {
		if strings.Contains(c, "-k 104.16.0.1") {
			killed = true
		}
	}
	if !killed {
		t.Errorf("no state kill for the dropped check address; calls: %v", kernel.calls)
	}
	if !strings.Contains(kernel.loaded, "192.168.23.21") {
		t.Errorf("dropping a check closed the portal too:\n%s", kernel.loaded)
	}
}

// TestNoCheckHoleWithoutAGap: the checks only run while someone is logging
// in, so a check hole on a bare lockdown is refused.
func TestNoCheckHoleWithoutAGap(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	if err := b.Lockdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := b.AllowCheck(context.Background(), firewall.Host{Name: "probe", Addrs: []net.IP{net.ParseIP("17.253.1.2")}, Ports: []int{80}})
	if err == nil {
		t.Fatalf("a check hole opened on a bare lockdown:\n%s", kernel.loaded)
	}
}

// TestSealClosesTheCheckHole: the checks leave with the gap, including the
// connections they opened.
func TestSealClosesTheCheckHole(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	openTestGap(t, b)
	ctx := context.Background()
	if err := b.AllowCheck(ctx, firewall.Host{Name: "probe", Addrs: []net.IP{net.ParseIP("17.253.1.2")}, Ports: []int{80}}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(kernel.loaded, checkTable) {
		t.Errorf("the sealed ruleset still mentions the check table:\n%s", kernel.loaded)
	}
	killed := false
	for _, c := range kernel.calls {
		if strings.Contains(c, "-k 17.253.1.2") {
			killed = true
		}
	}
	if !killed {
		t.Errorf("seal did not kill the re-probe's states; calls: %v", kernel.calls)
	}
}

func countLoads(f *fakePfctl) int {
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, "-f -") {
			n++
		}
	}
	return n
}
