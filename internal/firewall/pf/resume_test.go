//go:build darwin

package pf

import (
	"context"
	"net"
	"strings"
	"testing"

	"portalguard/internal/firewall"
)

// TestSecondProcessWidensTheGapRatherThanReplacingIt is the regression test for
// the failure found at a BT Wi-Fi hotspot: `allow` is meant to be usable while
// a `run` waits in another terminal, and the second process starts with an
// empty allow-list.
//
// Getting this wrong is not a missing feature but a destructive one. pf loads
// a table declaration as a replacement, so a ruleset rendered from an empty
// list plus one new host evicts the portal address and the resolvers the first
// process pinned. The gap would look like it had widened while it had actually
// moved, and the login page would go dead at the exact moment the user added
// the host that was supposed to fix it.
func TestSecondProcessWidensTheGapRatherThanReplacingIt(t *testing.T) {
	kernel := newFakePfctl(t)
	ctx := context.Background()

	// The first process: the one that ran `portalguard run`.
	first := newTestBackend(t, kernel)
	if err := first.Lockdown(ctx); err != nil {
		t.Fatalf("lockdown: %v", err)
	}
	portalHost := firewall.Host{
		Name:  "www.example.net",
		Addrs: []net.IP{net.ParseIP("192.168.23.21")},
		// The non-standard port a portal redirect asked for, which is exactly
		// the detail a rebuild from defaults would lose.
		Ports: []int{80, 443, 8443},
	}
	resolvers := firewall.Host{
		Name:       "network resolvers",
		Addrs:      []net.IP{net.ParseIP("192.168.23.1")},
		Ports:      []int{53},
		AllowDNSTo: true,
	}
	if err := first.AllowHost(ctx, portalHost); err != nil {
		t.Fatalf("allow portal: %v", err)
	}
	if err := first.AllowHost(ctx, resolvers); err != nil {
		t.Fatalf("allow resolvers: %v", err)
	}

	// The second process: `sudo portalguard allow cdn.example.net`, run from
	// another terminal. It shares the kernel and nothing else.
	second := newTestBackend(t, kernel)
	cdn := firewall.Host{Name: "cdn.example.net", Addrs: []net.IP{net.ParseIP("104.16.0.1")}}
	if err := second.AllowHost(ctx, cdn); err != nil {
		t.Fatalf("second process could not widen the gap: %v", err)
	}

	rules := kernel.loaded
	for _, want := range []string{
		"192.168.23.21", // the portal, still pinned
		"192.168.23.1",  // the resolvers, still pinned
		"104.16.0.1",    // and the host just added
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("the widened ruleset dropped %s:\n%s", want, rules)
		}
	}
	if !strings.Contains(rules, "8443") {
		t.Errorf("the widened ruleset lost the non-standard portal port:\n%s", rules)
	}
	if got := kernel.tables[dnsTable]; len(got) != 1 {
		t.Errorf("the DNS table should still hold the resolvers, got %v", got)
	}
}

// TestSecondProcessRecoversThePhaseAndTheOpenPorts covers the read-only half:
// a fresh process must work out that a gap is open, and on which ports.
//
// It drives syncFromKernel rather than Status because Status gates on being
// root before it reads anything back, and these tests deliberately do not run
// as root. That gate is why `portalguard status` without sudo reports OFF over
// a locked-down machine, and says so in its own output.
func TestSecondProcessRecoversThePhaseAndTheOpenPorts(t *testing.T) {
	kernel := newFakePfctl(t)
	ctx := context.Background()

	first := newTestBackend(t, kernel)
	if err := first.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.AllowHost(ctx, firewall.Host{
		Name:  "portal",
		Addrs: []net.IP{net.ParseIP("192.168.23.21")},
		Ports: []int{80, 443, 8443},
	}); err != nil {
		t.Fatal(err)
	}

	second := newTestBackend(t, kernel)
	second.mu.Lock()
	second.syncFromKernel(ctx)
	phase, allowed := second.phase, second.allowed
	second.mu.Unlock()

	if phase != firewall.PhaseGap {
		t.Errorf("phase = %s, want %s", phase, firewall.PhaseGap)
	}
	if len(allowed) != 1 {
		t.Fatalf("allowed = %v, want the one open host", allowed)
	}
	if got := allowed[0].TCPPorts(); len(got) != 3 {
		t.Errorf("ports = %v, want the three the ruleset actually permits", got)
	}

	// And once the gap is sealed, the same read must report a bare lockdown
	// with nothing open - the persist-table trap the phase logic exists for.
	if err := first.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	third := newTestBackend(t, kernel)
	third.mu.Lock()
	third.syncFromKernel(ctx)
	phase, allowed = third.phase, third.allowed
	third.mu.Unlock()

	if phase != firewall.PhaseLocked {
		t.Errorf("after a seal, phase = %s, want %s", phase, firewall.PhaseLocked)
	}
	if len(allowed) != 0 {
		t.Errorf("after a seal, nothing should be allowed, got %v", allowed)
	}
}

// TestSealFromASecondProcessClosesEverything: the process that seals is often
// not the one that opened the gap, and it must close all of it, not just what
// it happens to remember.
func TestSealFromASecondProcessClosesEverything(t *testing.T) {
	kernel := newFakePfctl(t)
	ctx := context.Background()

	first := newTestBackend(t, kernel)
	_ = first.Lockdown(ctx)
	_ = first.AllowHost(ctx, firewall.Host{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.23.21")}})
	_ = first.AllowHost(ctx, firewall.Host{Name: "dns", Addrs: []net.IP{net.ParseIP("192.168.23.1")}, AllowDNSTo: true})

	second := newTestBackend(t, kernel)
	if err := second.Seal(ctx); err != nil {
		t.Fatalf("seal from a second process: %v", err)
	}
	if strings.Contains(kernel.loaded, "192.168.23.21") {
		t.Errorf("the sealed ruleset still permits the portal:\n%s", kernel.loaded)
	}

	var killed []string
	for _, call := range kernel.calls {
		if strings.HasPrefix(call, "-k ") {
			killed = append(killed, call)
		}
	}
	// Both addresses, read back from the kernel rather than from this
	// process's own (empty) bookkeeping.
	if len(killed) != 2 {
		t.Errorf("seal should kill states for both open addresses, killed %v", killed)
	}
}

// TestPortsFromRulesReadsBothSpellings pins the parser against the two forms
// the same rule takes: the list we write, and the expansion pfctl reads back.
func TestPortsFromRulesReadsBothSpellings(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		want  []int
	}{
		{
			name:  "as written",
			rules: "pass out quick inet  proto tcp to <" + portalTable + "> port { 80, 443, 8443 } keep state\n",
			want:  []int{80, 443, 8443},
		},
		{
			name: "as pfctl expands it",
			rules: "pass out quick inet proto tcp from any to <" + portalTable + "> port = 80 keep state\n" +
				"pass out quick inet proto tcp from any to <" + portalTable + "> port = 8443 keep state\n",
			want: []int{80, 8443},
		},
		{
			name: "the DNS rule is not the portal's",
			rules: "pass out log (all, user) quick inet proto { tcp udp } from any to <" + dnsTable + "> port = 53 keep state\n" +
				"pass out quick inet proto tcp from any to <" + portalTable + "> port = 443 keep state\n",
			want: []int{443},
		},
		{
			name:  "a bare lockdown permits nothing",
			rules: "block drop out quick all\n",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := portsFromRules(tc.rules, portalTable)
			if len(got) != len(tc.want) {
				t.Fatalf("ports = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ports = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestCountersSurviveAWidenFromAnotherProcess is the regression test for the
// empty leak report seen at the BT Wi-Fi hotspot, after `allow` from a second
// terminal started working.
//
// pf's per-rule counters are per *kernel*, not per process, and every reload
// resets them for everyone. The tally was per process. So the moment a second
// invocation could reload the ruleset - which is exactly what the cross-process
// `allow` fix enabled - it began banking the machine's counters into its own
// memory and then exiting, wiping the numbers the waiting `run` was accounting
// for and never handing them back.
//
// The sequence below is the one that was actually run at the hotspot.
func TestCountersSurviveAWidenFromAnotherProcess(t *testing.T) {
	kernel := newFakePfctl(t)
	ctx := context.Background()

	// Terminal 1: `sudo portalguard run`.
	run := newTestBackend(t, kernel)
	if err := run.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	kernel.traffic(50, 0) // blocked while the gap was being worked out
	if err := run.AllowHost(ctx, firewall.Host{
		Name: "www.btwifi.test", Addrs: []net.IP{net.ParseIP("192.168.23.21")}, Ports: []int{80, 443, 8443},
	}); err != nil {
		t.Fatal(err)
	}
	if err := run.AllowHost(ctx, firewall.Host{
		Name: "resolvers", Addrs: []net.IP{net.ParseIP("192.168.23.1")}, AllowDNSTo: true,
	}); err != nil {
		t.Fatal(err)
	}

	// The login page comes up blank, and the user reads it for a while.
	kernel.traffic(200, 30)

	// Terminal 2: `sudo portalguard allow cdn.btwifi.test`. A different
	// process, sharing only the kernel and /var/run.
	allow := newTestBackend(t, kernel)
	if err := allow.AllowHost(ctx, firewall.Host{
		Name: "cdn.btwifi.test", Addrs: []net.IP{net.ParseIP("104.16.0.1")},
	}); err != nil {
		t.Fatal(err)
	}

	// The login goes through under the widened ruleset.
	kernel.traffic(300, 40)

	// Back in terminal 1: seal, and print the report.
	if err := run.Seal(ctx); err != nil {
		t.Fatal(err)
	}

	rep := run.LeakReport()
	if rep.Empty() {
		t.Fatal("the report is empty after a full cycle; every sample was lost")
	}
	if got, want := rep.BlockedOutPackets, uint64(550); got != want {
		t.Errorf("BlockedOutPackets = %d, want %d (50 + 200 + 300; the 200 was banked by the other process)", got, want)
	}
	if got, want := rep.DNSPackets, uint64(70); got != want {
		t.Errorf("DNSPackets = %d, want %d", got, want)
	}
}

// TestAnEmptyReportSaysWhichKindOfEmpty. "No traffic was accounted for"
// carried a guess as its explanation - it told the user the counters could not
// be read without knowing whether that was true. Those are different findings
// and the report has to be able to tell them apart, or a real zero and a
// broken measurement look identical.
func TestAnEmptyReportSaysWhichKindOfEmpty(t *testing.T) {
	ctx := context.Background()

	t.Run("a genuine zero", func(t *testing.T) {
		kernel := newFakePfctl(t)
		b := newTestBackend(t, kernel)
		_ = b.Lockdown(ctx)
		_ = b.AllowHost(ctx, firewall.Host{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.23.21")}})
		_ = b.Seal(ctx) // no traffic() call: the network really was silent

		rep := b.LeakReport()
		if !rep.Empty() {
			t.Fatalf("want an empty report, got %+v", rep)
		}
		if rep.CountersUnavailable() {
			t.Error("the counters read fine and reported zero; the report must not claim they were unreadable")
		}
	})

	t.Run("a failed measurement", func(t *testing.T) {
		kernel := newFakePfctl(t)
		b := newTestBackend(t, kernel)
		_ = b.Lockdown(ctx)
		kernel.countersFail = true
		_ = b.AllowHost(ctx, firewall.Host{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.23.21")}})
		_ = b.Seal(ctx)

		rep := b.LeakReport()
		if !rep.Empty() {
			t.Fatalf("want an empty report, got %+v", rep)
		}
		if !rep.CountersUnavailable() {
			t.Error("every sample failed; the report must say so rather than read as a quiet network")
		}
	})
}
