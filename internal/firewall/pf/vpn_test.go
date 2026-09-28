//go:build darwin

package pf

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"portalguard/internal/firewall"
)

var testEndpoints = []firewall.Endpoint{
	{Addr: net.ParseIP("203.0.113.5"), Port: 51820, Proto: "udp"},
	{Port: 1194, Proto: "tcp"},
}

// TestHandoverPassesOnlyTheVPN: the handover ruleset is the lockdown plus
// the VPN's handshake, and still ends in the catch-all block.
func TestHandoverPassesOnlyTheVPN(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	ctx := context.Background()
	if err := b.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.AllowVPN(ctx, testEndpoints); err != nil {
		t.Fatalf("allow vpn: %v", err)
	}
	rules := kernel.loaded
	for _, want := range []string{
		"pass out quick inet  proto udp to 203.0.113.5 port 51820 keep state",
		"pass out quick inet  proto tcp to any port 1194 keep state",
		"pass out quick inet6 proto tcp to any port 1194 keep state",
		"block drop out quick all",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("handover ruleset is missing %q:\n%s", want, rules)
		}
	}
	if strings.Index(rules, "port 51820") > strings.Index(rules, "block drop out quick all") {
		t.Errorf("the VPN pass comes after the block, so it would never match:\n%s", rules)
	}
	if strings.Contains(rules, "<"+portalTable+">") {
		t.Errorf("a handover must not carry a portal gap:\n%s", rules)
	}
	b.mu.Lock()
	b.syncFromKernel(ctx)
	phase := b.phase
	b.mu.Unlock()
	if phase != firewall.PhaseLocked {
		t.Errorf("phase during handover = %s, want %s", phase, firewall.PhaseLocked)
	}
}

// TestNoHandoverThroughAnOpenGap: sealing comes first, always.
func TestNoHandoverThroughAnOpenGap(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	openTestGap(t, b)
	if err := b.AllowVPN(context.Background(), testEndpoints); !errors.Is(err, ErrGapOpen) {
		t.Fatalf("err = %v, want ErrGapOpen", err)
	}
}

// TestNoHandoverWithoutALockdown: there is nothing to hand over from.
func TestNoHandoverWithoutALockdown(t *testing.T) {
	b := newTestBackend(t, newFakePfctl(t))
	if err := b.AllowVPN(context.Background(), testEndpoints); !errors.Is(err, firewall.ErrNotLocked) {
		t.Fatalf("err = %v, want ErrNotLocked", err)
	}
}

// TestHandoverRefusesNonsense: a malformed endpoint must not become a rule.
func TestHandoverRefusesNonsense(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	if err := b.Lockdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, e := range []firewall.Endpoint{{Port: 0, Proto: "udp"}, {Port: 51820, Proto: "icmp"}} {
		if err := b.AllowVPN(context.Background(), []firewall.Endpoint{e}); err == nil {
			t.Errorf("accepted %+v", e)
		}
	}
}

// TestHandoverRulesParse puts the rendered ruleset through the real pfctl
// parser, which needs no root for -n.
func TestHandoverRulesParse(t *testing.T) {
	requirePfctlParse(t, render(gap{vpn: testEndpoints}))
}

// requirePfctlParse fails the test if pfctl will not parse rules. -n parses
// without loading, so it needs no root and touches nothing.
func requirePfctlParse(t *testing.T, rules string) {
	t.Helper()
	if _, err := os.Stat(pfctlPath); err != nil {
		t.Skip("no pfctl on this machine")
	}
	cmd := exec.Command(pfctlPath, "-n", "-a", AnchorName, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pfctl rejected the ruleset: %v\n%s\n%s", err, out, rules)
	}
}
