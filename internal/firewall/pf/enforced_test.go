//go:build darwin

package pf

import (
	"context"
	"testing"
)

// TestEnforcedNoticesTheHookGoing is the regression test for the NordVPN
// finding: our rules were loaded and inert, and nothing said so.
func TestEnforcedNoticesTheHookGoing(t *testing.T) {
	kernel := newFakePfctl(t)
	b := newTestBackend(t, kernel)
	if err := b.Lockdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, why := b.Enforced(context.Background()); !ok {
		t.Fatalf("a fresh lockdown reads as not enforced: %s", why)
	}

	// Another tool reloads the main ruleset without our anchor in it.
	kernel.hookPresent = false
	ok, why := b.Enforced(context.Background())
	if ok {
		t.Fatal("the hook is gone and the lockdown still reads as enforced")
	}
	if why == "" {
		t.Error("not enforced, but no reason given")
	}
}
