package state

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"portalguard/internal/firewall"
)

func tempSession(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "portalguard.session")
}

func gapBackend() *fakeBackend {
	return &fakeBackend{
		phase: firewall.PhaseGap,
		allowed: []firewall.Host{
			{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.23.21")}, Ports: []int{80, 443, 8443}},
			{Name: "resolvers", Addrs: []net.IP{net.ParseIP("192.168.23.1")}, Ports: []int{53}, AllowDNSTo: true},
		},
	}
}

// TestResumeLetsASecondProcessWidenAGap is the regression test for the failure
// found at a BT Wi-Fi hotspot: `allow` existed precisely for a portal that
// spans several hostnames, and could not be used, because the state machine
// lived in the process that opened the gap and a second invocation started at
// IDLE.
func TestResumeLetsASecondProcessWidenAGap(t *testing.T) {
	path := tempSession(t)
	fw := gapBackend()
	ctx := context.Background()

	// What the first process left behind.
	if err := SaveSnapshot(path, Snapshot{
		State:   GapOpen,
		Portal:  PortalRef{Host: "www.example.net", Port: 8443, Addrs: []string{"192.168.23.21"}},
		Allowed: fw.allowed,
	}); err != nil {
		t.Fatal(err)
	}

	sess, err := Resume(ctx, fw, nil, nil, path)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := sess.Machine().State(); got != GapOpen {
		t.Fatalf("resumed at %s, want %s", got, GapOpen)
	}
	if err := sess.AllowExtra(ctx, "104.16.0.1"); err != nil {
		t.Fatalf("a resumed session must be able to widen the gap: %v", err)
	}
	if got := sess.Machine().State(); got != GapOpen {
		t.Errorf("state after widening = %s, want %s", got, GapOpen)
	}

	// The portal identity survives, so the resumed process can still say where
	// the login page is without probing the network again.
	if got := sess.Result().PortalHost; got != "www.example.net" {
		t.Errorf("portal host = %q, want it carried over from the snapshot", got)
	}
}

// TestResumeIgnoresASnapshotTheKernelContradicts is the safety property the
// whole design rests on. A session file is written by a process that may since
// have died or been followed by a release it knew nothing about, so the loaded
// ruleset decides and the file only enriches.
func TestResumeIgnoresASnapshotTheKernelContradicts(t *testing.T) {
	path := tempSession(t)
	if err := SaveSnapshot(path, Snapshot{
		State:   GapOpen,
		Allowed: []firewall.Host{{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.23.21")}}},
	}); err != nil {
		t.Fatal(err)
	}

	// Nothing of ours is loaded: somebody ran `release` after that file was
	// written.
	fw := &fakeBackend{phase: firewall.PhaseOff}
	sess, err := Resume(context.Background(), fw, nil, nil, path)
	if err != nil {
		t.Fatal(err)
	}
	if got := sess.Machine().State(); got != Idle {
		t.Errorf("resumed at %s over an unloaded firewall, want %s", got, Idle)
	}
	if got := sess.Allowed(); len(got) != 0 {
		t.Errorf("nothing is open, but the session reports %v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a snapshot the kernel contradicts should be cleared, not left to mislead the next run")
	}
}

// TestResumeWithoutASnapshotStillAdoptsFromTheKernel: losing the file must
// degrade the resumed session, not break it. The names go; the gap does not.
func TestResumeWithoutASnapshotStillAdoptsFromTheKernel(t *testing.T) {
	fw := gapBackend()
	sess, err := Resume(context.Background(), fw, nil, nil, tempSession(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := sess.Machine().State(); got != GapOpen {
		t.Errorf("resumed at %s, want %s from the loaded rules alone", got, GapOpen)
	}
	if got := sess.Allowed(); len(got) != 2 {
		t.Errorf("allowed = %v, want both open hosts recovered from the kernel", got)
	}
}

// TestResumeSeparatesSealedFromLockedDown covers the one thing the packet
// filter genuinely cannot tell us: a sealed gap and a bare lockdown are the
// same ruleset.
func TestResumeSeparatesSealedFromLockedDown(t *testing.T) {
	ctx := context.Background()

	t.Run("no snapshot means the safe reading", func(t *testing.T) {
		fw := &fakeBackend{phase: firewall.PhaseLocked}
		sess, err := Resume(ctx, fw, nil, nil, tempSession(t))
		if err != nil {
			t.Fatal(err)
		}
		if got := sess.Machine().State(); got != LockedDown {
			t.Errorf("state = %s, want %s", got, LockedDown)
		}
	})

	t.Run("the snapshot may pick between states sharing a phase", func(t *testing.T) {
		path := tempSession(t)
		if err := SaveSnapshot(path, Snapshot{State: Sealed}); err != nil {
			t.Fatal(err)
		}
		fw := &fakeBackend{phase: firewall.PhaseLocked}
		sess, err := Resume(ctx, fw, nil, nil, path)
		if err != nil {
			t.Fatal(err)
		}
		if got := sess.Machine().State(); got != Sealed {
			t.Errorf("state = %s, want %s", got, Sealed)
		}
		// And a sealed gap cannot be widened: there is nothing open to widen.
		if err := sess.AllowExtra(ctx, "104.16.0.1"); err == nil {
			t.Error("widening a sealed gap must be refused")
		}
	})

	t.Run("a snapshot cannot claim a phase the kernel denies", func(t *testing.T) {
		path := tempSession(t)
		// The file says the gap is open; the rules say everything is blocked.
		if err := SaveSnapshot(path, Snapshot{State: GapOpen}); err != nil {
			t.Fatal(err)
		}
		fw := &fakeBackend{phase: firewall.PhaseLocked}
		sess, err := Resume(ctx, fw, nil, nil, path)
		if err != nil {
			t.Fatal(err)
		}
		if got := sess.Machine().State(); got != LockedDown {
			t.Errorf("state = %s, want %s: the loaded ruleset decides", got, LockedDown)
		}
	})
}

// TestReconcileAllowedKeepsTheKernelInCharge: the snapshot supplies names, the
// kernel supplies the truth about what is open.
func TestReconcileAllowedKeepsTheKernelInCharge(t *testing.T) {
	remembered := []firewall.Host{
		{Name: "www.example.net", Addrs: []net.IP{net.ParseIP("192.168.23.21")}, Reason: "login page"},
		{Name: "gone.example.net", Addrs: []net.IP{net.ParseIP("203.0.113.9")}},
	}
	live := []firewall.Host{
		{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.23.21"), net.ParseIP("104.16.0.1")}},
	}

	got := reconcileAllowed(remembered, live)
	if len(got) != 2 {
		t.Fatalf("got %d hosts, want the remembered one plus the unaccounted address: %v", len(got), got)
	}
	if got[0].Name != "www.example.net" || got[0].Reason != "login page" {
		t.Errorf("the snapshot's name and reason should survive: %+v", got[0])
	}
	if len(got[0].Addrs) != 1 {
		t.Errorf("only the address that is still open should be kept: %v", got[0].Addrs)
	}
	if len(got[1].Addrs) != 1 || !got[1].Addrs[0].Equal(net.ParseIP("104.16.0.1")) {
		t.Errorf("an open address the snapshot does not account for must not be dropped: %+v", got[1])
	}
	for _, h := range got {
		for _, ip := range h.Addrs {
			if ip.Equal(net.ParseIP("203.0.113.9")) {
				t.Error("an address that is no longer open must not be reported as open")
			}
		}
	}
}

// TestSnapshotSurvivesARoundTrip, and anything unreadable is treated as absent
// rather than guessed at.
func TestSnapshotSurvivesARoundTrip(t *testing.T) {
	path := tempSession(t)
	want := Snapshot{
		State:   GapOpen,
		Portal:  PortalRef{URL: "http://www.example.net:8443/login", Host: "www.example.net", Port: 8443},
		Allowed: []firewall.Host{{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.23.21")}, Ports: []int{8443}}},
		Since:   time.Now().Truncate(time.Second),
	}
	if err := SaveSnapshot(path, want); err != nil {
		t.Fatal(err)
	}

	got, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != want.State || got.Portal.Port != 8443 {
		t.Errorf("round trip lost detail: %+v", got)
	}
	if len(got.Allowed) != 1 || !got.Allowed[0].Addrs[0].Equal(net.ParseIP("192.168.23.21")) {
		t.Errorf("round trip lost the pinned address: %+v", got.Allowed)
	}
	if got.PID != os.Getpid() {
		t.Errorf("PID = %d, want the writing process", got.PID)
	}

	t.Run("a file from another version is discarded", func(t *testing.T) {
		if err := os.WriteFile(path, []byte(`{"version":99,"state":"GAP_OPEN"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSnapshot(path); err != ErrNoSnapshot {
			t.Errorf("err = %v, want ErrNoSnapshot", err)
		}
	})

	t.Run("so is a state this build does not have", func(t *testing.T) {
		if err := os.WriteFile(path, []byte(`{"version":1,"state":"WAT"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSnapshot(path); err != ErrNoSnapshot {
			t.Errorf("err = %v, want ErrNoSnapshot", err)
		}
	})

	t.Run("and so is a torn file", func(t *testing.T) {
		if err := os.WriteFile(path, []byte(`{"version":1,"sta`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSnapshot(path); err != ErrNoSnapshot {
			t.Errorf("err = %v, want ErrNoSnapshot", err)
		}
	})
}

// TestSessionRecordsEveryTransition: the file is only useful if it is never
// stale, so it is written from an observer rather than at chosen call sites.
func TestSessionRecordsEveryTransition(t *testing.T) {
	path := tempSession(t)
	fw := &fakeBackend{}
	// A loopback login page, so the gap can be pinned to a real address.
	ps := newPortalServer("http://127.0.0.1:8080/login")
	defer ps.Close()

	sess := newTestSession(fw, ps.URL+"/generate_204")
	sess.PersistTo(path)
	ctx := context.Background()

	if _, err := sess.Detect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sess.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}

	snap, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("nothing was recorded: %v", err)
	}
	if snap.State != LockedDown {
		t.Errorf("recorded state = %s, want %s", snap.State, LockedDown)
	}
	if len(snap.History) < 3 {
		t.Errorf("history = %v, want the moves that got us here", snap.History)
	}
}

// TestUnpersistedSessionWritesNothing: the default must leave no file, so
// tests and read-only callers have nothing to clean up.
func TestUnpersistedSessionWritesNothing(t *testing.T) {
	dir := t.TempDir()
	fw := &fakeBackend{}
	sess := NewSession(fw, nil, nil)
	if _, err := sess.Machine().Apply(EventDetect, ""); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a session with no store wrote %v", entries)
	}
}
