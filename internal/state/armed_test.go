package state

import (
	"context"
	"net"
	"testing"

	"portalguard/internal/portal"
)

// TestArmLocksBeforeAnyNetworkIsKnown: arming is a lockdown straight from
// Idle, and an armed machine counts as engaged, so a crash releases it.
func TestArmLocksBeforeAnyNetworkIsKnown(t *testing.T) {
	fw := &fakeBackend{}
	s := newSession(NewMachine(), fw, nil, nil)
	if err := s.Arm(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.machine.State() != Armed || !s.machine.Engaged() {
		t.Fatalf("state %s, engaged %v", s.machine.State(), s.machine.Engaged())
	}
	if calls := fw.callsMade(); len(calls) != 1 || calls[0] != "lockdown" {
		t.Fatalf("calls %v, want a lockdown", calls)
	}
	if err := s.Arm(context.Background()); err == nil {
		t.Fatal("armed twice")
	}
}

// TestArmedTransitions: detection from Armed ends LockedDown either way, and
// nothing skips past it into the gap.
func TestArmedTransitions(t *testing.T) {
	for _, e := range []Event{EventPortalFound, EventNoPortal} {
		m, _ := NewMachineAt(Armed, "test")
		if st, err := m.Apply(e, ""); err != nil || st != LockedDown {
			t.Errorf("%s from Armed = %s, %v; want LockedDown", e, st, err)
		}
	}
	for _, e := range []Event{EventOpenGap, EventExtendGap, EventSeal, EventHandOff, EventDetect} {
		m, _ := NewMachineAt(Armed, "test")
		if m.Can(e) {
			t.Errorf("%s is legal from Armed", e)
		}
	}
}

func TestDetectArmedNeedsArming(t *testing.T) {
	s := newSession(NewMachine(), &fakeBackend{}, nil, nil)
	if _, err := s.DetectArmed(context.Background()); err == nil {
		t.Fatal("detected through a lockdown that was never armed")
	}
}

// TestProbeOpenerLetsOnlyDetectionThrough: the probes' own names are
// forwarded and opened, the hijack check's made-up name and the login host
// are forwarded only, and nothing else at all.
func TestProbeOpenerLetsOnlyDetectionThrough(t *testing.T) {
	fw := newCheckingBackend(&fakeBackend{})
	s := newSession(NewMachine(), fw, nil, nil)
	o := &probeOpener{s: s, probes: map[string]bool{"captive.apple.com": true}, resolve: map[string]bool{}}

	for name, want := range map[string]bool{
		"captive.apple.com":                  true,
		"CAPTIVE.apple.com.":                 true,
		"pg-0123abcd.portalguard.invalid":    true,
		"www.btwifi.com":                     false, // until the probes name it
		"imap.gmail.com":                     false,
		"portalguard.invalid.evil.com":       false,
		"captive.apple.com.attacker.example": false,
	} {
		if got := o.Wants(name); got != want {
			t.Errorf("Wants(%q) = %v, want %v", name, got, want)
		}
	}
	o.resolveOnly("www.btwifi.com")
	if !o.Wants("www.btwifi.com") {
		t.Error("the login host was not let through once named")
	}

	if err := o.Open("captive.apple.com", []net.IP{net.IPv4(192, 168, 23, 21)}); err != nil {
		t.Fatal(err)
	}
	if err := o.Open("www.btwifi.com", []net.IP{net.IPv4(192, 168, 23, 22)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := fw.checks["192.168.23.21"]; !ok {
		t.Error("the probe's answer was not opened, so the probe cannot connect")
	}
	if _, ok := fw.checks["192.168.23.22"]; ok {
		t.Error("the login host was opened during detection; it must only be resolved")
	}
}

// Detection through the lockdown needs a prober hook; this pins its contract.
var _ = portal.Prober{OnPortal: func(string) {}}
