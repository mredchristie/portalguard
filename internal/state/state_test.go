package state

import (
	"errors"
	"testing"
)

func TestHappyPath(t *testing.T) {
	m := NewMachine()
	steps := []struct {
		event Event
		want  State
	}{
		{EventDetect, Detecting},
		{EventPortalFound, PortalFound},
		{EventLockdown, LockedDown},
		{EventOpenGap, GapOpen},
		{EventExtendGap, GapOpen},
		{EventAuthenticated, Authenticated},
		{EventSeal, Sealed},
		{EventHandOff, HandedOff},
	}
	for _, step := range steps {
		got, err := m.Apply(step.event, "")
		if err != nil {
			t.Fatalf("apply %s: %v", step.event, err)
		}
		if got != step.want {
			t.Fatalf("after %s: state = %s, want %s", step.event, got, step.want)
		}
	}
	if n := len(m.History()); n != len(steps) {
		t.Errorf("history has %d entries, want %d", n, len(steps))
	}
}

func TestGapCannotOpenBeforeLockdown(t *testing.T) {
	m := NewMachine()
	_, _ = m.Apply(EventDetect, "")
	_, _ = m.Apply(EventPortalFound, "")

	// This is the transition that would leak traffic if it were allowed.
	_, err := m.Apply(EventOpenGap, "")
	var ite *InvalidTransitionError
	if !errors.As(err, &ite) {
		t.Fatalf("err = %v, want InvalidTransitionError", err)
	}
	if m.State() != PortalFound {
		t.Errorf("a rejected event must not move the machine, got %s", m.State())
	}
}

func TestNoPortalReturnsToIdle(t *testing.T) {
	m := NewMachine()
	_, _ = m.Apply(EventDetect, "")
	got, err := m.Apply(EventNoPortal, "OPEN_INTERNET")
	if err != nil {
		t.Fatal(err)
	}
	if got != Idle {
		t.Fatalf("state = %s, want %s", got, Idle)
	}
}

func TestReleaseIsLegalFromEveryState(t *testing.T) {
	for from := range transitions {
		m := NewMachine()
		m.state = from
		got, err := m.Apply(EventRelease, "")
		if err != nil {
			t.Errorf("release from %s: %v", from, err)
			continue
		}
		if got != Idle {
			t.Errorf("release from %s left state %s, want %s", from, got, Idle)
		}
	}
}

func TestEngagedStates(t *testing.T) {
	engaged := map[State]bool{
		LockedDown: true, GapOpen: true, Authenticated: true, Sealed: true,
		Idle: false, Detecting: false, PortalFound: false, HandedOff: false,
	}
	for s, want := range engaged {
		if s.Engaged() != want {
			t.Errorf("%s.Engaged() = %t, want %t", s, s.Engaged(), want)
		}
	}
}

func TestObserversSeeTransitions(t *testing.T) {
	m := NewMachine()
	var seen []Transition
	m.Observe(func(t Transition) { seen = append(seen, t) })

	_, _ = m.Apply(EventDetect, "starting")
	_, _ = m.Apply(EventNoPortal, "")
	// A rejected event must not be reported.
	_, _ = m.Apply(EventSeal, "")

	if len(seen) != 2 {
		t.Fatalf("observer saw %d transitions, want 2", len(seen))
	}
	if seen[0].Note != "starting" || seen[0].To != Detecting {
		t.Errorf("unexpected first transition: %s", seen[0])
	}
}

func TestCan(t *testing.T) {
	m := NewMachine()
	if !m.Can(EventDetect) {
		t.Error("detect should be legal from Idle")
	}
	if m.Can(EventSeal) {
		t.Error("seal should not be legal from Idle")
	}
}

func TestHandedOffCanRedetect(t *testing.T) {
	// Roaming onto a new network from a handed-off session must not need a
	// restart.
	m := NewMachine()
	m.state = HandedOff
	got, err := m.Apply(EventDetect, "")
	if err != nil || got != Detecting {
		t.Fatalf("state = %s, err = %v; want %s", got, err, Detecting)
	}
}
