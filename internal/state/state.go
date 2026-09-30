// Package state holds Portalguard's state machine: the ordered sequence a
// machine passes through between "I have just joined an unknown network" and
// "my VPN is up and the firewall is out of the way".
//
// The machine is pure. It validates transitions and records history; it does
// not touch the network or the packet filter. The wiring that does live in
// session.go, so the legal sequence can be tested without root.
package state

import (
	"fmt"
	"sync"
	"time"
)

// State is a position in the captive-portal dance.
type State string

const (
	// Idle is the resting state: no rules of ours are installed and the
	// machine's networking is whatever the OS says it is.
	Idle State = "IDLE"
	// Detecting means probes are in flight.
	Detecting State = "DETECTING"
	// PortalFound means we know a portal is present and where it lives, but
	// we have not touched the firewall yet.
	PortalFound State = "PORTAL_FOUND"
	// LockedDown means all traffic is blocked. Nothing leaks from here on.
	LockedDown State = "LOCKED_DOWN"
	// GapOpen means the portal host, and DNS for it, are the only things
	// allowed out. This is where the human logs in themselves.
	GapOpen State = "GAP_OPEN"
	// Authenticated means a re-probe succeeded: the portal has let us on.
	Authenticated State = "AUTHENTICATED"
	// Sealed means the gap is closed again. Traffic is blocked, and we are
	// ready to hand over.
	Sealed State = "SEALED"
	// HandedOff means the user's VPN is up and owns the connection. Our rules
	// have been released.
	HandedOff State = "HANDED_OFF"
	// Armed means everything is blocked before any network is known: the
	// lockdown came first, and detection happens through it. See armed.go.
	Armed State = "ARMED"
)

// Event is something that happened, which may move the machine.
type Event string

const (
	// EventDetect starts a detection run.
	EventDetect Event = "DETECT"
	// EventPortalFound reports that detection found a captive portal.
	EventPortalFound Event = "PORTAL_FOUND"
	// EventNoPortal reports open internet or no network: nothing to do.
	EventNoPortal Event = "NO_PORTAL"
	// EventLockdown reports that the firewall is now blocking everything.
	EventLockdown Event = "LOCKDOWN"
	// EventOpenGap reports that the portal hole has been punched.
	EventOpenGap Event = "OPEN_GAP"
	// EventExtendGap reports another host being added to the open gap, for
	// portals that span more than one hostname.
	EventExtendGap Event = "EXTEND_GAP"
	// EventAuthenticated reports that a re-probe reached the real internet.
	EventAuthenticated Event = "AUTHENTICATED"
	// EventSeal reports that the gap has been closed again.
	EventSeal Event = "SEAL"
	// EventHandOff reports that the VPN is up and our rules are released.
	EventHandOff Event = "HAND_OFF"
	// EventArm locks everything down before detection, rather than after.
	EventArm Event = "ARM"
	// EventRelease aborts from anywhere: rules torn down, back to Idle. This
	// is the escape hatch, and it is legal in every state.
	EventRelease Event = "RELEASE"
	// EventAdopt records a machine being placed at a state another process
	// reached, rather than moving there itself.
	//
	// It is deliberately absent from the transition table below. It is not a
	// move the machine makes; it is the machine being told where it already
	// is, and admitting it as a normal event would be a hole straight through
	// the table's whole purpose. Only NewMachineAt applies it, and only to a
	// state read back from the kernel. See session.go's Resume.
	EventAdopt Event = "ADOPT"
)

// ==== the legal moves =====================================================
// One table, and anything not in it is rejected. This is the safety net.

// transitions is the whole legal graph. Anything absent from this table is
// rejected, which is what stops, say, a gap being opened before a lockdown.
var transitions = map[State]map[Event]State{
	Idle: {
		EventDetect:  Detecting,
		EventArm:     Armed,
		EventRelease: Idle,
	},
	// Armed detection ends locked down either way. A portal goes on to the
	// gap; no portal goes on to the VPN handover, which a lockdown supports.
	// A trusted network is released.
	Armed: {
		EventPortalFound: LockedDown,
		EventNoPortal:    LockedDown,
		EventRelease:     Idle,
	},
	Detecting: {
		EventPortalFound: PortalFound,
		EventNoPortal:    Idle,
		EventRelease:     Idle,
	},
	PortalFound: {
		EventLockdown: LockedDown,
		EventRelease:  Idle,
	},
	LockedDown: {
		EventOpenGap: GapOpen,
		// A lockdown with no portal behind it - held while a VPN reconnects
		// on an ordinary network - hands straight over.
		EventHandOff: HandedOff,
		// A portal can vanish between detection and lockdown (someone else on
		// the account logged in); allow the shortcut to Authenticated.
		EventAuthenticated: Authenticated,
		EventRelease:       Idle,
	},
	GapOpen: {
		EventExtendGap:     GapOpen,
		EventAuthenticated: Authenticated,
		EventRelease:       Idle,
	},
	Authenticated: {
		EventSeal:    Sealed,
		EventRelease: Idle,
	},
	Sealed: {
		EventHandOff: HandedOff,
		EventRelease: Idle,
	},
	HandedOff: {
		// Networks change under you; a fresh detection run is legal here.
		EventDetect:  Detecting,
		EventRelease: Idle,
	},
}

// Engaged reports whether the firewall is holding traffic down in this state.
// It is what the exit handler consults to decide whether a release is needed.
func (s State) Engaged() bool {
	switch s {
	case Armed, LockedDown, GapOpen, Authenticated, Sealed:
		return true
	default:
		return false
	}
}

// ==== history =============================================================
// Every move is recorded, so logs can show how we got here.

// Transition is one recorded move.
type Transition struct {
	From  State     `json:"from"`
	Event Event     `json:"event"`
	To    State     `json:"to"`
	At    time.Time `json:"at"`
	// Note carries optional context, e.g. the portal host.
	Note string `json:"note,omitempty"`
}

func (t Transition) String() string {
	s := fmt.Sprintf("%s --%s--> %s", t.From, t.Event, t.To)
	if t.Note != "" {
		s += " (" + t.Note + ")"
	}
	return s
}

// InvalidTransitionError is returned when an event has no edge from the
// current state.
type InvalidTransitionError struct {
	From  State
	Event Event
}

func (e *InvalidTransitionError) Error() string {
	return fmt.Sprintf("state: cannot apply %s in state %s", e.Event, e.From)
}

// ==== the machine =========================================================
// Holds the current state. Pure - never touches network or firewall.

// Machine tracks the current state. It is safe for concurrent use.
type Machine struct {
	mu        sync.RWMutex
	state     State
	history   []Transition
	observers []func(Transition)
	now       func() time.Time
}

// NewMachine returns a machine in Idle.
func NewMachine() *Machine {
	return &Machine{state: Idle, now: time.Now}
}

// NewMachineAt returns a machine already standing at s, for a process picking
// up work an earlier one started. The note says where that belief came from
// and is recorded in history, so `status` can show a resumed session as
// resumed rather than passing it off as one this process drove.
//
// This is the one way into the machine that does not go through the transition
// table, which is why it validates s against the table's own key set: a state
// the table has never heard of has no legal moves out of it, and a machine
// parked there would refuse every event including the ones that release it.
func NewMachineAt(s State, note string) (*Machine, error) {
	if _, ok := transitions[s]; !ok {
		return nil, fmt.Errorf("state: cannot adopt unknown state %q", s)
	}
	m := &Machine{state: s, now: time.Now}
	m.history = append(m.history, Transition{
		From: Idle, Event: EventAdopt, To: s, At: m.now(), Note: note,
	})
	return m, nil
}

// State returns the current state.
func (m *Machine) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// Can reports whether an event is legal right now.
func (m *Machine) Can(e Event) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := transitions[m.state][e]
	return ok
}

// Apply moves the machine, returning the new state. The note is recorded in
// history and passed to observers.
func (m *Machine) Apply(e Event, note string) (State, error) {
	m.mu.Lock()
	from := m.state
	to, ok := transitions[from][e]
	if !ok {
		m.mu.Unlock()
		return from, &InvalidTransitionError{From: from, Event: e}
	}
	t := Transition{From: from, Event: e, To: to, At: m.now(), Note: note}
	m.state = to
	m.history = append(m.history, t)
	observers := make([]func(Transition), len(m.observers))
	copy(observers, m.observers)
	m.mu.Unlock()

	for _, fn := range observers {
		fn(t)
	}
	return to, nil
}

// Observe registers a callback fired after every successful transition.
// Callbacks run outside the machine's lock, in registration order.
func (m *Machine) Observe(fn func(Transition)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.observers = append(m.observers, fn)
}

// History returns a copy of every transition so far.
func (m *Machine) History() []Transition {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Transition(nil), m.history...)
}

// Engaged reports whether the firewall is currently holding traffic down.
func (m *Machine) Engaged() bool { return m.State().Engaged() }
