package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"portalguard/internal/state"
)

// ==== run, told as steps ===================================================
//
// The state machine's own log (LOCKED_DOWN --OPEN_GAP--> GAP_OPEN) is exact,
// and means nothing to someone standing in a café. By default run tells the
// same events as numbered steps in plain words, and the technical lines go
// only to the -trace file. -verbose brings them back instead.
//
// It is driven by the machine's transitions, not by run's code path, so it
// says only what actually happened: the same events a GUI would listen to.

// guide narrates one run. A nil guide says nothing, which is -verbose.
type guide struct {
	out  io.Writer
	step int
}

func (g *guide) stepf(format string, args ...any) {
	if g == nil {
		return
	}
	g.step++
	fmt.Fprintf(g.out, "\n%d  %s\n", g.step, fmt.Sprintf(format, args...))
}

func (g *guide) sayf(format string, args ...any) {
	if g == nil {
		return
	}
	fmt.Fprintf(g.out, "   %s\n", fmt.Sprintf(format, args...))
}

// transition tells one move of the machine.
func (g *guide) transition(t state.Transition) {
	if g == nil {
		return
	}
	switch t.Event {
	case state.EventDetect:
		g.stepf("Checking this network")
	case state.EventPortalFound:
		g.sayf("Found a login page: %s", t.Note)
	case state.EventNoPortal:
		switch t.Note {
		case "OPEN_INTERNET":
			g.sayf("There is no login page here: you are already online. Nothing to do.")
		default:
			g.sayf("No network to log in to (%s). Join the Wi-Fi first, then run this again.", strings.ToLower(t.Note))
		}
	case state.EventLockdown:
		g.stepf("Locking down")
		g.sayf("Everything on this Mac is blocked, so nothing can leak while you log in.")
	case state.EventOpenGap:
		g.stepf("Log in on the page that opens in your browser")
		g.sayf("Only the login page can get through. Other apps stay blocked.")
	case state.EventExtendGap:
		host, why, _ := strings.Cut(t.Note, " (")
		if why = strings.TrimSuffix(why, ")"); why != "" {
			g.sayf("Also opened %s (%s)", host, why)
		} else {
			g.sayf("Also opened %s", host)
		}
	case state.EventAuthenticated:
		g.sayf("You're logged in.")
	case state.EventSeal:
		g.stepf("Sealing")
		g.sayf("The gap is closed. Only your VPN may connect now.")
	}
}

// summary is the plain-words version of the leak report: what the lockdown
// held back, and what the DNS filter kept on the Mac.
func (g *guide) summary(sess *state.Session) {
	if g == nil {
		return
	}
	var parts []string
	if rep, ok := sess.Report(); ok && !rep.Empty() {
		if d := rep.GapDuration(); d > 0 {
			parts = append(parts, fmt.Sprintf("the gap was open for %s", d.Round(1e9)))
		}
		if rep.BlockedOutPackets > 0 {
			parts = append(parts, fmt.Sprintf("%d packets from other apps were held back", rep.BlockedOutPackets))
		}
	}
	if st, ok := sess.DNSFilterStats(); ok {
		parts = append(parts, fmt.Sprintf("%d lookups were refused on this Mac", st.Refused))
	}
	if len(parts) > 0 {
		g.sayf("While you logged in: %s.", strings.Join(parts, ", "))
		g.sayf("For the full report, run with -verbose.")
	}
}

// isTerminal reports whether f is a terminal rather than a file or a pipe.
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
