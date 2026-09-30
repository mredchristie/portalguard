package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

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
//
// With a feed it is also the progress feed (-json): every event goes out as
// one JSON object per line, for a GUI to read, and out is io.Discard. The
// narration and the feed are the same calls, so they cannot drift apart.
type guide struct {
	out  io.Writer
	step int

	mu   sync.Mutex
	feed *json.Encoder
}

// emit sends one event down the feed, if there is one. Every event has a
// type and a time; the rest depends on the type. See docs/feed.md.
func (g *guide) emit(typ string, fields map[string]any) {
	if g == nil || g.feed == nil {
		return
	}
	ev := map[string]any{"type": typ, "at": time.Now().UTC().Format(time.RFC3339Nano)}
	for k, v := range fields {
		ev[k] = v
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	_ = g.feed.Encode(ev)
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
	g.emit("transition", map[string]any{"from": t.From, "event": t.Event, "to": t.To, "note": t.Note})
	switch t.Event {
	case state.EventDetect:
		g.stepf("Checking this network")
	case state.EventPortalFound:
		g.sayf("Found a login page: %s", t.Note)
	case state.EventArm:
		g.stepf("Armed")
		g.sayf("Everything on this Mac is blocked before it joins a network, so nothing leaks when it does.")
	case state.EventNoPortal:
		if t.From == state.Armed {
			g.sayf("No login page here (%s).", strings.ToLower(strings.ReplaceAll(t.Note, "_", " ")))
			return
		}
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
	sum := map[string]any{}
	if rep, ok := sess.Report(); ok && !rep.Empty() {
		sum["gap_seconds"] = rep.GapDuration().Seconds()
		sum["blocked_out_packets"] = rep.BlockedOutPackets
	}
	if st, ok := sess.DNSFilterStats(); ok {
		parts = append(parts, fmt.Sprintf("%d lookups were refused on this Mac", st.Refused))
		sum["lookups_refused"] = st.Refused
		sum["lookups_forwarded"] = st.Forwarded
	}
	if auto := sess.AutoAllowed(); len(auto) > 0 {
		sum["opened_automatically"] = auto
	}
	g.emit("summary", sum)
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

// newFeed is a guide that says nothing on screen and reports every event as
// JSON lines on w.
func newFeed(w io.Writer) *guide {
	return &guide{out: io.Discard, feed: json.NewEncoder(w)}
}

// stdout writes to whatever os.Stdout is at the moment of writing. The guide
// is made before -trace swaps os.Stdout for the pipe that records it, and a
// writer holding the original would write straight past the record: the
// first -json preflight found the feed missing from its trace, and guided
// steps were missing from every trace the same way.
type stdout struct{}

func (stdout) Write(b []byte) (int, error) { return os.Stdout.Write(b) }
