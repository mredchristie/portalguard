package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"portalguard/internal/state"
)

// TestGuideTellsARunAsSteps: a whole run's transitions, told in order, as
// numbered steps with no state-machine names in them.
func TestGuideTellsARunAsSteps(t *testing.T) {
	var b bytes.Buffer
	g := &guide{out: &b}
	for _, tr := range []state.Transition{
		{Event: state.EventDetect},
		{Event: state.EventPortalFound, Note: "www.btwifi.com"},
		{Event: state.EventLockdown},
		{Event: state.EventOpenGap, Note: "www.btwifi.com"},
		{Event: state.EventExtendGap, Note: "cdn.btwifi.com (same site, automatic)"},
		{Event: state.EventExtendGap, Note: "reg.btwifi.com"},
		{Event: state.EventAuthenticated},
		{Event: state.EventSeal},
	} {
		g.transition(tr)
	}
	out := b.String()
	for _, want := range []string{
		"1  Checking this network",
		"Found a login page: www.btwifi.com",
		"2  Locking down",
		"3  Log in on the page that opens in your browser",
		"Also opened cdn.btwifi.com (same site, automatic)",
		"Also opened reg.btwifi.com\n",
		"You're logged in.",
		"4  Sealing",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, jargon := range []string{"GAP_OPEN", "-->", "LOCKED_DOWN"} {
		if strings.Contains(out, jargon) {
			t.Errorf("state-machine jargon %q on screen:\n%s", jargon, out)
		}
	}
}

func TestGuideNoPortal(t *testing.T) {
	var b bytes.Buffer
	g := &guide{out: &b}
	g.transition(state.Transition{Event: state.EventNoPortal, Note: "OPEN_INTERNET"})
	if !strings.Contains(b.String(), "already online") {
		t.Errorf("got %q", b.String())
	}
}

// TestNilGuideIsSilent: -verbose has no guide, and every call must be safe.
func TestNilGuideIsSilent(t *testing.T) {
	var g *guide
	g.stepf("x")
	g.sayf("y")
	g.transition(state.Transition{Event: state.EventSeal})
	g.summary(nil)
}

// TestFeedIsJSONLinesOnly: in -json mode every line on stdout is one event a
// GUI can parse, and nothing meant for a person gets mixed in.
func TestFeedIsJSONLinesOnly(t *testing.T) {
	var b bytes.Buffer
	g := newFeed(&b)
	g.emit("start", map[string]any{"command": "arm"})
	for _, tr := range []state.Transition{
		{From: state.Idle, Event: state.EventArm, To: state.Armed},
		{From: state.Armed, Event: state.EventPortalFound, To: state.LockedDown, Note: "www.btwifi.com"},
		{From: state.LockedDown, Event: state.EventOpenGap, To: state.GapOpen},
	} {
		g.transition(tr)
	}
	g.sayf("this is for a person, and must not appear")
	g.stepf("nor this")
	g.emit("suggest", map[string]any{"names": []string{"pay.example.com"}})

	var types []string
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("not a JSON line: %q", line)
		}
		if ev["at"] == nil {
			t.Errorf("event without a time: %v", ev)
		}
		types = append(types, ev["type"].(string))
	}
	if got := strings.Join(types, ","); got != "start,transition,transition,transition,suggest" {
		t.Errorf("event types = %s", got)
	}
	if strings.Contains(b.String(), "must not appear") {
		t.Error("narration leaked into the feed")
	}
}
