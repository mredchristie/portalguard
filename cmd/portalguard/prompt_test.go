package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"portalguard/internal/state"
)

// TestPromptOpensOnlyOnYes: anything but y is ignored, and a y opens exactly
// the last suggestion, once.
func TestPromptOpensOnlyOnYes(t *testing.T) {
	var out bytes.Buffer
	// A session with no gap: AllowExtra refuses before touching a firewall,
	// which is enough to see what the prompt tried to open.
	p := &allowPrompt{ctx: context.Background(), sess: state.NewSession(nil, nil, nil), out: &out}

	p.answer("y")
	if !strings.Contains(out.String(), "Nothing to open") {
		t.Fatalf("a y with nothing offered said %q", out.String())
	}

	p.offer([]string{"secure.worldpay.com"})
	out.Reset()
	for _, no := range []string{"", "n", "no", "why"} {
		p.answer(no)
	}
	if out.Len() != 0 {
		t.Fatalf("a non-yes answer did something: %q", out.String())
	}

	p.answer(" Y ")
	if !strings.Contains(out.String(), "could not open secure.worldpay.com") ||
		!strings.Contains(out.String(), "no open gap") {
		t.Fatalf("the y did not try the offered host: %q", out.String())
	}
	out.Reset()
	p.answer("y")
	if !strings.Contains(out.String(), "Nothing to open") {
		t.Fatalf("a second y reopened the same hosts: %q", out.String())
	}
}

// TestPromptNeedsATerminal: piped input gets no prompt, and a nil prompt is
// safe to offer to.
func TestPromptNeedsATerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	p := newAllowPrompt(context.Background(), nil, r, &bytes.Buffer{}, nil)
	if p != nil {
		t.Fatal("prompted on a pipe")
	}
	p.offer([]string{"x.test"})
}

// TestPromptOpensATypedHost: a host name typed at the prompt is opened, and
// sentences and stray keys are not mistaken for one.
func TestPromptOpensATypedHost(t *testing.T) {
	var out bytes.Buffer
	p := &allowPrompt{ctx: context.Background(), sess: state.NewSession(nil, nil, nil), out: &out}
	for _, junk := range []string{"ok", "what now?", "hello world.", ".com", "x"} {
		p.answer(junk)
	}
	if out.Len() != 0 {
		t.Fatalf("opened something from junk: %q", out.String())
	}
	p.answer("Pay.Example.com")
	if !strings.Contains(out.String(), "could not open pay.example.com") {
		t.Fatalf("the typed host was not tried: %q", out.String())
	}
}

// TestAppCancelAndAppGone: a GUI's "cancel" ends the run, and so does its
// stdin ending, because an app that has gone can no longer release anything.
func TestAppCancelAndAppGone(t *testing.T) {
	var why []string
	p := &allowPrompt{ctx: context.Background(), out: &bytes.Buffer{},
		cancel: func(w string) { why = append(why, w) }}
	p.answer("  Cancel ")
	if len(why) != 1 || !strings.Contains(why[0], "cancelled") {
		t.Fatalf("cancel line: %v", why)
	}
	p.read(strings.NewReader("")) // the app closed its end
	if len(why) != 2 || !strings.Contains(why[1], "app closed") {
		t.Fatalf("stdin ending: %v", why)
	}
}
