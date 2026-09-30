package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"portalguard/internal/state"
)

// ==== opening a suggestion from the same terminal ==========================
//
// The suggestion used to mean a second terminal and a sudo command. When run
// is attached to a terminal, typing y opens the same hosts from here, and
// typing a host name opens that host: the way to reach a payment page on
// another domain, which is never suggested, after -verbose has named it.
// Nothing is opened that was not typed.

// allowPrompt offers the latest suggestion for opening on a y.
type allowPrompt struct {
	ctx  context.Context
	sess *state.Session
	out  io.Writer

	mu      sync.Mutex
	pending []string
}

// newAllowPrompt starts reading answers from in, or returns nil when in is
// not a terminal: piped input is a script, and a script's lines are not
// answers to a question it never saw.
func newAllowPrompt(ctx context.Context, sess *state.Session, in *os.File, out io.Writer) *allowPrompt {
	if st, err := in.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return nil
	}
	p := &allowPrompt{ctx: ctx, sess: sess, out: out}
	go p.read(in)
	return p
}

// offer replaces what a y would open. Safe on a nil prompt.
func (p *allowPrompt) offer(names []string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.pending = append([]string(nil), names...)
	p.mu.Unlock()
	fmt.Fprintln(p.out, "  Or type y and press Enter to open them from here.")
}

func (p *allowPrompt) read(in io.Reader) {
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		p.answer(sc.Text())
	}
}

// answer acts on one line typed at the prompt.
func (p *allowPrompt) answer(line string) {
	a := strings.ToLower(strings.TrimSpace(line))
	var names []string
	switch {
	case a == "y" || a == "yes":
		p.mu.Lock()
		names = p.pending
		p.pending = nil
		p.mu.Unlock()
		if len(names) == 0 {
			fmt.Fprintln(p.out, "  Nothing to open.")
			return
		}
	case looksLikeHost(a):
		names = []string{a}
	default:
		return
	}
	for _, n := range names {
		t, err := parseAllowTarget(n)
		if err == nil {
			err = p.sess.AllowExtra(p.ctx, t.host, t.ports...)
		}
		if err != nil {
			fmt.Fprintf(p.out, "  could not open %s: %v\n", n, extendHint(err))
		}
	}
}

// looksLikeHost accepts what `allow` would: a dotted name or address, with an
// optional port, and nothing a stray keystroke or sentence would produce.
func looksLikeHost(s string) bool {
	if !strings.Contains(s, ".") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == ':', r == '[', r == ']':
		default:
			return false
		}
	}
	return true
}
