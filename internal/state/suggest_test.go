package state

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"portalguard/internal/firewall"
	"portalguard/internal/portal"
)

// watchingBackend is a fake that can also answer "what has been looked up",
// which is the optional capability SuggestAllow needs and most backends will
// not have.
type watchingBackend struct {
	fakeBackend
	mu   sync.Mutex
	seen []string
}

func (w *watchingBackend) NamesSeen() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.seen...)
}

func (w *watchingBackend) sees(names ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = names
}

// gapSession builds a session sitting in GAP_OPEN with the BT Wi-Fi portal
// from docs/gap-scope.md open, which is the only state suggestions are made
// from.
func gapSession(t *testing.T, fw firewall.Backend) *Session {
	t.Helper()
	m, err := NewMachineAt(GapOpen, "test")
	if err != nil {
		t.Fatal(err)
	}
	s := newSession(m, fw, portal.NewProber(), nil)
	s.last = portal.Result{Class: portal.Portal, PortalHost: "www.btwifi.com"}
	s.allowed = []firewall.Host{{Name: "www.btwifi.com"}}
	return s
}

func TestSuggestAllowNamesThePortalHostsThatAreNotOpen(t *testing.T) {
	fw := &watchingBackend{}
	// The real shape of the list: the portal's own hosts mixed into the
	// background noise of a laptop that has just found a network, because
	// the DNS hole is machine-wide.
	fw.sees(
		"cdn.btwifi.com",
		"gateway.icloud.com",
		"init.push.apple.com",
		"reg.btwifi.com.", // trailing root dot, as a DNS decode carries it
		"WWW.BTWIFI.COM",  // already open, and in the case tcpdump saw it
	)

	got := gapSession(t, fw).SuggestAllow()
	want := []string{"cdn.btwifi.com", "reg.btwifi.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SuggestAllow() = %v, want %v", got, want)
	}
}

func TestSuggestAllowSkipsHostsAlreadyWidenedFromAnotherTerminal(t *testing.T) {
	fw := &watchingBackend{}
	fw.sees("cdn.btwifi.com", "reg.btwifi.com")

	s := gapSession(t, fw)
	// What `portalguard allow cdn.btwifi.com` in a second terminal leaves
	// behind. This process is never told any other way.
	path := filepath.Join(t.TempDir(), "session")
	if err := SaveSnapshot(path, Snapshot{
		State:   GapOpen,
		Allowed: []firewall.Host{{Name: "www.btwifi.com"}, {Name: "cdn.btwifi.com"}},
	}); err != nil {
		t.Fatal(err)
	}
	s.store = path

	got := s.SuggestAllow()
	want := []string{"reg.btwifi.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SuggestAllow() = %v, want %v", got, want)
	}
}

func TestSuggestAllowSaysNothingWithoutAPortalOrAWatcher(t *testing.T) {
	t.Run("backend cannot watch names", func(t *testing.T) {
		s := gapSession(t, &fakeBackend{})
		if got := s.SuggestAllow(); got != nil {
			t.Errorf("SuggestAllow() = %v, want nil", got)
		}
	})
	t.Run("no portal host to compare against", func(t *testing.T) {
		fw := &watchingBackend{}
		fw.sees("cdn.btwifi.com", "init.push.apple.com")
		s := gapSession(t, fw)
		s.last = portal.Result{}
		if got := s.SuggestAllow(); got != nil {
			t.Errorf("SuggestAllow() = %v, want nil: without a portal host every lookup looks equally relevant", got)
		}
	})
}

// TestSuggestFiresOnlyOnSomethingNew is the property that keeps a three-second
// poll from printing the same advice two hundred times.
func TestSuggestFiresOnlyOnSomethingNew(t *testing.T) {
	fw := &watchingBackend{}
	s := gapSession(t, fw)

	var calls [][]string
	s.OnSuggestion(func(names []string) { calls = append(calls, names) })

	s.suggest() // nothing looked up yet
	fw.sees("cdn.btwifi.com")
	s.suggest() // new
	s.suggest() // same again
	fw.sees("cdn.btwifi.com", "reg.btwifi.com")
	s.suggest() // one new name

	want := [][]string{
		{"cdn.btwifi.com"},
		// The whole list, not only the new name: what this prints is a
		// command, and a command that opened only reg would be the wrong one.
		{"cdn.btwifi.com", "reg.btwifi.com"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("callback got %v, want %v", calls, want)
	}
}

func TestSuggestWithoutACallbackDoesNotPanic(t *testing.T) {
	fw := &watchingBackend{}
	fw.sees("cdn.btwifi.com")
	gapSession(t, fw).suggest()
}

// TestWaitForAuthSuggestsWhileItWaits ties the two together: the advice has to
// arrive during the wait, because that is the only stretch where the user can
// still act on it.
func TestWaitForAuthSuggestsWhileItWaits(t *testing.T) {
	fw := &watchingBackend{}
	fw.sees("cdn.btwifi.com")

	ps := newPortalServer("http://login.btwifi.com/login")
	defer ps.Close()

	s := gapSession(t, fw)
	s.prober = testProber(ps.URL + "/generate_204")
	// The re-probe resolves whatever host the portal redirects to. Answer it
	// here rather than let a unit test make a real DNS query: what is being
	// tested is the suggestion, and the addresses play no part in it.
	s.prober.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no DNS in this test")
		},
	}

	got := make(chan []string, 1)
	s.OnSuggestion(func(names []string) {
		select {
		case got <- names:
		default:
		}
		// The user acts on it: the portal login goes through, and the wait
		// ends the way it normally would.
		ps.login()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.WaitForAuth(ctx, time.Millisecond); err != nil {
		t.Fatalf("WaitForAuth: %v", err)
	}
	select {
	case names := <-got:
		if !reflect.DeepEqual(names, []string{"cdn.btwifi.com"}) {
			t.Errorf("suggested %v, want [cdn.btwifi.com]", names)
		}
	default:
		t.Error("the wait ended without ever suggesting the blocked host")
	}
}

func TestSiteOf(t *testing.T) {
	cases := map[string]string{
		"cdn.btwifi.com":         "btwifi.com",
		"WWW.BTWIFI.COM.":        "btwifi.com",
		"btwifi.com":             "btwifi.com",
		"portal.hotel.co.uk":     "hotel.co.uk",
		"hotel.co.uk":            "hotel.co.uk",
		"login.wifi.example.net": "example.net",
		"localhost":              "",
		"":                       "",
		"192.168.23.21":          "",
		"fe80::1":                "",
	}
	for in, want := range cases {
		if got := siteOf(in); got != want {
			t.Errorf("siteOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"CDN.BTWIFI.COM.":     "cdn.btwifi.com",
		" cdn.btwifi.com ":    "cdn.btwifi.com",
		"info.btwifi.com:442": "info.btwifi.com",
		"[fe80::1]:443":       "fe80::1",
		"fe80::1":             "fe80::1",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
