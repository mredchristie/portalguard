package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTraceKeepsOutputAndDNS: what the run prints still reaches the
// terminal, and lands in the file with the DNS verdicts between.
func TestTraceKeepsOutputAndDNS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.log")
	origOut, origErr := os.Stdout, os.Stderr
	tr, err := startTrace(path, []string{"run", "-verbose"})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Open this page and log in yourself:")
	tr.dns("cdn.guestwifi.test", "A", "auto")
	fmt.Fprintln(os.Stderr, "portalguard: gap opened automatically for cdn.guestwifi.test")
	tr.close()

	if os.Stdout != origOut || os.Stderr != origErr {
		t.Fatal("stdout and stderr were not put back")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{
		"args: run -verbose",
		"out   Open this page and log in yourself:",
		"dns   auto      A     cdn.guestwifi.test",
		"err   portalguard: gap opened automatically",
		"trace end",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("trace is missing %q:\n%s", want, got)
		}
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("trace mode %v, want 0600: it holds real hostnames", st.Mode().Perm())
	}
}
