//go:build darwin

package pf

import (
	"strings"
	"testing"
)

// TestPfctlNoiseIsNotRules: an empty anchor on a Mac without ALTQ still
// prints two lines, and they must not read as a loaded ruleset.
func TestPfctlNoiseIsNotRules(t *testing.T) {
	noise := "No ALTQ support in kernel\nALTQ related functions disabled\n"
	if got := strings.TrimSpace(stripPfctlNoise(noise)); got != "" {
		t.Fatalf("noise left %q", got)
	}
	rule := "block drop out quick all\n"
	if got := stripPfctlNoise(noise + rule); !strings.Contains(got, "block drop") {
		t.Fatalf("a real rule was dropped: %q", got)
	}
}
