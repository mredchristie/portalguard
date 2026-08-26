//go:build darwin

package pf

import (
	"os"
	"strings"
	"testing"
)

// stockPfConf is the macOS default, byte for byte from the development
// machine. If a future macOS changes it, this test is where it shows up.
const stockPfConf = `#
# Default PF configuration file.
#
# See pf.conf(5) for syntax.
#

#
# com.apple anchor point
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

func TestInsertHookPlacement(t *testing.T) {
	got, err := insertHook(stockPfConf)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(got, "\n")

	pos := func(want string) int {
		for i, l := range lines {
			if strings.TrimSpace(l) == want {
				return i
			}
		}
		return -1
	}

	ours := pos(`anchor "portalguard"`)
	apple := pos(`anchor "com.apple/*"`)
	dummynet := pos(`dummynet-anchor "com.apple/*"`)

	if ours < 0 {
		t.Fatalf("anchor line not inserted:\n%s", got)
	}
	// After the translation anchors: pf demands options, normalisation,
	// translation, then filtering, and ours is a filter anchor. Earlier is a
	// parse error.
	if ours < dummynet {
		t.Errorf("anchor at line %d is before dummynet-anchor at %d; pf will reject the ruleset", ours, dummynet)
	}
	// Before com.apple: quick means first match wins, and this is what stops
	// AirDrop or the Application Firewall passing traffic under our block.
	if ours > apple {
		t.Errorf("anchor at line %d is after com.apple at %d; our block could be undercut", ours, apple)
	}
	if !strings.Contains(got, "load anchor \"com.apple\"") {
		t.Error("the com.apple load line must survive untouched")
	}
}

func TestInsertHookThenRemoveIsIdentity(t *testing.T) {
	// Uninstall has to leave pf.conf exactly as it found it, or the revert
	// instructions in the docs are a lie.
	inserted, err := insertHook(stockPfConf)
	if err != nil {
		t.Fatal(err)
	}
	if got := removeHook(inserted); got != stockPfConf {
		t.Errorf("round trip changed pf.conf:\n--- want ---\n%s\n--- got ---\n%s", stockPfConf, got)
	}
}

func TestInsertHookRefusesUnknownLayout(t *testing.T) {
	// Rather than guess at a position in a pf.conf we do not recognise.
	_, err := insertHook("# a pf.conf from somewhere else\nblock all\n")
	if err == nil {
		t.Fatal("expected a refusal when the com.apple anchor point is absent")
	}
	if !strings.Contains(err.Error(), "by hand") {
		t.Errorf("the error should tell the user what to do: %v", err)
	}
}

func TestRemoveHookIsIdempotent(t *testing.T) {
	if got := removeHook(stockPfConf); got != stockPfConf {
		t.Error("removing an absent hook must change nothing")
	}
}

func TestAnchorReferencedParsesPfctlOutput(t *testing.T) {
	// What `pfctl -sr` prints once the hook is loaded.
	loaded := `anchor "portalguard" all
anchor "com.apple/*" all
`
	if !anchorReferenced(loaded, "portalguard") {
		t.Error("should recognise our anchor in the loaded main ruleset")
	}
	if anchorReferenced(`anchor "com.apple/*" all`, "portalguard") {
		t.Error("must not claim the hook exists when only com.apple is loaded")
	}
	// The dangerous false positive: rules stored in the anchor are not the
	// same as the anchor being referenced.
	if anchorReferenced("block drop out quick all\npass quick on lo0 all\n", "portalguard") {
		t.Error("anchor contents must not be mistaken for a main-ruleset reference")
	}
}

// TestRealPfConfIsStillTheShapeWeExpect reads the actual file, so a macOS
// update that changes its layout fails here rather than at 2am in a hotel.
func TestRealPfConfIsStillTheShapeWeExpect(t *testing.T) {
	conf, err := os.ReadFile(PfConfPath)
	if err != nil {
		t.Skipf("cannot read %s: %v", PfConfPath, err)
	}
	if strings.Contains(string(conf), beginMarker) {
		t.Skip("hook is already installed on this machine")
	}
	if _, err := insertHook(string(conf)); err != nil {
		t.Errorf("this machine's %s no longer has a place to insert the anchor: %v", PfConfPath, err)
	}
}
