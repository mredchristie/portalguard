package main

import (
	"strings"
	"testing"

	"portalguard/internal/state"
)

func TestParseAllowTarget(t *testing.T) {
	tests := []struct {
		arg       string
		wantHost  string
		wantPorts []int
		wantErr   bool
	}{
		{arg: "cdn.example.net", wantHost: "cdn.example.net"},
		{arg: "info.example.net:442", wantHost: "info.example.net", wantPorts: []int{442}},
		{arg: "192.168.23.21", wantHost: "192.168.23.21"},
		{arg: "192.168.23.21:8443", wantHost: "192.168.23.21", wantPorts: []int{8443}},
		// A bare IPv6 literal is a host, not a host and a port.
		{arg: "fe80::1", wantHost: "fe80::1"},
		{arg: "[fe80::1]:8443", wantHost: "fe80::1", wantPorts: []int{8443}},
		{arg: "example.net:0", wantErr: true},
		{arg: "example.net:99999", wantErr: true},
		{arg: "example.net:https", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.arg, func(t *testing.T) {
			got, err := parseAllowTarget(tc.arg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseAllowTarget(%q) = %+v, want an error", tc.arg, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAllowTarget(%q): %v", tc.arg, err)
			}
			if got.host != tc.wantHost {
				t.Errorf("host = %q, want %q", got.host, tc.wantHost)
			}
			if len(got.ports) != len(tc.wantPorts) {
				t.Fatalf("ports = %v, want %v", got.ports, tc.wantPorts)
			}
			for i := range got.ports {
				if got.ports[i] != tc.wantPorts[i] {
					t.Errorf("ports = %v, want %v", got.ports, tc.wantPorts)
				}
			}
		})
	}
}

// TestExtendHintSaysWhatToDoNext: the person hitting this is standing in front
// of a blank login page with no internet, which is the worst possible moment
// to be handed a state machine's internal vocabulary.
func TestExtendHintSaysWhatToDoNext(t *testing.T) {
	cases := []struct {
		from state.State
		want string
	}{
		{state.Idle, "run"},
		{state.LockedDown, "allow"},
		{state.Sealed, "release"},
	}
	for _, tc := range cases {
		t.Run(string(tc.from), func(t *testing.T) {
			err := extendHint(&state.InvalidTransitionError{From: tc.from, Event: state.EventExtendGap})
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("hint for %s does not suggest %q:\n%s", tc.from, tc.want, err)
			}
			if strings.Contains(err.Error(), "cannot apply") {
				t.Errorf("hint for %s still leaks the raw transition error:\n%s", tc.from, err)
			}
		})
	}
}
