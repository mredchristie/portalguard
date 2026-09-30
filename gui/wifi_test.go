package main

import "testing"

func TestTidyKeepsTheStrongestOfEachName(t *testing.T) {
	in := []Network{
		{SSID: "BTWi-fi", RSSI: -70, Open: true},
		{SSID: "BTWi-fi", RSSI: -52, Open: true},
		{SSID: "Home", RSSI: -40},
		{SSID: "", RSSI: -60}, // a name macOS withheld
		{SSID: "Cafe", RSSI: -52, Open: true},
	}
	got, hidden := tidy(in, "Home")
	if hidden != 1 {
		t.Errorf("hidden = %d, want 1", hidden)
	}
	want := []string{"Home", "BTWi-fi", "Cafe"}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, n := range got {
		if n.SSID != want[i] {
			t.Errorf("position %d = %s, want %s", i, n.SSID, want[i])
		}
	}
	if !got[0].Current || got[1].Current {
		t.Error("current network not marked")
	}
	if got[1].RSSI != -52 {
		t.Errorf("kept %d dBm for BTWi-fi, want the stronger -52", got[1].RSSI)
	}
}
