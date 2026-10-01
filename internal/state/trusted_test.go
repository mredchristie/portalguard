package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted.json")
	if _, ok := IsTrusted(path, "b4:ba:9d:d6:59:e9"); ok {
		t.Fatal("trusted before anything was saved")
	}
	if err := Trust(path, "B4:BA:9D:D6:59:E9", "home"); err != nil {
		t.Fatal(err)
	}
	tn, ok := IsTrusted(path, "b4:ba:9d:d6:59:e9")
	if !ok || tn.Label != "home" {
		t.Fatalf("IsTrusted = %+v, %v", tn, ok)
	}
	if _, ok := IsTrusted(path, ""); ok {
		t.Fatal("an unknown gateway (empty address) counted as trusted")
	}
	if was, err := Untrust(path, "b4:ba:9d:d6:59:e9"); err != nil || !was {
		t.Fatalf("Untrust = %v, %v", was, err)
	}
	if _, ok := IsTrusted(path, "b4:ba:9d:d6:59:e9"); ok {
		t.Fatal("still trusted after untrust")
	}
}

// TestUnreadableTrustIsNoTrust: a damaged file must never widen anything.
func TestUnreadableTrustIsNoTrust(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := LoadTrusted(path); len(n) != 0 {
		t.Fatalf("a damaged file trusted %v", n)
	}
}
