package netinfo

import (
	"strings"
	"testing"
)

func TestIsTunnelName(t *testing.T) {
	tunnels := []string{"utun0", "utun7", "ipsec0", "ppp0", "tun0", "wg0"}
	notTunnels := []string{"en0", "en4", "lo0", "awdl0", "bridge0", "gif0", "stf0"}
	for _, n := range tunnels {
		if !isTunnelName(n) {
			t.Errorf("%s should look like a tunnel", n)
		}
	}
	for _, n := range notTunnels {
		if isTunnelName(n) {
			t.Errorf("%s should not look like a tunnel", n)
		}
	}
}

func TestParseARP(t *testing.T) {
	good := map[string]string{
		"? (192.168.0.1) at b4:ba:9d:d6:59:e9 on en0 ifscope [ethernet]\n": "b4:ba:9d:d6:59:e9",
		"? (10.0.0.1) at 0:1a:B2:3:4:5 on en0 ifscope [ethernet]":          "00:1a:b2:03:04:05",
	}
	for in, want := range good {
		if got, err := parseARP(in); err != nil || got != want {
			t.Errorf("parseARP(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"? (192.168.0.1) at (incomplete) on en0 ifscope [ethernet]",
		"192.168.0.1 (192.168.0.1) -- no entry",
		"",
	} {
		if got, err := parseARP(bad); err == nil {
			t.Errorf("parseARP(%q) = %q, want an error", bad, got)
		}
	}
}

func TestParseHardwarePorts(t *testing.T) {
	out := `Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: a2:a3:99:45:d4:3f

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 80:a9:97:44:5e:4e
`
	if dev, ok := parseHardwarePorts(out); !ok || dev != "en0" {
		t.Errorf("parseHardwarePorts = %q, %v", dev, ok)
	}
	if _, ok := parseHardwarePorts("Hardware Port: Ethernet\nDevice: en4\n"); ok {
		t.Error("found Wi-Fi on a Mac without it")
	}
}

func TestJoinFailed(t *testing.T) {
	if joinFailed("") != nil {
		t.Error("an empty reply is success")
	}
	for _, bad := range []string{
		"Could not find network BTWi-fi.",
		"Failed to join network BTWi-fi.\nError: -3900  The operation couldn't be completed.",
	} {
		if joinFailed(bad) == nil {
			t.Errorf("%q read as success", bad)
		}
	}
}

func TestJoinFailedSaysWhatToDo(t *testing.T) {
	out := "Failed to join network HomeWiFi.\nError: -3900  The operation couldn't be completed. tmpErr\nFailed to join network HomeWiFi.\nError: -3900  The operation couldn't be completed. tmpErr"
	err := joinFailed(out)
	if err == nil || !strings.Contains(err.Error(), "needs its password") || strings.Count(err.Error(), "HomeWiFi") > 1 {
		t.Errorf("joinFailed = %v", err)
	}
}
