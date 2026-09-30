package netinfo

import "testing"

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
