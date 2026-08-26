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
