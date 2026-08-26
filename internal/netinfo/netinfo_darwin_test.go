//go:build darwin

package netinfo

import (
	"context"
	"testing"
)

// realRouteOutput is `route -n get default` from the development machine while
// NordVPN was connected.
const realRouteOutput = `   route to: default
destination: default
       mask: default
    gateway: 10.5.0.2
  interface: utun7
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1420         0
`

const wifiRouteOutput = `   route to: default
destination: default
       mask: default
    gateway: 192.168.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`

func TestParseDefaultRouteThroughTunnel(t *testing.T) {
	dr, err := parseDefaultRoute(realRouteOutput)
	if err != nil {
		t.Fatal(err)
	}
	if dr.Interface != "utun7" {
		t.Errorf("interface = %q, want utun7", dr.Interface)
	}
	if dr.Gateway.String() != "10.5.0.2" {
		t.Errorf("gateway = %v, want 10.5.0.2", dr.Gateway)
	}
}

func TestParseDefaultRouteOverWiFi(t *testing.T) {
	dr, err := parseDefaultRoute(wifiRouteOutput)
	if err != nil {
		t.Fatal(err)
	}
	if dr.Interface != "en0" || dr.Gateway.String() != "192.168.0.1" {
		t.Errorf("got %+v", dr)
	}
}

func TestParseDefaultRouteNoRoute(t *testing.T) {
	if _, err := parseDefaultRoute("route: writing to routing socket: not in table\n"); err == nil {
		t.Error("expected an error when there is no default route")
	}
}

// TestActiveTunnelIgnoresAddresslessUtuns is the regression test for the
// mistake that would make this tool unusable: macOS keeps several utun
// interfaces UP and RUNNING at all times for its own purposes, and only the
// one carrying a VPN has an address. A check that looked at interface names,
// or at "is any utun up", would refuse to run on every Mac.
func TestActiveTunnelIgnoresAddresslessUtuns(t *testing.T) {
	var addressless []string
	for _, name := range []string{"utun0", "utun1", "utun2", "utun3", "utun4", "utun5", "utun6"} {
		if interfaceAddr(name) == nil {
			addressless = append(addressless, name)
		}
	}
	if len(addressless) == 0 {
		t.Skip("no addressless utun interfaces on this machine to check against")
	}

	// Whatever ActiveTunnel reports, it must not be one of these.
	tun, err := ActiveTunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tun == nil {
		return
	}
	for _, name := range addressless {
		if tun.Interface == name {
			t.Errorf("reported %s as an active tunnel, but it has no address", name)
		}
	}
	if interfaceAddr(tun.Interface) == nil {
		t.Errorf("reported %s as active, but it has no address", tun.Interface)
	}
}
