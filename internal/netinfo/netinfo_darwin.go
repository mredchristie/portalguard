//go:build darwin

package netinfo

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// routePath is the absolute path to route(8).
const routePath = "/sbin/route"

// Default returns the machine's default route.
func Default(ctx context.Context) (DefaultRoute, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, routePath, "-n", "get", "default").Output()
	if err != nil {
		return DefaultRoute{}, fmt.Errorf("read default route: %w", err)
	}
	return parseDefaultRoute(string(out))
}

// parseDefaultRoute reads the key/value output of `route -n get default`.
func parseDefaultRoute(out string) (DefaultRoute, error) {
	var dr DefaultRoute
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "interface":
			dr.Interface = value
		case "gateway":
			dr.Gateway = net.ParseIP(value)
		}
	}
	if dr.Interface == "" {
		return dr, fmt.Errorf("no default route")
	}
	return dr, nil
}

// ActiveTunnel reports the VPN tunnel currently carrying this machine's
// traffic, or nil when there is none.
//
// All three conditions must hold: the default route leaves through the
// interface, the interface name looks like a tunnel, and it has an address.
// Checking only the name would refuse to run on every Mac in existence, since
// macOS keeps several addressless utun interfaces up at all times.
func ActiveTunnel(ctx context.Context) (*Tunnel, error) {
	dr, err := Default(ctx)
	if err != nil {
		// No default route is not a tunnel; it is a network that is not up
		// yet, which is exactly when portalguard is useful.
		return nil, nil
	}
	if !isTunnelName(dr.Interface) {
		return nil, nil
	}
	addr := interfaceAddr(dr.Interface)
	if addr == nil {
		return nil, nil
	}
	return &Tunnel{Interface: dr.Interface, Addr: addr, Gateway: dr.Gateway}, nil
}

// GatewayMAC returns the hardware address of the default gateway, which is how
// a trusted network is recognised: it needs no location permission, unlike
// the Wi-Fi name, which recent macOS hides from command-line tools.
func GatewayMAC(ctx context.Context, gw net.IP) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/arp", "-n", gw.String()).Output()
	if err != nil {
		return "", fmt.Errorf("arp %s: %w", gw, err)
	}
	return parseARP(string(out))
}

// WiFiDevice returns the Wi-Fi interface, usually en0.
func WiFiDevice(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/networksetup", "-listallhardwareports").Output()
	if err != nil {
		return "", fmt.Errorf("list network ports: %w", err)
	}
	dev, ok := parseHardwarePorts(string(out))
	if !ok {
		return "", fmt.Errorf("this Mac has no Wi-Fi interface")
	}
	return dev, nil
}

// JoinWiFi asks macOS to join a Wi-Fi network, with its password if it has
// one. It returns once macOS has answered; the network's address and DNS
// arrive shortly after.
func JoinWiFi(ctx context.Context, ssid, password string) error {
	dev, err := WiFiDevice(ctx)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := []string{"-setairportnetwork", dev, ssid}
	if password != "" {
		args = append(args, password)
	}
	out, err := exec.CommandContext(ctx, "/usr/sbin/networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("join %q: %w: %s", ssid, err, strings.TrimSpace(string(out)))
	}
	if err := joinFailed(string(out)); err != nil {
		return fmt.Errorf("join %q: %w", ssid, err)
	}
	return nil
}

// ScopedDNS is every DNS server macOS knows, with the interface it belongs
// to, from `scutil --dns`. See parseSCUtilDNS.
func ScopedDNS(ctx context.Context) []ScopedResolver {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	return parseSCUtilDNS(string(out))
}

// ipBoundIf and ipv6BoundIf are Darwin's IP_BOUND_IF and IPV6_BOUND_IF.
const (
	ipBoundIf   = 25
	ipv6BoundIf = 125
)

// BindTo returns a dialer or listener Control that sends a socket out of one
// interface, whatever the routing table says. A network macOS has joined but
// not yet made primary has no default route, only one scoped to its
// interface, and a socket bound to that interface can use it.
func BindTo(name string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		var serr error
		err = c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIf, ifi.Index)
			} else {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, ifi.Index)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// IsPreferred reports whether macOS has ssid among its saved Wi-Fi networks.
func IsPreferred(ctx context.Context, ssid string) (bool, error) {
	dev, err := WiFiDevice(ctx)
	if err != nil {
		return false, err
	}
	out, err := exec.CommandContext(ctx, "/usr/sbin/networksetup", "-listpreferredwirelessnetworks", dev).Output()
	if err != nil {
		return false, err
	}
	for _, n := range parsePreferred(string(out)) {
		if n == ssid {
			return true, nil
		}
	}
	return false, nil
}

// LeaveWiFi takes this Mac off ssid and back to its usual network, by turning
// Wi-Fi off and on so macOS rejoins its best saved network with its own saved
// password. No password passes through here.
//
// macOS would pick the portal network straight back if it is saved: at EE
// WiFi it did, unprotected, with its own login window on top. So an open
// network is taken out of the saved list while macOS chooses, and put back
// where it was once the Mac is on something else. Open, it has no password to
// lose. forget leaves it out (it was saved only because PortalGuard joined
// it). A secured network is never removed: its password would go with it.
func LeaveWiFi(ctx context.Context, ssid string, forget, open bool) error {
	dev, err := WiFiDevice(ctx)
	if err != nil {
		return err
	}
	ns := func(args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, "/usr/sbin/networksetup", args...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("networksetup %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
		}
		return string(out), nil
	}
	list, err := ns("-listpreferredwirelessnetworks", dev)
	if err != nil {
		return err
	}
	index := -1
	for i, n := range parsePreferred(list) {
		if n == ssid {
			index = i
		}
	}
	remove := index >= 0 && (forget || open)
	putBack := remove && !forget
	if remove {
		if _, err := ns("-removepreferredwirelessnetwork", dev, ssid); err != nil {
			return err
		}
	}
	if _, err := ns("-setairportpower", dev, "off"); err != nil {
		return err
	}
	time.Sleep(time.Second)
	if _, err := ns("-setairportpower", dev, "on"); err != nil {
		return err
	}
	if !putBack {
		return nil
	}
	// Back in the list once the Mac is on another network (or after 20
	// seconds on none): a saved network is not switched to while the Mac is
	// connected elsewhere.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := Default(ctx); err == nil && r.Gateway != nil {
			break
		}
		time.Sleep(time.Second)
	}
	_, err = ns("-addpreferredwirelessnetworkatindex", dev, ssid, fmt.Sprint(index), "OPEN")
	return err
}
