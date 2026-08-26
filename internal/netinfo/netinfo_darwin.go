//go:build darwin

package netinfo

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
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
