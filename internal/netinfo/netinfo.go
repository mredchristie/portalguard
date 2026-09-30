// Package netinfo answers the few questions Portalguard needs to ask about the
// machine's live network configuration.
package netinfo

import (
	"fmt"
	"net"
	"strings"
)

// DefaultRoute describes where traffic goes when nothing more specific applies.
type DefaultRoute struct {
	Interface string
	Gateway   net.IP
}

// Tunnel is an active VPN-style interface that owns the default route.
type Tunnel struct {
	// Interface is the tunnel device, e.g. "utun7".
	Interface string
	// Addr is the address assigned to it.
	Addr net.IP
	// Gateway is the default route's gateway through it.
	Gateway net.IP
}

func (t Tunnel) String() string {
	return fmt.Sprintf("%s (%s)", t.Interface, t.Addr)
}

// ==== spotting a VPN ======================================================
// A tunnel-shaped name is not enough - macOS keeps several addressless
// utuns up at all times.

// tunnelPrefixes are the interface name prefixes used by VPN software on the
// platforms we care about.
var tunnelPrefixes = []string{"utun", "ipsec", "ppp", "tun", "tap", "gpd", "wg"}

// isTunnelName reports whether an interface name looks like a VPN tunnel.
//
// On its own this is nowhere near sufficient. macOS keeps a handful of utun
// interfaces up permanently for iCloud Private Relay and friends - eight were
// UP on the development machine with only one carrying a VPN - so a name match
// must always be combined with "and it has an address and owns the default
// route". See ActiveTunnel.
func isTunnelName(name string) bool {
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// interfaceAddr returns the first non-link-local address assigned to an
// interface, or nil when it has none. An addressless utun is one of macOS's
// permanently-up system tunnels, not a VPN.
func interfaceAddr(name string) net.IP {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		return ip
	}
	return nil
}

// parseARP reads the hardware address out of `arp -n <ip>`:
//
//	? (192.168.0.1) at b4:ba:9d:d6:59:e9 on en0 ifscope [ethernet]
//
// macOS drops leading zeros (0:1a:...), so it is normalised to two digits a
// byte, which is what makes two readings of the same router compare equal.
func parseARP(out string) (string, error) {
	_, rest, ok := strings.Cut(out, " at ")
	if !ok {
		return "", fmt.Errorf("no hardware address in %q", strings.TrimSpace(out))
	}
	field := strings.Fields(rest)
	if len(field) == 0 {
		return "", fmt.Errorf("no hardware address in %q", strings.TrimSpace(out))
	}
	parts := strings.Split(field[0], ":")
	if len(parts) != 6 {
		return "", fmt.Errorf("not a hardware address: %q", field[0])
	}
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return "", fmt.Errorf("not a hardware address: %q", field[0])
		}
		if len(p) == 1 {
			p = "0" + p
		}
		parts[i] = strings.ToLower(p)
	}
	return strings.Join(parts, ":"), nil
}
