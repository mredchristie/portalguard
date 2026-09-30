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

// parseHardwarePorts finds the Wi-Fi device in `networksetup
// -listallhardwareports`:
//
//	Hardware Port: Wi-Fi
//	Device: en0
func parseHardwarePorts(out string) (string, bool) {
	port := ""
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Hardware Port":
			port = v
		case "Device":
			if port == "Wi-Fi" || port == "AirPort" {
				return v, true
			}
		}
	}
	return "", false
}

// joinFailed reads networksetup's reply to -setairportnetwork: it exits 0
// either way, and says what went wrong in words.
func joinFailed(out string) error {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	low := strings.ToLower(out)
	failed := false
	for _, bad := range []string{"could not", "error", "failed", "unable"} {
		if strings.Contains(low, bad) {
			failed = true
		}
	}
	if !failed {
		return nil
	}
	// networksetup says it twice, once on each stream; and -3900 is how it
	// says a secured network was not given the password it needs.
	first, _, _ := strings.Cut(out, "\n")
	if strings.Contains(out, "-3900") {
		return fmt.Errorf("macOS could not join it; a secured network needs its password")
	}
	return fmt.Errorf("%s", strings.TrimSpace(first))
}

// ScopedResolver is a DNS server macOS knows for one interface.
type ScopedResolver struct {
	Addr      net.IP
	Interface string // e.g. en0; empty if scutil named none
}

// parseSCUtilDNS reads `scutil --dns`: every resolver block's nameservers
// and the interface it belongs to, skipping multicast DNS. It sees what
// /etc/resolv.conf does not yet: a network that has been joined but not made
// the primary one, which macOS holds back while it checks for a login page.
//
//	resolver #1
//	  nameserver[0] : 86.189.0.94
//	  if_index : 14 (en0)
func parseSCUtilDNS(out string) []ScopedResolver {
	var all []ScopedResolver
	seen := map[string]bool{}
	var addrs []net.IP
	iface, mdns := "", false
	flush := func() {
		if !mdns {
			for _, a := range addrs {
				if !seen[a.String()] {
					seen[a.String()] = true
					all = append(all, ScopedResolver{Addr: a, Interface: iface})
				}
			}
		}
		addrs, iface, mdns = nil, "", false
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "resolver #") || strings.HasPrefix(t, "DNS configuration") {
			flush()
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case strings.HasPrefix(k, "nameserver["):
			if ip := net.ParseIP(v); ip != nil {
				addrs = append(addrs, ip)
			}
		case k == "if_index":
			if i := strings.Index(v, "("); i >= 0 {
				iface = strings.TrimSuffix(v[i+1:], ")")
			}
		case k == "options" && strings.Contains(v, "mdns"):
			mdns = true
		}
	}
	flush()
	return all
}
