// Package vpn starts the user's VPN at the handover, for VPNs macOS itself
// knows about: the ones in System Settings, including app-provided tunnels
// such as WireGuard's. A VPN with its own system extension and no entry there
// (NordVPN's app) cannot be started this way, and the handover asks the user
// to connect it instead.
package vpn

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ErrUnsupported is returned off macOS.
var ErrUnsupported = errors.New("vpn: starting a VPN is only supported on macOS")

// Service is one VPN configuration macOS knows about.
type Service struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`   // e.g. com.wireguard.macos, IKEv2
	Status  string `json:"status"` // e.g. Disconnected, Connected
	Enabled bool   `json:"enabled"`
}

// WireGuard reports whether this is a WireGuard tunnel, whose handshake is a
// single UDP flow to its RemoteAddress.
func (s Service) WireGuard() bool { return strings.Contains(strings.ToLower(s.Kind), "wireguard") }

// listLine is one line of `scutil --nc list`:
//
//   - (Disconnected)   887B3792-...-E57C0678DD61 VPN (com.wireguard.macos) "My VPN"   [VPN:com.wireguard.macos]
var listLine = regexp.MustCompile(`^(\*)?\s*\(([^)]*)\)\s+([0-9A-Fa-f-]{36})\s+\S+(?:\s+\(([^)]*)\))?\s+"(.*)"\s+\[([^\]]*)\]\s*$`)

// parseList reads `scutil --nc list`.
func parseList(out string) []Service {
	var ss []Service
	for _, line := range strings.Split(out, "\n") {
		m := listLine.FindStringSubmatch(strings.TrimRight(line, " "))
		if m == nil {
			continue
		}
		kind := m[4]
		if kind == "" {
			kind = m[6]
		}
		ss = append(ss, Service{ID: m[3], Name: m[5], Kind: kind, Status: m[2], Enabled: m[1] == "*"})
	}
	return ss
}

// Find picks the service a name or ID refers to.
func Find(ss []Service, nameOrID string) (Service, bool) {
	for _, s := range ss {
		if strings.EqualFold(s.ID, nameOrID) || s.Name == nameOrID {
			return s, true
		}
	}
	return Service{}, false
}

// parseRemote reads the RemoteAddress line of `scutil --nc show`, and only
// that line: the rest carries keychain references that are nobody's business.
func parseRemote(out string) (host string, port int) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(k) != "RemoteAddress" {
			continue
		}
		v = strings.TrimSpace(v)
		if h, p, err := net.SplitHostPort(v); err == nil {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
				return h, n
			}
			return h, 0
		}
		return v, 0
	}
	return "", 0
}
