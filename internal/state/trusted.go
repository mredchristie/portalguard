package state

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// ==== trusted networks: where an armed Mac stands down =====================
//
// Armed mode locks down on every network it meets, which is right for a café
// and wrong for home. A trusted network is one you have said is yours, and
// an armed Mac that joins it releases instead of handing over to the VPN.
//
// It is recognised by the gateway's hardware address. That needs no location
// permission, where the Wi-Fi name does, and a network cannot change it
// without changing its router. A hostile network could still copy it, if it
// knew it; which is why trust is only acted on when detection also finds open
// internet. A "trusted" network that turns out to have a login page is
// treated as the stranger it is. See docs/architecture.md, "Armed mode".

// TrustedPath is where trusted networks are kept.
const TrustedPath = "/etc/portalguard/trusted.json"

const trustedVersion = 1

// TrustedNetwork is one network marked as yours.
type TrustedNetwork struct {
	GatewayMAC string    `json:"gateway_mac"`
	Label      string    `json:"label,omitempty"`
	AddedAt    time.Time `json:"added_at"`
}

type trustedFile struct {
	Version  int                       `json:"version"`
	Networks map[string]TrustedNetwork `json:"networks"`
}

// LoadTrusted returns the trusted networks by gateway hardware address, or
// none if the file is missing or cannot be read: no trust is the safe default.
func LoadTrusted(path string) map[string]TrustedNetwork {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]TrustedNetwork{}
	}
	var f trustedFile
	if json.Unmarshal(data, &f) != nil || f.Version != trustedVersion || f.Networks == nil {
		return map[string]TrustedNetwork{}
	}
	return f.Networks
}

// SaveTrusted writes the trusted networks, replacing the file.
func SaveTrusted(path string, networks map[string]TrustedNetwork) error {
	return writeJSONAtomic(path, trustedFile{Version: trustedVersion, Networks: networks}, "trusted networks")
}

// Trust adds the network behind gatewayMAC, or relabels it if it is there.
func Trust(path, gatewayMAC, label string) error {
	n := LoadTrusted(path)
	mac := strings.ToLower(gatewayMAC)
	n[mac] = TrustedNetwork{GatewayMAC: mac, Label: label, AddedAt: time.Now()}
	return SaveTrusted(path, n)
}

// Untrust removes it, and reports whether it was there.
func Untrust(path, gatewayMAC string) (bool, error) {
	n := LoadTrusted(path)
	mac := strings.ToLower(gatewayMAC)
	if _, ok := n[mac]; !ok {
		return false, nil
	}
	delete(n, mac)
	return true, SaveTrusted(path, n)
}

// IsTrusted reports whether gatewayMAC is a trusted network, and its label.
func IsTrusted(path, gatewayMAC string) (TrustedNetwork, bool) {
	tn, ok := LoadTrusted(path)[strings.ToLower(gatewayMAC)]
	return tn, ok && gatewayMAC != ""
}
