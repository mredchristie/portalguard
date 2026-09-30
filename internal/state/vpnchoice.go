package state

import (
	"encoding/json"
	"os"
)

// VPNChoicePath is where the VPN to start at the handover is kept.
const VPNChoicePath = "/etc/portalguard/vpn.json"

// VPNChoice is the VPN the handover starts by itself. See internal/vpn.
type VPNChoice struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Name    string `json:"name"`
}

// LoadVPNChoice returns the chosen VPN, if one has been chosen.
func LoadVPNChoice(path string) (VPNChoice, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return VPNChoice{}, false
	}
	var c VPNChoice
	if json.Unmarshal(data, &c) != nil || c.Version != 1 || c.ID == "" {
		return VPNChoice{}, false
	}
	return c, true
}

// SaveVPNChoice records the VPN to start.
func SaveVPNChoice(path, id, name string) error {
	return writeJSONAtomic(path, VPNChoice{Version: 1, ID: id, Name: name}, "VPN choice")
}

// ClearVPNChoice forgets it: the handover goes back to asking.
func ClearVPNChoice(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
