//go:build darwin

package backend

import (
	"portalguard/internal/firewall"
	"portalguard/internal/firewall/pf"
)

// New returns the macOS pf backend.
func New() firewall.Backend { return pf.New() }
