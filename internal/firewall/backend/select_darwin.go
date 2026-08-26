//go:build darwin

package backend

import (
	"github.com/mredchristie/portalguard/internal/firewall"
	"github.com/mredchristie/portalguard/internal/firewall/pf"
)

// New returns the macOS pf backend.
func New() firewall.Backend { return pf.New() }
