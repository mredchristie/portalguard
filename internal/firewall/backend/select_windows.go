//go:build windows

package backend

import (
	"github.com/mredchristie/portalguard/internal/firewall"
	"github.com/mredchristie/portalguard/internal/firewall/wfp"
)

// New returns the Windows WFP backend (currently a stub).
func New() firewall.Backend { return wfp.New() }
