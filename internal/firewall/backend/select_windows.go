//go:build windows

package backend

import (
	"portalguard/internal/firewall"
	"portalguard/internal/firewall/wfp"
)

// New returns the Windows WFP backend (currently a stub).
func New() firewall.Backend { return wfp.New() }
