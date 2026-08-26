//go:build linux

package backend

import (
	"portalguard/internal/firewall"
	"portalguard/internal/firewall/nftables"
)

// New returns the Linux nftables backend (currently a stub).
func New() firewall.Backend { return nftables.New() }
