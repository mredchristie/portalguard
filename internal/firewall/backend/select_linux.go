//go:build linux

package backend

import (
	"github.com/mredchristie/portalguard/internal/firewall"
	"github.com/mredchristie/portalguard/internal/firewall/nftables"
)

// New returns the Linux nftables backend (currently a stub).
func New() firewall.Backend { return nftables.New() }
