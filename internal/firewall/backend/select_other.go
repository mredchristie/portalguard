//go:build !darwin && !linux && !windows

package backend

import "portalguard/internal/firewall"

// New returns a backend that refuses to program anything.
func New() firewall.Backend { return firewall.Unsupported{} }
