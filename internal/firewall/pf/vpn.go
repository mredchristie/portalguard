//go:build darwin

package pf

import (
	"context"
	"errors"
	"fmt"

	"portalguard/internal/firewall"
)

// ==== the handover ========================================================
// See firewall.VPNOpener, and docs/pf-design.md, "The handover".

// ErrGapOpen is returned when a handover is asked for while the portal gap is
// still open. The gap has to be sealed first: handing over through an open
// gap would let the portal's hole outlive the login it was for.
var ErrGapOpen = errors.New("pf: the portal gap is still open; seal it before handing over to the VPN")

// AllowVPN reloads the lockdown with pass rules for the given VPN endpoints.
// The phase stays LOCKED: nothing but the VPN's handshake can leave, and an
// empty list puts the bare lockdown back.
func (b *Backend) AllowVPN(ctx context.Context, endpoints []firewall.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.syncFromKernel(ctx)
	switch b.phase {
	case firewall.PhaseOff:
		return firewall.ErrNotLocked
	case firewall.PhaseGap:
		return ErrGapOpen
	}
	for _, e := range endpoints {
		if e.Port < 1 || e.Port > 65535 || (e.Proto != "udp" && e.Proto != "tcp") {
			return fmt.Errorf("pf: refusing a VPN endpoint %s", e)
		}
	}
	return b.loadLocked(ctx, gap{vpn: endpoints})
}

var _ firewall.VPNOpener = (*Backend)(nil)
