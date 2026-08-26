// Package wfp is the planned Windows backend for Portalguard, built on the
// Windows Filtering Platform.
//
// It is a stub: the shape is here so the cross-platform architecture is
// visible, but no filters are installed yet.
//
// Design sketch (for when this is implemented):
//
//   - Open an engine handle (FwpmEngineOpen0) and create a *dynamic* session.
//     A dynamic session's filters are destroyed automatically by the OS when
//     the process handle closes, which gives Windows a stronger fail-safe than
//     either pf or nftables: a crash cannot leave the machine locked.
//   - Add a sublayer keyed by a Portalguard GUID so all filters can be
//     enumerated and removed together.
//   - Block filters at FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6 with a low weight,
//     permit filters for the portal hosts at a higher weight.
//
// Note that this needs Administrator rights, and that the API is COM-ish
// enough that we will likely wrap it via golang.org/x/sys/windows rather than
// shelling out to netsh (netsh advfirewall cannot express "block everything
// except this one host" without stomping on the user's own firewall profile).
package wfp

import (
	"context"
	"runtime"

	"github.com/mredchristie/portalguard/internal/firewall"
)

// Backend is the Windows Filtering Platform backend.
type Backend struct{}

// New returns a not-yet-implemented Windows backend.
func New() *Backend { return &Backend{} }

func (b *Backend) Name() string { return "wfp" }

func (b *Backend) Available(context.Context) (bool, string) {
	return false, "the Windows WFP backend is not implemented yet (running on " + runtime.GOOS + ")"
}

func (b *Backend) Lockdown(context.Context) error                 { return firewall.ErrNotImplemented }
func (b *Backend) AllowHost(context.Context, firewall.Host) error { return firewall.ErrNotImplemented }
func (b *Backend) Seal(context.Context) error                     { return firewall.ErrNotImplemented }
func (b *Backend) Release(context.Context) error                  { return nil }

func (b *Backend) Status(context.Context) (firewall.Status, error) {
	return firewall.Status{Backend: b.Name(), Phase: firewall.PhaseOff, Available: false}, nil
}

var _ firewall.Backend = (*Backend)(nil)
