package firewall

import (
	"context"
	"runtime"
)

// Unsupported is the backend used on platforms Portalguard has no driver for.
// It refuses to program anything, but Release still succeeds so the safety net
// works uniformly everywhere.
type Unsupported struct{}

func (Unsupported) Name() string { return "unsupported" }

func (Unsupported) Available(context.Context) (bool, string) {
	return false, "no firewall backend for " + runtime.GOOS + "/" + runtime.GOARCH
}

func (Unsupported) Lockdown(context.Context) error        { return ErrNotImplemented }
func (Unsupported) AllowHost(context.Context, Host) error { return ErrNotImplemented }
func (Unsupported) Seal(context.Context) error            { return ErrNotImplemented }
func (Unsupported) Release(context.Context) error         { return nil }

func (u Unsupported) Status(context.Context) (Status, error) {
	return Status{Backend: u.Name(), Phase: PhaseOff, Available: false}, nil
}

var _ Backend = Unsupported{}
