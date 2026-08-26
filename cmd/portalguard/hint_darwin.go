//go:build darwin

package main

import (
	"errors"

	"portalguard/internal/firewall/pf"
)

// pfNoAnchorHook exposes the pf-specific sentinel to the platform-neutral
// error helper in main.go.
func pfNoAnchorHook() error { return pf.ErrNoAnchorHook }

var _ = errors.Is
