//go:build !darwin

package netinfo

import (
	"context"
	"errors"
	"net"
)

// ErrUnsupported is returned on platforms where route inspection is not
// implemented yet.
var ErrUnsupported = errors.New("netinfo: not implemented on this platform")

// Default is not implemented off macOS yet.
func Default(context.Context) (DefaultRoute, error) { return DefaultRoute{}, ErrUnsupported }

// ActiveTunnel is not implemented off macOS yet. It reports "no tunnel"
// rather than an error so callers degrade to permissive rather than blocked.
func ActiveTunnel(context.Context) (*Tunnel, error) { return nil, nil }

// GatewayMAC is not implemented off macOS.
func GatewayMAC(context.Context, net.IP) (string, error) { return "", ErrUnsupported }
