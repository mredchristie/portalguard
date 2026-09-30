//go:build !darwin

package netinfo

import (
	"context"
	"errors"
	"net"
	"syscall"
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

// JoinWiFi is not implemented off macOS.
func JoinWiFi(context.Context, string, string) error { return ErrUnsupported }

// ScopedDNS is not implemented off macOS.
func ScopedDNS(context.Context) []ScopedResolver { return nil }

// BindTo is not implemented off macOS: sockets use the routing table.
func BindTo(string) func(network, address string, c syscall.RawConn) error { return nil }

// IsPreferred is not implemented off macOS.
func IsPreferred(context.Context, string) (bool, error) { return false, ErrUnsupported }

// LeaveWiFi is not implemented off macOS.
func LeaveWiFi(context.Context, string, bool, bool) error { return ErrUnsupported }

// WiFiGateway is not implemented off macOS.
func WiFiGateway(context.Context) (net.IP, error) { return nil, ErrUnsupported }
