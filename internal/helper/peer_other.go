//go:build !darwin

package helper

import (
	"errors"
	"net"
)

// PeerUID is not implemented off macOS, so the helper answers nobody there.
func PeerUID(*net.UnixConn) (int, error) { return -1, errors.New("helper: macOS only") }
