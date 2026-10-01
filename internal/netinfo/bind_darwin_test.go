//go:build darwin

package netinfo

import (
	"context"
	"net"
	"testing"
)

// TestBindToSendsOutOfThatInterface: a socket bound to lo0 still reaches
// loopback, and one bound to an interface that does not exist is refused
// rather than quietly using the routing table.
func TestBindToSendsOutOfThatInterface(t *testing.T) {
	lc := net.ListenConfig{Control: BindTo("lo0")}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind to lo0: %v", err)
	}
	pc.Close()

	bad := net.ListenConfig{Control: BindTo("nonexistent9")}
	if pc, err := bad.ListenPacket(context.Background(), "udp4", "127.0.0.1:0"); err == nil {
		pc.Close()
		t.Fatal("bound to an interface that does not exist")
	}
}
