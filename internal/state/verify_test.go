package state

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
)

// TestVerifyKnownHostRejectsAnUntrustedCertificate is the case that matters:
// a rogue access point can answer the DNS query and accept the TCP
// connection, but it cannot produce a certificate the system trust store
// accepts for someone else's hostname. httptest's server is exactly that
// shape - a real TLS listener with a certificate nothing trusts - so a pass
// here would be the bug this file exists to prevent.
func TestVerifyKnownHostRejectsAnUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	addr := srv.Listener.Addr().(*net.TCPAddr)
	err := defaultVerifyKnownHost(context.Background(), addr.IP, addr.Port, "cdn.example.test")
	if err == nil {
		t.Fatal("want an error for a self-signed certificate, got nil")
	}
}

func TestVerifyKnownHostFailsOnAPlainTCPServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	err = defaultVerifyKnownHost(context.Background(), addr.IP, addr.Port, "cdn.example.test")
	if err == nil {
		t.Fatal("want an error when the server never speaks TLS at all, got nil")
	}
}

func TestVerifyKnownHostFailsOnAClosedPort(t *testing.T) {
	// A listener opened and immediately closed reserves a port nothing is
	// behind - the connection-refused case, standing in for a network that
	// never answers for a known host at all.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()

	err = defaultVerifyKnownHost(context.Background(), addr.IP, addr.Port, "cdn.example.test")
	if err == nil {
		t.Fatal("want an error when nothing is listening, got nil")
	}
}
