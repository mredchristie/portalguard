package state

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ==== proving a known name, not just trusting it ===========================
//
// DNS on the network we are sitting inside of proves nothing: whoever runs
// that network answers our DNS queries, hostile or not. A rogue access point
// can broadcast a known SSID, or answer a known hostname, as easily as the
// real operator can. See docs/gap-scope.md, option C, for why the addresses
// that answer are pinned but never simply trusted by name.
//
// A valid, publicly trusted TLS certificate for the exact name being opened
// proves something DNS cannot: that whoever is on the other end holds the
// private key for that hostname. Forging one takes either that key or a
// compromised certificate authority - not a spoofed SSID and not control of
// the local DNS server. That is the check this file runs before a known host
// is ever opened without a human naming it.
//
// It is only used for that: a host the user names themselves with `allow`
// never goes through this. That trust is the human's to give, unconditionally,
// same as it always was - this only governs what Portalguard is willing to
// decide on its own.

// verifyTLSTimeout bounds the one connection this makes before deciding.
const verifyTLSTimeout = 5 * time.Second

// verifyKnownHost dials addr:port and completes a TLS handshake with standard
// certificate verification for name. Any failure - refused connection,
// timeout, self-signed or mismatched certificate - comes back as a non-nil
// error, and means the caller must not open the host automatically.
//
// A package variable, not a plain function, so tests can swap in a fake
// verifier rather than needing a certificate a real trust store accepts.
var verifyKnownHost = defaultVerifyKnownHost

func defaultVerifyKnownHost(ctx context.Context, addr net.IP, port int, name string) error {
	ctx, cancel := context.WithTimeout(ctx, verifyTLSTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("connect to %s: %w", name, err)
	}
	defer raw.Close()

	// No InsecureSkipVerify and no custom RootCAs: this must pass the same
	// check a browser would apply, against the system's trusted roots.
	conn := tls.Client(raw, &tls.Config{ServerName: name})
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("verify certificate for %s: %w", name, err)
	}
	return nil
}
