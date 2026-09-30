package dnsfilter

import (
	"encoding/binary"
	"testing"
)

// The filter reads packets from anything on the machine and replies from an
// untrusted network's resolver. None of them may crash it: a panic here takes
// the filter down in the middle of a login. Run with, for example:
//
//	go test -fuzz=FuzzHandle -fuzztime=30s ./internal/dnsfilter

// FuzzHandle drives the whole request path: parse, decide, reply. With no
// upstream, an allowed name ends in SERVFAIL rather than touching a network.
func FuzzHandle(f *testing.F) {
	f.Add(query(1, "www.guestwifi.test"))
	f.Add(query(2, "imap.mail.me.com"))
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1}) // a pointer loop
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, q []byte) {
		s := &Server{
			Policy:    NewPolicy("", "www.guestwifi.test"),
			pending:   map[uint16]chan []byte{},
			refused:   map[string]int{},
			forwarded: map[string]int{},
			auto:      map[string]int{},
		}
		r := s.handle(q)
		if r == nil {
			return
		}
		if len(r) < 12 {
			t.Fatalf("reply of %d bytes, shorter than a DNS header", len(r))
		}
		if r[2]&0x80 == 0 {
			t.Fatal("reply without the QR bit: a client would read it as a query")
		}
		if binary.BigEndian.Uint16(r[0:2]) != binary.BigEndian.Uint16(q[0:2]) {
			t.Fatal("reply does not carry the query's ID")
		}
	})
}

// FuzzQuestionName: whatever it accepts comes back normalised, and the
// helpers the reply path uses on the same packet do not panic.
func FuzzQuestionName(f *testing.F) {
	f.Add(query(1, "CDN.BTWiFi.com"))
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 63})
	f.Fuzz(func(t *testing.T, q []byte) {
		name, ok := questionName(q)
		_ = questionType(q)
		if !ok {
			return
		}
		if name != normalize(name) {
			t.Fatalf("questionName returned %q, not normalised", name)
		}
		_ = refusal(q)
		_ = servfail(q)
	})
}

// FuzzAnswerAddrs: an upstream reply is the network's to craft. Every
// address it yields must be a whole IPv4 or IPv6 address, because each one
// becomes a pf table entry.
func FuzzAnswerAddrs(f *testing.F) {
	ok := reply(query(1, "cdn.guestwifi.test"), 0)
	binary.BigEndian.PutUint16(ok[6:8], 1)
	ok = append(ok, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 198, 51, 100, 7)
	f.Add(ok)
	f.Add([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 9, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, r []byte) {
		for _, ip := range answerAddrs(r) {
			if len(ip) != 4 && len(ip) != 16 {
				t.Fatalf("address of %d bytes", len(ip))
			}
		}
	})
}
