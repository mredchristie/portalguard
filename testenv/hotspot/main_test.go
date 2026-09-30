package main

import (
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// query builds the packet a stub resolver sends for one name.
func query(name string, qtype uint16) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	return binary.BigEndian.AppendUint16(q, 1)
}

func testPortal() *portal {
	return &portal{config: config{
		domain: "guestwifi.test",
		self:   net.ParseIP("192.168.64.7"),
		cdn:    net.ParseIP("192.168.64.4"),
		reg:    net.ParseIP("192.168.64.5"),
		inet:   net.ParseIP("192.168.64.6"),
	}}
}

// answerIP pulls the address out of a one-answer reply, or nil.
func answerIP(t *testing.T, reply []byte, q []byte) net.IP {
	t.Helper()
	if reply[0] != q[0] || reply[1] != q[1] {
		t.Fatalf("reply id %x%x does not match query", reply[0], reply[1])
	}
	if reply[2]&0x80 == 0 {
		t.Fatalf("reply does not have QR set")
	}
	if binary.BigEndian.Uint16(reply[6:8]) == 0 {
		return nil
	}
	return net.IP(reply[len(reply)-4:])
}

func TestDNSLiesUntilLoginThenPointsAtTheInternet(t *testing.T) {
	p := testPortal()
	cases := []struct {
		name          string
		before, after string
	}{
		{"www.guestwifi.test", "192.168.64.7", "192.168.64.7"},
		{"cdn.guestwifi.test", "192.168.64.4", "192.168.64.4"},
		{"reg.guestwifi.test", "192.168.64.5", "192.168.64.5"},
		// Everything else is the portal until login, the internet after.
		{"captive.apple.com", "192.168.64.7", "192.168.64.6"},
		{"CONNECTIVITYCHECK.gstatic.com", "192.168.64.7", "192.168.64.6"},
	}
	for _, phase := range []string{"before", "after"} {
		p.authed.Store(phase == "after")
		for _, c := range cases {
			q := query(c.name, 1)
			reply, name, err := p.answer(q)
			if err != nil {
				t.Fatalf("%s %s: %v", phase, c.name, err)
			}
			if name != c.name {
				t.Errorf("parsed name %q, want %q", name, c.name)
			}
			want := c.before
			if phase == "after" {
				want = c.after
			}
			if got := answerIP(t, reply, q); got.String() != want {
				t.Errorf("%s login, %s = %v, want %s", phase, c.name, got, want)
			}
		}
	}
}

func TestDNSAnswersAAAAWithNothing(t *testing.T) {
	p := testPortal()
	q := query("www.guestwifi.test", 28)
	reply, _, err := p.answer(q)
	if err != nil {
		t.Fatal(err)
	}
	if got := answerIP(t, reply, q); got != nil {
		t.Errorf("AAAA answered with %v, want an empty NOERROR", got)
	}
	if reply[3]&0x0F != 0 {
		t.Errorf("rcode %d, want NOERROR", reply[3]&0x0F)
	}
}

func TestDNSRejectsGarbage(t *testing.T) {
	p := testPortal()
	for _, q := range [][]byte{nil, make([]byte, 11), append(query("a.b", 1)[:13], 0xC0)} {
		if _, _, err := p.answer(q); err == nil {
			t.Errorf("answered a malformed query %x", q)
		}
	}
}

// TestHostileDNSSendsCDNAndRegToTheImpostor: in dns mode, the remembered
// hosts resolve to net, and /reset puts the truth back.
func TestHostileDNSSendsCDNAndRegToTheImpostor(t *testing.T) {
	p := testPortal()
	p.hostile.Store("dns")
	for _, h := range []string{"cdn.guestwifi.test", "reg.guestwifi.test"} {
		if got := p.resolve(h); !got.Equal(p.inet) {
			t.Errorf("%s = %v in dns mode, want the impostor %v", h, got, p.inet)
		}
	}
	if got := p.resolve("www.guestwifi.test"); !got.Equal(p.self) {
		t.Errorf("www moved too: %v", got)
	}
	rec := httptest.NewRecorder()
	p.handleReset(rec, httptest.NewRequest(http.MethodPost, "/reset", nil))
	if got := p.resolve("cdn.guestwifi.test"); !got.Equal(p.cdn) {
		t.Errorf("reset left cdn at %v", got)
	}
}

// TestHostilePageStillNamesTheLogin: the malformed interception page is
// served as a 200, with the real login in it after the bait.
func TestHostilePageStillNamesTheLogin(t *testing.T) {
	p := testPortal()
	p.hostile.Store("page")
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, httptest.NewRequest(http.MethodGet, "/hotspot-detect.html", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), p.loginURL()) {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "\xc5url=") {
		t.Fatal("the bait bytes are missing")
	}
}

func TestSelfSignedIsForTheNamesAndUntrusted(t *testing.T) {
	cert, err := selfSigned("cdn.guestwifi.test", "reg.guestwifi.test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("cdn.guestwifi.test"); err != nil {
		t.Fatalf("not for cdn: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "cdn.guestwifi.test"}); err == nil {
		t.Fatal("the system trusts the impostor's certificate")
	}
}
