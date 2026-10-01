package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func levels(fs []finding) string {
	var l []string
	for _, f := range fs {
		l = append(l, f.Level)
	}
	return strings.Join(l, ",")
}

func TestResolverFindings(t *testing.T) {
	v4, v6 := net.ParseIP("192.168.0.1"), net.ParseIP("fd25::1")
	cases := []struct {
		in   []net.IP
		want string
	}{
		{nil, "warn"},                 // nothing to filter towards
		{[]net.IP{v6}, "warn"},        // the filter forwards over IPv4 only
		{[]net.IP{v4}, "ok"},          // the common case
		{[]net.IP{v4, v6}, "ok,info"}, // and the IPv6 redirect is worth watching
	}
	for _, c := range cases {
		if got := levels(resolverFindings(c.in)); got != c.want {
			t.Errorf("resolverFindings(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestFilterPortsBusyIsAFail(t *testing.T) {
	if got := levels(filterPortFindings(func(string, string) bool { return true })); got != "ok" {
		t.Errorf("all free: %s", got)
	}
	fs := filterPortFindings(func(network, addr string) bool { return !strings.HasSuffix(addr, ":53530") })
	if levels(fs) != "fail" || !strings.Contains(fs[0].Title, "53530") {
		t.Errorf("busy listen port: %+v", fs)
	}
}

func TestPrintFindingsVerdict(t *testing.T) {
	var b bytes.Buffer
	printFindings(&b, []finding{{"ok", "fine", ""}, {"warn", "hmm", "do this\nthen that"}})
	if !strings.Contains(b.String(), "Ready:") || !strings.Contains(b.String(), "        then that") {
		t.Errorf("output:\n%s", b.String())
	}
	b.Reset()
	printFindings(&b, []finding{{"fail", "broken", "fix it"}})
	if !strings.Contains(b.String(), "Not ready") {
		t.Errorf("a fail must say not ready:\n%s", b.String())
	}
}
