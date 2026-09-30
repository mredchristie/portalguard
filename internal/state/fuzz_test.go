package state

import (
	"strings"
	"testing"
)

// FuzzSiteOf: auto-allow opens whatever sameSite accepts, so the site it is
// given must really be a suffix of the portal host, on a label boundary, and
// never a shared hosting domain.
//
//	go test -fuzz=FuzzSiteOf -fuzztime=30s ./internal/state
func FuzzSiteOf(f *testing.F) {
	for _, h := range []string{"www.btwifi.com", "portal.hotel.co.uk", "d1.cloudfront.net", "192.168.1.1", "a..b", ".", "x.co.uk."} {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, host string) {
		site := siteOf(host)
		if site == "" {
			return
		}
		h := normalizeHost(host)
		if h != site && !strings.HasSuffix(h, "."+site) {
			t.Fatalf("siteOf(%q) = %q, which %q is not under", host, site, h)
		}
		if auto := autoAllowSite(host); auto != "" {
			if sharedHosting[auto] {
				t.Fatalf("autoAllowSite(%q) trusted shared hosting %q", host, auto)
			}
			if !sameSite(host, auto) {
				t.Fatalf("the portal host %q is not on its own site %q", host, auto)
			}
		}
	})
}
