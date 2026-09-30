package portal

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A portal's interstitial page and its redirect URLs are hostile input: the
// network writes them. Nothing parsing them may panic, and a port taken from
// one ends up in a pf rule, so it must be a real port.
//
//	go test -fuzz=FuzzMetaRefresh -fuzztime=30s ./internal/portal

func FuzzMetaRefresh(f *testing.F) {
	f.Add([]byte(`<meta http-equiv="refresh" content="0; url=/login">`), "http://www.guestwifi.test:8443/")
	f.Add([]byte(`<script>window.location = "https://x.test/a"</script>`), "http://a/")
	f.Add([]byte("caf\xc3\xa9 "), "::")
	// A multi-byte character straddling snippet's 240-byte cut.
	f.Add([]byte(strings.Repeat("a", 239)+"\xc3\xa9"), "http://a/")
	f.Fuzz(func(t *testing.T, body []byte, base string) {
		_ = metaRefreshURL(body, base)
		_ = isAppleSuccess(body)
		if s := snippet(body); utf8.Valid(body) && !utf8.ValidString(s) {
			t.Fatalf("snippet cut a character in half: %q", s)
		}
	})
}

func FuzzSplitURL(f *testing.F) {
	for _, u := range []string{"http://www.btwifi.com:8443/login", "https://x/", "http://[::1]:80/", "http://h:99999/"} {
		f.Add(u)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, port, ok := splitURL(raw)
		if ok && (port < 0 || port > 65535) {
			t.Fatalf("splitURL(%q) gave port %d", raw, port)
		}
	})
}
