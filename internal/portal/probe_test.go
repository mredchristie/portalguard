package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newProber builds a Prober aimed at a single test endpoint, with the DNS
// checks off so tests never touch a real resolver.
func newProber(url string, expect Expectation) *Prober {
	p := NewProber()
	p.Probes = []Probe{{Name: "test", URL: url, Expect: expect}}
	p.Timeout = 2 * time.Second
	p.SkipDNSCheck = true
	return p
}

func TestDetectOpenInternet204(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	res := newProber(srv.URL+"/generate_204", ExpectNoContent).Detect(context.Background())
	if res.Class != OpenInternet {
		t.Fatalf("class = %s, want %s (%s)", res.Class, OpenInternet, res.Probes[0].Reason)
	}
	if res.PortalHost != "" {
		t.Errorf("portal host = %q, want empty", res.PortalHost)
	}
}

func TestDetectOpenInternetAppleSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"))
	}))
	defer srv.Close()

	res := newProber(srv.URL+"/hotspot-detect.html", ExpectAppleSuccess).Detect(context.Background())
	if res.Class != OpenInternet {
		t.Fatalf("class = %s, want %s (%s)", res.Class, OpenInternet, res.Probes[0].Reason)
	}
}

func TestDetectPortalRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://login.hotel.example:8080/portal?ap=42", http.StatusFound)
	}))
	defer srv.Close()

	res := newProber(srv.URL+"/generate_204", ExpectNoContent).Detect(context.Background())
	if res.Class != Portal {
		t.Fatalf("class = %s, want %s", res.Class, Portal)
	}
	if res.PortalHost != "login.hotel.example" {
		t.Errorf("portal host = %q, want login.hotel.example", res.PortalHost)
	}
	if res.PortalPort != 8080 {
		t.Errorf("portal port = %d, want 8080", res.PortalPort)
	}
	if !strings.HasPrefix(res.PortalURL, "http://login.hotel.example:8080/portal") {
		t.Errorf("portal URL = %q", res.PortalURL)
	}
}

func TestDetectPortalRelativeRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login.html")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	res := newProber(srv.URL+"/generate_204", ExpectNoContent).Detect(context.Background())
	if res.Class != Portal {
		t.Fatalf("class = %s, want %s", res.Class, Portal)
	}
	// A relative Location must be resolved against the probe URL, otherwise
	// there is no host to open a hole for.
	if !strings.HasSuffix(res.PortalURL, "/login.html") || res.PortalHost == "" {
		t.Errorf("portal URL = %q, host = %q", res.PortalURL, res.PortalHost)
	}
}

func TestDetectPortalSubstitutedBodyWithMetaRefresh(t *testing.T) {
	// The nastier case: HTTP 200 on the right URL, wrong content.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head>
<meta http-equiv="refresh" content="0; url=http://gateway.lan/welcome">
</head><body>Redirecting to the login page</body></html>`))
	}))
	defer srv.Close()

	res := newProber(srv.URL+"/hotspot-detect.html", ExpectAppleSuccess).Detect(context.Background())
	if res.Class != Portal {
		t.Fatalf("class = %s, want %s", res.Class, Portal)
	}
	if res.PortalHost != "gateway.lan" {
		t.Errorf("portal host = %q, want gateway.lan", res.PortalHost)
	}
}

func TestDetectPortal511(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://portal.example/login")
		w.WriteHeader(http.StatusNetworkAuthenticationRequired)
	}))
	defer srv.Close()

	res := newProber(srv.URL+"/generate_204", ExpectNoContent).Detect(context.Background())
	if res.Class != Portal {
		t.Fatalf("class = %s, want %s", res.Class, Portal)
	}
	if res.PortalHost != "portal.example" {
		t.Errorf("portal host = %q, want portal.example", res.PortalHost)
	}
}

func TestDetectPortalWrongStatus(t *testing.T) {
	// A 200 where a 204 was promised is interception even with an empty body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := newProber(srv.URL+"/generate_204", ExpectNoContent).Detect(context.Background())
	if res.Class != Portal {
		t.Fatalf("class = %s, want %s (%s)", res.Class, Portal, res.Probes[0].Reason)
	}
	// With nothing better to go on, the portal is whatever answered the probe.
	if res.PortalURL != srv.URL+"/generate_204" {
		t.Errorf("portal URL = %q, want the probe URL", res.PortalURL)
	}
}

func TestDetectNoNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL + "/generate_204"
	srv.Close() // nothing is listening now

	res := newProber(url, ExpectNoContent).Detect(context.Background())
	if res.Class != NoNetwork {
		t.Fatalf("class = %s, want %s", res.Class, NoNetwork)
	}
	if res.Probes[0].Err == "" {
		t.Error("expected the transport error to be recorded")
	}
}

func TestDetectAmbiguousPrefersPortal(t *testing.T) {
	// Some portals whitelist one well-known probe endpoint. Disagreement must
	// resolve towards "portal": locking down is the recoverable mistake.
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer open.Close()
	captive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://login.example/", http.StatusFound)
	}))
	defer captive.Close()

	p := NewProber()
	p.SkipDNSCheck = true
	p.Timeout = 2 * time.Second
	p.Probes = []Probe{
		{Name: "open", URL: open.URL + "/generate_204", Expect: ExpectNoContent},
		{Name: "captive", URL: captive.URL + "/hotspot-detect.html", Expect: ExpectAppleSuccess},
	}

	res := p.Detect(context.Background())
	if res.Class != Portal {
		t.Fatalf("class = %s, want %s", res.Class, Portal)
	}
	if !res.Ambiguous {
		t.Error("expected the disagreement to be flagged as ambiguous")
	}
	if res.PortalHost != "login.example" {
		t.Errorf("portal host = %q, want login.example", res.PortalHost)
	}
}

func TestDetectRecordsRemoteAddr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	res := newProber(srv.URL+"/generate_204", ExpectNoContent).Detect(context.Background())
	if res.Probes[0].RemoteAddr == "" {
		t.Error("expected the connected address to be captured")
	}
}

func TestSplitURL(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		ok   bool
	}{
		{"http://a.example/x", "a.example", 80, true},
		{"https://a.example/x", "a.example", 443, true},
		{"http://a.example:8080/x", "a.example", 8080, true},
		{"http://10.0.0.1/x", "10.0.0.1", 80, true},
		{"http://[fe80::1]:8080/x", "fe80::1", 8080, true},
		{"not a url", "", 0, false},
	}
	for _, c := range cases {
		host, port, ok := splitURL(c.in)
		if host != c.host || port != c.port || ok != c.ok {
			t.Errorf("splitURL(%q) = %q, %d, %t; want %q, %d, %t",
				c.in, host, port, ok, c.host, c.port, c.ok)
		}
	}
}

func TestMetaRefreshURL(t *testing.T) {
	base := "http://captive.apple.com/hotspot-detect.html"
	cases := []struct{ body, want string }{
		{`<meta http-equiv="refresh" content="0; url=http://p.example/login">`, "http://p.example/login"},
		{`<META HTTP-EQUIV=refresh CONTENT="2;URL=/login">`, "http://captive.apple.com/login"},
		{`<script>window.location = "http://p.example/go";</script>`, "http://p.example/go"},
		{`<html>nothing here</html>`, ""},
	}
	for _, c := range cases {
		if got := metaRefreshURL([]byte(c.body), base); got != c.want {
			t.Errorf("metaRefreshURL(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

func TestIsLocalAddr(t *testing.T) {
	local := []string{"192.168.0.1", "10.5.0.2", "172.16.4.4", "127.0.0.1", "169.254.1.1", "100.64.0.2"}
	public := []string{"17.253.144.10", "8.8.8.8", "2606:4700::1111", "100.128.0.1"}
	for _, s := range local {
		if !isLocalAddr(mustIP(t, s)) {
			t.Errorf("%s should count as local", s)
		}
	}
	for _, s := range public {
		if isLocalAddr(mustIP(t, s)) {
			t.Errorf("%s should not count as local", s)
		}
	}
}

// At EE WiFi one check ran to its timeout while the other had already found
// the login page, holding the page back 5 seconds. With FirstPortal the first
// portal ends detection; without it, everything is waited for.
func TestDetectFirstPortalStopsWaiting(t *testing.T) {
	captive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.0.2.1/login", http.StatusFound)
	}))
	defer captive.Close()
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(release)

	p := newProber(captive.URL+"/generate_204", ExpectNoContent)
	p.Probes = append(p.Probes, Probe{Name: "slow", URL: slow.URL + "/hotspot-detect.html", Expect: ExpectAppleSuccess})
	p.FirstPortal = true

	res := p.Detect(context.Background())
	if res.Class != Portal || res.PortalHost != "192.0.2.1" {
		t.Fatalf("class = %s, host = %q; want PORTAL at 192.0.2.1", res.Class, res.PortalHost)
	}
	if res.Took > time.Second {
		t.Errorf("took %s: waited for the slow probe (timeout %s)", res.Took, p.Timeout)
	}
	if !res.Stopped {
		t.Error("Stopped not set")
	}
	if got := res.Probes[1].Class; got != Skipped {
		t.Errorf("slow probe class = %s, want %s", got, Skipped)
	}
}

// Without a portal there is nothing to stop for: an open network waits for
// every probe, as before.
func TestDetectFirstPortalOpenWaitsForAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	p := newProber(srv.URL+"/generate_204", ExpectNoContent)
	p.FirstPortal = true
	res := p.Detect(context.Background())
	if res.Class != OpenInternet || res.Stopped {
		t.Fatalf("class = %s, stopped = %v; want OPEN_INTERNET, not stopped", res.Class, res.Stopped)
	}
}
