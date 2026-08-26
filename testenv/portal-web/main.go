// Command fakeportal is a captive portal for testing Portalguard without
// going to a cafe.
//
// It behaves the way a real hotel portal does: every request is intercepted
// until somebody clicks "Accept", after which the well-known probe endpoints
// answer honestly and detection flips to OPEN_INTERNET.
//
// What it does not do is route traffic. It cannot: it is one HTTP server, not
// a gateway. It simulates the portal's *answers*, which is exactly the surface
// Portalguard's detection reads, so it exercises the real code path end to
// end. Testing that traffic is genuinely blocked needs the pf backend and a
// real network.
//
// It never asks for credentials, because Portalguard never submits any.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// interceptMode selects how the portal announces itself, so both branches of
// the detector can be exercised.
type interceptMode string

const (
	// modeRedirect is the common case: a 302 to the login page.
	modeRedirect interceptMode = "redirect"
	// modeInterstitial serves HTTP 200 with a meta-refresh bounce, which is
	// what portals that want to set a cookie first tend to do.
	modeInterstitial interceptMode = "interstitial"
	// mode511 is the RFC 6585 way, which almost nothing does in practice.
	mode511 interceptMode = "511"
)

// portal holds the one bit of state that matters: has the human accepted yet.
type portal struct {
	authed   atomic.Bool
	loginURL string
	mode     interceptMode
}

// appleSuccessBody is byte-for-byte what captive.apple.com serves.
const appleSuccessBody = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>\n"

func main() {
	var (
		addr     = flag.String("addr", envOr("LISTEN", ":8080"), "listen address")
		loginURL = flag.String("login-url", envOr("PORTAL_URL", ""), "externally reachable URL of the login page")
		mode     = flag.String("mode", envOr("MODE", string(modeRedirect)), "interception style: redirect|interstitial|511")
	)
	flag.Parse()

	p := &portal{loginURL: *loginURL, mode: interceptMode(*mode)}
	switch p.mode {
	case modeRedirect, modeInterstitial, mode511:
	default:
		log.Fatalf("unknown mode %q", p.mode)
	}

	mux := http.NewServeMux()
	// The probe endpoints, on the paths the real ones use, so a probe list can
	// be pointed here by swapping only the host.
	mux.HandleFunc("/generate_204", p.handleGenerate204)
	mux.HandleFunc("/hotspot-detect.html", p.handleAppleProbe)
	// The portal's own pages are never intercepted: that would be a loop.
	mux.HandleFunc("/login", p.handleLogin)
	mux.HandleFunc("/accept", p.handleAccept)
	mux.HandleFunc("/reset", p.handleReset)
	mux.HandleFunc("/status", p.handleStatus)
	// Everything else gets the portal treatment, as on a real network.
	mux.HandleFunc("/", p.handleCatchAll)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           logging(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("fake captive portal on %s (mode=%s, login=%s)", *addr, p.mode, p.effectiveLoginURL(nil))
	log.Printf("click Accept at the login page, or POST /accept, to simulate a successful login")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// effectiveLoginURL returns the login URL to send clients to. When it was not
// configured we build it from the request's Host header, which keeps the
// container usable from the LAN without knowing its own address.
func (p *portal) effectiveLoginURL(r *http.Request) string {
	if p.loginURL != "" {
		return p.loginURL
	}
	if r != nil && r.Host != "" {
		return "http://" + r.Host + "/login"
	}
	return "http://localhost:8080/login"
}

// handleGenerate204 answers the Google-style probe.
func (p *portal) handleGenerate204(w http.ResponseWriter, r *http.Request) {
	if p.authed.Load() {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p.intercept(w, r)
}

// handleAppleProbe answers the Apple-style probe.
func (p *portal) handleAppleProbe(w http.ResponseWriter, r *http.Request) {
	if p.authed.Load() {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(appleSuccessBody))
		return
	}
	p.intercept(w, r)
}

func (p *portal) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	if p.authed.Load() {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<html><body><h1>Online</h1><p>You asked for %s. "+
			"A real network would be routing this now.</p></body></html>", template.HTMLEscapeString(r.URL.Path))
		return
	}
	p.intercept(w, r)
}

// intercept is the portal's answer to any request made before login.
func (p *portal) intercept(w http.ResponseWriter, r *http.Request) {
	login := p.effectiveLoginURL(r)
	switch p.mode {
	case mode511:
		w.Header().Set("Location", login)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNetworkAuthenticationRequired)
		_, _ = fmt.Fprintf(w, `<html><body>You must <a href="%s">log in</a>.</body></html>`, login)
	case modeInterstitial:
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<html><head>
<meta http-equiv="refresh" content="0; url=%s">
</head><body>Redirecting you to the login page...</body></html>`, login)
	default:
		http.Redirect(w, r, login, http.StatusFound)
	}
}

func (p *portal) handleAccept(w http.ResponseWriter, r *http.Request) {
	p.authed.Store(true)
	log.Print("ACCEPTED: probes will now report open internet")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (p *portal) handleReset(w http.ResponseWriter, r *http.Request) {
	p.authed.Store(false)
	log.Print("RESET: the portal is intercepting again")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (p *portal) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authenticated": p.authed.Load(),
		"mode":          string(p.mode),
	})
}

func (p *portal) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	data := struct {
		Authed bool
		Mode   string
	}{p.authed.Load(), string(p.mode)}
	if err := loginTmpl.Execute(w, data); err != nil {
		log.Printf("render login page: %v", err)
	}
}

// loginTmpl is deliberately a terms-acceptance page, not a credential form:
// Portalguard's whole design rests on the human doing the logging in, so the
// test fixture should not model anything it could be tempted to automate.
var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Guest Wi-Fi</title>
<style>
 body{font:16px/1.5 -apple-system,system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;color:#111}
 .ok{color:#0a7a35} .bad{color:#a12} button{font:inherit;padding:.6rem 1.2rem;cursor:pointer}
 code{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px}
</style></head><body>
<h1>Guest Wi-Fi</h1>
{{if .Authed}}
<p class="ok"><strong>You are connected.</strong> Probe endpoints now answer normally,
so <code>portalguard detect</code> should report OPEN_INTERNET.</p>
<form method="get" action="/reset"><button>Log me out again</button></form>
{{else}}
<p class="bad">This network requires you to accept the terms before you can browse.</p>
<p>Interception mode: <code>{{.Mode}}</code></p>
<form method="post" action="/accept"><button>Accept and connect</button></form>
{{end}}
</body></html>
`))

// logging prints one line per request so you can watch detection happen.
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s  ua=%q", r.RemoteAddr, r.Method, r.URL.Path, truncate(r.UserAgent(), 40))
		next.ServeHTTP(w, r)
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
