// Command hotspot is a BT-shaped captive portal, spread across hosts the way
// real ones are, for running Portalguard against with nothing on loopback.
//
// testenv/portal-web is one host on 127.0.0.1, and loopback is the one path
// the lockdown never filters - so anything aimed at it passes whether or not
// the gap rules work. This fixture runs each host in its own container, each
// with its own address on the container network, reached over a bridge
// interface pf filters like any other. Blocked means blocked.
//
// The shape is the one found at BT Wi-Fi (see docs/gap-scope.md):
//
//	www   the login page, on 8443, plus the probe interception on 80
//	      and the network's DNS server, which lies until you log in
//	cdn   the script that reveals the login page, and its stylesheet
//	reg   where the login form posts
//	net   "the internet": where the probe names resolve once you are in
//
// The login page ships hidden and is revealed by a script from cdn, so with
// cdn blocked it comes up blank, exactly as BT's did. With reg blocked the
// button does nothing. And once you are logged in, the probe names resolve
// to net - outside the gap - which is the case that showed the re-probe
// could never see a login finish.
//
// One binary, four roles, picked by -role. See testenv/hotspot.sh.
//
// It never asks for credentials: Portalguard never submits any, so the
// fixture does not model anything it could be tempted to automate.
package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// appleSuccessBody is byte-for-byte what captive.apple.com serves.
const appleSuccessBody = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>\n"

type config struct {
	role   string
	domain string
	self   net.IP
	cdn    net.IP
	reg    net.IP
	inet   net.IP
	secret string
	certs  string
}

func main() {
	var c config
	var self, cdn, reg, inet string
	flag.StringVar(&c.role, "role", env("ROLE", ""), "www | cdn | reg | net")
	flag.StringVar(&c.domain, "domain", env("DOMAIN", "guestwifi.test"), "the portal's domain")
	flag.StringVar(&self, "self", env("SELF_IP", ""), "www: this host's address (default: its first non-loopback IPv4)")
	flag.StringVar(&cdn, "cdn", env("CDN_IP", ""), "www: the cdn host's address")
	flag.StringVar(&reg, "reg", env("REG_IP", ""), "www: the reg host's address")
	flag.StringVar(&inet, "net", env("NET_IP", ""), "www: where every other name resolves after login")
	flag.StringVar(&c.secret, "secret", env("SECRET", ""), "shared by www and reg, so only reg can complete a login")
	flag.StringVar(&c.certs, "certs", env("CERTS", "/pg/certs"), "directory holding cert.pem and key.pem; HTTPS is served only if present")
	flag.Parse()
	c.self, c.cdn, c.reg, c.inet = net.ParseIP(self), net.ParseIP(cdn), net.ParseIP(reg), net.ParseIP(inet)
	if c.self == nil {
		c.self = ownAddr()
	}

	switch c.role {
	case "www":
		if c.self == nil || c.cdn == nil || c.reg == nil || c.inet == nil || c.secret == "" {
			log.Fatal("www needs -self, -cdn, -reg, -net and -secret")
		}
		runWWW(c)
	case "cdn":
		runCDN(c)
	case "reg":
		if c.secret == "" {
			log.Fatal("reg needs -secret")
		}
		runReg(c)
	case "net":
		runNet()
	default:
		log.Fatalf("unknown -role %q", c.role)
	}
}

// ==== www: the portal, its probe interception, and its DNS =================

type portal struct {
	config
	authed atomic.Bool

	// Names asked of this network's DNS since /dnsmark, which is how a test
	// proves what left the machine during the gap: this server is the
	// network's resolver, so a name that never arrives here never left.
	logMu   sync.Mutex
	marked  bool
	dnsSeen []string
}

func (p *portal) host(sub string) string { return sub + "." + p.domain }

func (p *portal) loginURL() string { return "http://" + p.host("www") + ":8443/login" }

// scheme is https when certificates were supplied, so the page references
// cdn and reg the way BT's does, and remembered hosts can pass a real
// certificate check.
func (p *portal) scheme() string {
	if haveCerts(p.certs) {
		return "https"
	}
	return "http"
}

func runWWW(c config) {
	p := &portal{config: c}

	go p.serveDNS()

	// Port 80: what the OS probes and any plain-HTTP page hit. Intercepted
	// until login, like every hotel network.
	probes := http.NewServeMux()
	probes.HandleFunc("/", p.handleIntercept)
	go serve(":80", probes)

	// Port 8443: the login page, on the odd port BT uses.
	site := http.NewServeMux()
	site.HandleFunc("/login", p.handleLogin)
	site.HandleFunc("/complete", p.handleComplete)
	site.HandleFunc("/accept", p.handleAccept)
	site.HandleFunc("/reset", p.handleReset)
	site.HandleFunc("/status", p.handleStatus)
	site.HandleFunc("/dnsmark", p.handleDNSMark)
	site.HandleFunc("/dnslog", p.handleDNSLog)
	site.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	log.Printf("www: login page %s, dns on :53, cdn=%s reg=%s net=%s", p.loginURL(), p.cdn, p.reg, p.inet)
	serve(":8443", site)
}

func (p *portal) handleIntercept(w http.ResponseWriter, r *http.Request) {
	if p.authed.Load() {
		// DNS has moved the probe names to net by now; this only answers a
		// client still holding a cached address.
		answerProbe(w, r)
		return
	}
	http.Redirect(w, r, p.loginURL(), http.StatusFound)
}

func (p *portal) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{
		"Authed":   p.authed.Load(),
		"CDN":      p.scheme() + "://" + p.host("cdn"),
		"Reg":      p.scheme() + "://" + p.host("reg"),
		"Complete": "http://" + p.host("www") + ":8443/complete",
	}
	if err := loginPage.Execute(w, data); err != nil {
		log.Printf("render login page: %v", err)
	}
}

// handleComplete is where reg sends the browser after the form is posted.
// Only reg knows the secret, so the login cannot complete without reg having
// been reached - which is what makes a blocked reg a failed login.
func (p *portal) handleComplete(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("grant") != p.secret {
		http.Error(w, "this login was not granted", http.StatusForbidden)
		return
	}
	p.authed.Store(true)
	log.Print("LOGGED IN: probe names now resolve to the internet")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleAccept logs in without the browser, for scripted recordings.
func (p *portal) handleAccept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p.authed.Store(true)
	log.Print("LOGGED IN (scripted): probe names now resolve to the internet")
	w.WriteHeader(http.StatusNoContent)
}

func (p *portal) handleReset(w http.ResponseWriter, r *http.Request) {
	p.authed.Store(false)
	log.Print("RESET: intercepting again")
	w.WriteHeader(http.StatusNoContent)
}

func (p *portal) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": p.authed.Load()})
}

// handleDNSMark starts a fresh record of the names asked of this resolver.
func (p *portal) handleDNSMark(w http.ResponseWriter, r *http.Request) {
	p.logMu.Lock()
	p.marked, p.dnsSeen = true, nil
	p.logMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// handleDNSLog returns every distinct name asked since the mark.
func (p *portal) handleDNSLog(w http.ResponseWriter, r *http.Request) {
	p.logMu.Lock()
	names := append([]string(nil), p.dnsSeen...)
	p.logMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(names)
}

func (p *portal) recordDNS(name string) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if !p.marked {
		return
	}
	for _, n := range p.dnsSeen {
		if n == name {
			return
		}
	}
	p.dnsSeen = append(p.dnsSeen, name)
}

// ==== the DNS server ======================================================
// The portal's own names always resolve truthfully. Everything else points
// at the portal until login, and at "the internet" after it.

func (p *portal) resolve(name string) net.IP {
	switch strings.TrimSuffix(strings.ToLower(name), ".") {
	case p.host("www"):
		return p.self
	case p.host("cdn"):
		return p.cdn
	case p.host("reg"):
		return p.reg
	}
	if p.authed.Load() {
		return p.inet
	}
	return p.self
}

func (p *portal) serveDNS() {
	conn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatalf("dns: %v", err)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("dns: read: %v", err)
			continue
		}
		reply, name, err := p.answer(buf[:n])
		if err != nil {
			log.Printf("dns: %v", err)
			continue
		}
		log.Printf("dns: %s asked for %s", from, name)
		p.recordDNS(name)
		_, _ = conn.WriteTo(reply, from)
	}
}

// answer builds the reply to one query. It handles exactly what a stub
// resolver sends - one question, class IN - and answers A with one address
// and anything else with an empty NOERROR, so AAAA lookups fall back to v4.
func (p *portal) answer(q []byte) (reply []byte, name string, err error) {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil, "", fmt.Errorf("not a single-question query")
	}
	var labels []string
	i := 12
	for {
		if i >= len(q) {
			return nil, "", fmt.Errorf("truncated name")
		}
		l := int(q[i])
		i++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || i+l > len(q) {
			return nil, "", fmt.Errorf("unsupported name encoding")
		}
		labels = append(labels, string(q[i:i+l]))
		i += l
	}
	if i+4 > len(q) {
		return nil, "", fmt.Errorf("truncated question")
	}
	qtype := binary.BigEndian.Uint16(q[i : i+2])
	question := q[12 : i+4]
	name = strings.Join(labels, ".")

	reply = make([]byte, 12, 12+len(question)+16)
	copy(reply[0:2], q[0:2])     // id
	reply[2] = 0x84 | (q[2] & 1) // QR, AA, and RD copied back
	reply[3] = 0x80              // RA, NOERROR
	binary.BigEndian.PutUint16(reply[4:6], 1)
	reply = append(reply, question...)

	ip := p.resolve(name).To4()
	if qtype != 1 || ip == nil {
		return reply, name, nil
	}
	binary.BigEndian.PutUint16(reply[6:8], 1)
	reply = append(reply,
		0xC0, 0x0C, // the name, by pointer to the question
		0, 1, 0, 1, // A, IN
		0, 0, 0, 2, // TTL 2s: answers change at login, so nothing may cache them
		0, 4)
	reply = append(reply, ip...)
	return reply, name, nil
}

// ==== cdn: the script the login page cannot render without ================

func runCDN(c config) {
	mux := http.NewServeMux()
	mux.HandleFunc("/site.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, siteJS)
	})
	mux.HandleFunc("/site.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, siteCSS)
	})
	log.Print("cdn: serving site.js and site.css")
	serveBoth(c, mux)
}

// ==== reg: where the login form posts =====================================

func runReg(c config) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		back, err := url.Parse(r.FormValue("return"))
		if err != nil || back.Host == "" {
			http.Error(w, "no return address", http.StatusBadRequest)
			return
		}
		q := back.Query()
		q.Set("grant", c.secret)
		back.RawQuery = q.Encode()
		log.Printf("reg: login granted, sending the browser back to %s", back.Host)
		http.Redirect(w, r, back.String(), http.StatusSeeOther)
	})
	log.Print("reg: accepting logins")
	serveBoth(c, mux)
}

// ==== net: the internet, as far as the probes can tell ====================

func runNet() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", answerProbe)
	log.Print("net: answering the connectivity probes")
	serve(":80", mux)
}

// answerProbe is what the real probe endpoints serve.
func answerProbe(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/generate_204":
		w.WriteHeader(http.StatusNoContent)
	case "/hotspot-detect.html":
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, appleSuccessBody)
	default:
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h1>The internet</h1><p>A stand-in, for the probes.</p></body></html>")
	}
}

// ==== plumbing ============================================================

// Keep-alives are off on every server. Portalguard kills every connection
// to the gap's addresses when it seals, silently, so a browser holding one
// open from an earlier run sends its next request - the Accept click - into a
// connection pf no longer knows, and waits on it with nothing on screen to say
// why. That is what one take of the demo did. A fresh connection per request
// cannot outlive a seal.
func serve(addr string, h http.Handler) {
	srv := &http.Server{Addr: addr, Handler: logging(h), ReadHeaderTimeout: 5 * time.Second}
	srv.SetKeepAlivesEnabled(false)
	log.Fatal(srv.ListenAndServe())
}

// serveBoth serves h on 80, and on 443 too when certificates are present.
func serveBoth(c config, h http.Handler) {
	if haveCerts(c.certs) {
		go func() {
			srv := &http.Server{
				Addr:              ":443",
				Handler:           logging(h),
				ReadHeaderTimeout: 5 * time.Second,
				TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
			}
			srv.SetKeepAlivesEnabled(false)
			log.Fatal(srv.ListenAndServeTLS(c.certs+"/cert.pem", c.certs+"/key.pem"))
		}()
	}
	serve(":80", h)
}

// ownAddr is this host's first non-loopback IPv4 address: inside a container,
// the one the container network gave it.
func ownAddr() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			return n.IP.To4()
		}
	}
	return nil
}

func haveCerts(dir string) bool {
	_, err1 := os.Stat(dir + "/cert.pem")
	_, err2 := os.Stat(dir + "/key.pem")
	return err1 == nil && err2 == nil
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s%s", r.RemoteAddr, r.Method, r.Host, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// ==== the page ============================================================

// The login page ships hidden, the way BT's does: `.site { display: none }`
// until a script from cdn reveals it. Block cdn and you get a white page with
// no error on it, which is the whole point of the fixture.
var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbour Hotel Guest Wi-Fi</title>
<link rel="preconnect" href="{{.Reg}}">
<link rel="stylesheet" href="{{.CDN}}/site.css">
<style>.site{display:none}</style>
<script src="{{.CDN}}/site.js" defer></script>
</head><body>
<main class="site">
  <header><span class="mark">H</span> Harbour Hotel</header>
  {{if .Authed}}
  <h1>You're connected</h1>
  <p>Enjoy your stay. You can close this page.</p>
  {{else}}
  <h1>Guest Wi-Fi</h1>
  <p>Complimentary for guests. By connecting you agree to the terms of use.</p>
  <form method="post" action="{{.Reg}}/login">
    <input type="hidden" name="return" value="{{.Complete}}">
    <button>Accept and connect</button>
  </form>
  {{end}}
</main>
</body></html>
`))

const siteJS = `document.addEventListener('DOMContentLoaded', function () {
  document.querySelector('.site').style.display = 'block';
});
`

const siteCSS = `body{margin:0;min-height:100vh;display:grid;place-items:center;
  font:17px/1.5 -apple-system,system-ui,sans-serif;background:#0f2a3d;color:#0f2a3d}
.site{background:#fff;border-radius:14px;padding:2.2rem 2.4rem;max-width:26rem;
  box-shadow:0 20px 50px rgba(0,0,0,.35)}
header{display:flex;align-items:center;gap:.6rem;font-weight:600;letter-spacing:.02em;margin-bottom:1rem}
.mark{display:inline-grid;place-items:center;width:2rem;height:2rem;border-radius:50%;
  background:#c8a24a;color:#fff;font-weight:700}
h1{margin:.2rem 0 .4rem;font-size:1.7rem}
p{color:#3d5566}
button{margin-top:1rem;width:100%;font:inherit;font-weight:600;padding:.8rem;border:0;
  border-radius:10px;background:#c8a24a;color:#fff;cursor:pointer}
`
