package state

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"portalguard/internal/firewall"
)

// ==== opening the portal's own site automatically =========================
//
// A portal's login page loads more than one host: BT Wi-Fi's needs its CDN
// for the script that reveals the page, and its registration host for the
// form. Until v0.4 each of those was a blank page and an `allow` command.
//
// Hosts on the portal's own site are now opened automatically, as the page
// asks for them. The reasoning, and why it is not the whole-domain allow that
// docs/gap-scope.md option C rejected, is in that document under option F.
// In short: the network already chooses the login page's address,
// so opening more of the same site adds little it could not already do; the
// DNS filter keeps every other app's lookups on the machine, so nothing else
// can use those addresses; and HTTPS resources still have to pass the
// browser's own certificate check.
//
// Where it cannot decide (an IP-only portal, a portal on shared hosting, a
// host on another domain), nothing is opened, and the suggestion and `allow`
// work exactly as before.

// maxAutoAllow bounds how many hosts one gap opens by itself. BT Wi-Fi needs
// three; a page asking for dozens is not a login page worth trusting blindly,
// and past the cap it falls back to asking.
const maxAutoAllow = 10

// sharedHosting lists domains whose subdomains belong to unrelated customers.
// A portal on one of these has no "own site" to open: cdn.cloudfront.net and
// evil.cloudfront.net share nothing but a hosting bill. Compared against
// siteOf's answer, so each entry is written the way siteOf would reduce it.
var sharedHosting = map[string]bool{
	// Cloud and CDN platforms
	"amazonaws.com": true, "cloudfront.net": true, "awsglobalaccelerator.com": true,
	"azurewebsites.net": true, "azureedge.net": true, "azurefd.net": true,
	"cloudapp.net": true, "trafficmanager.net": true, "windows.net": true,
	"appspot.com": true, "googleusercontent.com": true, "googleapis.com": true,
	"web.app": true, "firebaseapp.com": true, "run.app": true,
	"akamaized.net": true, "akamaiedge.net": true, "akamaihd.net": true,
	"edgekey.net": true, "edgesuite.net": true, "fastly.net": true,
	"fastlylb.net": true, "cdn77.org": true, "b-cdn.net": true,
	"cloudflare.net": true, "workers.dev": true, "pages.dev": true,
	"digitaloceanspaces.com": true, "ondigitalocean.app": true,
	// App and static hosts
	"herokuapp.com": true, "github.io": true, "gitlab.io": true,
	"netlify.app": true, "vercel.app": true, "onrender.com": true,
	"fly.dev": true, "glitch.me": true, "surge.sh": true, "now.sh": true,
	"ngrok.io": true, "ngrok-free.app": true, "repl.co": true,
	// Site builders and blogs
	"wixsite.com": true, "squarespace.com": true, "myshopify.com": true,
	"wordpress.com": true, "blogspot.com": true, "weebly.com": true,
	// Dynamic DNS
	"duckdns.org": true, "dyndns.org": true, "no-ip.com": true, "ddns.net": true,
}

// autoAllowSite is the site whose hosts may be opened automatically for a
// portal at portalHost, or "" when none may be.
func autoAllowSite(portalHost string) string {
	site := siteOf(portalHost)
	if site == "" || sharedHosting[site] {
		return ""
	}
	return site
}

// sameSite reports whether name is site itself or a host under it. The dot
// matters: "evilbtwifi.com" and "btwifi.com.evil.net" are not btwifi.com.
func sameSite(name, site string) bool {
	n := normalizeHost(name)
	return site != "" && (n == site || strings.HasSuffix(n, "."+site))
}

// errAutoClosed and errAutoCap are why an automatic open was declined. Either
// way the name is refused and reaches the suggestion, as in v0.3.
var (
	errAutoClosed = errors.New("the gap is closing")
	errAutoCap    = fmt.Errorf("already opened %d hosts automatically", maxAutoAllow)
)

// UseAutoAllow turns automatic opening of the portal's own site on or off. It
// is off for a session unless asked for, so tests and every caller written
// before it get exactly the v0.3 behaviour. Takes effect at StartDNSFilter.
func (s *Session) UseAutoAllow(on bool) {
	s.mu.Lock()
	s.autoOn = on
	s.mu.Unlock()
}

// AutoAllowed returns the hosts opened automatically in this session.
func (s *Session) AutoAllowed() []string {
	s.mu.Lock()
	a := s.auto
	s.mu.Unlock()
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.order...)
}

// autoAllow is the DNS filter's dnsfilter.AutoAllower for one gap.
type autoAllow struct {
	s    *Session
	site string

	// mu is held for the whole of an Open, and by close. That is what stops
	// an open racing a seal: once close returns, no Open is in flight and
	// none will start, so the seal cannot be followed by a stray AllowHost
	// that would open a fresh gap on a machine that was just sealed.
	mu     sync.Mutex
	closed bool
	opened map[string]bool
	order  []string
	capped bool
	// have is every address opened so far, so the browser asking again for
	// a name it already has does not reload the firewall each time.
	have map[string]bool
}

func newAutoAllow(s *Session, site string) *autoAllow {
	return &autoAllow{s: s, site: site, opened: map[string]bool{}, have: map[string]bool{}}
}

// Wants is asked about every name the filter would refuse, and a yes sends
// the query to the network. So it is a yes only for a name that is open or
// can still be opened: past the cap, a host's AAAA and HTTPS lookups were
// forwarded although its A answer would never be opened, and the network
// heard names it should not have. Found by the hostile hotspot.
func (a *autoAllow) Wants(name string) bool {
	if !sameSite(name, a.site) || !a.s.machine.Can(EventExtendGap) {
		return false
	}
	name = normalizeHost(name)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return false
	}
	if a.opened[name] || len(a.opened) < maxAutoAllow {
		return true
	}
	// Said here, the first time a host is turned away, because past the cap
	// nothing reaches Open to say it: otherwise auto-allow would stop with
	// no word as to why.
	a.noteCap()
	return false
}

// noteCap says, once, that the cap has been reached. The caller holds a.mu.
func (a *autoAllow) noteCap() {
	if !a.capped {
		a.capped = true
		a.s.logf("opened %d hosts automatically; anything more has to be allowed by hand", maxAutoAllow)
	}
}

// Open widens the gap for name, pinned to the addresses the filter was just
// given for it, on 80 and 443 only.
func (a *autoAllow) Open(name string, addrs []net.IP) error {
	name = normalizeHost(name)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || !a.s.machine.Can(EventExtendGap) {
		return errAutoClosed
	}
	if !a.opened[name] && len(a.opened) >= maxAutoAllow {
		a.noteCap()
		return errAutoCap
	}
	if a.opened[name] && a.haveAll(addrs) {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := firewall.Host{
		Name:   name,
		Addrs:  addrs,
		Ports:  []int{80, 443},
		Reason: "same site as the portal, opened automatically",
	}
	if err := a.s.fw.AllowHost(ctx, h); err != nil {
		return err
	}
	a.s.mu.Lock()
	a.s.allowed = append(a.s.allowed, h)
	a.s.mu.Unlock()
	for _, ip := range addrs {
		a.have[ip.String()] = true
	}
	// A second answer for the same name (its AAAA after its A, or a rotated
	// address) widens that host's hole; it is not a new host to announce.
	if a.opened[name] {
		return nil
	}
	a.opened[name] = true
	a.order = append(a.order, name)
	if _, err := a.s.machine.Apply(EventExtendGap, name+" (same site, automatic)"); err != nil {
		a.s.logf("%s opened but could not record the transition: %v", name, err)
	}
	a.s.logf("gap opened automatically for %s (same site as the portal)", h)
	return nil
}

func (a *autoAllow) haveAll(addrs []net.IP) bool {
	for _, ip := range addrs {
		if !a.have[ip.String()] {
			return false
		}
	}
	return true
}

// close stops any further automatic opens, waiting for one in flight.
func (a *autoAllow) close() {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
}

// stopAutoAllow is called before the gap is sealed or released.
func (s *Session) stopAutoAllow() {
	s.mu.Lock()
	a := s.auto
	s.mu.Unlock()
	if a != nil {
		a.close()
	}
}

// ==== without the DNS filter ==============================================
//
// With no filter (no rdr hook, a VPN's leftover `set skip on lo0`, or
// -no-dns-filter), lookups go straight to the network, and the first sign of
// a missing host is pf's log seeing its name go past. That is too late for
// the browser's first try, which has already been blocked, so a host opened
// this way asks for a reload. Still better than a command to type.

// startAutoFromLog sets up auto-allow for a gap opened without the filter.
// Called by OpenGap; a no-op when the filter already set it up, or when it is
// off, or when the portal has no site of its own.
func (s *Session) startAutoFromLog(portalHost string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.autoOn || s.auto != nil || s.dns != nil {
		return
	}
	if site := autoAllowSite(portalHost); site != "" {
		s.auto = newAutoAllow(s, site)
		s.logf("auto-allow: no DNS filter, so hosts on %s open when the firewall's log sees them; the page may need a reload", site)
	}
}

// autoFromLog opens the portal's own hosts that pf's log has seen looked up.
// Called from WaitForAuth, before the suggestion, so a host it opens is not
// also printed as a command to run.
func (s *Session) autoFromLog(ctx context.Context) {
	s.mu.Lock()
	a, filtered := s.auto, s.dns != nil
	s.mu.Unlock()
	if a == nil || filtered || a.full() {
		return
	}
	for _, name := range s.SuggestAllow() {
		if !a.Wants(name) {
			continue
		}
		h, err := autoResolve(ctx, name, []int{80, 443}, "")
		if err != nil {
			continue
		}
		if err := a.Open(name, h.Addrs); err != nil {
			s.logf("could not open %s automatically: %v", name, err)
			continue
		}
		s.logf("reload the login page if it is still blank")
	}
}

// autoResolve is resolveHost, swappable so tests never touch real DNS.
var autoResolve = resolveHost

// full reports whether the cap has been reached.
func (a *autoAllow) full() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed || len(a.opened) >= maxAutoAllow
}
