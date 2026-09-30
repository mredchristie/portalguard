package portal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// ==== what a clean response looks like ====================================
// Each probe has a known-good answer. Anything else means someone is
// in the middle.

// Expectation describes what an untampered response to a probe looks like.
type Expectation string

const (
	// ExpectAppleSuccess is Apple's hotspot-detect page: HTTP 200 with a body
	// whose title is "Success".
	ExpectAppleSuccess Expectation = "apple_success"
	// ExpectNoContent is Google's generate_204 style endpoint: HTTP 204 with
	// an empty body.
	ExpectNoContent Expectation = "no_content"
)

// Probe is one endpoint whose untampered response we know.
type Probe struct {
	Name   string      `json:"name"`
	URL    string      `json:"url"`
	Expect Expectation `json:"expect"`
}

// DefaultProbes is the probe list used when none is configured. Both are plain
// HTTP by design; both are endpoints portals are used to intercepting.
func DefaultProbes() []Probe {
	return []Probe{
		{
			Name:   "apple",
			URL:    "http://captive.apple.com/hotspot-detect.html",
			Expect: ExpectAppleSuccess,
		},
		{
			Name:   "google",
			URL:    "http://connectivitycheck.gstatic.com/generate_204",
			Expect: ExpectNoContent,
		},
	}
}

// defaultUserAgent mimics macOS's own captive network assistant. Some portals
// only serve their redirect to a client that looks like a captive-network
// probe, so imitating it makes detection more reliable, not less honest.
const defaultUserAgent = "CaptiveNetworkSupport-455.1 wispr"

// maxBody bounds how much of a probe response we read. Portal login pages can
// be large; we only need enough to recognise them and to spot a meta refresh.
const maxBody = 64 << 10

// ==== the prober ==========================================================
// Config for a run: probe list, timeouts, which resolver to use.

// Prober runs the probe list against the current network.
//
// The zero value is not usable; call NewProber.
type Prober struct {
	// Probes is the endpoint list. Defaults to DefaultProbes.
	Probes []Probe
	// Timeout bounds each individual probe.
	Timeout time.Duration
	// UserAgent is sent with every probe.
	UserAgent string
	// Resolver is used for probe hostnames and for the DNS integrity check.
	// nil means the system resolver.
	Resolver *net.Resolver
	// SkipDNSCheck disables the resolver-integrity checks, which cost one
	// extra lookup.
	SkipDNSCheck bool
	// OnPortal, if set, is told the login host as soon as the probes name
	// it, before it is resolved and pinned. Detection through a lockdown
	// uses it to let exactly that lookup through its filter.
	OnPortal func(host string)
	// Control, if set, is applied to every connection the probes make: how
	// detection binds them to the Wi-Fi interface when macOS has joined a
	// network but not yet given it a default route.
	Control func(network, address string, c syscall.RawConn) error
}

// NewProber returns a Prober with sensible defaults.
func NewProber() *Prober {
	return &Prober{
		Probes:    DefaultProbes(),
		Timeout:   5 * time.Second,
		UserAgent: defaultUserAgent,
	}
}

// ==== results =============================================================
// What one probe told us, kept per-probe so -v can show the working.

// ProbeResult is what one probe endpoint told us.
type ProbeResult struct {
	Probe      Probe          `json:"probe"`
	Class      Classification `json:"class"`
	Reason     string         `json:"reason"`
	StatusCode int            `json:"status_code,omitempty"`
	// Location is the raw redirect target, when the response was a redirect.
	Location string `json:"location,omitempty"`
	// PortalURL is where this probe thinks the login page is: a Location
	// header, a meta refresh, or the probe's own URL when the response was
	// simply substituted.
	PortalURL string `json:"portal_url,omitempty"`
	// RemoteAddr is the address we actually connected to. When a probe for
	// captive.apple.com lands on 192.168.x.x, the network is intercepting.
	RemoteAddr  string        `json:"remote_addr,omitempty"`
	BodySnippet string        `json:"body_snippet,omitempty"`
	Elapsed     time.Duration `json:"elapsed"`
	Err         string        `json:"err,omitempty"`
	// dnsErr records that the failure was specifically name resolution.
	dnsErr bool
}

// ==== running the probes ==================================================
// Fire every probe, then fold the answers into one verdict.

// Detect runs every probe and returns a single verdict.
func (p *Prober) Detect(ctx context.Context) Result {
	start := time.Now()
	probes := p.Probes
	if len(probes) == 0 {
		probes = DefaultProbes()
	}

	// All at once: each can wait out its own timeout on a slow network, and
	// one after another they added up (9.7 seconds at EE WiFi, where 0.9 was
	// usual). Results keep the probe list's order, so classification is
	// exactly as before.
	res := Result{At: start, Probes: make([]ProbeResult, len(probes))}
	var wg sync.WaitGroup
	for i, pr := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res.Probes[i] = p.runProbe(ctx, pr)
		}()
	}
	if !p.SkipDNSCheck {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res.DNS = p.checkDNS(ctx, probes)
		}()
	}
	wg.Wait()

	p.classify(&res)

	if res.Class == Portal && res.PortalURL != "" {
		if p.OnPortal != nil {
			if host, _, ok := splitURL(res.PortalURL); ok {
				p.OnPortal(host)
			}
		}
		p.pinPortal(ctx, &res)
	}
	res.Took = time.Since(start)
	return res
}

// classify folds the per-probe verdicts into one.
func (p *Prober) classify(res *Result) {
	var open, portal, dead, dnsFail int
	for _, pr := range res.Probes {
		switch pr.Class {
		case OpenInternet:
			open++
		case Portal:
			portal++
			if res.PortalURL == "" && pr.PortalURL != "" {
				res.PortalURL = pr.PortalURL
			}
		case NoNetwork:
			dead++
			if pr.dnsErr {
				dnsFail++
			}
		}
	}

	switch {
	case portal > 0:
		res.Class = Portal
		// A portal that whitelists one probe endpoint still needs a login.
		res.Ambiguous = open > 0
	case open > 0:
		res.Class = OpenInternet
	default:
		res.Class = NoNetwork
		res.DNSFailure = dead > 0 && dnsFail == dead
	}

	// A hijacked resolver on a network where every probe timed out is still a
	// portal: the network is answering DNS but dropping our traffic.
	if res.Class == NoNetwork && res.DNS.Hijacked {
		res.Class = Portal
		res.Ambiguous = true
	}

	if u := res.PortalURL; u != "" {
		if host, port, ok := splitURL(u); ok {
			res.PortalHost, res.PortalPort = host, port
		}
	}
}

// pinPortal resolves the portal hostname so firewall rules can be written
// against addresses rather than names.
func (p *Prober) pinPortal(ctx context.Context, res *Result) {
	if res.PortalHost == "" {
		return
	}
	if ip := net.ParseIP(res.PortalHost); ip != nil {
		res.PortalAddrs = []string{ip.String()}
		return
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	addrs, err := p.resolver().LookupIPAddr(ctx, res.PortalHost)
	if err != nil {
		return
	}
	for _, a := range addrs {
		res.PortalAddrs = append(res.PortalAddrs, a.IP.String())
	}
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 5 * time.Second
}

func (p *Prober) resolver() *net.Resolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	return net.DefaultResolver
}

// runProbe performs a single probe request and classifies the response.
func (p *Prober) runProbe(ctx context.Context, probe Probe) ProbeResult {
	out := ProbeResult{Probe: probe}
	start := time.Now()
	defer func() { out.Elapsed = time.Since(start) }()

	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.URL, nil)
	if err != nil {
		out.Class = NoNetwork
		out.Reason = "malformed probe URL"
		out.Err = err.Error()
		return out
	}
	ua := p.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	req.Header.Set("User-Agent", ua)
	// Any cached 204 would make a portal look like open internet.
	req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	req.Header.Set("Pragma", "no-cache")

	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				out.RemoteAddr = info.Conn.RemoteAddr().String()
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := p.client().Do(req)
	if err != nil {
		out.Class = NoNetwork
		out.Err = err.Error()
		out.dnsErr = isDNSError(err)
		switch {
		case out.dnsErr:
			out.Reason = "name resolution failed"
		case errors.Is(err, context.DeadlineExceeded):
			out.Reason = "timed out"
		default:
			out.Reason = "request failed"
		}
		return out
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	out.StatusCode = resp.StatusCode
	out.BodySnippet = snippet(body)
	out.Location = resp.Header.Get("Location")

	classifyResponse(&out, probe, resp, body)
	return out
}

// client builds a fresh HTTP client per probe: no connection reuse, no proxy,
// and redirects surfaced rather than followed, because the redirect target is
// exactly what we are looking for.
func (p *Prober) client() *http.Client {
	dialer := &net.Dialer{Timeout: p.timeout(), Resolver: p.resolver(), Control: p.Control}
	return &http.Client{
		Timeout: p.timeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:                 nil, // a system proxy would mask interception
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,
			DisableCompression:    true,
			ResponseHeaderTimeout: p.timeout(),
		},
	}
}

// ==== reading a single response ===========================================
// Redirect, 511, meta-refresh, or the wrong body: all mean a portal.

// classifyResponse turns one HTTP response into a per-probe verdict.
func classifyResponse(out *ProbeResult, probe Probe, resp *http.Response, body []byte) {
	// RFC 6585: the honest way for a portal to announce itself.
	if resp.StatusCode == http.StatusNetworkAuthenticationRequired {
		out.Class = Portal
		out.Reason = "511 Network Authentication Required"
		out.PortalURL = firstNonEmpty(absolute(resp, out.Location), metaRefreshURL(body, probe.URL), probe.URL)
		return
	}

	if isRedirect(resp.StatusCode) {
		if loc := absolute(resp, out.Location); loc != "" {
			out.Class = Portal
			out.Reason = fmt.Sprintf("%d redirect to %s", resp.StatusCode, loc)
			out.PortalURL = loc
			return
		}
		out.Class = Portal
		out.Reason = fmt.Sprintf("%d redirect with no usable Location", resp.StatusCode)
		out.PortalURL = probe.URL
		return
	}

	switch probe.Expect {
	case ExpectNoContent:
		if resp.StatusCode == http.StatusNoContent && len(body) == 0 {
			out.Class = OpenInternet
			out.Reason = "204 with empty body, as expected"
			return
		}
	case ExpectAppleSuccess:
		if resp.StatusCode == http.StatusOK && isAppleSuccess(body) {
			out.Class = OpenInternet
			out.Reason = "expected success page"
			return
		}
	default:
		// An unknown expectation can only judge transport-level success.
		if resp.StatusCode == http.StatusOK {
			out.Class = OpenInternet
			out.Reason = "200 OK (no body expectation configured)"
			return
		}
	}

	// Right status, wrong content, or an outright substituted page: something
	// answered on the endpoint's behalf.
	out.Class = Portal
	out.Reason = fmt.Sprintf("unexpected response (%d, %d bytes) where %s was expected",
		resp.StatusCode, len(body), probe.Expect)
	out.PortalURL = firstNonEmpty(metaRefreshURL(body, probe.URL), probe.URL)
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// appleSuccessRe matches the body Apple serves at hotspot-detect.html.
var appleSuccessRe = regexp.MustCompile(`(?i)<title>\s*success\s*</title>`)

func isAppleSuccess(body []byte) bool {
	return appleSuccessRe.Match(body)
}

// metaRefreshRe finds `<meta http-equiv="refresh" content="0; url=...">`,
// which is how many portals bounce a client without sending a 302.
var metaRefreshRe = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']([^"']*)["']`)

// refreshURLRe finds the url= part of a refresh's content attribute.
var refreshURLRe = regexp.MustCompile(`(?i)url\s*=`)

// jsRedirectRe finds the other common bounce: window.location = "...".
var jsRedirectRe = regexp.MustCompile(`(?is)(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']`)

// metaRefreshURL extracts a login URL from a portal's interstitial body.
func metaRefreshURL(body []byte, base string) string {
	// Every refresh on the page, not just the first: one with an empty url=
	// resolves to the page itself, and a page that leads with one would
	// otherwise hide the real login behind it.
	for _, m := range metaRefreshRe.FindAllSubmatch(body, 8) {
		content := string(m[1])
		// Matched on the original bytes. Lowercasing a copy to search it
		// shifts every offset after an invalid byte (it becomes a 3-byte
		// replacement character), and slicing the original with that offset
		// panicked: a portal page could crash detection. Found by
		// FuzzMetaRefresh.
		if loc := refreshURLRe.FindStringIndex(content); loc != nil {
			if ref := strings.Trim(strings.TrimSpace(content[loc[1]:]), `"'`); ref != "" {
				return resolveRef(base, ref)
			}
		}
	}
	if m := jsRedirectRe.FindSubmatch(body); m != nil {
		return resolveRef(base, string(m[1]))
	}
	return ""
}

// resolveRef turns a possibly relative URL into an absolute one.
func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	return b.ResolveReference(r).String()
}

// absolute resolves a Location header against the request URL.
func absolute(resp *http.Response, loc string) string {
	if loc == "" {
		return ""
	}
	if resp.Request != nil && resp.Request.URL != nil {
		if u, err := resp.Request.URL.Parse(loc); err == nil {
			return u.String()
		}
	}
	return loc
}

// ==== small helpers =======================================================
// URL parsing and string tidying. Nothing clever here.

// splitURL returns the host and effective port of a URL.
func splitURL(raw string) (host string, port int, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", 0, false
	}
	host = u.Hostname()
	if ps := u.Port(); ps != "" {
		// The portal writes this URL. A port pf cannot take would fail the
		// gap's whole ruleset, so one out of range is treated like one that
		// does not parse: the host stands, on the default ports. Found by
		// FuzzSplitURL.
		p, err := strconv.Atoi(ps)
		if err != nil || p < 1 || p > 65535 {
			return host, 0, host != ""
		}
		return host, p, true
	}
	switch u.Scheme {
	case "https":
		return host, 443, true
	default:
		return host, 80, true
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func snippet(body []byte) string {
	const n = 240
	s := strings.Join(strings.Fields(string(body)), " ")
	if len(s) > n {
		// Back off to a character boundary: a byte cut can split one, and
		// the half left over is not text.
		cut := n
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		return s[:cut] + "..."
	}
	return s
}

// isDNSError reports whether an error came from name resolution rather than
// from the connection itself.
func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}
