package portal

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
)

// ==== following the portal's own redirects ================================
//
// The probe stops at the first redirect on purpose: that Location is what
// detection is looking for. But a portal can bounce through more hosts before
// the login page, and each one missing from the gap is a dead end the user
// cannot see past. Every hop is an address the portal itself sent us to, so
// pinning it costs almost nothing in trust. See docs/gap-scope.md, option B.

// maxHops bounds the chain. Real portals take one or two; more than this is a
// loop or something hostile, and either way not worth following.
const maxHops = 5

// Hop is one host the portal's redirect chain passed through.
type Hop struct {
	URL   string   `json:"url"`
	Host  string   `json:"host"`
	Port  int      `json:"port"`
	Addrs []string `json:"addrs,omitempty"`
}

// FollowChain walks the redirects from res.PortalURL and records every host
// it reaches other than the portal host itself, pinned to the addresses it
// resolved to. It follows 3xx Location headers and meta refreshes, stops at
// the first page that is neither, and never sends anything but a GET.
//
// Call it once, at detection, while the network is still open. It is not part
// of Detect because Detect is also the re-probe run through the gap, where a
// hop outside the gap would cost a timeout on every poll.
func (p *Prober) FollowChain(ctx context.Context, res *Result) {
	if res.Class != Portal || res.PortalURL == "" {
		return
	}
	seen := map[string]bool{hopKey(res.PortalHost, res.PortalPort): true}
	visited := map[string]bool{}
	next := res.PortalURL
	for i := 0; i < maxHops && next != "" && !visited[next]; i++ {
		visited[next] = true
		cur := next
		next = p.nextHop(ctx, cur)
		if next == "" {
			return
		}
		host, port, ok := splitURL(next)
		if !ok || !isWebURL(next) {
			return
		}
		key := hopKey(host, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		hop := Hop{URL: next, Host: host, Port: port}
		hop.Addrs = p.pin(ctx, host)
		if len(hop.Addrs) > 0 {
			res.Hops = append(res.Hops, hop)
		}
	}
}

// nextHop fetches u and returns where it sends the browser next, or "".
func (p *Prober) nextHop(ctx context.Context, u string) string {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	ua := p.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	req.Header.Set("User-Agent", ua)
	resp, err := p.client().Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if isRedirect(resp.StatusCode) {
		return absolute(resp, resp.Header.Get("Location"))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return metaRefreshURL(body, u)
}

// pin resolves a hop's host to addresses, as pinPortal does for the portal.
func (p *Prober) pin(ctx context.Context, host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	addrs, err := p.resolver().LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.IP.String()
	}
	return out
}

func hopKey(host string, port int) string { return host + ":" + strconv.Itoa(port) }

// isWebURL keeps the chain to http and https: a redirect to anything else is
// not a page the gap could serve.
func isWebURL(u string) bool {
	return len(u) > 7 && (u[:7] == "http://" || (len(u) > 8 && u[:8] == "https://"))
}
