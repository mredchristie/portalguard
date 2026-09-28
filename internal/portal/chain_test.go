package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// hostPort splits a test server's URL.
func hostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, _ := url.Parse(raw)
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p
}

// TestFollowChainPinsEveryHop: the portal redirects to an auth host, which
// meta-refreshes to the login page. Both further hosts must end up as hops.
func TestFollowChainPinsEveryHop(t *testing.T) {
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>Accept the terms</body></html>")
	}))
	defer login.Close()
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><head><meta http-equiv="refresh" content="0; url=%s/login"></head></html>`, login.URL)
	}))
	defer auth.Close()
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, auth.URL+"/start", http.StatusFound)
	}))
	defer portal.Close()

	host, port := hostPort(t, portal.URL)
	res := Result{Class: Portal, PortalURL: portal.URL + "/", PortalHost: host, PortalPort: port}
	NewProber().FollowChain(context.Background(), &res)

	if len(res.Hops) != 2 {
		t.Fatalf("hops = %+v, want the auth host and the login host", res.Hops)
	}
	_, authPort := hostPort(t, auth.URL)
	_, loginPort := hostPort(t, login.URL)
	if res.Hops[0].Port != authPort || res.Hops[1].Port != loginPort {
		t.Errorf("hops in the wrong order: %+v", res.Hops)
	}
	for _, h := range res.Hops {
		if len(h.Addrs) == 0 {
			t.Errorf("hop %s was not pinned to an address", h.URL)
		}
	}
}

// TestFollowChainStopsOnALoop: a portal that redirects in a circle must not
// be followed forever, and must not add itself as a hop.
func TestFollowChainStopsOnALoop(t *testing.T) {
	var self string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, self+"/again", http.StatusFound)
	}))
	defer srv.Close()
	self = srv.URL

	host, port := hostPort(t, srv.URL)
	res := Result{Class: Portal, PortalURL: srv.URL + "/", PortalHost: host, PortalPort: port}
	NewProber().FollowChain(context.Background(), &res)
	if len(res.Hops) != 0 {
		t.Errorf("a self-redirect produced hops: %+v", res.Hops)
	}
}

// TestFollowChainIgnoresNonWebRedirects: a redirect to another scheme is not
// a host the gap could serve.
func TestFollowChainIgnoresNonWebRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://files.example.net/terms", http.StatusFound)
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	res := Result{Class: Portal, PortalURL: srv.URL + "/", PortalHost: host, PortalPort: port}
	NewProber().FollowChain(context.Background(), &res)
	if len(res.Hops) != 0 {
		t.Errorf("hops = %+v, want none", res.Hops)
	}
}

// TestFollowChainOnlyForPortals: nothing to follow on an open network.
func TestFollowChainOnlyForPortals(t *testing.T) {
	res := Result{Class: OpenInternet, PortalURL: "http://127.0.0.1:1/"}
	NewProber().FollowChain(context.Background(), &res)
	if len(res.Hops) != 0 {
		t.Errorf("followed a chain on an open network: %+v", res.Hops)
	}
}
