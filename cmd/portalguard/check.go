package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

// checkURL is a plain-HTTP endpoint with no meaningful body: any response at
// all means the request got out and back. Same family as detect's default
// probes, but check asks a much narrower question - not "is there a portal
// here", just "did that request complete" - so one endpoint is enough.
const checkURL = "http://connectivitycheck.gstatic.com/generate_204"

// runCheck is the one-line reachability check: no flags, no curl syntax,
// just an answer. Useful on its own for confirming what a lockdown, a gap,
// or a release actually did to the network, not just for a demo.
func runCheck(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard check

Makes one HTTP request and prints whether the internet is reachable.
Touches nothing: never changes the firewall.

Exit codes: 0 reachable, 1 blocked.
`)
	}
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, checkURL, nil)
	if err != nil {
		return fail(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("internet: blocked")
		return exitError
	}
	resp.Body.Close()

	fmt.Println("internet: reachable")
	return exitOK
}
