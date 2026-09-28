package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"portalguard/internal/portal"
)

// ==== probe flags =========================================================
// Lets -probe and -probes-file override the default endpoints.

// probeList collects repeated -probe flags.
type probeList []portal.Probe

func (p *probeList) String() string { return fmt.Sprintf("%d probes", len(*p)) }

// Set accepts either a bare URL, with the expectation inferred from the
// well-known endpoint shapes, or an explicit "expect=url" pair.
func (p *probeList) Set(v string) error {
	url, expect := v, portal.Expectation("")
	if i := strings.Index(v, "="); i > 0 && !strings.Contains(v[:i], "/") {
		expect, url = portal.Expectation(v[:i]), v[i+1:]
	}
	if expect == "" {
		expect = inferExpectation(url)
	}
	switch expect {
	case portal.ExpectAppleSuccess, portal.ExpectNoContent:
	default:
		return fmt.Errorf("unknown expectation %q (want %s or %s)",
			expect, portal.ExpectAppleSuccess, portal.ExpectNoContent)
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("probe URL %q must start with http:// or https://", url)
	}
	*p = append(*p, portal.Probe{Name: probeName(url), URL: url, Expect: expect})
	return nil
}

// inferExpectation guesses what an untampered response looks like from the
// shape of the URL, so `-probe http://host/generate_204` just works.
func inferExpectation(url string) portal.Expectation {
	switch {
	case strings.Contains(url, "generate_204"), strings.Contains(url, "gen_204"):
		return portal.ExpectNoContent
	case strings.Contains(url, "hotspot-detect"), strings.Contains(url, "ncsi"):
		return portal.ExpectAppleSuccess
	default:
		return portal.ExpectNoContent
	}
}

func probeName(url string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
	if i := strings.Index(s, "/"); i > 0 {
		s = s[:i]
	}
	return s
}

// proberFlags registers the flags that shape a detection run. Both detect and
// run use it so the probe list is configurable everywhere.
func proberFlags(fs *flag.FlagSet) func() (*portal.Prober, error) {
	var probes probeList
	fs.Var(&probes, "probe", "probe endpoint, repeatable: [expect=]URL (expect: apple_success|no_content)")
	file := fs.String("probes-file", "", "JSON file holding a probe list, replacing the defaults")
	timeout := fs.Duration("timeout", 5*time.Second, "per-probe timeout")
	ua := fs.String("user-agent", "", "override the probe user agent")
	skipDNS := fs.Bool("no-dns-check", false, "skip the DNS hijack checks")

	return func() (*portal.Prober, error) {
		p := portal.NewProber()
		p.Timeout = *timeout
		p.SkipDNSCheck = *skipDNS
		if *ua != "" {
			p.UserAgent = *ua
		}
		switch {
		case *file != "":
			loaded, err := loadProbes(*file)
			if err != nil {
				return nil, err
			}
			p.Probes = loaded
		case len(probes) > 0:
			p.Probes = probes
		}
		if len(p.Probes) == 0 {
			return nil, fmt.Errorf("no probes configured")
		}
		return p, nil
	}
}

// loadProbes reads a probe list from JSON, e.g.
//
//	[{"name":"lab","url":"http://192.168.1.1/generate_204","expect":"no_content"}]
func loadProbes(path string) ([]portal.Probe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read probes file: %w", err)
	}
	var probes []portal.Probe
	if err := json.Unmarshal(data, &probes); err != nil {
		return nil, fmt.Errorf("parse probes file: %w", err)
	}
	if len(probes) == 0 {
		return nil, fmt.Errorf("probes file %s is empty", path)
	}
	for i, pr := range probes {
		if pr.URL == "" {
			return nil, fmt.Errorf("probe %d has no url", i)
		}
		if pr.Expect == "" {
			probes[i].Expect = inferExpectation(pr.URL)
		}
		if probes[i].Name == "" {
			probes[i].Name = probeName(pr.URL)
		}
	}
	return probes, nil
}

// ==== the detect command ==================================================
// Read-only. Probes the network, prints the verdict, exits 0/10/20.

func runDetect(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard detect [flags]

Probes the current network and classifies it as OPEN_INTERNET, PORTAL or
NO_NETWORK. Touches nothing: this command never changes the firewall.

Exit codes: 0 open internet, 10 portal, 20 no network, 1 error.

flags:
`)
		fs.PrintDefaults()
	}
	build := proberFlags(fs)
	asJSON := fs.Bool("json", false, "emit the full result as JSON")
	verbose := fs.Bool("v", false, "show per-probe detail")
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}

	prober, err := build()
	if err != nil {
		return fail(err)
	}

	res := prober.Detect(ctx)
	prober.FollowChain(ctx, &res)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return fail(err)
		}
		return classExit(res.Class)
	}

	printResult(res, *verbose)
	return classExit(res.Class)
}

func classExit(c portal.Classification) int {
	switch c {
	case portal.OpenInternet:
		return exitOK
	case portal.Portal:
		return exitPortal
	default:
		return exitNoNetwork
	}
}

// ==== output ==============================================================
// Human-readable rendering. -json gives the whole structure instead.

func printResult(res portal.Result, verbose bool) {
	fmt.Printf("%s  %s\n", res.Class, res.Summary())

	if res.Class == portal.Portal {
		if res.PortalURL != "" {
			fmt.Printf("  login page : %s\n", res.PortalURL)
		}
		if res.PortalHost != "" {
			fmt.Printf("  portal host: %s", res.PortalHost)
			if res.PortalPort != 0 {
				fmt.Printf(" (port %d)", res.PortalPort)
			}
			fmt.Println()
		}
		if len(res.PortalAddrs) > 0 {
			fmt.Printf("  addresses  : %s\n", strings.Join(res.PortalAddrs, ", "))
		}
		for _, h := range res.Hops {
			fmt.Printf("  redirects  : %s:%d (%s)\n", h.Host, h.Port, strings.Join(h.Addrs, ", "))
		}
	}

	if res.DNS.Hijacked {
		fmt.Println("  DNS        : HIJACKED")
		for _, r := range res.DNS.Reasons {
			fmt.Printf("               - %s\n", r)
		}
	} else if res.DNS.Checked && verbose {
		fmt.Println("  DNS        : no interception detected")
	}

	if verbose {
		fmt.Println("  probes:")
		for _, p := range res.Probes {
			fmt.Printf("    %-28s %-14s %s\n", p.Probe.Name, p.Class, p.Reason)
			if p.RemoteAddr != "" {
				fmt.Printf("      %-26s connected to %s in %s\n", "", p.RemoteAddr, p.Elapsed.Round(time.Millisecond))
			}
			if p.Err != "" {
				fmt.Printf("      %-26s error: %s\n", "", p.Err)
			}
			if p.BodySnippet != "" && p.Class == portal.Portal {
				fmt.Printf("      %-26s body: %s\n", "", p.BodySnippet)
			}
		}
		fmt.Printf("  took %s\n", res.Took.Round(time.Millisecond))
	}
}
