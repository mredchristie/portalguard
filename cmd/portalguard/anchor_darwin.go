//go:build darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"portalguard/internal/firewall"
	"portalguard/internal/firewall/pf"
)

// runInstallAnchor adds the one line to /etc/pf.conf that makes our anchor's
// rules actually get evaluated. Without it, everything portalguard loads is
// stored and ignored.
func runInstallAnchor(ctx context.Context, args []string) int {
	if err := requireRoot("install-anchor"); err != nil {
		return fail(err)
	}
	installed, _ := pf.AnchorInstalled()
	skipped := pf.LoopbackSkipped(ctx)
	if installed && skipped {
		// The hooks may be loaded and still useless to the DNS filter: a
		// runtime `set skip on lo0` survives a plain reload of pf.conf.
		if err := pf.ClearLoopbackSkip(ctx); err != nil {
			return fail(err)
		}
		fmt.Println("pf was skipping loopback. Internet Sharing sets that (Apple's container tool and")
		fmt.Println("some VMs start it), and NordVPN's kill switch leaves it behind.")
		fmt.Printf("pf has been flushed and %s loaded again, so the DNS filter can run.\n", pf.PfConfPath)
		fmt.Println("open connections may need a moment to reconnect.")
		return exitOK
	}
	if installed && pf.HooksLoaded(ctx) {
		fmt.Printf("already installed: %s references the portalguard anchors, and pf has them loaded\n", pf.PfConfPath)
		return exitOK
	}
	if installed {
		// On disk but not loaded: something replaced pf's ruleset with one
		// of its own. Putting ours back replaces theirs in turn.
		if err := pf.ReloadPfConf(ctx); err != nil {
			return fail(err)
		}
		fmt.Printf("the anchors were in %s but not in pf's loaded rules, so it has been reloaded.\n", pf.PfConfPath)
		fmt.Println("something had replaced pf's rules, usually a VPN kill switch (NordVPN does, and")
		fmt.Println("leaves them behind after it disconnects).")
		return exitOK
	}
	if err := pf.InstallAnchor(ctx); err != nil {
		return fail(err)
	}
	fmt.Printf("installed the portalguard anchor point in %s\n", pf.PfConfPath)
	fmt.Printf("the original is backed up at %s\n", pf.BackupPath)
	fmt.Println("the anchor is empty and filters nothing until portalguard runs.")
	fmt.Println("to revert: sudo portalguard uninstall-anchor")
	return exitOK
}

func runUninstallAnchor(ctx context.Context, args []string) int {
	if err := requireRoot("uninstall-anchor"); err != nil {
		return fail(err)
	}
	if err := pf.UninstallAnchor(ctx); err != nil {
		return fail(err)
	}
	fmt.Printf("removed the portalguard anchor point from %s\n", pf.PfConfPath)
	return exitOK
}

// ipList collects repeated address flags for print-rules.
type ipList []net.IP

func (l *ipList) String() string { return fmt.Sprintf("%d addresses", len(*l)) }

func (l *ipList) Set(v string) error {
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip == nil {
		return fmt.Errorf("%q is not an IP address", v)
	}
	*l = append(*l, ip)
	return nil
}

// runPrintRules writes a ruleset to stdout without touching pf. It is how the
// rules get parse checked before anything is loaded:
//
//	sudo portalguard print-rules -phase gap | sudo pfctl -a portalguard -n -f -
//
// `-n` parses and loads nothing.
func runPrintRules(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("print-rules", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard print-rules [flags]

Renders the pf anchor ruleset to stdout. Touches nothing, needs no root.

To parse check it without loading (this does need root, for /dev/pf):
  portalguard print-rules -phase locked | sudo pfctl -a portalguard -n -f -
  portalguard print-rules -phase gap    | sudo pfctl -a portalguard -n -f -

flags:
`)
		fs.PrintDefaults()
	}
	phase := fs.String("phase", "locked", "which ruleset: locked|gap")
	var portal, dns ipList
	fs.Var(&portal, "portal", "portal address for the gap ruleset, repeatable")
	fs.Var(&dns, "dns", "resolver address for the gap ruleset, repeatable")
	ports := fs.String("ports", "80,443", "portal TCP ports for the gap ruleset")
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}

	switch *phase {
	case "locked":
		fmt.Print(pf.PreviewRules(nil))
		return exitOK
	case "gap":
		// Defaults that look like a real hotel network, so the command is
		// useful with no flags at all.
		if len(portal) == 0 {
			portal = ipList{net.ParseIP("192.168.1.1")}
		}
		if len(dns) == 0 {
			dns = ipList{net.ParseIP("192.168.1.1")}
		}
		parsed, err := parsePorts(*ports)
		if err != nil {
			return fail(err)
		}
		fmt.Print(pf.PreviewRules([]firewall.Host{
			{Name: "portal", Addrs: portal, Ports: parsed, Reason: "captive portal login page"},
			{Name: "resolvers", Addrs: dns, Ports: []int{53}, AllowDNSTo: true, Reason: "portal DNS"},
		}))
		return exitOK
	default:
		return fail(fmt.Errorf("unknown phase %q (want locked or gap)", *phase))
	}
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		var p int
		if _, err := fmt.Sscanf(f, "%d", &p); err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("%q is not a valid TCP port", f)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports given")
	}
	return out, nil
}

// clearLoopbackSkipForRun clears a `set skip on lo0` before run locks down,
// so the DNS filter can run. It is the state a VPN kill switch leaves behind
// the moment you disconnect it to log in, which is exactly when run starts.
// Returns whether it changed anything.
func clearLoopbackSkipForRun(ctx context.Context) (bool, error) {
	if !pf.LoopbackSkipped(ctx) {
		return false, nil
	}
	return true, pf.ClearLoopbackSkip(ctx)
}
