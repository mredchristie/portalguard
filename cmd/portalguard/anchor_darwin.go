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
	if installed {
		fmt.Printf("already installed: %s references the portalguard anchor\n", pf.PfConfPath)
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
