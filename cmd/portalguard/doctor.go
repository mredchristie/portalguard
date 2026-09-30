package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"portalguard/internal/dnsfilter"
	"portalguard/internal/netinfo"
	"portalguard/internal/state"
	"portalguard/internal/vpn"
)

// ==== is this Mac ready to run? ============================================
//
// doctor answers that before a portal does. It is read-only: every problem it
// finds comes with the command that fixes it, and it runs none of them. As a
// user, not everything can be seen; with sudo it also reads the firewall.

// finding is one line of the diagnosis.
type finding struct {
	Level  string `json:"level"` // ok, info, warn or fail
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

func runDoctor(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the findings as JSON")
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}
	root := os.Geteuid() == 0
	var fs2 []finding
	fs2 = append(fs2, networkFindings(ctx)...)
	fs2 = append(fs2, filterPortFindings(listenFree)...)
	fs2 = append(fs2, pfFindings(ctx, root)...)
	fs2 = append(fs2, neighbourFindings()...)
	fs2 = append(fs2, knownFinding(len(state.LoadKnownNetworks(state.KnownNetworksPath))))
	fs2 = append(fs2, trustFinding(ctx))
	fs2 = append(fs2, vpnFinding(ctx))
	if !root {
		fs2 = append(fs2, finding{"info", "the firewall was not checked",
			fmt.Sprintf("that needs root: sudo %s doctor", invokedAs())})
	}

	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(fs2)
	} else {
		printFindings(os.Stdout, fs2)
	}
	if failed(fs2) {
		return exitError
	}
	return exitOK
}

func failed(fs []finding) bool {
	for _, f := range fs {
		if f.Level == "fail" {
			return true
		}
	}
	return false
}

func printFindings(w io.Writer, fs []finding) {
	fmt.Fprintf(w, "portalguard %s doctor\n\n", version)
	for _, f := range fs {
		fmt.Fprintf(w, "  %-5s %s\n", f.Level, f.Title)
		if f.Detail != "" {
			for _, line := range strings.Split(f.Detail, "\n") {
				fmt.Fprintf(w, "        %s\n", line)
			}
		}
	}
	fmt.Fprintln(w)
	if failed(fs) {
		fmt.Fprintln(w, "Not ready: fix the fail lines above, then run doctor again.")
	} else {
		fmt.Fprintln(w, "Ready: nothing here stops a run.")
	}
}

// networkFindings: is there a network, is a VPN in the way, and what DNS
// will the filter have to work with.
func networkFindings(ctx context.Context) []finding {
	var out []finding
	if r, err := netinfo.Default(ctx); err != nil || r.Interface == "" {
		out = append(out, finding{"warn", "no default route", "join a network before run; doctor can still check the rest"})
	} else {
		out = append(out, finding{"ok", fmt.Sprintf("network: default route on %s via %s", r.Interface, r.Gateway), ""})
	}
	if tun, err := netinfo.ActiveTunnel(ctx); err == nil && tun != nil {
		out = append(out, finding{"warn", fmt.Sprintf("a VPN is up: %s", tun),
			"run refuses to start beside one. Disconnect it (quit its app if it has a kill switch) before run."})
	}
	return append(out, resolverFindings(state.SystemResolvers())...)
}

// resolverFindings judges the DNS servers the network handed out.
func resolverFindings(rs []net.IP) []finding {
	var v4, v6 []string
	for _, ip := range rs {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	var out []finding
	switch {
	case len(rs) == 0:
		out = append(out, finding{"warn", "no DNS servers configured", "the DNS filter needs the network's resolver; join a network first"})
	case len(v4) == 0:
		out = append(out, finding{"warn", "only IPv6 DNS servers: " + strings.Join(v6, ", "),
			"the DNS filter forwards over IPv4, so run would fall back to the machine-wide DNS hole"})
	default:
		out = append(out, finding{"ok", "DNS servers: " + strings.Join(append(v4, v6...), ", "), ""})
	}
	if len(v6) > 0 && len(v4) > 0 {
		out = append(out, finding{"info", "this network hands out an IPv6 DNS server",
			"lookups sent to it are filtered too; what the filter lets out goes over IPv4"})
	}
	return out
}

// filterPortFindings: the DNS filter binds two fixed ports. Something else on
// either means no filter.
func filterPortFindings(free func(network, addr string) bool) []finding {
	var busy []string
	for _, c := range []struct{ network, addr string }{
		{"udp", fmt.Sprintf("127.0.0.1:%d", dnsfilter.ListenPort)},
		{"tcp", fmt.Sprintf("127.0.0.1:%d", dnsfilter.ListenPort)},
		{"udp", fmt.Sprintf(":%d", dnsfilter.UpstreamPort)},
	} {
		if !free(c.network, c.addr) {
			busy = append(busy, c.network+" "+c.addr)
		}
	}
	if len(busy) > 0 {
		return []finding{{"fail", "the DNS filter's ports are in use: " + strings.Join(busy, ", "),
			fmt.Sprintf("a run may already be going (sudo %s status), or another program holds them", invokedAs())}}
	}
	return []finding{{"ok", fmt.Sprintf("the DNS filter's ports are free (%d, %d)", dnsfilter.ListenPort, dnsfilter.UpstreamPort), ""}}
}

// listenFree reports whether addr can be bound right now.
func listenFree(network, addr string) bool {
	if network == "tcp" {
		l, err := net.Listen(network, addr)
		if err != nil {
			return false
		}
		l.Close()
		return true
	}
	c, err := net.ListenPacket(network, addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// neighbourFindings: software known to rewrite pf underneath portalguard.
func neighbourFindings() []finding {
	var out []finding
	if _, err := os.Stat("/Library/PrivilegedHelperTools/com.nordvpn.macos.helper"); err == nil {
		out = append(out, finding{"info", "NordVPN is installed",
			"its kill switch replaces pf's rules when it connects and leaves `set skip on lo0` behind;\ndisconnect it before run, which clears what it leaves"})
	}
	if exec.Command("/usr/bin/pgrep", "-x", "InternetSharing").Run() == nil {
		out = append(out, finding{"info", "Internet Sharing is running (a VM or container tool starts it)",
			"it sets `set skip on lo0`, which stops the DNS filter; run clears it before locking down"})
	}
	return out
}

func knownFinding(n int) finding {
	if n == 0 {
		return finding{"info", "no remembered networks yet", "after a login, `sudo portalguard remember` saves what you opened"}
	}
	return finding{"ok", fmt.Sprintf("%d remembered network(s) in %s", n, state.KnownNetworksPath), ""}
}

// trustFinding says whether an armed Mac would stand down on this network.
func trustFinding(ctx context.Context) finding {
	n := len(state.LoadTrusted(state.TrustedPath))
	mac, err := currentGatewayMAC(ctx)
	if err == nil {
		if tn, ok := state.IsTrusted(state.TrustedPath, mac); ok {
			return finding{"ok", fmt.Sprintf("this network is trusted (%s): arm stands down here", firstNonEmpty(tn.Label, mac)), ""}
		}
	}
	if n == 0 {
		return finding{"info", "no trusted networks", fmt.Sprintf("at home: sudo %s trust home, so arm stands down there", invokedAs())}
	}
	return finding{"ok", fmt.Sprintf("%d trusted network(s); this one is not among them", n), ""}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// vpnFinding says whether the handover will start a VPN by itself.
func vpnFinding(ctx context.Context) finding {
	if s, ok := chosenVPN(ctx); ok {
		detail := "the default VPN ports stay open to any address until its tunnel is up"
		if es, ok := chosenEndpoints(); ok {
			detail = "only its server, " + describe(es) + ", may be reached until its tunnel is up"
		}
		return finding{"ok", fmt.Sprintf("the handover starts your VPN: %q", s.Name), detail}
	}
	if ss, err := vpn.List(ctx); err == nil && len(ss) > 0 {
		return finding{"info", fmt.Sprintf("the handover asks you to connect your VPN; it could start %q itself", ss[0].Name),
			fmt.Sprintf("sudo %s vpn use %q", invokedAs(), ss[0].Name)}
	}
	return finding{"info", "the handover asks you to connect your VPN", ""}
}
