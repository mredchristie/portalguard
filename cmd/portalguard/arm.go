package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"portalguard/internal/netinfo"
	"portalguard/internal/portal"
	"portalguard/internal/state"
)

// ==== arm: the lockdown comes first ========================================
//
// See internal/state/armed.go for why. This is the waiting: for a network to
// appear (or, with -next, for a different one), then detection through the
// lockdown, then the choice between standing down on a trusted network and
// carrying on to the login or the VPN.

// describe says what the network looks like, for the log.
func (n network) describe() string {
	gw := "none"
	if n.gateway != nil {
		gw = n.gateway.String()
	} else if n.iface != "" {
		gw = "none yet (reachable through " + n.iface + ")"
	}
	dns := "none"
	if len(n.resolvers) > 0 {
		dns = strings.Join(n.resolvers, ", ")
	}
	return fmt.Sprintf("gateway %s, DNS %s", gw, dns)
}

// network is what identifies the network this Mac is on, for noticing a join.
type network struct {
	gateway   net.IP
	resolvers []string
	// iface is the resolver's interface when there is no gateway yet: a
	// network macOS has joined and not yet made primary. Detection can work
	// through it (see state.DetectArmed), so it does not wait for macOS.
	iface string
}

func (n network) ready() bool {
	if n.gateway == nil && n.iface == "" {
		return false
	}
	for _, r := range n.resolvers {
		if net.ParseIP(r).To4() != nil {
			return true
		}
	}
	return false
}

func (n network) key() string {
	return fmt.Sprintf("%s|%s", n.gateway, strings.Join(n.resolvers, ","))
}

func currentNetwork(ctx context.Context) network {
	var n network
	if r, err := netinfo.Default(ctx); err == nil {
		n.gateway = r.Gateway
	}
	for _, ip := range state.SystemResolvers() {
		n.resolvers = append(n.resolvers, ip.String())
	}
	sort.Strings(n.resolvers)
	if n.gateway == nil {
		for _, r := range netinfo.ScopedDNS(ctx) {
			if r.Interface != "" && r.Addr.To4() != nil {
				n.iface = r.Interface
				break
			}
		}
	}
	return n
}

// joinSpec is the network to join once armed, if any: the app's list, or
// -join. The password, when there is one, comes in a file the engine deletes
// as soon as it has read it, so it is never on a command line.
type joinSpec struct {
	ssid, passwordFile string
	// returnAfter: if the run is cancelled from the app, leave ssid again
	// and let macOS rejoin its usual network. wasSaved records whether ssid
	// was a saved network before PortalGuard joined it: only one PortalGuard
	// added is forgotten on the way out.
	returnAfter, wasSaved bool
	// open: the network has no password, so it can safely be taken out of
	// the saved list while macOS picks another (see netinfo.LeaveWiFi).
	open bool
}

// alreadyOnIt is how long, after asking macOS to join, a network that has
// not changed is taken to be the one that was asked for: joining the network
// the Mac is already on changes nothing, and there is no name to compare
// (macOS hides it from command-line tools).
var alreadyOnIt = 10 * time.Second

// armedDetect arms, waits for a network, and detects through the lockdown.
// released is true when a trusted network was found and the lockdown lifted.
func armedDetect(ctx context.Context, sess *state.Session, g *guide, note func(string, ...any), next bool, wait time.Duration, join *joinSpec) (res portal.Result, released bool, err error) {
	start := currentNetwork(ctx)
	if err := sess.Arm(ctx); err != nil {
		return res, false, err
	}
	var joined time.Time
	if join.ssid != "" {
		// Locked first, joined second: whatever the Mac sends the moment the
		// network appears has nowhere to go.
		password := ""
		if join.passwordFile != "" {
			b, err := os.ReadFile(join.passwordFile)
			os.Remove(join.passwordFile)
			if err != nil {
				return res, false, fmt.Errorf("read the Wi-Fi password: %w", err)
			}
			password = strings.TrimRight(string(b), "\r\n")
		}
		join.wasSaved, _ = netinfo.IsPreferred(ctx, join.ssid)
		g.emit("joining", map[string]any{"ssid": join.ssid, "was_saved": join.wasSaved})
		g.sayf("Joining %s...", join.ssid)
		logf("joining %q (was on %s)", join.ssid, start.describe())
		askedAt := time.Now()
		if err := netinfo.JoinWiFi(ctx, join.ssid, password); err != nil {
			// Nothing was joined, so there is nothing to protect: give the
			// network back rather than leave the Mac locked with nowhere to go.
			if rerr := sess.Release(ctx); rerr != nil {
				return res, false, fmt.Errorf("%v; and releasing failed: %v", err, rerr)
			}
			return res, true, fmt.Errorf("%v. PortalGuard has stood down, so this Mac is back on the network it was on", err)
		}
		joined = time.Now()
		logf("macOS joined %q in %s", join.ssid, joined.Sub(askedAt).Round(100*time.Millisecond))
	}
	if next || !start.ready() || join.ssid != "" {
		g.emit("waiting", map[string]any{"for": "network", "timeout_seconds": wait.Seconds()})
		if join.ssid == "" {
			g.sayf("Join the Wi-Fi now. Waiting up to %s...", wait)
			if g == nil {
				fmt.Printf("Armed: everything is blocked. Join the network now; waiting up to %s.\n", wait)
			}
		}
		// on reports whether the network to detect is here: a new one after
		// -next or -join, any one otherwise; and, after -join, the same one
		// once it has had time to change and has not (it was already on it).
		on := func(cur network) bool {
			if !cur.ready() {
				return false
			}
			changed := cur.key() != start.key()
			switch {
			case join.ssid != "":
				return changed || time.Since(joined) > alreadyOnIt
			case next:
				return changed
			default:
				return true
			}
		}
		deadline := time.Now().Add(wait)
		// Every change is logged, and the state every ten seconds: a join that
		// never produces a usable network (the first EE attempt sat here in
		// silence) must say what it is waiting for.
		last, lastLog := "", time.Time{}
		for {
			cur := currentNetwork(ctx)
			if d := cur.describe(); d != last || time.Since(lastLog) > 10*time.Second {
				logf("network: %s", d)
				last, lastLog = d, time.Now()
			}
			if on(cur) {
				break
			}
			if time.Now().After(deadline) {
				return res, false, fmt.Errorf("no network joined within %s. The lockdown stays in place: sudo %s release to lift it", wait, invokedAs())
			}
			select {
			case <-ctx.Done():
				return res, false, ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}

	g.stepf("Checking this network")
	cur := currentNetwork(ctx)
	mac, _ := netinfo.GatewayMAC(ctx, cur.gateway)
	tn, trusted := state.IsTrusted(state.TrustedPath, mac)

	res, err = sess.DetectArmed(ctx)
	if err != nil {
		return res, false, err
	}
	switch {
	case trusted && res.Class == portal.OpenInternet:
		if err := sess.Release(ctx); err != nil {
			return res, false, err
		}
		label := tn.Label
		if label == "" {
			label = "a network you trust"
		}
		g.emit("trusted", map[string]any{"label": label, "gateway_mac": mac})
		g.sayf("This is %s. PortalGuard has stood down.", label)
		if g == nil {
			fmt.Printf("Trusted network (%s): released.\n", label)
		}
		return res, true, nil
	case trusted:
		note("this network's router matches a trusted one, but it is not open internet (%s), so it is treated as a stranger", res.Class)
	}
	return res, false, nil
}

// ==== trust and untrust ====================================================

func runTrust(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	list := fs.Bool("list", false, "list trusted networks instead")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard trust [label]

Marks the network this Mac is on now as yours (home, work): an armed Mac that
joins it, and finds open internet there, stands down instead of locking down.
It is recognised by its router's hardware address.

flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}
	if *list {
		ns := state.LoadTrusted(state.TrustedPath)
		if len(ns) == 0 {
			fmt.Println("no trusted networks")
		}
		for mac, tn := range ns {
			fmt.Printf("%s  %s  (added %s)\n", mac, tn.Label, tn.AddedAt.Format("2 Jan 2006"))
		}
		return exitOK
	}
	if err := requireRoot("trust"); err != nil {
		return fail(err)
	}
	mac, err := currentGatewayMAC(ctx)
	if err != nil {
		return fail(err)
	}
	if err := state.Trust(state.TrustedPath, mac, strings.Join(fs.Args(), " ")); err != nil {
		return fail(err)
	}
	fmt.Printf("Trusted: the network whose router is %s.\n", mac)
	fmt.Println("An armed Mac that joins it, and finds open internet, will stand down there.")
	return exitOK
}

func runUntrust(ctx context.Context, args []string) int {
	if err := requireRoot("untrust"); err != nil {
		return fail(err)
	}
	mac := ""
	if len(args) > 0 {
		mac = args[0]
	} else {
		var err error
		if mac, err = currentGatewayMAC(ctx); err != nil {
			return fail(err)
		}
	}
	was, err := state.Untrust(state.TrustedPath, mac)
	if err != nil {
		return fail(err)
	}
	if !was {
		fmt.Printf("%s was not trusted.\n", mac)
		return exitOK
	}
	fmt.Printf("No longer trusted: %s.\n", mac)
	return exitOK
}

func currentGatewayMAC(ctx context.Context) (string, error) {
	r, err := netinfo.Default(ctx)
	if err != nil || r.Gateway == nil {
		return "", errors.New("not on a network: join the one you want to trust first")
	}
	return netinfo.GatewayMAC(ctx, r.Gateway)
}

// runLeave takes the Mac off a Wi-Fi network PortalGuard joined and back to
// its usual one: the app's "give the network back" after a run that stopped
// with an error. See netinfo.LeaveWiFi.
func runLeave(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("leave", flag.ContinueOnError)
	forget := fs.Bool("forget", false, "also remove it from macOS's saved networks (it was saved only because PortalGuard joined it)")
	open := fs.Bool("open", false, "it is an open network: keep it out of macOS's choice while it rejoins another, then save it again")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: portalguard leave [-forget] <network>")
		return exitUsageError
	}
	if err := requireRoot("leave"); err != nil {
		return fail(err)
	}
	if err := netinfo.LeaveWiFi(ctx, fs.Arg(0), *forget, *open); err != nil {
		return fail(err)
	}
	fmt.Printf("Left %s; macOS is rejoining its usual network.\n", fs.Arg(0))
	return exitOK
}
