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

// network is what identifies the network this Mac is on, for noticing a join.
type network struct {
	gateway   net.IP
	resolvers []string
}

func (n network) ready() bool {
	if n.gateway == nil {
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
	return n
}

// armedDetect arms, waits for a network, and detects through the lockdown.
// released is true when a trusted network was found and the lockdown lifted.
func armedDetect(ctx context.Context, sess *state.Session, g *guide, note func(string, ...any), next bool, wait time.Duration) (res portal.Result, released bool, err error) {
	start := currentNetwork(ctx)
	if err := sess.Arm(ctx); err != nil {
		return res, false, err
	}
	if next || !start.ready() {
		g.sayf("Join the Wi-Fi now. Waiting up to %s...", wait)
		if g == nil {
			fmt.Printf("Armed: everything is blocked. Join the network now; waiting up to %s.\n", wait)
		}
		deadline := time.Now().Add(wait)
		for {
			cur := currentNetwork(ctx)
			if cur.ready() && (!next || cur.key() != start.key()) {
				break
			}
			if time.Now().After(deadline) {
				return res, false, fmt.Errorf("no network joined within %s; the lockdown stays until you release it or it exits", wait)
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
