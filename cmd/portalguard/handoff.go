package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"portalguard/internal/firewall"
	"portalguard/internal/firewall/backend"
	"portalguard/internal/state"
)

// ==== handing over to the VPN =============================================
// Hold the lockdown, let only the VPN out, step aside when the tunnel is up.

// endpointFlags collects repeated -vpn values.
type endpointFlags []string

func (e *endpointFlags) String() string     { return strings.Join(*e, ", ") }
func (e *endpointFlags) Set(v string) error { *e = append(*e, v); return nil }

const vpnFlagHelp = "a VPN server to let through during the handover, as host:port[/udp|tcp]; repeatable. Default: the standard WireGuard, OpenVPN and IKEv2 ports, to any address"

// endpoints turns the -vpn values into endpoints, or the defaults when none
// were given. resolve is nil when DNS is unreachable, which makes a hostname
// an error that says to use an address instead.
func (e endpointFlags) endpoints(resolve func(string) ([]net.IP, error)) ([]firewall.Endpoint, error) {
	if len(e) == 0 {
		return state.DefaultVPNEndpoints(), nil
	}
	var out []firewall.Endpoint
	for _, spec := range e {
		es, err := state.ParseEndpoint(spec, resolve)
		if err != nil {
			return nil, err
		}
		out = append(out, es...)
	}
	return out, nil
}

// runHandoff hands a sealed, or simply locked-down, machine over to a VPN.
func runHandoff(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("handoff", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard handoff [-vpn host:port/proto]... [-wait 3m]

Keeps the lockdown in place and lets out only your VPN client's connection.
The moment the VPN's tunnel carries your traffic, portalguard releases its
rules and steps aside. Nothing goes out in the clear in between.

Works after a sealed login, or after a plain lockdown on any network:

  sudo portalguard lockdown
  sudo portalguard handoff        # then connect your VPN

flags:
`)
		fs.PrintDefaults()
	}
	var vpns endpointFlags
	fs.Var(&vpns, "vpn", vpnFlagHelp)
	wait := fs.Duration("wait", 3*time.Minute, "how long to wait for the VPN tunnel before giving up (the lockdown stays)")
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}
	if err := requireRoot("handoff"); err != nil {
		return fail(err)
	}
	// Locked down means no DNS, so a named server has to be an address here.
	endpoints, err := vpns.endpoints(nil)
	if err != nil {
		return fail(err)
	}

	fw := backend.New()
	if ok, why := fw.Available(ctx); !ok {
		return fail(fmt.Errorf("%s backend unavailable: %s", fw.Name(), why))
	}
	sess, err := state.Resume(ctx, fw, nil, logf, state.SessionPath)
	if err != nil {
		return fail(err)
	}
	if err := handOff(ctx, sess, endpoints, *wait, nil); err != nil {
		return fail(err)
	}
	return exitOK
}

// handOff runs the handover and says what happened. Shared by `handoff` and
// by `run`, which hands over by itself once it has sealed.
func handOff(ctx context.Context, sess *state.Session, endpoints []firewall.Endpoint, wait time.Duration, g *guide) error {
	if g != nil {
		g.stepf("Connect your VPN now")
		g.sayf("Until its tunnel is up, only VPN traffic can leave. Waiting up to %s...", wait)
	} else {
		fmt.Printf("\nConnect your VPN now. Until its tunnel is up, only VPN traffic can leave.\n")
		fmt.Printf("Waiting up to %s for the tunnel...\n", wait)
	}

	res, err := sess.HandOff(ctx, endpoints, wait)
	var ne *state.NotEnforcedError
	switch {
	case errors.As(err, &ne):
		return fmt.Errorf("%v.\n"+
			"  portalguard's rules are loaded but no longer applied, so it is not holding anything back.\n"+
			"  run `sudo %s release` to clear them", ne, invokedAs())
	case errors.Is(err, state.ErrNoTunnel):
		return fmt.Errorf("no VPN tunnel came up within %s, so the lockdown is still in place.\n"+
			"  connect the VPN and run `sudo %s handoff` again, or `sudo %s release` to give up",
			wait, invokedAs(), invokedAs())
	case err != nil:
		return err
	}
	// The rules are gone, so the session file describes nothing any more.
	state.ClearSnapshot(state.SessionPath)
	if g != nil {
		g.sayf("Your VPN is up on %s.", res.Interface)
		if res.TakenOver {
			g.sayf("Its own firewall took over while it connected, and PortalGuard cleared its rules.")
		}
		fmt.Fprintln(g.out, "\nAll done. PortalGuard has stepped aside; your VPN has the connection.")
		return nil
	}
	if res.TakenOver {
		fmt.Printf("\nYour VPN is up on %s.\n", res.Interface)
		fmt.Println("While it connected, its own firewall replaced portalguard's, so its kill switch,")
		fmt.Println("not portalguard, held traffic back until the tunnel was up.")
		fmt.Println("Portalguard has cleared its own rules and stepped aside.")
		return nil
	}
	fmt.Printf("\nYour VPN is up on %s. Portalguard has stepped aside; the VPN owns the connection.\n", res.Interface)
	return nil
}
