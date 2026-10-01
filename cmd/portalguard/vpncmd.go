package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"portalguard/internal/firewall"
	"portalguard/internal/state"
	"portalguard/internal/vpn"
)

// ==== choosing the VPN the handover starts ================================

func runVPN(ctx context.Context, args []string) int {
	usage := func() int {
		fmt.Fprintf(os.Stderr, `usage: portalguard vpn list | use <name> | clear

Chooses a VPN for the handover to start by itself, once the login is sealed
and only VPN traffic may leave. Only VPNs in macOS's own settings can be
started this way (WireGuard's app puts its tunnels there; NordVPN's does not):
for any other, the handover asks you to connect it.
`)
		return exitUsageError
	}
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "list":
		ss, err := vpn.List(ctx)
		if err != nil {
			return fail(err)
		}
		chosen, _ := state.LoadVPNChoice(state.VPNChoicePath)
		if len(args) > 1 && args[1] == "-json" {
			if ss == nil {
				ss = []vpn.Service{}
			}
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"services": ss, "chosen": chosen.ID})
			return exitOK
		}
		if len(ss) == 0 {
			fmt.Println("macOS knows no VPNs portalguard can start.")
			return exitOK
		}
		for _, s := range ss {
			mark := " "
			if s.ID == chosen.ID {
				mark = "*"
			}
			fmt.Printf("%s %-24q %-24s %s\n", mark, s.Name, s.Kind, s.Status)
		}
		if chosen.ID == "" {
			fmt.Printf("\nTo have the handover start one: sudo %s vpn use \"<name>\"\n", invokedAs())
		}
		return exitOK
	case "use":
		if len(args) < 2 {
			return usage()
		}
		if err := requireRoot("vpn use"); err != nil {
			return fail(err)
		}
		name := strings.Join(args[1:], " ")
		ss, err := vpn.List(ctx)
		if err != nil {
			return fail(err)
		}
		s, ok := vpn.Find(ss, name)
		if !ok {
			return fail(fmt.Errorf("no VPN called %q; see: %s vpn list", name, invokedAs()))
		}
		if err := state.SaveVPNChoice(state.VPNChoicePath, s.ID, s.Name); err != nil {
			return fail(err)
		}
		fmt.Printf("The handover will start %q by itself.\n", s.Name)
		if es, ok := chosenEndpoints(); ok {
			fmt.Printf("Only its server, %s, may be reached until its tunnel is up.\n", describe(es))
		}
		return exitOK
	case "clear":
		if err := requireRoot("vpn clear"); err != nil {
			return fail(err)
		}
		if err := state.ClearVPNChoice(state.VPNChoicePath); err != nil {
			return fail(err)
		}
		fmt.Println("The handover will ask you to connect your VPN.")
		return exitOK
	}
	return usage()
}

// chosenVPN returns the chosen VPN, if it still exists.
func chosenVPN(ctx context.Context) (vpn.Service, bool) {
	c, ok := state.LoadVPNChoice(state.VPNChoicePath)
	if !ok {
		return vpn.Service{}, false
	}
	ss, err := vpn.List(ctx)
	if err != nil {
		return vpn.Service{}, false
	}
	return vpn.Find(ss, c.ID)
}

// chosenEndpoints pins the handover's hole to the chosen VPN's own server,
// when that is knowable without DNS: a WireGuard tunnel configured with an
// address and port. Anything else keeps the default ports.
func chosenEndpoints() ([]firewall.Endpoint, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, ok := chosenVPN(ctx)
	if !ok || !s.WireGuard() {
		return nil, false
	}
	host, port, err := vpn.Remote(ctx, s.ID)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || port == 0 {
		return nil, false
	}
	return []firewall.Endpoint{{Addr: ip, Port: port, Proto: "udp"}}, true
}

func describe(es []firewall.Endpoint) string {
	var s []string
	for _, e := range es {
		s = append(s, e.String())
	}
	return strings.Join(s, ", ")
}
