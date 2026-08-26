// Command portalguard manages the firewall around a captive portal login so a
// full-tunnel VPN user never has to drop their tunnel on a hotel network.
//
// It never submits credentials and never bypasses a portal's payment or terms
// screen. The human logs in themselves; portalguard only decides what may
// leave the machine while they do.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// version is set at build time via -ldflags.
var version = "dev"

// Exit codes are part of the interface: `portalguard detect` is meant to be
// driven from a shell script.
const (
	exitOK         = 0
	exitError      = 1
	exitPortal     = 10
	exitNoNetwork  = 20
	exitUsageError = 64
)

// ==== the command table ===================================================
// Every subcommand, its summary, and what runs it.

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) int
}

func commands() []command {
	return []command{
		{"detect", "probe the current network and classify it", runDetect},
		{"status", "show the firewall and state machine status", runStatus},
		{"lockdown", "block all traffic (root)", runLockdown},
		{"allow", "open the gap for the detected portal, or a named host (root)", runAllow},
		{"seal", "close the gap, leaving the lockdown in place (root)", runSeal},
		{"release", "tear down all portalguard rules and restore networking (root)", runRelease},
		{"run", "the whole flow: detect, lock down, open the gap, wait, seal (root)", runFlow},
		{"print-rules", "print the pf ruleset without loading it", runPrintRules},
		{"install-anchor", "add the portalguard anchor point to /etc/pf.conf (root, once)", runInstallAnchor},
		{"uninstall-anchor", "remove it again (root)", runUninstallAnchor},
		{"version", "print the version", runVersion},
	}
}

// ==== startup =============================================================
// Parse the subcommand, set up Ctrl-C handling, dispatch.

func main() {
	os.Exit(run())
}

func run() int {
	args := os.Args[1:]
	if len(args) == 0 {
		usage(os.Stderr)
		return exitUsageError
	}

	name := args[0]
	if name == "-h" || name == "--help" || name == "help" {
		usage(os.Stdout)
		return exitOK
	}

	// Ctrl-C must be a clean, releasing exit, not a kill: every command that
	// touches the firewall installs its own safety net on top of this.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, c := range commands() {
		if c.name == name {
			return c.run(ctx, args[1:])
		}
	}

	fmt.Fprintf(os.Stderr, "portalguard: unknown command %q\n\n", name)
	usage(os.Stderr)
	return exitUsageError
}

func usage(w *os.File) {
	fmt.Fprintf(w, `portalguard %s - hold the line while you log in to a captive portal

usage: portalguard <command> [flags]

commands:
`, version)
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-17s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, `
Commands marked (root) program the packet filter and must be run with sudo.

detect exit codes: 0 open internet, 10 captive portal, 20 no network, 1 error.

If portalguard is ever killed hard and your network stays blocked, run:
  sudo portalguard release
`)
}

// ==== shared helpers ======================================================
// Error printing, the root check, and hints for the errors people actually hit.

func runVersion(context.Context, []string) int {
	fmt.Println(version)
	return exitOK
}

// fail prints an error consistently and returns the error exit code.
func fail(err error) int {
	fmt.Fprintf(os.Stderr, "portalguard: %v\n", err)
	return exitError
}

// requireRoot reports a clear, actionable message when a privileged command is
// run without sudo, rather than letting pfctl fail obscurely.
func requireRoot(cmd string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf("`portalguard %s` programs the packet filter and needs root: try `sudo portalguard %s`", cmd, cmd)
}

// hint adds an actionable next step to the errors a user is most likely to
// hit, rather than leaving them with a bare pfctl failure.
func hint(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pfNoAnchorHook()) {
		return fmt.Errorf("%w\n\nWhy this matters: rules loaded into an unreferenced anchor are stored\nand never evaluated, so portalguard would report LOCKED_DOWN over a wide\nopen network. It refuses rather than pretend.", err)
	}
	return err
}
