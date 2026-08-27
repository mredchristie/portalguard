package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"portalguard/internal/firewall"
	"portalguard/internal/firewall/backend"
	"portalguard/internal/netinfo"
	"portalguard/internal/portal"
	"portalguard/internal/state"
)

// ==== the VPN guard =======================================================
// Refuse to engage while a tunnel owns the default route - its kill
// switch would fight ours.

// checkNoActiveVPN refuses to engage the firewall while a VPN owns the default
// route.
//
// A VPN kill switch works the same way our lockdown does - block everything,
// permit the tunnel - and two tools independently asserting "block everything
// except my thing" over one interface produce whatever the rule ordering
// happens to give. That is not something to debug live on a hotel network.
//
// portalguard is designed to run *before* the VPN, not beside it: lock down,
// open the gap, log in, seal, then the VPN comes up and our rules are gone.
// There is no phase where both are meant to be enforcing.
//
// The override exists because a hard refusal would punish anyone whose VPN
// this misreads. It is opt-in and loud.
func checkNoActiveVPN(ctx context.Context, override bool) error {
	tun, err := netinfo.ActiveTunnel(ctx)
	if err != nil || tun == nil {
		return nil
	}
	if override {
		logf("WARNING: %s is up and carrying the default route", tun)
		logf("WARNING: proceeding anyway because --allow-active-vpn was given;")
		logf("WARNING: if the VPN has a kill switch, its rules and ours will fight")
		return nil
	}
	return fmt.Errorf(`%s is up and carrying the default route (gateway %s).

A VPN kill switch and portalguard's lockdown will fight over pf rules.
portalguard is meant to run before the VPN, not beside it.

Disconnect the VPN first, then re-run.
To override anyway: --allow-active-vpn`, tun, tun.Gateway)
}

// vpnFlag registers the override on a command's flag set.
func vpnFlag(fs *flag.FlagSet) *bool {
	return fs.Bool("allow-active-vpn", false,
		"engage the firewall even though a VPN owns the default route (its kill switch may fight ours)")
}

// logf is the CLI's logger: plain lines on stderr so stdout stays parseable.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "portalguard: "+format+"\n", args...)
}

// ==== read-only commands ==================================================
// Status just reports. It changes nothing.

func runStatus(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit status as JSON")
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}

	fw := backend.New()
	st, err := fw.Status(ctx)
	if err != nil {
		return fail(err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(st); err != nil {
			return fail(err)
		}
		return exitOK
	}

	fmt.Printf("backend  : %s\n", st.Backend)
	fmt.Printf("available: %t\n", st.Available)
	fmt.Printf("phase    : %s\n", st.Phase)
	fmt.Printf("managed  : %t\n", st.Managed)
	for _, h := range st.Allowed {
		fmt.Printf("allowed  : %s\n", h)
	}
	if st.Detail != "" {
		fmt.Printf("detail   :\n%s\n", indent(st.Detail, "  "))
	}
	if !st.Available && os.Geteuid() != 0 {
		fmt.Println("\n(run with sudo to read the live pf ruleset)")
	}
	return exitOK
}

func indent(s, prefix string) string {
	out := prefix
	for _, r := range s {
		out += string(r)
		if r == '\n' {
			out += prefix
		}
	}
	return out
}

// ==== commands that change the firewall ===================================
// All need sudo. Release is the escape hatch and must always work.

// runLockdown blocks everything. It deliberately does not detect first: the
// user may want to lock down before they know what they are dealing with.
func runLockdown(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("lockdown", flag.ContinueOnError)
	allowVPN := vpnFlag(fs)
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}
	// The VPN check comes before the root check on purpose: it is the more
	// informative failure, and it is actionable without sudo.
	if err := checkNoActiveVPN(ctx, *allowVPN); err != nil {
		return fail(err)
	}
	if err := requireRoot("lockdown"); err != nil {
		return fail(err)
	}
	fw := backend.New()
	if ok, why := fw.Available(ctx); !ok {
		return fail(fmt.Errorf("%s backend unavailable: %s", fw.Name(), why))
	}
	if err := fw.Lockdown(ctx); err != nil {
		return fail(hint(err))
	}
	logf("all traffic blocked. run `sudo %s release` to undo", invokedAs())
	return exitOK
}

// runSeal closes the gap but keeps the lockdown.
func runSeal(ctx context.Context, args []string) int {
	if err := requireRoot("seal"); err != nil {
		return fail(err)
	}
	fw := backend.New()
	if err := fw.Seal(ctx); err != nil {
		return fail(hint(err))
	}
	logf("gap closed; traffic is still blocked. bring up your VPN, then `sudo %s release`", invokedAs())
	return exitOK
}

// runRelease is the escape hatch. It must work in every situation, so it does
// not check availability first and reports partial failure loudly.
func runRelease(ctx context.Context, args []string) int {
	if err := requireRoot("release"); err != nil {
		return fail(err)
	}
	fw := backend.New()
	if err := fw.Release(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "portalguard: release failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "portalguard: fall back to `sudo pfctl -a portalguard -F all`")
		return exitError
	}
	logf("rules released; normal networking restored")
	return exitOK
}

// runAllow opens the gap for the detected portal, or widens it for a host the
// user names when a portal bounces through somewhere unexpected.
func runAllow(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("allow", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard allow [host]

With no host, detects the portal and opens the gap for it. With a host,
widens an already-open gap to include that host as well.

flags:
`)
		fs.PrintDefaults()
	}
	build := proberFlags(fs)
	allowVPN := vpnFlag(fs)
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}
	// The VPN check comes before the root check on purpose: it is the more
	// informative failure, and it is actionable without sudo.
	if err := checkNoActiveVPN(ctx, *allowVPN); err != nil {
		return fail(err)
	}
	if err := requireRoot("allow"); err != nil {
		return fail(err)
	}

	prober, err := build()
	if err != nil {
		return fail(err)
	}

	fw := backend.New()
	safety := firewall.InstallSafetyNet(fw, logf)
	defer safety.Stop()

	sess := state.NewSession(fw, prober, logf)

	if fs.NArg() > 0 {
		if err := sess.AllowExtra(ctx, fs.Arg(0)); err != nil {
			return fail(hint(err))
		}
		return exitOK
	}

	res, err := sess.Detect(ctx)
	if err != nil {
		return fail(err)
	}
	if res.Class != portal.Portal {
		logf("no portal to open a gap for (%s)", res.Class)
		return classExit(res.Class)
	}
	if err := sess.Lockdown(ctx); err != nil {
		return fail(hint(err))
	}
	if err := sess.OpenGap(ctx); err != nil {
		return fail(hint(err))
	}
	fmt.Printf("gap open. log in yourself at: %s\n", res.PortalURL)
	return exitOK
}

// runFlow drives the whole sequence and blocks until the user has logged in.
// ==== the leak report =====================================================
// Printed at seal. Never silent - a missing report and a clean one are
// different things.

// printReport shows what the firewall accounted for.
//
// It never returns silently. A missing report and an empty one mean different
// things, and both mean something different again from "nothing leaked" - so
// each says which it is. Silence here once cost a debugging session: the
// report was absent and there was no output to say whether that was because
// the backend could not account for traffic, because the counters read as
// zero, or because the code was not in the binary at all.
//
// redact, when true, generalises hostnames to categories before printing -
// for a report headed somewhere other than your own reading, e.g. pasted
// into a bug report, or a screen recording. The default is full detail, for
// local use.
//
// verbose, when true and process attribution backed off, additionally
// prints why. That detail (rep.ProcessNote) is diagnostic - which of the
// two ways the raw pflog path can fail, and the specific bytes involved -
// not something a normal user needs, so it stays out of the report unless
// asked for.
//
// auditLog, when non-empty, writes the full, unredacted report to that path
// - never to stdout. It exists so a redacted run's own printed output can be
// verified against real ground truth (e.g. by the e2e suite, checking that
// nothing raw reached what got displayed or recorded) without the real
// hostnames ever appearing on screen. Most callers leave it empty.
func printReport(sess *state.Session, redact, verbose bool, auditLog string) {
	rep, ok := sess.Report()
	if !ok {
		fmt.Println("\nThis firewall backend cannot account for the traffic it filtered,")
		fmt.Println("so there is no leak report. That is a missing measurement, not a")
		fmt.Println("clean result.")
		return
	}
	if rep.Empty() {
		fmt.Println("\nNo traffic was accounted for. That usually means the counters could not")
		fmt.Println("be read, not that nothing happened.")
		return
	}
	if auditLog != "" {
		if err := os.WriteFile(auditLog, []byte(rep.String()), 0o600); err != nil {
			logf("could not write -audit-log %s: %v", auditLog, err)
		}
	}
	if redact {
		rep = rep.Redact() // touches Names only; ProcessNote is unaffected
	}
	fmt.Println("\n--- what happened while portalguard was engaged ---")
	fmt.Print(rep.String())
	fmt.Println("---")
	if verbose && rep.ProcessNote != "" {
		fmt.Printf("\ndiagnostic: process attribution backed off: %s\n", rep.ProcessNote)
	}
}

// ==== the whole flow ======================================================
// detect, lock down, open the gap, wait for you to log in, seal.

func runFlow(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard run [flags]

Detects the portal, blocks everything, opens a gap for the login page only,
waits for you to log in yourself, then seals back up ready for your VPN.

portalguard never enters credentials or accepts terms on your behalf.

flags:
`)
		fs.PrintDefaults()
	}
	build := proberFlags(fs)
	wait := fs.Duration("wait", 10*time.Minute, "how long to wait for you to finish logging in")
	poll := fs.Duration("poll", 3*time.Second, "how often to re-probe while waiting")
	allowVPN := vpnFlag(fs)
	redact := fs.Bool("redact", false, "generalise hostnames in the leak report to categories, for output you plan to share")
	verbose := fs.Bool("verbose", false, "if process attribution backs off, print why (diagnostic; not shown by default)")
	auditLog := fs.String("audit-log", "", "write the full, unredacted report to this file (never to stdout) - for verifying a -redact run against ground truth without displaying it")
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}
	// The VPN check comes before the root check on purpose: it is the more
	// informative failure, and it is actionable without sudo.
	if err := checkNoActiveVPN(ctx, *allowVPN); err != nil {
		return fail(err)
	}
	if err := requireRoot("run"); err != nil {
		return fail(err)
	}

	prober, err := build()
	if err != nil {
		return fail(err)
	}

	fw := backend.New()
	if ok, why := fw.Available(ctx); !ok {
		return fail(fmt.Errorf("%s backend unavailable: %s", fw.Name(), why))
	}

	// From here on the firewall may be engaged, so the safety net matters.
	safety := firewall.InstallSafetyNet(fw, logf)
	defer safety.Stop()

	sess := state.NewSession(fw, prober, logf)
	sess.Machine().Observe(func(t state.Transition) { logf("%s", t) })

	err = firewall.Guard(fw, logf, func() error {
		res, err := sess.Detect(ctx)
		if err != nil {
			return err
		}
		if res.Class != portal.Portal {
			logf("nothing to do (%s)", res.Class)
			return nil
		}

		if err := sess.Lockdown(ctx); err != nil {
			return err
		}
		if err := sess.OpenGap(ctx); err != nil {
			// The lockdown is still standing; release it rather than
			// leaving the user offline with no explanation.
			_ = sess.Release(ctx)
			return err
		}

		fmt.Printf("\nOpen this page and log in yourself:\n  %s\n\n", res.PortalURL)
		fmt.Println("Everything else on this machine is blocked while you do.")
		fmt.Printf("Waiting up to %s for the login to go through...\n", *wait)

		waitCtx, cancel := context.WithTimeout(ctx, *wait)
		defer cancel()
		if err := sess.WaitForAuth(waitCtx, *poll); err != nil {
			_ = sess.Release(ctx)
			return fmt.Errorf("gave up waiting for the portal login: %w", err)
		}

		if err := sess.Seal(ctx); err != nil {
			return err
		}
		fmt.Println("\nAuthenticated and sealed. Traffic is still blocked.")

		printReport(sess, *redact, *verbose, *auditLog)

		fmt.Printf("Bring up your VPN now, then run: sudo %s release\n", invokedAs())
		return nil
	})
	if err != nil {
		return fail(hint(err))
	}
	return exitOK
}
