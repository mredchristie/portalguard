package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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
	if quietLog {
		// Guided run: the technical line is for the record, not the screen.
		activeTrace.line("log", fmt.Sprintf("portalguard: "+format, args...))
		return
	}
	fmt.Fprintf(os.Stderr, "portalguard: "+format+"\n", args...)
}

// quietLog sends logf to the -trace file only, while a guided run tells the
// screen what is happening in plain words. activeTrace is that file, if any.
var (
	quietLog    bool
	activeTrace *tracer
)

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
	// Only as root: without it pf cannot be read, and "can't tell" must not
	// print as "yes".
	if st.Phase != firewall.PhaseOff && st.Available {
		if e, ok := fw.(firewall.Enforcer); ok {
			if ok, why := e.Enforced(ctx); ok {
				fmt.Println("enforced : yes")
			} else {
				fmt.Printf("enforced : NO - %s\n", why)
			}
		}
	}
	fmt.Printf("managed  : %t\n", st.Managed)
	fmt.Printf("session  : %s\n", sessionLine(st))
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
	if e, ok := fw.(firewall.Enforcer); ok {
		if ok, why := e.Enforced(ctx); !ok {
			return fail(fmt.Errorf("the lockdown loaded but is not being applied: %s", why))
		}
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
	// Record the seal. The ruleset after a seal is byte-for-byte the ruleset
	// of a bare lockdown, so this is the one distinction the kernel genuinely
	// cannot make for us, and the next invocation would otherwise offer to
	// widen a gap that is already closed.
	recordSeal()
	logf("gap closed; traffic is still blocked. run `sudo %s handoff`, then connect your VPN", invokedAs())
	return exitOK
}

// recordSeal rewrites the session file to say the gap is sealed, keeping
// whatever the earlier invocation knew about the portal.
func recordSeal() {
	snap, err := state.LoadSnapshot(state.SessionPath)
	if err != nil {
		// No session file, so there is nothing to correct. The next
		// invocation will read LOCKED_DOWN from the kernel, which is the safe
		// reading of a sealed machine: it will not offer to widen a gap.
		return
	}
	snap.State = state.Sealed
	if err := state.SaveSnapshot(state.SessionPath, snap); err != nil {
		logf("sealed, but could not update the session file: %v", err)
	}
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
	// The rules are gone, so the session file describes nothing. Resume would
	// discard it anyway on reading PhaseOff from the kernel; removing it here
	// just keeps `status` honest in the meantime.
	state.ClearSnapshot(state.SessionPath)
	logf("rules released; normal networking restored")
	return exitOK
}

// runAllow opens the gap for the detected portal, or widens it for a host the
// user names when a portal bounces through somewhere unexpected.
func runAllow(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("allow", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard allow [host[:port] ...]

With no host, detects the portal and opens the gap for it.

With one or more hosts, widens a gap that is already open - including one
opened by a `+"`portalguard run`"+` still waiting in another terminal. Portals
routinely span several hostnames (a CDN for their stylesheets, a separate
host for the login POST), and a blocked one usually shows up as a blank
page rather than as an error.

  sudo portalguard allow cdn.example.net
  sudo portalguard allow cdn.example.net reg.example.net info.example.net:442

A bare host opens 80 and 443. Give host:port to open one specific port
instead; note that pf holds one port set for the whole gap, so a port
opened for one host is open for every host in it.

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
	// This process exits once the gap is open or widened, so anything it
	// started that would outlive it (the leak log reader) is stopped first.
	if d, ok := fw.(interface{ Detach() }); ok {
		defer d.Detach()
	}

	if fs.NArg() > 0 {
		return extendGap(ctx, fw, prober, fs.Args())
	}

	safety := firewall.InstallSafetyNet(fw, logf)
	defer safety.Stop()

	sess := state.NewSession(fw, prober, logf)
	sess.PersistTo(state.SessionPath)
	sess.UseKnownNetworks(state.KnownNetworksPath)

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
	if opened := sess.OpenKnown(ctx); len(opened) > 0 {
		fmt.Printf("gap widened automatically (known network, TLS verified): %s\n", strings.Join(opened, ", "))
	}
	fmt.Printf("gap open. log in yourself at: %s\n", res.PortalURL)
	return exitOK
}

// ==== remembering a network ================================================

func runRemember(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("remember", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard remember

Saves whatever is currently open beyond the portal's own host - the hosts a
previous `+"`allow`"+` widened the gap with - as a known network, so the next visit
to a site sharing this portal's domain can try opening them automatically.

Nothing is trusted blindly on a later visit: OpenKnown still requires each
remembered host to complete a fresh TLS handshake with a certificate valid
for its name before it is opened. remember only shortens the list of hosts a
human has to diagnose and name by hand; it does not change what Portalguard
is willing to open without one. See docs/gap-scope.md, option E.

Requires an open gap with something extra already allowed:

  sudo portalguard allow
  sudo portalguard allow cdn.example.net reg.example.net
  sudo portalguard remember
`)
		fs.PrintDefaults()
	}
	build := proberFlags(fs)
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}
	if err := requireRoot("remember"); err != nil {
		return fail(err)
	}

	prober, err := build()
	if err != nil {
		return fail(err)
	}

	sess, err := state.Resume(ctx, backend.New(), prober, logf, state.SessionPath)
	if err != nil {
		return fail(err)
	}

	site, added, err := sess.Remember(state.KnownNetworksPath)
	if err != nil {
		return fail(err)
	}
	if len(added) == 0 {
		fmt.Printf("nothing new to remember for %s\n", site)
		return exitOK
	}
	fmt.Printf("remembered for %s: %s\n", site, strings.Join(added, ", "))
	fmt.Println("A later visit to a portal on this domain will try these automatically, once each one verifies.")
	return exitOK
}

// ==== widening a gap somebody else opened =================================
// The one command that acts on a firewall this process did not engage.

// extendGap adds hosts to a gap that is already open, which is usually a gap
// this process did not open: the common case is a `portalguard run` still
// waiting in another terminal while the user works out that the login page is
// blank because its stylesheets are blocked.
//
// Deliberately no safety net. Everywhere else, the process that engaged the
// firewall releases it on the way out, which is the fail-safe the whole design
// rests on. Here the firewall belongs to somebody else, and a Ctrl-C between
// two hostnames must not tear down a lockdown this process never installed and
// cannot put back. Widening is additive and leaves nothing to unwind, so
// exiting without touching anything is the correct failure.
func extendGap(ctx context.Context, fw firewall.Backend, prober *portal.Prober, args []string) int {
	targets := make([]allowTarget, 0, len(args))
	for _, arg := range args {
		t, err := parseAllowTarget(arg)
		if err != nil {
			return fail(err)
		}
		targets = append(targets, t)
	}

	sess, err := state.Resume(ctx, fw, prober, logf, state.SessionPath)
	if err != nil {
		return fail(err)
	}
	// Record what this process adds. The kernel keeps the addresses but not
	// the names, so without this the hostnames typed here were gone the
	// moment it exited - and a `remember` after it saved the kernel's
	// placeholder, "portal", instead of the hosts that were actually opened.
	sess.PersistTo(state.SessionPath)

	for _, t := range targets {
		if err := sess.AllowExtra(ctx, t.host, t.ports...); err != nil {
			return fail(hint(extendHint(err)))
		}
		fmt.Printf("gap widened: %s\n", t)
	}
	return exitOK
}

// allowTarget is one host the user asked to let through, with the ports they
// asked for.
type allowTarget struct {
	host  string
	ports []int
}

func (t allowTarget) String() string {
	if len(t.ports) == 0 {
		return t.host + " (ports 80, 443)"
	}
	return fmt.Sprintf("%s (port %d)", t.host, t.ports[0])
}

// parseAllowTarget reads a `host` or `host:port` argument.
func parseAllowTarget(arg string) (allowTarget, error) {
	host, port, err := net.SplitHostPort(arg)
	if err != nil {
		// Not a host:port pair. A bare IPv6 literal ("fe80::1") lands here
		// too, which is the right answer: it is a host, not a host and a port.
		return allowTarget{host: arg}, nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return allowTarget{}, fmt.Errorf("bad port in %q: want host or host:port, with the port in 1-65535", arg)
	}
	return allowTarget{host: host, ports: []int{n}}, nil
}

// extendHint turns the state machine's refusal into something a user standing
// in front of a blank login page can act on.
func extendHint(err error) error {
	var bad *state.InvalidTransitionError
	if !errors.As(err, &bad) || bad.Event != state.EventExtendGap {
		return err
	}
	switch bad.From {
	case state.Idle:
		return fmt.Errorf(`there is no open gap to widen: no portalguard rules are loaded.

Open one first, in this terminal or another:
  sudo %s run`, invokedAs())
	case state.LockedDown:
		return fmt.Errorf(`traffic is blocked, but no gap is open, so there is nothing to widen.

  sudo %s allow          # detect the portal and open the gap
  sudo %s release        # or give the network back`, invokedAs(), invokedAs())
	case state.Sealed, state.Authenticated:
		return fmt.Errorf(`the gap has already been closed (%s), so it cannot be widened.

If the login did not actually finish, start again:
  sudo %s release
  sudo %s run`, bad.From, invokedAs(), invokedAs())
	default:
		return err
	}
}

// sessionLine renders the part of the status the packet filter cannot answer:
// which state the machine had reached, and who left it there.
//
// It reports the *reconciled* state, not whatever the file claims, so what
// status shows is exactly what the next `allow` or `seal` would act on. A file
// saying GAP_OPEN over a ruleset that permits nothing must not be rendered as
// an open gap: that mismatch is the thing a user reads status to rule out.
func sessionLine(st firewall.Status) string {
	if !st.Available {
		return "unknown (the session file and the live ruleset both need root)"
	}

	snap, err := state.LoadSnapshot(state.SessionPath)
	if err != nil {
		if st.Phase == firewall.PhaseOff {
			return "none"
		}
		adopted, _ := state.AdoptedState(st, state.Snapshot{})
		return fmt.Sprintf("%s, recovered from the loaded ruleset alone (no session file)", adopted)
	}

	adopted, _ := state.AdoptedState(st, snap)
	line := fmt.Sprintf("%s (pid %d, since %s)", adopted, snap.PID, snap.Since.Format(time.RFC3339))
	if adopted != snap.State {
		// Say so out loud. The two disagreeing means either a release this
		// file knew nothing about, or a process that died mid-session, and
		// both are worth seeing rather than quietly resolving.
		line += fmt.Sprintf("\n           the session file says %s; the loaded ruleset says otherwise, and wins", snap.State)
	}
	return line
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
// verbose, when true, also lists every name the DNS filter refused, and if
// process attribution backed off, prints why. That detail (rep.ProcessNote) is diagnostic - which of the
// two ways the raw pflog path can fail, and the specific bytes involved -
// not something a normal user needs, so it stays out of the report unless
// asked for.
//
// auditLog, when non-empty, writes the full, unredacted report to that path
// - never to stdout. It exists so a redacted run's own printed output can be
// verified against real ground truth (e.g. by the e2e suite, checking that
// nothing raw reached what got displayed or recorded) without the real
// hostnames ever appearing on screen. Most callers leave it empty.
// writeAuditLog writes the full report to path, for a guided run, which
// prints only a summary. See printReport's auditLog.
func writeAuditLog(sess *state.Session, path string) {
	if path == "" {
		return
	}
	if rep, ok := sess.Report(); ok && !rep.Empty() {
		if err := os.WriteFile(path, []byte(rep.String()), 0o600); err != nil {
			logf("could not write -audit-log %s: %v", path, err)
		}
	}
}

func printReport(sess *state.Session, redact, verbose bool, auditLog string) {
	rep, ok := sess.Report()
	if !ok {
		fmt.Println("\nThis firewall backend cannot account for the traffic it filtered,")
		fmt.Println("so there is no leak report. That is a missing measurement, not a")
		fmt.Println("clean result.")
		return
	}
	if rep.Empty() {
		// Two very different things look identical here, and the older
		// wording asserted the worse one without checking. Ask the report
		// which it was.
		if rep.CountersUnavailable() {
			fmt.Println("\nNo traffic was accounted for, because the counters could not be read.")
			fmt.Println("That is a missing measurement, not a clean result.")
		} else {
			fmt.Println("\nThe counters were read and every one of them was zero: nothing was")
			fmt.Println("blocked, and nothing went through the gap, while portalguard was engaged.")
		}
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
	if st, ok := sess.DNSFilterStats(); ok {
		fmt.Printf("\nThe DNS filter refused %d lookup(s) for %d name(s); none of them left this machine.\n",
			st.Refused, len(st.RefusedNames))
		fmt.Printf("It let %d through, for the %d name(s) the login needed", st.Forwarded, len(st.ForwardedNames))
		if !redact && len(st.ForwardedNames) > 0 {
			fmt.Printf(": %s", strings.Join(st.ForwardedNames, ", "))
		}
		fmt.Println(".")
		if auto := sess.AutoAllowed(); len(auto) > 0 && !redact {
			fmt.Printf("Opened automatically as the login page asked for them: %s.\n", strings.Join(auto, ", "))
		}
		// Everything refused, not just the portal's own site: a login that
		// hands off to a payment page on another domain shows up here, and
		// nowhere else, when the page just sits there.
		if verbose && !redact && len(st.RefusedNames) > 0 {
			fmt.Printf("Refused: %s.\n", strings.Join(st.RefusedNames, ", "))
		}
	}
	fmt.Println("---")
	if verbose && rep.ProcessNote != "" {
		fmt.Printf("\ndiagnostic: process attribution backed off: %s\n", rep.ProcessNote)
	}
}

// ==== telling the user what is missing ====================================
// The gap stays the user's decision. This is the evidence for it.

// printSuggestion prints the hosts the portal is asking for and not reaching,
// with the command that would let them through.
//
// Worded as what was observed, not as what is wrong: these are names that
// were looked up and are not in the gap, which is a fact. Whether the login
// page needs them is something only the person looking at the page knows -
// plenty of portals resolve a host they never load.
func printSuggestion(names []string) {
	if len(names) == 0 {
		return
	}
	fmt.Printf("\n  Looked up but not open: %s\n", strings.Join(names, ", "))
	fmt.Println("  If the login page is blank or broken, these are what to open:")
	fmt.Printf("    sudo %s allow %s\n\n", invokedAs(), strings.Join(names, " "))
}

// ==== the whole flow ======================================================
// detect, lock down, open the gap, wait for you to log in, seal.

func runFlow(ctx context.Context, args []string) int { return runFlowMode(ctx, args, false) }

// runArm is run with the lockdown first: see internal/state/armed.go.
func runArm(ctx context.Context, args []string) int { return runFlowMode(ctx, args, true) }

func runFlowMode(ctx context.Context, args []string, armed bool) int {
	name := "run"
	if armed {
		name = "arm"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: portalguard run [flags]

Detects the portal, blocks everything, opens a gap for the login page only,
waits for you to log in yourself, seals back up, then hands over to your VPN:
only the VPN's connection may leave until its tunnel is up, and then
portalguard steps aside.

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
	verbose := fs.Bool("verbose", false, "show the technical log and the full report instead of plain steps, and list every name refused as it happens")
	var vpns endpointFlags
	fs.Var(&vpns, "vpn", vpnFlagHelp)
	noHandoff := fs.Bool("no-handoff", false, "stop at SEALED instead of handing over to your VPN")
	noDNSFilter := fs.Bool("no-dns-filter", false, "let the gap's DNS go straight to the network's resolver, for every app, as v0.2 did")
	noAutoAllow := fs.Bool("no-auto-allow", false, "never open the portal's own hosts automatically; suggest them for allow instead, as v0.3 did")
	handoffWait := fs.Duration("handoff-wait", 3*time.Minute, "how long to wait for the VPN tunnel after sealing")
	var next *bool
	var joinWait *time.Duration
	var join joinSpec
	if armed {
		fs.StringVar(&join.ssid, "join", "", "once locked down, join this Wi-Fi network, then detect it")
		fs.StringVar(&join.passwordFile, "join-password-file", "", "a file holding the -join network's password; deleted once read")
		next = fs.Bool("next", false, "wait for the next network rather than checking the one this Mac is on now")
		joinWait = fs.Duration("join-wait", 30*time.Minute, "how long to wait, armed, for a network to join")
	}
	asJSON := fs.Bool("json", false, "report progress as JSON lines on stdout instead of text, for a GUI; stdin then takes host names to open")
	tracePath := fs.String("trace", "", "record everything this run prints, and every DNS query with what the filter did, timestamped, to this file (holds real hostnames)")
	auditLog := fs.String("audit-log", "", "write the full, unredacted report to this file (never to stdout) - for verifying a -redact run against ground truth without displaying it")
	if err := fs.Parse(args); err != nil {
		return exitUsageError
	}
	// Plain steps when a person is watching, the technical log when a script
	// is: e2e and anything else that captures run's output reads the log.
	// Decided before -trace swaps stdout for a pipe.
	var g *guide
	switch {
	case *asJSON:
		g = newFeed(stdout{})
		quietLog = true
		defer func() { quietLog = false }()
	case !*verbose && isTerminal(os.Stdout):
		g = &guide{out: stdout{}}
		quietLog = true
		defer func() { quietLog = false }()
	}
	// note tells the user something that matters in either mode.
	note := func(format string, args ...any) {
		logf(format, args...)
		g.sayf("note: "+format, args...)
		g.emit("note", map[string]any{"text": fmt.Sprintf(format, args...)})
	}

	// First, so a run that fails its preflight is on record too.
	var tr *tracer
	if *tracePath != "" {
		var err error
		if tr, err = startTrace(*tracePath, append([]string{name}, args...)); err != nil {
			return fail(err)
		}
		defer tr.close()
		activeTrace = tr
		defer func() { activeTrace = nil }()
	}
	if g != nil {
		fmt.Fprintln(g.out, "PortalGuard")
	}
	g.emit("start", map[string]any{"command": name, "version": version})
	// The VPN check comes before the root check on purpose: it is the more
	// informative failure, and it is actionable without sudo.
	if err := checkNoActiveVPN(ctx, *allowVPN); err != nil {
		return fail(err)
	}
	if err := requireRoot(name); err != nil {
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

	// Before anything is engaged: the fix flushes pf, which is only safe
	// while nothing of ours is loaded.
	if !*noDNSFilter {
		if cleared, err := clearLoopbackSkipForRun(ctx); err != nil {
			note("pf skips loopback and it could not be cleared, so the DNS filter will be off: %v", err)
		} else if cleared {
			logf("pf was skipping loopback (a VPN kill switch or Internet Sharing leaves that behind); reset it so the DNS filter can run")
		}
	}

	// A GUI drives a -json run through stdin: host names to open, and
	// "cancel". Read from the start, so a cancel works while armed and
	// waiting too, and so the app closing (stdin reaching its end) gives the
	// network back rather than leave it locked with nothing in charge.
	var prompt *allowPrompt
	var appCancelled atomic.Bool
	fed := g != nil && g.feed != nil

	// From here on the firewall may be engaged, so the safety net matters.
	safety := firewall.InstallSafetyNet(fw, logf)
	defer safety.Stop()

	sess := state.NewSession(fw, prober, logf)
	sess.Machine().Observe(func(t state.Transition) {
		logf("%s", t)
		g.transition(t)
	})
	// Record every move, so `allow` from a second terminal can widen the gap
	// this run is about to open while this one sits waiting for the login.
	sess.PersistTo(state.SessionPath)
	sess.UseKnownNetworks(state.KnownNetworksPath)

	if fed {
		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		ctx = runCtx
		prompt = newAllowPrompt(ctx, sess, os.Stdin, os.Stdout, g)
		prompt.cancel = func(why string) {
			if appCancelled.CompareAndSwap(false, true) {
				g.emit("note", map[string]any{"text": why})
				cancel()
			}
		}
	}

	err = firewall.Guard(fw, logf, func() error {
		var res portal.Result
		if armed {
			var released bool
			res, released, err = armedDetect(ctx, sess, g, note, *next, *joinWait, join)
			if err != nil || released {
				return err
			}
			if res.Class != portal.Portal {
				// An open network, not trusted: the lockdown stands, and
				// only the VPN may leave until its tunnel is up.
				if *noHandoff {
					g.stepf("Connect your VPN when you are ready")
					g.sayf("Traffic stays blocked until then: sudo %s handoff, then connect it.", invokedAs())
					if g == nil {
						fmt.Printf("No portal. When you are ready: sudo %s handoff, then connect your VPN.\n", invokedAs())
					}
					return nil
				}
				endpoints, err := vpns.endpoints(state.SystemResolve(ctx))
				if err != nil {
					note("%v; handing over on the default VPN ports instead", err)
					endpoints = state.DefaultVPNEndpoints()
				}
				return handOff(ctx, sess, endpoints, *handoffWait, g)
			}
		} else {
			res, err = sess.Detect(ctx)
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
		}
		// Before the gap, so its rules carry the filter from the first load.
		// Without it the gap still works, with the machine-wide DNS hole.
		// The portal's own site opens as the page asks for it: through the
		// filter when it runs, from pf's log when it does not.
		sess.UseAutoAllow(!*noAutoAllow)
		sess.UseVerboseDNS(*verbose)
		if tr != nil {
			sess.UseDNSTrace(tr.dns)
		}
		if !*noDNSFilter {
			if err := sess.StartDNSFilter(ctx); err != nil {
				note("dns filter off, so every app's lookups can reach the network during the gap: %v", err)
			}
		}
		if err := sess.OpenGap(ctx); err != nil {
			// The lockdown is still standing; release it rather than
			// leaving the user offline with no explanation.
			_ = sess.Release(ctx)
			return err
		}
		// Only for hosts this site has been seen and verified on before -
		// each one still has to complete a fresh TLS handshake before it is
		// opened. See docs/gap-scope.md, option E.
		// (A guided run has already said so, as each one opened.)
		if opened := sess.OpenKnown(ctx); len(opened) > 0 && g == nil {
			fmt.Printf("Opened automatically (known network, TLS verified): %s\n", strings.Join(opened, ", "))
		}

		g.emit("login_url", map[string]any{"url": res.PortalURL})
		if g != nil {
			g.sayf("If it does not open by itself: %s", res.PortalURL)
		} else {
			fmt.Printf("\nOpen this page and log in yourself:\n  %s\n\n", res.PortalURL)
			fmt.Println("Everything else on this machine is blocked while you do.")
		}
		if err := openBrowser(res.PortalURL); err != nil {
			note("could not open a browser automatically: %v", err)
		}
		g.emit("waiting", map[string]any{"for": "login", "timeout_seconds": wait.Seconds()})
		if g != nil {
			g.sayf("Waiting for you to finish (up to %s)...", *wait)
		} else {
			fmt.Printf("Waiting up to %s for the login to go through...\n", *wait)
		}

		// A portal host that is missing from the gap usually shows up as a
		// blank page rather than as an error, so say what is being looked
		// for and not reached while the gap is still open and the user can
		// still act on it. This opens nothing: it prints the command, and
		// the person decides whether to run it.
		if prompt == nil {
			prompt = newAllowPrompt(ctx, sess, os.Stdin, os.Stdout, g)
		}
		if prompt != nil && *verbose {
			fmt.Println("Refused names are listed as they happen. Type one and press Enter to open it.")
		}
		sess.OnSuggestion(func(names []string) {
			g.emit("suggest", map[string]any{"names": names})
			if g == nil || g.feed == nil {
				printSuggestion(names)
			}
			prompt.offer(names)
		})

		waitCtx, cancel := context.WithTimeout(ctx, *wait)
		defer cancel()
		if err := sess.WaitForAuth(waitCtx, *poll); err != nil {
			_ = sess.Release(ctx)
			var ne *state.NotEnforcedError
			if errors.As(err, &ne) {
				return fmt.Errorf("stopped: %v.\n"+
					"  something else took over the firewall while you were logging in, so this\n"+
					"  machine was no longer locked down. portalguard has cleared its rules", ne)
			}
			return fmt.Errorf("gave up waiting for the portal login: %w", err)
		}

		// Named VPN servers are resolved now, while the gap still lets DNS
		// through. After the seal there is no DNS to ask.
		var endpoints []firewall.Endpoint
		if !*noHandoff {
			endpoints, err = vpns.endpoints(state.SystemResolve(ctx))
			if err != nil {
				note("%v; handing over on the default VPN ports instead", err)
				endpoints = state.DefaultVPNEndpoints()
			}
		}

		if err := sess.Seal(ctx); err != nil {
			return err
		}
		if g != nil {
			g.summary(sess)
			writeAuditLog(sess, *auditLog)
		} else {
			fmt.Println("\nAuthenticated and sealed. Traffic is still blocked.")
			printReport(sess, *redact, *verbose, *auditLog)
		}

		if *noHandoff {
			g.emit("waiting", map[string]any{"for": "handoff"})
			if g != nil {
				g.stepf("Connect your VPN when you are ready")
				g.sayf("Traffic stays blocked until then: sudo %s handoff, then connect it.", invokedAs())
				return nil
			}
			fmt.Printf("When you are ready: sudo %s handoff, then connect your VPN.\n", invokedAs())
			return nil
		}
		return handOff(ctx, sess, endpoints, *handoffWait, g)
	})
	if appCancelled.Load() {
		// Cancelled from the app: an error on the way out is the cancel
		// itself, and the network goes back whatever state it was in.
		rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
		rerr := sess.Release(rctx)
		rcancel()
		if rerr != nil {
			g.emit("error", map[string]any{"text": "cancelled, but releasing failed: " + rerr.Error()})
			return fail(rerr)
		}
		g.emit("done", map[string]any{"state": sess.Machine().State(), "cancelled": true})
		return exitOK
	}
	if err != nil {
		g.emit("error", map[string]any{"text": hint(err).Error()})
		return fail(hint(err))
	}
	g.emit("done", map[string]any{"state": sess.Machine().State()})
	return exitOK
}
