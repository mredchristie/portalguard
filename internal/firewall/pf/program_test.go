//go:build darwin

package pf

import (
	"context"
	"net"
	"regexp"
	"strings"
	"testing"

	"portalguard/internal/firewall"
)

// fakePfctl stands in for pfctl and ifconfig, so the whole rule-programming
// sequence can be exercised without root and without touching the machine.
//
// It models the two behaviours that make the real thing awkward: the anchor
// hook has to be visible in the main ruleset before Lockdown will proceed, and
// per-rule counters reset whenever a ruleset is loaded.
type fakePfctl struct {
	calls       []string
	loaded      string // the anchor ruleset currently "in the kernel"
	hookPresent bool
	// rdrHookPresent is whether the main ruleset reaches our rdr-anchor,
	// which the DNS filter needs.
	rdrHookPresent bool
	// skipLoopback is `set skip on lo0` in the main ruleset, as Internet
	// Sharing loads it.
	skipLoopback bool
	// blockedOut and dns are the packet counts `-s rules -v` reports for the
	// *currently loaded* ruleset. A load resets them to zero, exactly as pf
	// does, and traffic() is how a test says packets arrived since then.
	blockedOut int
	dns        int
	tables     map[string][]string
	// countersFail makes `-s rules -v` error, standing in for the case where
	// the counters genuinely could not be read.
	countersFail bool
	// stateDir stands in for /var/run: the files every invocation on this
	// machine shares. One fake kernel is one machine, so every backend built
	// against it sees the same bookkeeping, which is what lets a test model
	// two processes properly.
	stateDir string
}

// traffic says that n packets were blocked and d went through the DNS hole
// since the ruleset now loaded was loaded.
func (f *fakePfctl) traffic(n, d int) {
	f.blockedOut += n
	f.dns += d
}

func newFakePfctl(t *testing.T) *fakePfctl {
	t.Helper()
	return &fakePfctl{hookPresent: true, tables: map[string][]string{}, stateDir: t.TempDir()}
}

// countersFor is a plausible statistics dump: one block rule with traffic, and
// a DNS rule that only has traffic once the gap ruleset is loaded.
func countersFor(rules string, blockedOut, dns int) string {
	out := "block drop out quick all\n" +
		"  [ Evaluations: 900       Packets: " + itoa(blockedOut) + "        Bytes: 1000       States: 0     ]\n"
	if strings.Contains(rules, "<"+dnsTable+">") {
		out += "pass out log (all, user) quick inet proto { tcp udp } from any to <" + dnsTable + "> port = 53 keep state\n" +
			"  [ Evaluations: 300       Packets: " + itoa(dns) + "         Bytes: 500        States: 4     ]\n"
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func (f *fakePfctl) run(_ context.Context, path string, stdin []byte, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	joined := strings.Join(args, " ")

	switch {
	case strings.HasSuffix(path, "ifconfig"):
		// No pflog device in the test environment; the gap must still open.
		return "", errNoDevice

	case joined == "-s rules":
		// The main ruleset, used to check the anchor hook.
		if f.hookPresent {
			return "anchor \"portalguard\" all\nanchor \"com.apple/*\" all\n", nil
		}
		return "anchor \"com.apple/*\" all\n", nil

	case joined == "-s Interfaces -v":
		if f.skipLoopback {
			return "en0\nlo0 (skip)\nawdl0 (skip)\n", nil
		}
		return "en0\nlo0\nawdl0 (skip)\n", nil

	case joined == "-s nat":
		if f.rdrHookPresent {
			return "rdr-anchor \"portalguard\" all\nrdr-anchor \"com.apple/*\" all\n", nil
		}
		return "rdr-anchor \"com.apple/*\" all\n", nil

	case strings.Contains(joined, "-f -"):
		f.loaded = string(stdin)
		// A load resets pf's per-rule statistics, for every process on the
		// machine and not only the one that loaded.
		f.blockedOut, f.dns = 0, 0
		// A table declaration carrying addresses *replaces* the table's
		// contents. Modelling that is the point: it is what makes a second
		// process rendering its ruleset from an empty allow-list destructive
		// rather than merely incomplete.
		f.loadTables(f.loaded)
		return "", nil

	case strings.Contains(joined, "-F Tables"):
		f.tables = map[string][]string{}
		return "", nil

	case strings.Contains(joined, "-s rules -v"):
		if f.countersFail {
			return "", errString("pfctl: DIOCGETRULES: Operation not supported")
		}
		return countersFor(f.loaded, f.blockedOut, f.dns), nil

	case strings.Contains(joined, "-a portalguard -s rules"):
		return f.loaded, nil

	case strings.Contains(joined, "-T show"):
		for name, addrs := range f.tables {
			if strings.Contains(joined, "-t "+name) {
				return strings.Join(addrs, "\n"), nil
			}
		}
		return "", nil

	case joined == "-E":
		return "pf enabled\nToken : 1234567890\n", nil
	}
	return "", nil
}

// tableRe matches the table declarations render() emits.
var tableRe = regexp.MustCompile(`(?m)^table <([a-z_]+)> persist(?: \{ ([^}]*) \})?`)

// loadTables applies a ruleset's table declarations, the way pf does: a
// declaration with a body replaces whatever the table held, and one without a
// body leaves an empty table behind.
func (f *fakePfctl) loadTables(rules string) {
	for _, m := range tableRe.FindAllStringSubmatch(rules, -1) {
		name, body := m[1], strings.TrimSpace(m[2])
		if body == "" {
			f.tables[name] = nil
			continue
		}
		f.tables[name] = strings.Fields(body)
	}
}

var errNoDevice = &net.OpError{Op: "ifconfig", Err: errString("device does not exist")}

type errString string

func (e errString) Error() string { return string(e) }

func newTestBackend(t *testing.T, f *fakePfctl) *Backend {
	t.Helper()
	// Redirect the files that live in /var/run: it is not writable by tests,
	// and a test must never touch the real ones. They point into the fake
	// kernel's own directory, so two backends built against one fake share
	// them exactly as two invocations on one machine would.
	origToken, origCounters := tokenPath, counterPath
	tokenPath = f.stateDir + "/pf-token"
	counterPath = f.stateDir + "/counters"
	t.Cleanup(func() { tokenPath, counterPath = origToken, origCounters })

	b := New()
	b.exec = f.run
	return b
}

// TestCountersAccumulateAcrossTheRealSequence is the test that a unit test of
// any single function cannot be.
//
// pf resets per-rule statistics on every ruleset load, and portalguard loads a
// new ruleset at each phase change. The counts are therefore only correct if
// every reload banks the outgoing ruleset's numbers first - a property that
// lives in the *sequence* Lockdown -> AllowHost -> Seal, not in any one of
// them. Reading the counters once at the end would report zero packets blocked
// during lockdown, which is a comfortable and wrong answer.
func TestCountersAccumulateAcrossTheRealSequence(t *testing.T) {
	f := newFakePfctl(t)
	b := newTestBackend(t, f)
	ctx := context.Background()

	if err := b.Lockdown(ctx); err != nil {
		t.Fatalf("lockdown: %v", err)
	}
	// Nothing banked yet: this process had loaded no ruleset before now.
	if got := b.LeakReport(); !got.Empty() {
		t.Errorf("report should be empty immediately after lockdown, got %+v", got)
	}

	portalHost := firewall.Host{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.0.1")}}
	dnsHost := firewall.Host{Name: "resolvers", Addrs: []net.IP{net.ParseIP("192.168.0.1")}, AllowDNSTo: true, Ports: []int{53}}

	// 100 packets are blocked under each ruleset in turn. Each reload resets
	// pf's counters, so the totals are only right if every reload banks the
	// outgoing ruleset's numbers on the way past.
	f.traffic(100, 0)
	if err := b.AllowHost(ctx, portalHost); err != nil {
		t.Fatalf("allow portal: %v", err)
	}
	f.traffic(100, 0)
	if err := b.AllowHost(ctx, dnsHost); err != nil {
		t.Fatalf("allow dns: %v", err)
	}
	f.traffic(100, 12)
	if err := b.Seal(ctx); err != nil {
		t.Fatalf("seal: %v", err)
	}

	rep := b.LeakReport()
	if rep.Empty() {
		t.Fatal("report is empty after a full cycle; the counters were never banked")
	}
	// Three reloads happened after the first, each banking 100 blocked
	// packets: allow(portal), allow(dns), seal.
	if rep.BlockedOutPackets != 300 {
		t.Errorf("BlockedOutPackets = %d, want 300 (banked at each of three reloads)", rep.BlockedOutPackets)
	}
	// DNS counters only exist once the gap ruleset is loaded, and are banked
	// by the seal's reload.
	if rep.DNSPackets == 0 {
		t.Error("DNS packets were not banked; the gap's counters were lost at seal")
	}
	if rep.GapDuration() <= 0 {
		t.Error("gap window was not recorded")
	}
	if len(rep.Resolvers) == 0 {
		t.Error("report should name the resolvers the DNS hole pointed at")
	}
}

// TestGapOpensEvenWhenTheLogDeviceCannotBeCreated is the degradation path.
// Losing the leak log is bad; failing to open the gap over it would leave the
// user unable to log in at all.
func TestGapOpensEvenWhenTheLogDeviceCannotBeCreated(t *testing.T) {
	f := newFakePfctl(t)
	b := newTestBackend(t, f)
	ctx := context.Background()

	if err := b.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	err := b.AllowHost(ctx, firewall.Host{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.0.1")}})
	if err != nil {
		t.Fatalf("gap must open even with no pflog device: %v", err)
	}
	// And the ruleset must not name a device that is not there.
	if strings.Contains(f.loaded, "to "+LogInterface) {
		t.Errorf("ruleset names a log device that could not be created:\n%s", f.loaded)
	}
}

// TestLockdownRefusesWithoutTheAnchorHook guards the failure that would leave
// portalguard reporting LOCKED_DOWN over a wide open network.
func TestLockdownRefusesWithoutTheAnchorHook(t *testing.T) {
	f := newFakePfctl(t)
	f.hookPresent = false
	b := newTestBackend(t, f)

	err := b.Lockdown(context.Background())
	if err == nil {
		t.Fatal("lockdown must refuse when the main ruleset does not reference the anchor")
	}
	if !strings.Contains(err.Error(), "install-anchor") {
		t.Errorf("the error should say how to fix it: %v", err)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "-f -") {
			t.Error("no ruleset should have been loaded after the hook check failed")
		}
	}
}

// TestSealEmptiesTheTables pins the fix for the residue bug: persist tables
// outlive the ruleset that referenced them, so seal must flush them.
func TestSealEmptiesTheTables(t *testing.T) {
	f := newFakePfctl(t)
	b := newTestBackend(t, f)
	ctx := context.Background()

	_ = b.Lockdown(ctx)
	_ = b.AllowHost(ctx, firewall.Host{Name: "portal", Addrs: []net.IP{net.ParseIP("192.168.0.1")}})
	if err := b.Seal(ctx); err != nil {
		t.Fatal(err)
	}

	var flushed bool
	for _, call := range f.calls {
		if strings.Contains(call, "-F Tables") {
			flushed = true
		}
	}
	if !flushed {
		t.Errorf("seal must flush the gap tables; calls were:\n  %s", strings.Join(f.calls, "\n  "))
	}
}

// TestRelockKeepsTheAccount: armed detection opens a detection gap and then
// locks down again. That second lockdown is not a fresh engagement, and what
// was blocked before it (the join burst) must still be in the report.
func TestRelockKeepsTheAccount(t *testing.T) {
	f := newFakePfctl(t)
	b := newTestBackend(t, f)
	ctx := context.Background()
	if err := b.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	f.traffic(250, 0) // the join burst, held back while armed
	dnsHost := firewall.Host{Name: "resolvers", Addrs: []net.IP{net.ParseIP("192.168.0.1")}, AllowDNSTo: true, Ports: []int{53}}
	if err := b.AllowHost(ctx, dnsHost); err != nil {
		t.Fatal(err)
	}
	f.traffic(10, 4)
	if err := b.Lockdown(ctx); err != nil { // back to a bare lockdown after detection
		t.Fatal(err)
	}
	if got := b.LeakReport().BlockedOutPackets; got != 260 {
		t.Errorf("BlockedOutPackets after the re-lock = %d, want 260: the join burst was wiped", got)
	}

	// A new engagement, in a new process, still starts from nothing.
	if err := b.Release(ctx); err != nil {
		t.Fatal(err)
	}
	b2 := newTestBackend(t, f)
	if err := b2.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	if got := b2.LeakReport(); !got.Empty() {
		t.Errorf("a fresh lockdown inherited an old account: %+v", got)
	}
}
