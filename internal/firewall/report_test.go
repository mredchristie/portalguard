package firewall

import (
	"net"
	"strings"
	"testing"
	"time"
)

func sampleReport() Report {
	open := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	return Report{
		GapOpened:         open,
		GapClosed:         open.Add(47 * time.Second),
		BlockedOutPackets: 412,
		BlockedOutBytes:   38104,
		BlockedInPackets:  133,
		BlockedInBytes:    9800,
		DNSPackets:        46,
		DNSBytes:          4922,
		PortalPackets:     88,
		PortalBytes:       21400,
		Resolvers:         []net.IP{net.ParseIP("192.168.0.1")},
		Source:            "pf rule counters (pfctl -s rules -v)",
	}
}

// TestReportWithCountersOnlyDoesNotClaimToKnowWhich is the honesty test.
//
// A report that says how much went through the DNS hole must not read as
// though it knows what was asked for. The failure being guarded against is a
// user seeing a leak summary with no hostnames and concluding nothing
// sensitive leaked, when the truth is that nobody looked.
func TestReportWithCountersOnlyDoesNotClaimToKnowWhich(t *testing.T) {
	got := sampleReport().String()

	if !strings.Contains(got, "not known") {
		t.Errorf("must say the hostnames are unknown:\n%s", got)
	}
	if !strings.Contains(got, "needs packet logging") {
		t.Errorf("must say why they are unknown:\n%s", got)
	}
	// Packets are not lookups: a query and its reply both count.
	if !strings.Contains(got, "packets, not lookups") {
		t.Errorf("must not let a packet count read as a query count:\n%s", got)
	}
	for _, forbidden := range []string{"no leaks", "nothing leaked", "queries"} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Errorf("must not contain %q:\n%s", forbidden, got)
		}
	}
}

func TestReportIncludesTheNumbersThatMatter(t *testing.T) {
	got := sampleReport().String()
	for _, want := range []string{"47s", "412 packets", "46 packets", "192.168.0.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
}

func TestReportEnrichedNamesWhatItKnows(t *testing.T) {
	r := sampleReport()
	r.Names = []string{"api.icloud.com", "imap.mail.me.com"}
	r.Processes = []string{"mDNSResponder(142)"}
	got := r.String()

	if !strings.Contains(got, "api.icloud.com") || !strings.Contains(got, "mDNSResponder(142)") {
		t.Errorf("enriched report should list what it knows:\n%s", got)
	}
	// And must drop the disclaimer, which would now be false.
	if strings.Contains(got, "not known") {
		t.Errorf("enriched report should not still say the names are unknown:\n%s", got)
	}
	if !r.Enriched() {
		t.Error("Enriched() should be true once names are present")
	}
}

// TestReportHostnamesKnownProcessesNot is the middle of the three honest
// states: hostnames come from tcpdump's stable public DNS decode, process
// attribution from a reverse-engineered struct that a future macOS could
// break. This is the state that must exist once that struct assumption
// fails on a run that still captured hostnames just fine - and it must not
// collapse into either of the other two.
func TestReportHostnamesKnownProcessesNot(t *testing.T) {
	r := sampleReport()
	r.Names = []string{"api.icloud.com", "imap.mail.me.com"}
	r.ProcessesUnavailable = true
	got := r.String()

	if !strings.Contains(got, "api.icloud.com") {
		t.Errorf("hostnames must still be listed:\n%s", got)
	}
	if !r.Enriched() {
		t.Error("Enriched() should be true once names are present, regardless of process attribution")
	}
	// Must not read as the full disclaimer - that would understate what is
	// actually known here.
	if strings.Contains(got, "not known") {
		t.Errorf("must not fall back to the full disclaimer when hostnames are known:\n%s", got)
	}
	if strings.Contains(got, "needs packet logging") {
		t.Errorf("must not claim packet logging was unavailable when it plainly was:\n%s", got)
	}
	// Must say plainly that process attribution specifically did not work,
	// not stay silent about it.
	if !strings.Contains(got, "could not be determined") {
		t.Errorf("must say process attribution failed, not just omit it:\n%s", got)
	}
	if strings.Contains(got, "Asked by:") {
		t.Errorf("must not print an empty or fabricated 'Asked by' line:\n%s", got)
	}
}

// TestReportProcessesDeclinedByKernelHasItsOwnWording checks the third case:
// the kernel explicitly not attributing a packet to a process is a
// different and more useful claim than this package failing to determine
// it, and must render with different wording, not collapse into the
// generic "could not be determined" line.
func TestReportProcessesDeclinedByKernelHasItsOwnWording(t *testing.T) {
	r := sampleReport()
	r.Names = []string{"api.icloud.com"}
	r.ProcessesUnavailable = true
	r.ProcessesDeclinedByKernel = true
	got := r.String()

	if !strings.Contains(got, "The kernel did not attribute") {
		t.Errorf("expected the kernel-decline wording:\n%s", got)
	}
	if strings.Contains(got, "could not be determined") {
		t.Errorf("must not also print the generic unavailable wording:\n%s", got)
	}
	if strings.Contains(got, "not known") {
		t.Errorf("must not fall back to the full disclaimer:\n%s", got)
	}
}

// TestReportProcessNoteStaysOutOfStringByDefault checks that the diagnostic
// carried on the report (ProcessNote) is genuinely diagnostic: a normal
// user reading String() output must never see it, only a caller that goes
// looking for it (e.g. cmd/portalguard's -verbose) should.
func TestReportProcessNoteStaysOutOfStringByDefault(t *testing.T) {
	r := sampleReport()
	r.Names = []string{"api.icloud.com"}
	r.ProcessesUnavailable = true
	r.ProcessNote = "[parse] pflog pid 100000 is outside [1,99999]; raw bytes: 3d 02 00 00"

	got := r.String()
	if strings.Contains(got, "ProcessNote") || strings.Contains(got, "raw bytes") {
		t.Errorf("String() must not leak the diagnostic note into user-facing output:\n%s", got)
	}
	// But it must still be there for a caller that wants it.
	if r.ProcessNote == "" {
		t.Error("ProcessNote must survive on the Report struct for a caller to read")
	}
}

// TestReportReadsCorrectlyWithNoDNS guards the opposite failure: when the gap
// genuinely carried no DNS, saying so plainly is correct and must not be
// hedged into sounding like a measurement failure.
func TestReportReadsCorrectlyWithNoDNS(t *testing.T) {
	r := sampleReport()
	r.DNSPackets, r.DNSBytes = 0, 0
	got := r.String()

	if !strings.Contains(got, "No DNS went through the gap") {
		t.Errorf("should state plainly that no DNS went through:\n%s", got)
	}
	if strings.Contains(got, "not known") {
		t.Errorf("nothing to disclaim when nothing went through:\n%s", got)
	}
}

// TestHostnameCategoryRecognisesNamedProviders locks in the actual
// motivation for widening the keyword list: a real capture's hostnames
// (Apple push, Spotify, Grammarly, Google) were all landing in "other"
// because the domains real traffic uses (push.apple.com, scdn.co,
// grammarly.io, googleapis.com) didn't match anything, even though a human
// reading the raw list could identify every one of them.
func TestHostnameCategoryRecognisesNamedProviders(t *testing.T) {
	cases := map[string]string{
		"1-courier.push.apple.com": "push notifications",
		"gcm-http.googleapis.com":  "push notifications",
		"audio-sp-ak.scdn.co":      "streaming/media",
		"spclient.wg.spotify.com":  "streaming/media",
		"gnar.grammarly.io":        "writing/productivity tools",
		"www.grammarly.com":        "writing/productivity tools",
		"swcdn.apple.com":          "software update/delivery",
		"gspe1-ssl.ls.apple.com":   "Apple services",
		"www.googleapis.com":       "Google services",
		"fonts.gstatic.com":        "Google services",
		// More specific buckets must still win over the general fallback.
		"api.icloud.com": "cloud sync/storage",
		"push.apple.com": "push notifications",
	}
	for host, want := range cases {
		if got := hostnameCategory(host); got != want {
			t.Errorf("hostnameCategory(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestRedactClearsResolverAddresses is the regression test for a real leak:
// an already-redacted demo recording still plainly showed
// "fd12:3456:789a::53" - an IPv6 resolver address whose
// interface identifier is modified-EUI-64 and therefore encodes a real MAC
// address, since Redact only ever touched Names. Resolvers must be cleared
// regardless of whether there are any hostnames to redact - a
// counters-only report (no Names at all) can still carry Resolvers.
func TestRedactClearsResolverAddresses(t *testing.T) {
	r := sampleReport() // Resolvers = 192.168.0.1, no Names set
	red := r.Redact()
	if len(red.Resolvers) != 0 {
		t.Errorf("Redact must clear Resolvers even with no Names, got %v", red.Resolvers)
	}

	r2 := sampleReport()
	r2.Names = []string{"imap.mail.me.com"}
	r2.Resolvers = append(r2.Resolvers, net.ParseIP("fd12:3456:789a::53"))
	got := r2.Redact().String()
	if strings.Contains(got, "fd25") || strings.Contains(got, "192.168.0.1") {
		t.Errorf("redacted report must not contain a resolver address:\n%s", got)
	}
}

// TestRedactGeneralisesHostnamesToCategories checks the actual privacy
// property: none of the real hostnames survive into the redacted output,
// literally or as a substring, and it still degrades to "other" rather than
// erroring on an unrecognised provider.
func TestRedactGeneralisesHostnamesToCategories(t *testing.T) {
	r := sampleReport()
	r.Names = []string{
		"imap.mail.me.com",
		"api.icloud.com",
		"edge-web-gew4.dual-gslb.spotify.com",
		"totally-unrecognised-vendor.example",
	}
	red := r.Redact()

	joined := strings.Join(red.Names, " | ")
	for _, raw := range r.Names {
		if strings.Contains(joined, raw) {
			t.Errorf("redacted output must not contain the raw hostname %q, got: %q", raw, joined)
		}
	}
	for _, want := range []string{"mail", "cloud sync/storage", "streaming/media", "other"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected category %q in redacted names, got: %q", want, joined)
		}
	}
	// The original must be untouched - Redact returns a copy.
	if r.Names[0] != "imap.mail.me.com" {
		t.Error("Redact must not mutate the receiver's Names")
	}
}

// TestRedactedReportStillSatisfiesTheEnrichmentCheck exists because the e2e
// suite's PHASE B4 assertion greps RUN_LOG for a non-empty "Hostnames
// queried:" line. Redact must keep satisfying that exact pattern - this is
// the fast, local proof that it does, without needing a second live pf
// cycle to check it.
func TestRedactedReportStillSatisfiesTheEnrichmentCheck(t *testing.T) {
	r := sampleReport()
	r.Names = []string{"imap.mail.me.com", "api.icloud.com", "spotify.com"}
	got := r.Redact().String()

	if !strings.Contains(got, "Hostnames queried:") {
		t.Fatalf("redacted report lost the enrichment line entirely:\n%s", got)
	}
	line := got[strings.Index(got, "Hostnames queried:"):]
	line = line[:strings.IndexByte(line, '\n')]
	if strings.TrimSpace(strings.TrimPrefix(line, "Hostnames queried:")) == "" {
		t.Errorf("Hostnames queried: line is empty after redaction:\n%s", got)
	}
}

func TestRedactOfAnUnenrichedReportIsANoop(t *testing.T) {
	r := sampleReport() // no Names set
	red := r.Redact()
	if red.Enriched() {
		t.Error("redacting a report with no hostnames must not fabricate any")
	}
}

func TestReportEmpty(t *testing.T) {
	if !(Report{}).Empty() {
		t.Error("a zero report is empty")
	}
	if sampleReport().Empty() {
		t.Error("a populated report is not empty")
	}
}

func TestGapDuration(t *testing.T) {
	if got := sampleReport().GapDuration(); got != 47*time.Second {
		t.Errorf("GapDuration() = %s, want 47s", got)
	}
	// An unopened gap has no duration, rather than a nonsense one measured
	// from the zero time.
	if got := (Report{GapClosed: time.Now()}).GapDuration(); got != 0 {
		t.Errorf("GapDuration() with no open time = %s, want 0", got)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{0: "0 B", 512: "512 B", 2048: "2.0 kB", 3 << 20: "3.0 MB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
