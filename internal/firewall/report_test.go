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
