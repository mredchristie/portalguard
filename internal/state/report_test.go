package state

import (
	"context"
	"testing"
	"time"

	"portalguard/internal/firewall"
)

// reportingBackend is a fake that accounts for its traffic, like the pf
// backend does.
type reportingBackend struct {
	fakeBackend
	report firewall.Report
}

func (r *reportingBackend) LeakReport() firewall.Report { return r.report }

// plainBackend deliberately does not implement firewall.Reporter.
type plainBackend struct{ fakeBackend }

// TestSessionReportSurvivesTheWholeCycle is the test that should have caught a
// broken report wiring without needing root, a portal, or an e2e run.
//
// The report is produced at the end of a long sequence, which is exactly the
// kind of thing that silently stops being reachable: an early return, a
// changed interface, a call site that moved. Driving the real Session through
// every transition and asking for the report at the end pins the wiring, and
// fails in milliseconds rather than after a network-cutting e2e.
func TestSessionReportSurvivesTheWholeCycle(t *testing.T) {
	ps := newPortalServer("http://127.0.0.1:8080/login")
	defer ps.Close()

	fw := &reportingBackend{report: firewall.Report{
		GapOpened:         time.Now().Add(-30 * time.Second),
		GapClosed:         time.Now(),
		BlockedOutPackets: 412,
		DNSPackets:        46,
	}}
	s := newTestSession(fw, ps.URL+"/generate_204")
	ctx := context.Background()

	if _, err := s.Detect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Lockdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.OpenGap(ctx); err != nil {
		t.Fatal(err)
	}
	ps.login()
	if ok, err := s.CheckAuth(ctx); err != nil || !ok {
		t.Fatalf("CheckAuth = %t, %v", ok, err)
	}
	if err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}

	rep, ok := s.Report()
	if !ok {
		t.Fatal("a backend that implements Reporter must produce a report after seal")
	}
	if rep.Empty() {
		t.Error("report is empty despite the backend reporting counts")
	}
	if rep.BlockedOutPackets != 412 {
		t.Errorf("BlockedOutPackets = %d, want 412", rep.BlockedOutPackets)
	}
	if rep.GapDuration() <= 0 {
		t.Error("report should carry a gap duration after a full cycle")
	}
}

// TestSessionReportAbsentForNonReportingBackend pins the other half: a backend
// that cannot account for traffic must be distinguishable from one that
// counted zero. Conflating them is how "we did not look" becomes "nothing
// leaked".
func TestSessionReportAbsentForNonReportingBackend(t *testing.T) {
	s := NewSession(&plainBackend{}, nil, nil)
	rep, ok := s.Report()
	if ok {
		t.Error("a backend that does not implement Reporter must report ok=false")
	}
	if !rep.Empty() {
		t.Error("the zero report should be empty")
	}
}

// TestSessionReportAvailableBeforeSeal covers the abort path: a run torn down
// without ever sealing still has something to say.
func TestSessionReportAvailableBeforeSeal(t *testing.T) {
	ps := newPortalServer("http://127.0.0.1:8080/login")
	defer ps.Close()

	fw := &reportingBackend{report: firewall.Report{BlockedOutPackets: 7}}
	s := newTestSession(fw, ps.URL+"/generate_204")
	ctx := context.Background()

	_, _ = s.Detect(ctx)
	_ = s.Lockdown(ctx)
	_ = s.OpenGap(ctx)
	if err := s.Release(ctx); err != nil {
		t.Fatal(err)
	}

	rep, ok := s.Report()
	if !ok || rep.Empty() {
		t.Errorf("an aborted run should still report: ok=%t empty=%t", ok, rep.Empty())
	}
}

// TestReportingBackendIsStillAPlainBackend guards against the optional
// interface being bolted on in a way that breaks the required one.
func TestReportingBackendIsStillAPlainBackend(t *testing.T) {
	var _ firewall.Backend = (*reportingBackend)(nil)
	var _ firewall.Reporter = (*reportingBackend)(nil)
	var _ firewall.Backend = (*plainBackend)(nil)
	if _, ok := any(&plainBackend{}).(firewall.Reporter); ok {
		t.Error("plainBackend must not accidentally satisfy Reporter")
	}
}
