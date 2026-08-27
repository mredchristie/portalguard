//go:build darwin

package pf

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// errNotFound stands in for "ps could not find that pid" - the ordinary,
// expected outcome when looking up a pid this test fabricated.
var errNotFound = errors.New("pid not found")

// ==== the text path: hostnames =============================================

// TestDNSQueryRegex is checked against the real line captured from pflog1
// during the 2026-08-27 verification (docs/pf-design.md, "Verified against
// a real capture") and against tcpdump's decode of pg-demo/before.pcap, so
// the pattern is validated against real tcpdump output, not invented.
func TestDNSQueryRegex(t *testing.T) {
	cases := map[string]string{
		"03:43:46.045970 rule 0.portalguard.0/0(match): pass out on lo0: 127.0.0.1.52803 > 127.0.0.1.53: 791+ [1au] A? pgverify-test-query.invalid. (56)": "pgverify-test-query.invalid",
		"1787786165.262353 IP 192.168.0.56.54954 > 192.168.0.1.53: 21564+ A? edge-web-gew4.dual-gslb.spotify.com. (53)":                                   "edge-web-gew4.dual-gslb.spotify.com",
		"1787786165.262403 IP 192.168.0.56.60672 > 192.168.0.1.53: 10870+ AAAA? edge-web-gew4.dual-gslb.spotify.com. (53)":                                "edge-web-gew4.dual-gslb.spotify.com",
		"1787786165.262438 IP 192.168.0.56.58098 > 192.168.0.1.53: 57756+ PTR? lb._dns-sd._udp.Home. (38)":                                                "lb._dns-sd._udp.Home",
	}
	for line, want := range cases {
		m := dnsQueryRe.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("no match for %q", line)
			continue
		}
		if m[1] != want {
			t.Errorf("dnsQueryRe(%q) = %q, want %q", line, m[1], want)
		}
	}
}

func TestDNSQueryRegexNoFalseMatchOnANonDNSLine(t *testing.T) {
	// The ICMP line from the same capture as the good case above - the
	// regex must not fire on it.
	line := "03:43:46.046120 rule 0..0/0(match): pass in on lo0: 127.0.0.1 > 127.0.0.1: ICMP 127.0.0.1 udp port 53 unreachable, length 36"
	if m := dnsQueryRe.FindStringSubmatch(line); m != nil {
		t.Errorf("unexpected match on a non-DNS line: %v", m)
	}
}

// ==== the raw path: uid/pid ================================================

// fakePflogRecord builds a payload with the reverse-engineered layout from
// docs/pf-design.md's byte table, so tests exercise the same offsets the
// real parser trusts rather than a simplified stand-in for them.
func fakePflogRecord(t *testing.T, length int, af, action, reason, dir byte, uid, pid uint32) []byte {
	t.Helper()
	slot := wordAlign4(length)
	// A little extra after the header, standing in for the IP packet that
	// always follows it in a real capture.
	buf := make([]byte, slot+20)
	buf[pflogOffLength] = byte(length)
	buf[pflogOffAF] = af
	buf[2] = action
	buf[3] = reason
	binary.LittleEndian.PutUint32(buf[pflogOffUID:], uid)
	binary.LittleEndian.PutUint32(buf[pflogOffPID:], pid)
	buf[pflogOffDir] = dir
	return buf
}

func TestParsePflogRecordExtractsUIDAndPID(t *testing.T) {
	r := newLogReader()
	r.psLookup = func(pid int) (string, error) { return "", errNotFound } // force the "pid N" fallback, deterministically

	// uid 501 is this dev machine's own real account, so it resolves via
	// the same os/user.LookupId check the parser itself uses; pid 4242 is
	// an ordinary in-range value, not the 100000 that turned out to be the
	// live bug.
	payload := fakePflogRecord(t, 61, afINET, 0 /*PF_PASS*/, 0 /*match*/, dirOut, 501, 4242)
	if err := r.parsePflogRecord(payload); err != nil {
		t.Fatalf("parsePflogRecord: %v", err)
	}

	names, processes, unavailable, note, _ := r.Stop()
	_ = names
	if unavailable {
		t.Errorf("a well-formed record must not mark process attribution unavailable (note: %q)", note)
	}
	want := "pid 4242(4242)"
	if len(processes) != 1 || processes[0] != want {
		t.Errorf("processes = %v, want [%q]", processes, want)
	}
}

// TestParsePflogRecordRejectsAPidOutsideDarwinsRange checks the genuinely
// invalid case, distinct from pidSentinel (100000) itself, which is now a
// recognised, non-error "not attributed" signal - see
// TestParsePflogRecordRecognisesTheKernelSentinel below. 100001 is still
// outside Darwin's pid ceiling, but is not the specific value the kernel
// uses to mean "no info", so it must still be rejected as implausible.
func TestParsePflogRecordRejectsAPidOutsideDarwinsRange(t *testing.T) {
	r := newLogReader()
	payload := fakePflogRecord(t, 61, afINET, 0, 0, dirOut, 501, 100001)
	err := r.parsePflogRecord(payload)
	if err == nil {
		t.Fatal("expected an error for pid 100001, which Darwin can never assign")
	}
	if !strings.Contains(err.Error(), "pid") {
		t.Errorf("error should say what looked wrong, got: %v", err)
	}
	// parsePflogRecord reports the problem; readRaw is what turns that into
	// processesUnavailable (see TestMarkUnavailableLogsOnce) - checked
	// separately rather than here, since this test is about the parser.
}

// TestParsePflogRecordRecognisesTheKernelSentinel is the resolution of the
// "offsets are misaligned" question: a 2026-08-27 capture fired three DNS
// queries from processes whose real pids were known (72837, 72839, 72841,
// captured via $! at spawn time) and none of the six resulting pflog
// records - queries or their kernel-generated replies - carried any of
// them. Every one carried pidSentinel. uid was real on the same records
// (501), so this is not a parse offset problem: it is confirmed to be this
// platform's own "not attributed" signal, and must be treated as one, not
// as a parse failure.
func TestParsePflogRecordRecognisesTheKernelSentinel(t *testing.T) {
	r := newLogReader()
	payload := fakePflogRecord(t, 61, afINET, 0, 0, dirOut, 501, pidSentinel)
	if err := r.parsePflogRecord(payload); err != nil {
		t.Fatalf("pidSentinel must not be treated as a parse error: %v", err)
	}
	if r.kernelDeclinedPID != 1 {
		t.Errorf("kernelDeclinedPID = %d, want 1", r.kernelDeclinedPID)
	}
	_, processes, unavailable, _, _ := r.Stop()
	if len(processes) != 0 {
		t.Errorf("a sentinel record must not be reported as a process, got %v", processes)
	}
	// Reported via ProcessesDeclinedByKernel at Stop, not per-record - see
	// TestStopReportsKernelDeclineWhenEveryRecordIsTheSentinel.
	_ = unavailable
}

// TestParsePflogRecordRejectionShowsTheFieldItself is the regression test
// for a diagnostic bug, not a parsing bug: the error used to dump
// firstBytes(payload, 16) unconditionally, which is the length/af/ifname
// region at the front of every header and looks identical no matter which
// check failed. That read as "the offsets must be wrong" when the offsets
// were actually fine - the message just never showed the field it was
// complaining about. The dump must now contain the pid field's own bytes,
// not the header's opening bytes.
func TestParsePflogRecordRejectionShowsTheFieldItself(t *testing.T) {
	r := newLogReader()
	// pid 100001 = 0xa1 0x86 0x01 0x00 little-endian - distinctive enough
	// that finding it in the error proves the dump moved to the real field,
	// and distinct from pidSentinel (100000) so this exercises the genuine
	// rejection path, not the recognised-sentinel path.
	payload := fakePflogRecord(t, 61, afINET, 0, 0, dirOut, 501, 100001)
	err := r.parsePflogRecord(payload)
	if err == nil {
		t.Fatal("expected an error for pid 100001")
	}
	if !strings.Contains(err.Error(), "a1 86 01 00") {
		t.Errorf("error must show the pid field's own bytes (a1 86 01 00), got: %v", err)
	}
	// The header's opening bytes (length=61=0x3d, af=2) must not be what
	// the dump shows here - that was the actual source of the earlier
	// confusion, and asserting its absence keeps it from creeping back.
	if strings.Contains(err.Error(), "3d 02 00 00") {
		t.Errorf("error must not dump the header's opening bytes for a pid failure, got: %v", err)
	}
}

func TestParsePflogRecordRejectsPidZero(t *testing.T) {
	r := newLogReader()
	payload := fakePflogRecord(t, 61, afINET, 0, 0, dirOut, 501, 0)
	if err := r.parsePflogRecord(payload); err == nil {
		t.Fatal("expected an error for pid 0, which no real socket-owning process has")
	}
}

// TestParsePflogRecordRejectsAnUnresolvableUID checks the other half of the
// live bug's fix: a uid that does not correspond to any real account on
// this machine is rejected via an actual lookup, not a range guess.
func TestParsePflogRecordRejectsAnUnresolvableUID(t *testing.T) {
	r := newLogReader()
	// Comfortably past any uid this machine's accounts could plausibly use.
	const noSuchUID = 4111222333
	payload := fakePflogRecord(t, 61, afINET, 0, 0, dirOut, noSuchUID, 4242)
	err := r.parsePflogRecord(payload)
	if err == nil {
		t.Fatal("expected an error for a uid with no matching account")
	}
	if !strings.Contains(err.Error(), "uid") {
		t.Errorf("error should say what looked wrong, got: %v", err)
	}
}

// TestStopFlagsSingleProcessAcrossManyHostnames is the whole-run heuristic:
// each individual record can pass its own checks and the aggregate result
// can still be implausible. This cannot be caught per-packet, only once
// everything is collected.
func TestStopFlagsSingleProcessAcrossManyHostnames(t *testing.T) {
	r := newLogReader()
	for _, n := range []string{"a.example", "b.example", "c.example", "d.example"} {
		r.names[n] = struct{}{}
	}
	r.processes["mDNSResponder(99)"] = struct{}{}

	names, processes, unavailable, note, _ := r.Stop()
	if !unavailable {
		t.Fatal("four hostnames attributed to one process should be distrusted, not reported")
	}
	if processes != nil {
		t.Errorf("processes should be cleared once distrusted, got %v", processes)
	}
	if len(names) != 4 {
		t.Errorf("hostnames must survive independently of the process distrust, got %v", names)
	}
	if !strings.Contains(note, "distinct hostnames") {
		t.Errorf("note should explain why, got: %q", note)
	}
}

// TestStopDoesNotFlagOneProcessWithFewHostnames guards against the
// heuristic being trigger-happy: a single, genuinely busy process (like
// mDNSResponder) making a couple of queries is ordinary, not suspicious.
func TestStopDoesNotFlagOneProcessWithFewHostnames(t *testing.T) {
	r := newLogReader()
	r.names["a.example"] = struct{}{}
	r.names["b.example"] = struct{}{}
	r.processes["mDNSResponder(99)"] = struct{}{}

	_, processes, unavailable, _, _ := r.Stop()
	if unavailable {
		t.Error("two hostnames from one process is ordinary, not implausible")
	}
	if len(processes) != 1 {
		t.Errorf("processes should be left alone, got %v", processes)
	}
}

// TestStopReportsKernelDeclineWhenEveryRecordIsTheSentinel is the whole-run
// counterpart to TestParsePflogRecordRecognisesTheKernelSentinel: once
// everything is collected, a run where every attributable record was the
// sentinel and nothing else explains the empty Processes list must report
// that specifically, not the generic "unavailable" wording.
func TestStopReportsKernelDeclineWhenEveryRecordIsTheSentinel(t *testing.T) {
	r := newLogReader()
	for _, n := range []string{"a.example", "b.example"} {
		r.names[n] = struct{}{}
	}
	for i := 0; i < 3; i++ {
		payload := fakePflogRecord(t, 61, afINET, 0, 0, dirOut, 501, pidSentinel)
		if err := r.parsePflogRecord(payload); err != nil {
			t.Fatalf("parsePflogRecord: %v", err)
		}
	}

	names, processes, unavailable, note, declinedByKernel := r.Stop()
	if !declinedByKernel {
		t.Fatal("expected declinedByKernel = true")
	}
	if !unavailable {
		t.Error("declinedByKernel must still set the general unavailable flag for JSON/API consumers")
	}
	if len(processes) != 0 {
		t.Errorf("no process should be reported, got %v", processes)
	}
	if len(names) != 2 {
		t.Errorf("hostnames must survive independently, got %v", names)
	}
	if !strings.HasPrefix(note, "["+string(failureKernel)+"]") {
		t.Errorf("note must be tagged [kernel], got: %q", note)
	}
}

// TestStopDoesNotReportKernelDeclineIfARealProcessWasFound guards the
// priority rule: if even one record on the run carried a real, trusted pid,
// Processes is non-empty and the kernel-decline conclusion must not fire -
// there is a real answer to report, not an absence to explain.
func TestStopDoesNotReportKernelDeclineIfARealProcessWasFound(t *testing.T) {
	r := newLogReader()
	r.psLookup = func(pid int) (string, error) { return "", errNotFound }

	sentinel := fakePflogRecord(t, 61, afINET, 0, 0, dirOut, 501, pidSentinel)
	if err := r.parsePflogRecord(sentinel); err != nil {
		t.Fatalf("parsePflogRecord (sentinel): %v", err)
	}
	real := fakePflogRecord(t, 61, afINET, 0, 0, dirOut, 501, 4242)
	if err := r.parsePflogRecord(real); err != nil {
		t.Fatalf("parsePflogRecord (real): %v", err)
	}

	_, processes, _, _, declinedByKernel := r.Stop()
	if declinedByKernel {
		t.Error("a run with a real process found must not also claim the kernel declined everything")
	}
	if len(processes) != 1 {
		t.Errorf("the one real process must still be reported, got %v", processes)
	}
}

func TestParsePflogRecordSkipsPacketsWithNoUserInfo(t *testing.T) {
	r := newLogReader()
	// pf's sentinel for "this rule did not carry log(user)" - must be
	// skipped silently, not treated as a malformed header.
	payload := fakePflogRecord(t, 61, afINET, 0, 0, dirOut, noInfo, noInfo)
	if err := r.parsePflogRecord(payload); err != nil {
		t.Fatalf("parsePflogRecord: %v", err)
	}
	_, processes, unavailable, note, _ := r.Stop()
	if unavailable {
		t.Errorf("the no-info sentinel must not be treated as a format break (note: %q)", note)
	}
	if len(processes) != 0 {
		t.Errorf("no process should be recorded for a no-info packet, got %v", processes)
	}
}

// TestParsePflogRecordRejectsAnUnrecognisedShape is the sanity-check
// failure path: a header whose af byte is not one this package recognises.
// This is the scenario the middle report state (report_test.go,
// TestReportHostnamesKnownProcessesNot) exists for - it must fail loudly
// enough to log, not silently produce a wrong uid/pid.
func TestParsePflogRecordRejectsAnUnrecognisedShape(t *testing.T) {
	r := newLogReader()
	payload := fakePflogRecord(t, 61, 99 /* not AF_INET or AF_INET6 */, 0, 0, dirOut, 501, 100000)
	err := r.parsePflogRecord(payload)
	if err == nil {
		t.Fatal("expected an error for an unrecognised af byte, got nil")
	}
	if !strings.Contains(err.Error(), "af byte") {
		t.Errorf("error should say what looked wrong, got: %v", err)
	}
}

func TestParsePflogRecordRejectsATooShortPayload(t *testing.T) {
	r := newLogReader()
	err := r.parsePflogRecord(make([]byte, 10))
	if err == nil {
		t.Fatal("expected an error for a payload too short to hold the fields this package reads")
	}
}

// TestMarkUnavailableLogsOnce checks the "log it once" requirement: repeated
// failures must not keep overwriting or re-appending the note.
func TestMarkUnavailableLogsOnce(t *testing.T) {
	r := newLogReader()
	r.markUnavailable(failureParse, "first failure: af byte 99")
	r.markUnavailable(failureParse, "second failure: should not replace the first")

	_, _, unavailable, note, _ := r.Stop()
	if !unavailable {
		t.Fatal("expected processesUnavailable to be true")
	}
	if !strings.Contains(note, "first failure") {
		t.Errorf("note should keep the first diagnosis, got: %q", note)
	}
	if strings.Contains(note, "second failure") {
		t.Errorf("note should not be overwritten by a later failure, got: %q", note)
	}
}

// TestMarkUnavailableTagsTheFailureKind is the actual ask: the note must
// let a reader tell "offsets are wrong" from "the heuristic is too
// aggressive" apart without parsing English prose to guess which happened.
func TestMarkUnavailableTagsTheFailureKind(t *testing.T) {
	parseReader := newLogReader()
	parseReader.markUnavailable(failureParse, "af byte 99 is neither AF_INET nor AF_INET6")
	_, _, _, parseNote, _ := parseReader.Stop()
	if !strings.HasPrefix(parseNote, "[parse] ") {
		t.Errorf("a per-record parse failure must be tagged [parse], got: %q", parseNote)
	}

	heuristicReader := newLogReader()
	for _, n := range []string{"a.example", "b.example", "c.example"} {
		heuristicReader.names[n] = struct{}{}
	}
	heuristicReader.processes["mDNSResponder(99)"] = struct{}{}
	_, _, _, heuristicNote, _ := heuristicReader.Stop()
	if !strings.HasPrefix(heuristicNote, "[heuristic] ") {
		t.Errorf("the many-hostnames-one-process check must be tagged [heuristic], got: %q", heuristicNote)
	}

	if parseNote == heuristicNote {
		t.Error("the two failure kinds must not collapse into the same note")
	}
}

func TestWordAlign4(t *testing.T) {
	cases := map[int]int{0: 0, 1: 4, 3: 4, 4: 4, 5: 8, 61: 64, 64: 64}
	for in, want := range cases {
		if got := wordAlign4(in); got != want {
			t.Errorf("wordAlign4(%d) = %d, want %d", in, got, want)
		}
	}
}
