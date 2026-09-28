//go:build darwin

package pf

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// tcpdumpPath is the absolute path to tcpdump; we do not trust PATH for a
// process spawned from a privileged run.
const tcpdumpPath = "/usr/sbin/tcpdump"

// dnsQueryRe pulls the queried name out of tcpdump's own DNS decode, e.g.
// "791+ [1au] A? pgverify-test-query.invalid. (56)". This is tcpdump's
// stable, public protocol decoder - unlike the pflog uid/pid fields below,
// nothing about it is reverse-engineered. Verified against a real pflog1
// capture and against pg-demo/before.pcap; see docs/pf-design.md, "Verified
// against a real capture".
var dnsQueryRe = regexp.MustCompile(`\b(?:A|AAAA|PTR)\?\s+(\S+)\.\s+\(\d+\)`)

// pflog header layout, read from a live capture rather than a header file:
// if_pflog.h ships in no macOS SDK. See docs/pf-design.md, "Verified
// against a real capture", for the byte table this comes from and why each
// offset is trusted. BPF word-aligns the captured header to a 4-byte
// boundary, which is why the usable slot is wider than the header's own
// length byte says.
const (
	pflogOffLength = 0
	pflogOffAF     = 1
	pflogOffDir    = 60
	pflogOffUID    = 44
	pflogOffPID    = 48

	// pflogFieldsNeeded is the furthest fixed-offset field this package
	// reads (dir, at 60) plus one, so a payload shorter than this cannot
	// safely be indexed at all, independent of what its length byte claims.
	pflogFieldsNeeded = pflogOffDir + 1

	// pflogMinLength and pflogMaxLength bound the header's own self-reported
	// length byte. The captured value on 2026-08-27 (tcpdump 4.99.1, Apple
	// 158) was 61; the range gives headroom for minor pf revisions without
	// accepting a value that could not possibly be this struct.
	pflogMinLength = 52
	pflogMaxLength = 200

	afINET  = 2  // AF_INET
	afINET6 = 30 // AF_INET6, the BSD/macOS value - Linux's differs

	dirIn  = 1 // PF_IN
	dirOut = 2 // PF_OUT

	noInfo = 0xffffffff // pf's "no uid/pid available" sentinel

	// pidMax is Darwin's traditional pid ceiling. A parsed pid at or above
	// it cannot be real on this kernel, full stop - not a plausibility
	// judgement call, a hard fact about this OS.
	pidMax = 99999

	// pidSentinel is pidMax+1: confirmed, not assumed, by a 2026-08-27
	// capture that fired three DNS queries from processes whose real pids
	// were captured via $! at spawn time (72837, 72839, 72841) and compared
	// against what six pflog records reported. Every one - queries and
	// their kernel-generated replies alike - carried pid 100000. uid was
	// real (501, and the ICMP replies' distinct 0x7fffffff sentinel) on the
	// same records, so this is not a parse offset problem; it is this
	// platform's own "no pid attributed" value for this field, distinct
	// from the ffffffff/7fffffff sentinels already handled. See
	// docs/pf-design.md, "Resolved: pid 100000 is a kernel sentinel".
	pidSentinel = pidMax + 1
)

// wordAlign4 rounds up to the next multiple of 4, matching BPF's padding of
// the pflog header inside the capture.
func wordAlign4(n int) int { return (n + 3) &^ 3 }

// failureKind classifies why the raw path stopped trusting itself, because
// the two ways it can fail need opposite fixes and must not be confused for
// each other:
//
//   - failureParse means one record's own bytes looked wrong - a bad
//     length, af, dir, pid, or an unresolvable uid. That points at the
//     reverse-engineered struct offsets themselves being wrong.
//   - failureHeuristic means every record parsed cleanly on its own terms,
//     but the aggregate result looked implausible (see manyHostnames in
//     Stop). That points at the heuristic being too eager, not at the
//     parse being wrong - a single genuinely busy process can trigger it.
type failureKind string

const (
	failureParse     failureKind = "parse"
	failureHeuristic failureKind = "heuristic"
	// failureKernel is not a failure of this package's reading at all - it
	// tags the case where the kernel itself declined to attribute a packet
	// (pidSentinel below), which needs its own report wording, not the
	// generic "could not be determined" a parse or heuristic failure gets.
	failureKernel failureKind = "kernel"
)

// logReader tails pflog1 for the life of an open gap.
//
// Two independent tcpdump processes read the same device: one decodes text
// for hostnames (tcpdump's protocol decoder - stable, public), the other
// emits a raw pcap stream this package parses by hand for uid/pid (an
// undocumented struct this package reverse-engineered). They are separate
// OS processes on purpose, not just separate goroutines over one stream: a
// crash or format break in the raw path must not take the text path down
// with it, and a future macOS is far more likely to break the
// reverse-engineered struct than tcpdump's DNS decoder.
type logReader struct {
	textCmd *exec.Cmd
	rawCmd  *exec.Cmd
	wg      sync.WaitGroup

	mu                   sync.Mutex
	names                map[string]struct{}
	processes            map[string]struct{}
	processesUnavailable bool
	note                 string // diagnostic detail, set once, for Status()

	// kernelDeclinedPID counts records whose pid was pidSentinel - not a
	// parse failure, so it does not halt reading like markUnavailable does.
	// Evaluated once, in Stop: if every record on this run said this and
	// none reported a real pid, that is the report, not a fallback for one.
	kernelDeclinedPID int

	pidNameCache map[int]string
	// psLookup resolves a pid to a command name. A field rather than a
	// direct exec.Command call so tests can replace it without shelling
	// out to a real, running process.
	psLookup func(pid int) (string, error)
}

func newLogReader() *logReader {
	return &logReader{
		names:        make(map[string]struct{}),
		processes:    make(map[string]struct{}),
		pidNameCache: make(map[int]string),
		psLookup:     psLookupReal,
	}
}

// Start spawns both tcpdump processes against pflog1. A failure to start
// either is returned; the caller treats it the same as any other
// leak-logging setup failure - the gap still opens, the report just cannot
// be enriched. ctx is only a backstop (a forceful kill if the process this
// belongs to is ever torn down by cancellation without going through Stop);
// the ordinary path always calls Stop for a clean shutdown.
func (r *logReader) Start(ctx context.Context) error {
	textCmd := exec.CommandContext(ctx, tcpdumpPath, "-n", "-e", "-l", "-i", LogInterface)
	textOut, err := textCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("leak reader: text tcpdump stdout: %w", err)
	}
	if err := textCmd.Start(); err != nil {
		return fmt.Errorf("leak reader: start text tcpdump: %w", err)
	}

	rawCmd := exec.CommandContext(ctx, tcpdumpPath, "-n", "-i", LogInterface, "-w", "-")
	rawOut, err := rawCmd.StdoutPipe()
	if err != nil {
		_ = textCmd.Process.Kill()
		return fmt.Errorf("leak reader: raw tcpdump stdout: %w", err)
	}
	if err := rawCmd.Start(); err != nil {
		_ = textCmd.Process.Kill()
		return fmt.Errorf("leak reader: start raw tcpdump: %w", err)
	}

	r.textCmd, r.rawCmd = textCmd, rawCmd

	r.wg.Add(2)
	go func() { defer r.wg.Done(); r.readText(textOut) }()
	go func() { defer r.wg.Done(); r.readRaw(rawOut) }()
	return nil
}

// Stop signals both tcpdump processes to shut down cleanly (SIGTERM, so
// each flushes its own stdio/pcap buffer before exiting rather than being
// killed mid-write), waits for both reader goroutines to drain, and returns
// what was found. declinedByKernel is true when every record this run saw
// carried pidSentinel and none reported a real pid - the kernel explicitly
// not attributing these packets, which reads differently from this package
// failing to determine it and must not be reported as the same thing.
func (r *logReader) Stop() (names, processes []string, unavailable bool, note string, declinedByKernel bool) {
	if r.textCmd != nil && r.textCmd.Process != nil {
		_ = r.textCmd.Process.Signal(syscall.SIGTERM)
	}
	if r.rawCmd != nil && r.rawCmd.Process != nil {
		_ = r.rawCmd.Process.Signal(syscall.SIGTERM)
	}
	r.wg.Wait()
	if r.textCmd != nil {
		_ = r.textCmd.Wait()
	}
	if r.rawCmd != nil {
		_ = r.rawCmd.Wait()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	names = setToSortedSlice(r.names)
	processes = setToSortedSlice(r.processes)

	// A whole-run check, not a per-packet one: many distinct hostnames
	// almost never come from exactly one process, so this is checked once
	// everything is collected rather than at each record. Each individual
	// record can pass its own sanity checks and the aggregate can still be
	// implausible - this is what catches that.
	const manyHostnames = 3
	if !r.processesUnavailable && len(names) >= manyHostnames && len(processes) == 1 {
		r.processesUnavailable = true
		r.note = fmt.Sprintf(
			"[%s] %d distinct hostnames but only one distinct process (%s) - too implausible to trust",
			failureHeuristic, len(names), processes[0])
		processes = nil
	}

	// Evaluated last and only if nothing else already explains the empty
	// Processes list: a genuine parse or heuristic failure is more
	// actionable than "the kernel declined", so it takes priority if both
	// somehow happened on the same run.
	if !r.processesUnavailable && len(processes) == 0 && r.kernelDeclinedPID > 0 {
		r.processesUnavailable = true
		declinedByKernel = true
		r.note = fmt.Sprintf(
			"[%s] every log(user) record this run saw (%d) carried pid %d, the confirmed kernel sentinel for "+
				"'not attributed' - not a read failure",
			failureKernel, r.kernelDeclinedPID, pidSentinel)
	}

	return names, processes, r.processesUnavailable, r.note, declinedByKernel
}

// Peek returns the hostnames seen so far, leaving both tcpdump processes
// running.
//
// Stop is the only other way to read this set, and it reads it once, at the
// end, when the gap is already closing. That is too late for the question a
// user standing in front of a half-rendered login page is actually asking:
// which host did that page just ask for and not get. Peek exists so the
// names can be read while the gap is still open and still widenable.
//
// It reports lookups, not blocks. DNS is open through the gap, so a name
// here means something on this machine resolved it, not that the connection
// which followed was allowed - and the set includes every background
// daemon's lookups too, because the DNS hole is machine-wide. Filtering that
// into something worth showing a person is the caller's job, not the
// reader's; see state.SuggestAllow.
func (r *logReader) Peek() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return setToSortedSlice(r.names)
}

func setToSortedSlice(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ==== the text path: hostnames ============================================
// Reads tcpdump's own DNS decode. Independent of the raw path below: this
// keeps running, and keeps finding hostnames, even if that path's struct
// assumptions break on a future macOS.

func (r *logReader) readText(out io.ReadCloser) {
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		m := dnsQueryRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		r.mu.Lock()
		r.names[m[1]] = struct{}{}
		r.mu.Unlock()
	}
}

// ==== the raw path: uid/pid ================================================
// Parses tcpdump's own pcap stream by hand, because tcpdump's text decoder
// never prints uid/pid at any verbosity - confirmed empirically, see
// docs/pf-design.md. A single malformed header is treated as "the struct
// layout no longer holds" for the rest of this run, not a one-off: pf's
// header shape does not vary packet to packet, so a mismatch here means our
// assumptions are wrong, not that this one packet is unusual.

func (r *logReader) readRaw(out io.ReadCloser) {
	br := bufio.NewReader(out)

	var global [24]byte
	if _, err := io.ReadFull(br, global[:]); err != nil {
		// Nothing captured before shutdown is an ordinary short-gap outcome,
		// not a format break; do not diagnose it as one.
		return
	}
	if magic := binary.LittleEndian.Uint32(global[0:4]); magic != 0xa1b2c3d4 {
		r.markUnavailable(failureParse, fmt.Sprintf("unexpected pcap magic %#08x from tcpdump's own -w - stream", magic))
		return
	}

	for {
		var rec [16]byte
		if _, err := io.ReadFull(br, rec[:]); err != nil {
			return // EOF at a record boundary is the normal shutdown path
		}
		inclLen := binary.LittleEndian.Uint32(rec[8:12])
		payload := make([]byte, inclLen)
		if _, err := io.ReadFull(br, payload); err != nil {
			return // truncated by shutdown mid-record, not a format break
		}
		if err := r.parsePflogRecord(payload); err != nil {
			r.markUnavailable(failureParse, err.Error())
			return
		}
	}
}

// parsePflogRecord reads uid/pid out of one captured pflog header. Every
// bound checked here is a sanity check against the reverse-engineered
// layout, not a parse of a documented struct - see docs/pf-design.md for
// what each one is checking against and why it is trusted.
func (r *logReader) parsePflogRecord(payload []byte) error {
	if len(payload) < pflogFieldsNeeded {
		return fmt.Errorf("pflog record too short (%d bytes) to hold the fields this package reads up to offset %d; raw bytes: % x",
			len(payload), pflogOffDir, payload)
	}

	length := int(payload[pflogOffLength])
	af := payload[pflogOffAF]
	dir := payload[pflogOffDir]

	if length < pflogMinLength || length > pflogMaxLength {
		return fmt.Errorf(
			"pflog header length %d outside the expected [%d,%d] - the struct layout this package reverse-engineered on 2026-08-27 (tcpdump 4.99.1, Apple 158) may no longer hold; raw bytes: % x",
			length, pflogMinLength, pflogMaxLength, firstBytes(payload, 16))
	}
	if af != afINET && af != afINET6 {
		return fmt.Errorf("pflog af byte %d is neither AF_INET(2) nor AF_INET6(30); raw bytes: % x", af, firstBytes(payload, 16))
	}
	if dir != dirIn && dir != dirOut {
		return fmt.Errorf("pflog dir byte %d is neither PF_IN(1) nor PF_OUT(2); raw bytes: % x", dir, firstBytes(payload, 16))
	}
	if slot := wordAlign4(length); slot > len(payload) {
		return fmt.Errorf("pflog header slot %d (length %d word-aligned) exceeds the %d-byte record", slot, length, len(payload))
	}

	uid := binary.LittleEndian.Uint32(payload[pflogOffUID : pflogOffUID+4])
	pid := binary.LittleEndian.Uint32(payload[pflogOffPID : pflogOffPID+4])
	if uid == noInfo || pid == noInfo {
		return nil // this packet's rule did not carry log(user)
	}

	// pidSentinel is not a parse failure: confirmed against real ground
	// truth (see its own comment) to be this platform's own "the kernel did
	// not attribute this packet to a process" signal, distinct from the
	// noInfo case above. It does not halt the run the way an error from
	// this function does - kernelDeclinedPID is just counted, and Stop
	// decides once everything is in whether every record said this.
	if pid == pidSentinel {
		r.mu.Lock()
		r.kernelDeclinedPID++
		r.mu.Unlock()
		return nil
	}

	// Below this point, a pid this package has not already recognised as a
	// sentinel is being asked to be a real one - so it has to actually look
	// real. One is a hard fact about this kernel (pids above pidMax cannot
	// exist), the other is an actual lookup against the real account
	// database rather than a guess.
	//
	// The error dumps the field's own bytes (offset pflogOffUID/pflogOffPID
	// specifically), not just the header's opening bytes - a prior version
	// of this message always showed firstBytes(payload, 16), which is the
	// length/af/ifname region and looks identical regardless of which check
	// actually failed. That cost a debugging round: it read as "landing on
	// the interface name field" when it was really just an unrelated part
	// of the same, correctly-aligned header.
	if pid == 0 || pid > pidMax {
		return fmt.Errorf("pflog pid %d is outside [1,%d], which is not a real pid on this kernel; pid field (offset %d) raw bytes: % x",
			pid, pidMax, pflogOffPID, payload[pflogOffPID:pflogOffPID+4])
	}
	if _, err := user.LookupId(strconv.Itoa(int(uid))); err != nil {
		return fmt.Errorf("pflog uid %d does not resolve to a real account (%v); uid field (offset %d) raw bytes: % x",
			uid, err, pflogOffUID, payload[pflogOffUID:pflogOffUID+4])
	}

	name, _ := r.processName(int(pid))
	r.mu.Lock()
	r.processes[fmt.Sprintf("%s(%d)", name, pid)] = struct{}{}
	r.mu.Unlock()
	return nil
}

func firstBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// markUnavailable records the first raw-path failure and nothing after it:
// once the struct assumption is wrong, every subsequent packet would fail
// the same way, and repeating the diagnostic would only bury it. kind is
// tagged onto the front of the note so a reader can tell "offsets are
// wrong" (parse) from "the heuristic is too aggressive" (heuristic) without
// parsing English out of the detail.
func (r *logReader) markUnavailable(kind failureKind, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.processesUnavailable {
		return
	}
	r.processesUnavailable = true
	r.note = fmt.Sprintf("[%s] %s", kind, detail)
}

// processName resolves a pid to a command name via ps, the same
// unprivileged lookup a person would run by hand. A failure (the process
// has since exited, most often) falls back to the bare pid rather than
// dropping the attribution entirely.
func (r *logReader) processName(pid int) (string, error) {
	r.mu.Lock()
	if name, ok := r.pidNameCache[pid]; ok {
		r.mu.Unlock()
		return name, nil
	}
	r.mu.Unlock()

	name, err := r.psLookup(pid)
	if err != nil || name == "" {
		name = fmt.Sprintf("pid %d", pid)
	}

	r.mu.Lock()
	r.pidNameCache[pid] = name
	r.mu.Unlock()
	return name, err
}

// psLookupReal is the default psLookup: ps -o comm= -p <pid>, no sudo
// needed, the same as a person would run by hand.
func psLookupReal(pid int) (string, error) {
	out, err := exec.Command("/bin/ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
