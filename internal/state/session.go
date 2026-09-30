package state

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"portalguard/internal/dnsfilter"
	"portalguard/internal/firewall"
	"portalguard/internal/portal"
)

// ErrNoPortal is returned when an action needs a known portal and detection
// has not found one.
var ErrNoPortal = errors.New("state: no captive portal detected yet")

// ==== the session =========================================================
// Ties detection and the firewall to the state machine.

// Session drives one pass through the state machine, wiring detection and the
// packet filter to the transitions.
//
// The invariant it exists to maintain: the firewall is only ever loosened
// while the machine says it should be, and any error on the way in leaves the
// machine no less locked down than it was.
type Session struct {
	machine *Machine
	fw      firewall.Backend
	prober  *portal.Prober
	logf    firewall.Logf

	mu      sync.Mutex
	last    portal.Result
	allowed []firewall.Host
	// store is where a snapshot is written after every transition, or "" for
	// a session that leaves nothing behind. See PersistTo.
	store string
	since time.Time
	// knownPath is where OpenKnown looks for remembered networks, or "" to
	// try none. See UseKnownNetworks.
	knownPath string

	// onSuggest is told about portal hosts that are being looked up and are
	// not in the gap; suggested remembers which have been passed on already,
	// so a three-second poll does not repeat itself. See OnSuggestion.
	onSuggest func([]string)
	suggested map[string]bool

	// dns is the filtering resolver, while this session is running one. See
	// dnsfilter.go.
	dns *dnsfilter.Server

	// autoOn asks StartDNSFilter to open the portal's own site as the page
	// asks for it; auto is what does so. See autoallow.go.
	autoOn bool
	auto   *autoAllow
	// dnsVerbose has the filter log each name the first time it refuses it,
	// so a login stuck on another domain (a payment page) can be spotted
	// while it is happening. See UseVerboseDNS.
	dnsVerbose bool
	// dnsTrace is told about every query the filter answers. See UseDNSTrace.
	dnsTrace func(name, qtype, verdict string)

	// gapMu is held across AllowExtra's check-and-open and across Seal and
	// Release, so a host added from inside this process (the prompt) can
	// never land after the seal and open a new gap on a sealed machine.
	gapMu sync.Mutex
}

// NewSession wires a session. A nil prober gets the default probe list.
func NewSession(fw firewall.Backend, prober *portal.Prober, logf firewall.Logf) *Session {
	return newSession(NewMachine(), fw, prober, logf)
}

func newSession(m *Machine, fw firewall.Backend, prober *portal.Prober, logf firewall.Logf) *Session {
	if prober == nil {
		prober = portal.NewProber()
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &Session{machine: m, fw: fw, prober: prober, logf: logf, since: time.Now()}
	// Recording on every transition rather than at chosen call sites: the
	// snapshot is only useful if it is never stale, and "remember to save
	// here" is exactly the kind of thing a new command forgets.
	m.Observe(func(Transition) { s.save() })
	return s
}

// ==== leaving something behind ============================================
// One invocation records what the next one cannot work out for itself.

// PersistTo makes the session record a snapshot at path after every
// transition, so a later invocation can pick up where this one left off.
//
// A session with no store is the default, and is what tests and any read-only
// caller want: nothing is written, and nothing has to be cleaned up.
func (s *Session) PersistTo(path string) {
	s.mu.Lock()
	s.store = path
	s.mu.Unlock()
	s.save()
}

// save writes the current snapshot, if this session has a store.
//
// Failures are logged and swallowed, for the same reason the pf enable token
// is written best-effort: refusing to lock the machine down because a
// bookkeeping file would not write is the tail wagging the dog. What is lost
// is the host *names* and the portal identity; the gap itself is recovered
// from the kernel either way.
func (s *Session) save() {
	s.mu.Lock()
	path := s.store
	snap := s.snapshotLocked()
	s.mu.Unlock()

	if path == "" {
		return
	}
	if err := SaveSnapshot(path, snap); err != nil {
		s.logf("could not record the session for the next invocation: %v", err)
	}
}

// snapshotLocked builds the on-disk view of this session. The caller must hold
// s.mu.
func (s *Session) snapshotLocked() Snapshot {
	return Snapshot{
		State: s.machine.State(),
		Portal: PortalRef{
			URL:   s.last.PortalURL,
			Host:  s.last.PortalHost,
			Port:  s.last.PortalPort,
			Addrs: s.last.PortalAddrs,
		},
		Allowed: append([]firewall.Host(nil), s.allowed...),
		Since:   s.since,
		History: s.machine.History(),
	}
}

// Snapshot returns what this session would record, whether or not it has a
// store. It is what `status` renders and what a long-running UI would poll.
func (s *Session) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

// ==== picking up where another process left off ===========================
// The kernel decides the phase; the snapshot only supplies the names.

// Resume builds a session that adopts whatever an earlier invocation left in
// place, so `allow`, `seal` and `status` work as separate commands rather than
// only inside a single `run`.
//
// The ordering here is the whole safety argument: **the kernel decides the
// phase, and the snapshot only enriches it.** A snapshot is a file written by
// a process that may since have died, been killed, or been followed by a
// `release` it knew nothing about. Letting it decide would mean a stale file
// could convince this process that a gap is open when the machine is in fact
// wide open, or fully blocked. Reading the loaded ruleset first means the
// worst a stale snapshot can do is be ignored - which is also why nothing has
// to guarantee the file gets cleaned up.
//
// What the snapshot adds is the part no packet filter can hold: which state
// the machine had reached (a bare lockdown and a sealed gap are the same
// ruleset), and the hostnames and reasons behind the addresses in the tables.
func Resume(ctx context.Context, fw firewall.Backend, prober *portal.Prober, logf firewall.Logf, path string) (*Session, error) {
	st, err := fw.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("read firewall status: %w", err)
	}

	snap, snapErr := LoadSnapshot(path)
	if snapErr != nil {
		snap = Snapshot{}
	}

	adopted, note := AdoptedState(st, snap)
	if adopted == Idle && !errors.Is(snapErr, ErrNoSnapshot) {
		// Nothing of ours is loaded, so the snapshot describes a session that
		// has already been released. Drop it rather than leave a file behind
		// that says otherwise.
		ClearSnapshot(path)
		snap = Snapshot{}
	}

	m, err := NewMachineAt(adopted, note)
	if err != nil {
		return nil, err
	}

	s := newSession(m, fw, prober, logf)
	s.mu.Lock()
	s.allowed = reconcileAllowed(snap.Allowed, st.Allowed)
	if adopted != Idle && snap.Portal.Host != "" {
		// The portal identity comes from the earlier invocation's detection
		// run, not from one of ours. Nothing here is re-probed: this process
		// has not looked at the network, and says so by leaving Result's probe
		// detail empty.
		s.last = portal.Result{
			Class:       portal.Portal,
			PortalURL:   snap.Portal.URL,
			PortalHost:  snap.Portal.Host,
			PortalPort:  snap.Portal.Port,
			PortalAddrs: snap.Portal.Addrs,
		}
	}
	if !snap.Since.IsZero() {
		s.since = snap.Since
	}
	s.mu.Unlock()
	return s, nil
}

// AdoptedState reconciles the loaded ruleset with the snapshot, and says which
// of the two decided.
//
// Exported so `status` can show exactly the state the next `allow` would act
// on. Rendering the snapshot's own claim instead would let status report
// GAP_OPEN over a ruleset that permits nothing, which is precisely the
// mismatch a user reads status to rule out.
//
// The firewall phase is coarser than the machine: PhaseLocked covers both a
// bare lockdown and a gap that has been sealed, and PhaseGap covers both a
// user who is still logging in and one whose re-probe has already come back
// clean. The snapshot is allowed to pick between the states that share a
// phase, and nothing else.
func AdoptedState(st firewall.Status, snap Snapshot) (State, string) {
	switch st.Phase {
	case firewall.PhaseGap:
		if snap.State == Authenticated {
			return snap.State, "resumed: the gap is open in the loaded ruleset, and the session file says the re-probe had already succeeded"
		}
		return GapOpen, resumeNote(snap, "the gap is open in the loaded ruleset")
	case firewall.PhaseLocked:
		if snap.State == Authenticated || snap.State == Sealed {
			return snap.State, "resumed: traffic is blocked in the loaded ruleset, and the session file says " + string(snap.State)
		}
		return LockedDown, resumeNote(snap, "traffic is blocked in the loaded ruleset")
	default:
		return Idle, "no portalguard rules are loaded"
	}
}

func resumeNote(snap Snapshot, kernel string) string {
	if snap.State == "" {
		return "resumed from the kernel alone: " + kernel + ", and there is no session file"
	}
	return "resumed: " + kernel
}

// reconcileAllowed merges what the snapshot remembers with what the packet
// filter is actually enforcing.
//
// The kernel decides which addresses are open. The snapshot only supplies the
// names, ports and reasons that a table of addresses cannot hold. So a
// remembered host whose addresses are no longer open is dropped, and an open
// address no remembered host accounts for is kept as it came back from the
// kernel - because the one thing this must never do is leave something that is
// genuinely open out of the picture.
func reconcileAllowed(remembered, live []firewall.Host) []firewall.Host {
	if len(live) == 0 {
		return nil
	}
	open := map[string]bool{}
	for _, h := range live {
		for _, ip := range h.Addrs {
			open[ip.String()] = true
		}
	}

	var out []firewall.Host
	accounted := map[string]bool{}
	for _, h := range remembered {
		var keep []net.IP
		for _, ip := range h.Addrs {
			if open[ip.String()] {
				keep = append(keep, ip)
				accounted[ip.String()] = true
			}
		}
		if len(keep) == 0 {
			continue
		}
		h.Addrs = keep
		out = append(out, h)
	}

	for _, h := range live {
		var unaccounted []net.IP
		for _, ip := range h.Addrs {
			if !accounted[ip.String()] {
				unaccounted = append(unaccounted, ip)
				accounted[ip.String()] = true
			}
		}
		if len(unaccounted) == 0 {
			continue
		}
		h.Addrs = unaccounted
		out = append(out, h)
	}
	return out
}

// Machine exposes the state machine for observers and status output.
func (s *Session) Machine() *Machine { return s.machine }

// Result returns the most recent detection result.
func (s *Session) Result() portal.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// ==== the flow, in order ==================================================
// Detect, lock down, open the gap, wait for login, seal, hand off.

// Detect runs the probes and moves the machine to PortalFound or back to Idle.
func (s *Session) Detect(ctx context.Context) (portal.Result, error) {
	if _, err := s.machine.Apply(EventDetect, ""); err != nil {
		return portal.Result{}, err
	}

	res := s.prober.Detect(ctx)
	// Follow the portal's redirects now, while the network is open. Only
	// here: the re-probe during the gap reuses Detect, and must not.
	s.prober.FollowChain(ctx, &res)

	s.mu.Lock()
	s.last = res
	s.mu.Unlock()

	if res.Class == portal.Portal {
		note := res.PortalHost
		if note == "" {
			note = "portal host unknown"
		}
		if _, err := s.machine.Apply(EventPortalFound, note); err != nil {
			return res, err
		}
		return res, nil
	}
	if _, err := s.machine.Apply(EventNoPortal, string(res.Class)); err != nil {
		return res, err
	}
	return res, nil
}

// Lockdown blocks all traffic. From here nothing leaks while the user works
// out what the portal wants.
func (s *Session) Lockdown(ctx context.Context) error {
	if !s.machine.Can(EventLockdown) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventLockdown}
	}
	if err := s.fw.Lockdown(ctx); err != nil {
		return fmt.Errorf("lockdown: %w", err)
	}
	_, err := s.machine.Apply(EventLockdown, s.fw.Name())
	return err
}

// OpenGap punches the single hole the human needs: the portal host on its own
// port plus 80/443, and DNS to the resolvers this network handed us.
//
// DNS is included because a portal's login flow almost always needs to resolve
// its own hostname, and because the portal's resolver is the only one reachable
// while we are locked down. It is the widest part of the gap and the reason
// this state is meant to be short-lived.
func (s *Session) OpenGap(ctx context.Context) error {
	if !s.machine.Can(EventOpenGap) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventOpenGap}
	}

	s.mu.Lock()
	res := s.last
	s.mu.Unlock()

	if res.Class != portal.Portal {
		return ErrNoPortal
	}

	hosts, err := gapHosts(res)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if err := s.fw.AllowHost(ctx, h); err != nil {
			// Leave the lockdown in place: a half-open gap is still closed
			// enough to be safe, and Release is always available.
			return fmt.Errorf("allow %s: %w", h.Name, err)
		}
		s.mu.Lock()
		s.allowed = append(s.allowed, h)
		s.mu.Unlock()
		s.logf("gap opened for %s", h)
	}

	s.startAutoFromLog(res.PortalHost)
	_, err = s.machine.Apply(EventOpenGap, res.PortalHost)
	return err
}

// AllowExtra widens the gap for one more host. Portals routinely bounce
// through a second hostname (a payment provider, a CDN for their CSS), and the
// user has to be able to add it without dropping the lockdown.
func (s *Session) AllowExtra(ctx context.Context, host string, ports ...int) error {
	s.gapMu.Lock()
	defer s.gapMu.Unlock()
	if !s.machine.Can(EventExtendGap) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventExtendGap}
	}
	// The name goes to the DNS filter first, or resolving it here is the
	// very lookup the filter refuses.
	s.allowDNSName(host)
	h, err := resolveViaFilter(ctx, host, ports, "manually added by the user")
	if err != nil {
		return err
	}
	// The browser's earlier lookup of this name was refused, and macOS
	// caches that. Without a flush, reloading the page keeps failing on the
	// cached refusal long after the name has been allowed.
	flushSystemDNSCache()
	if err := s.fw.AllowHost(ctx, h); err != nil {
		return fmt.Errorf("allow %s: %w", host, err)
	}
	s.mu.Lock()
	s.allowed = append(s.allowed, h)
	s.mu.Unlock()
	s.logf("gap widened for %s", h)

	_, err = s.machine.Apply(EventExtendGap, host)
	return err
}

// ==== known networks: open only what proves itself =========================
//
// The gap stays decided by a human for anything OpenGap or AllowExtra touch.
// This is the one exception, and it earns it by substituting a stronger
// proof than a person glancing at a hostname would give it: a valid TLS
// certificate for the exact name, checked fresh on this network, on this
// connection. See docs/gap-scope.md, option E, and verifyKnownHost for why
// that stands in for consent here and DNS alone never could.

// UseKnownNetworks makes OpenKnown consult the remembered-networks file at
// path. A session with no known-networks path is the default, and OpenKnown
// is then a no-op: nothing is tried that a human did not name.
func (s *Session) UseKnownNetworks(path string) {
	s.mu.Lock()
	s.knownPath = path
	s.mu.Unlock()
}

// OpenKnown tries to widen an already-open gap using hosts remembered for the
// portal's site, opening only the ones that complete a TLS handshake with a
// certificate valid for their name. It returns the hostnames actually opened.
//
// A host that fails verification - wrong certificate, self-signed, refused,
// timed out - is not opened and is not treated as an error. It simply falls
// back to the existing suggestion path: if the portal turns out to need it,
// the leak reader will notice it being looked up and SuggestAllow will name
// it, same as any host nobody has told Portalguard about.
func (s *Session) OpenKnown(ctx context.Context) []string {
	s.mu.Lock()
	path := s.knownPath
	portalHost := s.last.PortalHost
	open := make(map[string]bool, len(s.allowed)+1)
	open[normalizeHost(portalHost)] = true
	for _, h := range s.allowed {
		open[normalizeHost(h.Name)] = true
	}
	s.mu.Unlock()

	if path == "" {
		return nil
	}
	site := siteOf(portalHost)
	if site == "" {
		return nil
	}
	kn, ok := LoadKnownNetworks(path)[site]
	if !ok {
		return nil
	}

	var opened []string
	for _, spec := range kn.Hosts {
		host, port := splitHostPort(spec)
		if open[normalizeHost(host)] {
			continue
		}

		ports := []int{80, 443}
		verifyPort := 443
		if port != 0 {
			ports, verifyPort = []int{port}, port
		}

		h, err := resolveHost(ctx, host, ports, "known network, verified by TLS certificate")
		if err != nil {
			s.logf("known host %s did not resolve: %v", host, err)
			continue
		}

		var verifyErr error
		verified := false
		for _, addr := range h.Addrs {
			if verifyErr = s.verifyThroughCheck(ctx, addr, verifyPort, host); verifyErr == nil {
				verified = true
				break
			}
		}
		if !verified {
			s.logf("known host %s did not verify (%v) - not opened automatically", host, verifyErr)
			continue
		}

		if err := s.fw.AllowHost(ctx, h); err != nil {
			s.logf("known host %s verified but could not be opened: %v", host, err)
			continue
		}
		s.mu.Lock()
		s.allowed = append(s.allowed, h)
		s.mu.Unlock()
		if _, err := s.machine.Apply(EventExtendGap, host+" (known network, TLS verified)"); err != nil {
			s.logf("known host %s opened but could not record the transition: %v", host, err)
		}
		s.logf("gap opened automatically for %s (known network, TLS verified)", h)
		opened = append(opened, host)
	}
	return opened
}

// Remember saves the gap's current extra hosts - the ones widened onto it
// beyond the portal's own host - as a known network under the portal's site,
// so OpenKnown can try them automatically on a later visit.
//
// It requires an open gap with something extra already allowed: it can only
// remember hosts that were actually reached and, implicitly, judged
// necessary by whoever ran `allow` on them - never hosts named blind. It does
// not remember the portal host itself, which is re-detected and re-pinned
// fresh on every visit regardless, and can legitimately vary by branch in a
// way a chain's CDN and auth hosts do not.
func (s *Session) Remember(path string) (site string, added []string, err error) {
	s.mu.Lock()
	portalHost := s.last.PortalHost
	extra := make([]firewall.Host, 0, len(s.allowed))
	nameless := 0
	for _, h := range s.allowed {
		if h.AllowDNSTo || h.Check || normalizeHost(h.Name) == normalizeHost(portalHost) {
			continue
		}
		// A host recovered from the kernel alone carries a table's label,
		// not a hostname. Remembering it would save a word, not a host.
		if !rememberable(h.Name) {
			nameless++
			continue
		}
		extra = append(extra, h)
	}
	s.mu.Unlock()

	site = siteOf(portalHost)
	if site == "" {
		return "", nil, fmt.Errorf("no portal host to remember a network for")
	}
	if len(extra) == 0 && nameless > 0 {
		return site, nil, fmt.Errorf("hosts are open beyond the portal, but their names were not recorded when they were added; run allow for them again, then remember")
	}
	if len(extra) == 0 {
		return site, nil, fmt.Errorf("nothing extra is open to remember; allow a host first")
	}

	networks := LoadKnownNetworks(path)
	kn, existed := networks[site]
	if !existed {
		kn = KnownNetwork{Site: site, AddedAt: time.Now()}
	}
	have := map[string]bool{}
	for _, spec := range kn.Hosts {
		h, _ := splitHostPort(spec)
		have[normalizeHost(h)] = true
	}
	for _, h := range extra {
		if have[normalizeHost(h.Name)] {
			continue
		}
		spec := h.Name
		if len(h.Ports) == 1 && h.Ports[0] != 80 && h.Ports[0] != 443 {
			spec = fmt.Sprintf("%s:%d", h.Name, h.Ports[0])
		}
		kn.Hosts = append(kn.Hosts, spec)
		have[normalizeHost(h.Name)] = true
		added = append(added, h.Name)
	}
	if len(added) == 0 {
		return site, nil, nil
	}
	kn.LastSeen = time.Now()
	networks[site] = kn

	if err := SaveKnownNetworks(path, networks); err != nil {
		return site, nil, err
	}
	return site, added, nil
}

// splitHostPort reads a "host" or "host:port" entry, the same form `allow`
// accepts on the command line. port is 0 when none was given, meaning the
// default 80/443.
func splitHostPort(spec string) (host string, port int) {
	h, p, err := net.SplitHostPort(spec)
	if err != nil {
		return spec, 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return spec, 0
	}
	return h, n
}

// CheckAuth re-probes through the open gap. A success means the portal has let
// the user on, which is the only signal we trust: we never read the portal's
// own "you are logged in" page.
func (s *Session) CheckAuth(ctx context.Context) (bool, error) {
	res := s.prober.Detect(ctx)
	s.mu.Lock()
	s.last = res
	s.mu.Unlock()

	if res.Class != portal.OpenInternet {
		return false, nil
	}
	if !s.machine.Can(EventAuthenticated) {
		return true, &InvalidTransitionError{From: s.machine.State(), Event: EventAuthenticated}
	}
	_, err := s.machine.Apply(EventAuthenticated, "re-probe reached the real internet")
	return true, err
}

// WaitForAuth polls until the re-probe succeeds, the context is cancelled, or
// the deadline passes.
func (s *Session) WaitForAuth(ctx context.Context, every time.Duration) error {
	if every <= 0 {
		every = 3 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		// A login wait over a lockdown that is no longer applied is a wait
		// over an open machine. Stop and say so rather than carry on
		// reporting a gap that is now the whole network.
		if ok, why := s.enforced(ctx); !ok {
			return &NotEnforcedError{Why: why}
		}
		s.openProbeChecks(ctx)
		s.autoFromLog(ctx)
		ok, err := s.CheckAuth(ctx)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		// The wait is the whole reason this is worth doing here: it is the
		// only stretch where the gap is open, the user is looking at the
		// portal, and a missing host can still be added.
		s.suggest()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// OnSuggestion registers a callback for portal hosts that are being looked up
// and are not in the gap - the ones a blank login page is quietly waiting on.
// It fires from WaitForAuth.
//
// It fires only when a name appears that has not been passed on before, so a
// poll every three seconds does not turn into the same advice printed two
// hundred times. What it passes is the whole current list rather than only
// the new part, because the point of the list is a command the user can run
// as it stands, and a command that omits the host mentioned a minute ago
// would open the wrong set.
func (s *Session) OnSuggestion(f func(names []string)) {
	s.mu.Lock()
	s.onSuggest = f
	s.mu.Unlock()
}

// suggest passes the current suggestions on, if anything in them is new.
func (s *Session) suggest() {
	s.mu.Lock()
	f := s.onSuggest
	s.mu.Unlock()
	if f == nil {
		return
	}

	// Computed outside the lock: SuggestAllow takes s.mu itself, and reads
	// the session file.
	names := s.SuggestAllow()
	if len(names) == 0 {
		return
	}

	s.mu.Lock()
	fresh := false
	if s.suggested == nil {
		s.suggested = map[string]bool{}
	}
	for _, n := range names {
		if !s.suggested[n] {
			s.suggested[n] = true
			fresh = true
		}
	}
	s.mu.Unlock()

	if fresh {
		f(names)
	}
}

// Seal closes the gap again, leaving a bare lockdown. Traffic is still
// blocked; this is the state we hand to the VPN from.
func (s *Session) Seal(ctx context.Context) error {
	s.gapMu.Lock()
	defer s.gapMu.Unlock()
	if !s.machine.Can(EventSeal) {
		return &InvalidTransitionError{From: s.machine.State(), Event: EventSeal}
	}
	// Before the seal, not after: an automatic open that landed between the
	// two would open a new gap on a sealed machine.
	s.stopAutoAllow()
	if err := s.fw.Seal(ctx); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	// The gap's DNS rules went with the seal; the resolver behind them goes
	// now. Its record stays, for the report.
	s.stopDNSFilter()
	s.mu.Lock()
	s.allowed = nil
	s.mu.Unlock()

	_, err := s.machine.Apply(EventSeal, "gap closed")
	return err
}

// Report returns the backend's account of what it filtered, and whether the
// backend could supply one at all.
//
// Not every backend can account for its own traffic, so this is an optional
// capability rather than part of the Backend interface: a backend that cannot
// is simply not a firewall.Reporter, instead of stubbing a method that would
// have to return zeros indistinguishable from "nothing happened".
func (s *Session) Report() (firewall.Report, bool) {
	r, ok := s.fw.(firewall.Reporter)
	if !ok {
		return firewall.Report{}, false
	}
	return r.LeakReport(), true
}

// Release tears everything down and returns to Idle. It is legal from any
// state and is what the crash handler and `portalguard release` call.
func (s *Session) Release(ctx context.Context) error {
	s.gapMu.Lock()
	defer s.gapMu.Unlock()
	s.stopAutoAllow()
	err := s.fw.Release(ctx)
	s.stopDNSFilter()
	s.mu.Lock()
	s.allowed = nil
	s.mu.Unlock()
	if _, aerr := s.machine.Apply(EventRelease, ""); err == nil {
		err = aerr
	}
	return err
}

// Allowed returns the holes currently open.
func (s *Session) Allowed() []firewall.Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]firewall.Host(nil), s.allowed...)
}

// ==== working out what to allow ===========================================
// Turns a detection result into the smallest allowed-host list.

// gapHosts turns a detection result into the minimal host list for the gap.
func gapHosts(res portal.Result) ([]firewall.Host, error) {
	if len(res.PortalAddrs) == 0 {
		return nil, fmt.Errorf("%w: no address for portal host %q", ErrNoPortal, res.PortalHost)
	}

	ports := []int{80, 443}
	if res.PortalPort != 0 && res.PortalPort != 80 && res.PortalPort != 443 {
		ports = append(ports, res.PortalPort)
	}

	hosts := []firewall.Host{{
		Name:   res.PortalHost,
		Addrs:  parseIPs(res.PortalAddrs),
		Ports:  ports,
		Reason: "captive portal login page",
	}}

	// Every host the portal redirected through on the way to its login page,
	// pinned at detection like the portal host itself.
	for _, hop := range res.Hops {
		ports := []int{80, 443}
		if hop.Port != 80 && hop.Port != 443 {
			ports = append(ports, hop.Port)
		}
		if addrs := parseIPs(hop.Addrs); len(addrs) > 0 {
			hosts = append(hosts, firewall.Host{
				Name:   hop.Host,
				Addrs:  addrs,
				Ports:  ports,
				Reason: "the portal redirected through it",
			})
		}
	}

	if dns := systemResolvers(); len(dns) > 0 {
		hosts = append(hosts, firewall.Host{
			Name:       "network resolvers",
			Addrs:      dns,
			AllowDNSTo: true,
			Ports:      []int{53},
			Reason:     "the portal login flow needs to resolve its own hostname",
		})
	}
	return hosts, nil
}

// resolveHost pins a hostname to addresses for a firewall rule.
func resolveHost(ctx context.Context, host string, ports []int, reason string) (firewall.Host, error) {
	h := firewall.Host{Name: host, Ports: ports, Reason: reason}
	if ip := net.ParseIP(host); ip != nil {
		h.Addrs = []net.IP{ip}
		return h, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return h, fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, a := range addrs {
		h.Addrs = append(h.Addrs, a.IP)
	}
	if len(h.Addrs) == 0 {
		return h, fmt.Errorf("resolve %s: no addresses", host)
	}
	return h, nil
}

func parseIPs(ss []string) []net.IP {
	var out []net.IP
	for _, s := range ss {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// systemResolvers reads the resolvers currently configured for the machine.
//
// On macOS and Linux /etc/resolv.conf is the portable-enough answer: macOS
// keeps it in step with the primary service's DNS. It misses per-interface
// resolvers that only scutil knows about, which is a gap worth closing before
// v1 - a split-DNS setup could leave the portal's resolver out of the gap.
func systemResolvers() []net.IP {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
