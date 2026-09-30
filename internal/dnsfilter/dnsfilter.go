// Package dnsfilter is the resolver Portalguard runs for the length of the
// gap, so that DNS leaves the machine only for names the login needs.
//
// While the gap is open, pf redirects every DNS query bound for the network's
// resolver to this server on 127.0.0.1. It forwards the names on its
// allowlist - the portal's own, the probe endpoints, remembered hosts, and
// anything a human passes to `allow` - and answers everything else REFUSED
// without it ever leaving the machine. Its own queries go upstream from one
// fixed source port, which is the only DNS pf lets out.
//
// Before this, the gap's DNS hole was machine-wide: every background daemon's
// queued lookups went to the portal's resolver the moment it opened. Scoping
// the rule to the browser's uid could not work on macOS, where every lookup is
// sent by mDNSResponder; see docs/pf-design.md, "The DNS hole is
// machine-wide".
package dnsfilter

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Ports. Fixed rather than chosen, because the pf rules name them and a
// second Portalguard process has to be able to render the same rules.
const (
	// ListenPort is where pf redirects the gap's DNS, on 127.0.0.1 and ::1.
	ListenPort = 53530
	// UpstreamPort is the source port of the filter's own upstream queries.
	// Below macOS's ephemeral range (49152-65535), so no ordinary socket
	// lands on it by chance, and it is what pf's one DNS pass rule matches.
	UpstreamPort = 41053
)

// upstreamTimeout bounds one forwarded query.
const upstreamTimeout = 3 * time.Second

// ==== the allowlist =======================================================

// Policy is the set of names the filter forwards. Exact names only: a whole
// domain would let a portal's DNS vouch for anything under it, which is the
// trust docs/gap-scope.md option C was rejected for.
type Policy struct {
	mu    sync.RWMutex
	names map[string]bool
	// file, if set, is a list of further names, one per line, re-read when it
	// changes. It is how `portalguard allow` in a second process reaches the
	// filter running inside `run`.
	file     string
	fileMod  time.Time
	fromFile map[string]bool
}

// NewPolicy returns a policy allowing names, plus whatever file lists.
func NewPolicy(file string, names ...string) *Policy {
	p := &Policy{names: map[string]bool{}, file: file}
	for _, n := range names {
		p.Allow(n)
	}
	return p
}

// Allow adds a name.
func (p *Policy) Allow(name string) {
	if n := normalize(name); n != "" && net.ParseIP(n) == nil {
		p.mu.Lock()
		p.names[n] = true
		p.mu.Unlock()
	}
}

// Allowed reports whether name may be forwarded.
func (p *Policy) Allowed(name string) bool {
	n := normalize(name)
	p.reload()
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.names[n] || p.fromFile[n]
}

// reload re-reads the allow file if it has changed since last time.
func (p *Policy) reload() {
	if p.file == "" {
		return
	}
	st, err := os.Stat(p.file)
	if err != nil {
		return
	}
	p.mu.RLock()
	same := st.ModTime().Equal(p.fileMod)
	p.mu.RUnlock()
	if same {
		return
	}
	data, err := os.ReadFile(p.file)
	if err != nil {
		return
	}
	names := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if n := normalize(line); n != "" {
			names[n] = true
		}
	}
	p.mu.Lock()
	p.fromFile, p.fileMod = names, st.ModTime()
	p.mu.Unlock()
}

// AppendAllowFile adds names to an allow file, for a second process to hand
// names to a filter it does not own.
func AppendAllowFile(path string, names ...string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, n := range names {
		if n = normalize(n); n != "" {
			if _, err := fmt.Fprintln(f, n); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// ==== the server ==========================================================

// Server is the filtering resolver.
type Server struct {
	// Upstreams are the network's resolvers, tried in order.
	Upstreams []net.IP
	Policy    *Policy
	// Logf, if set, is told about each refusal the first time a name is seen.
	Logf func(format string, args ...any)
	// OnRefused, if set, is told each name the first time it is refused.
	OnRefused func(name string)
	// Trace, if set, is told about every query and what became of it:
	// "forwarded", "auto" (forwarded and opened), "refused" or "servfail".
	// For reviewing a real network afterwards; Logf only sees first refusals.
	Trace func(name, qtype, verdict string)
	// UpstreamControl, if set, is applied to the upstream sockets: binding
	// them to the Wi-Fi interface when the network has no default route yet.
	UpstreamControl func(network, address string, c syscall.RawConn) error
	// Auto, if set, is asked about names the policy does not list, and can
	// have them forwarded and opened as they are asked for. See AutoAllower.
	Auto AutoAllower

	// ListenAddr and UpstreamSourcePort default to the fixed ports the pf
	// rules name. They are settable so tests can run without those ports
	// (UpstreamSourcePort -1 means any free port).
	ListenAddr         string
	UpstreamSourcePort int
	upstreamDst        int // the resolvers' port; 53 unless a test says otherwise

	udp []net.PacketConn
	tcp []net.Listener
	// One upstream socket per family, both on the fixed source port. IPv6
	// matters as much as IPv4: a dual-stack network hands out both kinds of
	// resolver, and macOS will happily send every lookup over IPv6. The first
	// real-network run found exactly that, with an IPv4-only filter.
	upstream4, upstream6 *net.UDPConn

	mu        sync.Mutex
	nextID    uint16
	pending   map[uint16]chan []byte
	refused   map[string]int
	forwarded map[string]int
	auto      map[string]int
	wg        sync.WaitGroup
}

// AutoAllower opens a name the policy does not list, at the moment it is
// asked for, rather than refusing it and waiting for someone to run `allow`.
type AutoAllower interface {
	// Wants reports whether name should be forwarded instead of refused.
	Wants(name string) bool
	// Open is given the addresses in the upstream answer before the reply
	// goes back, so the firewall is open by the time the client connects to
	// them. An error, or an answer with nothing to open, is refused like any
	// other name: the client never learns an address it cannot reach, and
	// the name reaches the suggestion as it did before.
	Open(name string, addrs []net.IP) error
}

// Start binds the listener and the upstream socket and begins serving.
func (s *Server) Start() error {
	if len(s.Upstreams) == 0 {
		return errors.New("dnsfilter: no upstream resolver")
	}
	if s.Policy == nil {
		s.Policy = NewPolicy("")
	}
	addr := s.ListenAddr
	if addr == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", ListenPort)
	}
	port := s.UpstreamSourcePort
	switch {
	case port == 0:
		port = UpstreamPort
	case port < 0:
		port = 0
	}
	if s.upstreamDst == 0 {
		s.upstreamDst = 53
	}
	s.pending = map[uint16]chan []byte{}
	s.refused = map[string]int{}
	s.forwarded = map[string]int{}
	s.auto = map[string]int{}

	lc := net.ListenConfig{Control: s.UpstreamControl}
	if pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", port)); err == nil {
		s.upstream4 = pc.(*net.UDPConn)
	}
	if pc, err := lc.ListenPacket(context.Background(), "udp6", fmt.Sprintf("[::]:%d", port)); err == nil {
		s.upstream6 = pc.(*net.UDPConn)
	}
	if s.upstream4 == nil && s.upstream6 == nil {
		return fmt.Errorf("dnsfilter: no upstream socket on port %d", port)
	}

	addrs := []string{addr}
	if s.ListenAddr == "" {
		addrs = append(addrs, fmt.Sprintf("[::1]:%d", ListenPort))
	}
	for _, a := range addrs {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			if len(s.udp) == 0 {
				s.closeAll()
				return fmt.Errorf("dnsfilter: listen %s: %w", a, err)
			}
			continue // no IPv6 loopback: IPv4 alone still works
		}
		ln, err := net.Listen("tcp", a)
		if err != nil {
			pc.Close()
			if len(s.udp) == 0 {
				s.closeAll()
				return fmt.Errorf("dnsfilter: listen tcp %s: %w", a, err)
			}
			continue
		}
		s.udp = append(s.udp, pc)
		s.tcp = append(s.tcp, ln)
	}
	for _, up := range []*net.UDPConn{s.upstream4, s.upstream6} {
		if up != nil {
			s.wg.Add(1)
			go s.readUpstream(up)
		}
	}
	for i := range s.udp {
		s.wg.Add(2)
		go s.serveUDP(s.udp[i])
		go s.serveTCP(s.tcp[i])
	}
	return nil
}

// Addr is where the server listens (the first address, IPv4).
func (s *Server) Addr() net.Addr { return s.udp[0].LocalAddr() }

// Stop closes every socket and waits for the server to finish.
func (s *Server) Stop() {
	s.closeAll()
	s.wg.Wait()
}

func (s *Server) closeAll() {
	var cs []io.Closer
	for _, c := range s.udp {
		cs = append(cs, c)
	}
	for _, l := range s.tcp {
		cs = append(cs, l)
	}
	for _, u := range []*net.UDPConn{s.upstream4, s.upstream6} {
		if u != nil {
			cs = append(cs, u)
		}
	}
	for _, c := range cs {
		c.Close()
	}
}

// Refused returns the names that were refused, most asked first.
func (s *Server) Refused() []string { return s.names(s.refused) }

// Forwarded returns the names that were forwarded, most asked first.
func (s *Server) Forwarded() []string { return s.names(s.forwarded) }

// AutoAllowed returns the names Auto opened, most asked first.
func (s *Server) AutoAllowed() []string { return s.names(s.auto) }

// Counts returns how many queries were refused and forwarded.
func (s *Server) Counts() (refused, forwarded int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.refused {
		refused += n
	}
	for _, n := range s.forwarded {
		forwarded += n
	}
	return refused, forwarded
}

func (s *Server) names(m map[string]int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

func (s *Server) serveUDP(pc net.PacketConn) {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if r := s.handle(q); r != nil {
				_, _ = pc.WriteTo(r, from)
			}
		}()
	}
}

func (s *Server) serveTCP(ln net.Listener) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * upstreamTimeout))
			for {
				var n uint16
				if binary.Read(c, binary.BigEndian, &n) != nil {
					return
				}
				q := make([]byte, n)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				r := s.handle(q)
				if r == nil {
					return
				}
				if binary.Write(c, binary.BigEndian, uint16(len(r))) != nil {
					return
				}
				if _, err := c.Write(r); err != nil {
					return
				}
			}
		}(c)
	}
}

// handle answers one query: forwarded if its name is allowed, REFUSED if not.
func (s *Server) handle(q []byte) []byte {
	name, ok := questionName(q)
	if !ok {
		// A query that is not a plain hostname lookup is refused rather than
		// ignored, so the app asking fails now instead of timing out. Too
		// short to be a query at all, or a reply, gets nothing.
		if len(q) >= 12 && q[2]&0x80 == 0 {
			return refusal(q)
		}
		return nil
	}
	r, verdict := s.decide(q, name)
	if s.Trace != nil {
		s.Trace(name, questionType(q), verdict)
	}
	return r
}

// decide answers one query and says what it did with it.
func (s *Server) decide(q []byte, name string) ([]byte, string) {
	if !s.Policy.Allowed(name) {
		if s.Auto != nil && s.Auto.Wants(name) {
			if r, verdict := s.autoAllow(q, name); r != nil {
				return r, verdict
			}
		}
		s.mu.Lock()
		first := s.refused[name] == 0
		s.refused[name]++
		s.mu.Unlock()
		if first && s.Logf != nil {
			s.Logf("dns filter: refused %s", name)
		}
		if first && s.OnRefused != nil {
			s.OnRefused(name)
		}
		return refusal(q), "refused"
	}
	s.mu.Lock()
	s.forwarded[name]++
	s.mu.Unlock()
	r, err := s.forward(q)
	if err != nil {
		return servfail(q), "servfail"
	}
	return r, "forwarded"
}

// autoAllow forwards a query Auto wants, opens the addresses in the answer,
// and returns the reply, or nil to have the query refused after all.
//
// A reply with no addresses in it (no such name, or an HTTPS record without
// address hints) goes back as it is: it gives the client nothing to connect
// to. A reply with any address, hints included, goes back only once Open has
// succeeded.
func (s *Server) autoAllow(q []byte, name string) ([]byte, string) {
	r, err := s.forward(q)
	if err != nil {
		return servfail(q), "servfail"
	}
	addrs := answerAddrs(r)
	if len(addrs) > 0 {
		if err := s.Auto.Open(name, addrs); err != nil {
			if s.Logf != nil {
				s.Logf("dns filter: could not open %s automatically: %v", name, err)
			}
			return nil, ""
		}
	}
	s.mu.Lock()
	s.forwarded[name]++
	if len(addrs) > 0 {
		s.auto[name]++
	}
	s.mu.Unlock()
	// "auto" only for an answer that opened something: an AAAA or HTTPS
	// reply with no address in it was forwarded, not opened, and counting it
	// as opened made the trace overstate what auto-allow did.
	if len(addrs) > 0 {
		return r, "auto"
	}
	return r, "forwarded"
}

// forward sends q upstream from the fixed port under a fresh ID, and returns
// the reply with the client's ID put back.
func (s *Server) forward(q []byte) ([]byte, error) {
	orig := binary.BigEndian.Uint16(q[0:2])
	ch := make(chan []byte, 1)
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()

	out := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(out[0:2], id)
	for _, up := range s.Upstreams {
		conn := s.upstream4
		if up.To4() == nil {
			conn = s.upstream6
		}
		if conn == nil {
			continue
		}
		if _, err := conn.WriteToUDP(out, &net.UDPAddr{IP: up, Port: s.upstreamDst}); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
		select {
		case r := <-ch:
			cancel()
			binary.BigEndian.PutUint16(r[0:2], orig)
			return r, nil
		case <-ctx.Done():
			cancel()
		}
	}
	return nil, errors.New("dnsfilter: no upstream answered")
}

func (s *Server) readUpstream(conn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		id := binary.BigEndian.Uint16(buf[0:2])
		s.mu.Lock()
		ch := s.pending[id]
		s.mu.Unlock()
		if ch != nil {
			select {
			case ch <- append([]byte(nil), buf[:n]...):
			default:
			}
		}
	}
}

// ==== DNS wire format, the little of it needed ============================

// questionName reads the name from a single-question query.
func questionName(q []byte) (string, bool) {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 || q[2]&0x80 != 0 {
		return "", false
	}
	var labels []string
	for i := 12; ; {
		if i >= len(q) {
			return "", false
		}
		l := int(q[i])
		i++
		if l == 0 {
			if i+4 > len(q) {
				return "", false
			}
			return normalize(strings.Join(labels, ".")), true
		}
		if l&0xC0 != 0 || i+l > len(q) {
			return "", false
		}
		// Hostname characters only. A label may hold any byte on the wire,
		// and some read as a different name once joined and normalised: the
		// one label "cdn.guestwifi.test" looks exactly like the allowed
		// three, and "test " like "test" once trimmed, while the resolver
		// sees neither. Found by FuzzQuestionName.
		if !hostLabel(q[i : i+l]) {
			return "", false
		}
		labels = append(labels, string(q[i:i+l]))
		i += l
	}
}

// answerAddrs returns the A and AAAA records in a successful reply's answer
// section, whatever name they are for: a CNAME chain ends in addresses owned
// by another name, and those are what the client will connect to.
func answerAddrs(r []byte) []net.IP {
	if len(r) < 12 || r[3]&0x0F != 0 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(r[4:6]))
	an := int(binary.BigEndian.Uint16(r[6:8]))
	i := 12
	for ; qd > 0; qd-- {
		if i = skipName(r, i); i < 0 || i+4 > len(r) {
			return nil
		}
		i += 4
	}
	var out []net.IP
	for ; an > 0; an-- {
		if i = skipName(r, i); i < 0 || i+10 > len(r) {
			return out
		}
		typ := binary.BigEndian.Uint16(r[i : i+2])
		n := int(binary.BigEndian.Uint16(r[i+8 : i+10]))
		i += 10
		if i+n > len(r) {
			return out
		}
		switch {
		case typ == 1 && n == 4, typ == 28 && n == 16:
			out = append(out, net.IP(append([]byte(nil), r[i:i+n]...)))
		case typ == 64 || typ == 65:
			out = append(out, svcbHints(r[i:i+n])...)
		}
		i += n
	}
	return out
}

// svcbHints returns the ipv4hint and ipv6hint addresses in one SVCB or HTTPS
// record's data (RFC 9460). Browsers ask for HTTPS records alongside A and
// AAAA and may connect to a hint before either answers, so a hint auto-allow
// did not open is a connection that fails.
func svcbHints(d []byte) []net.IP {
	// SvcPriority, then TargetName: uncompressed, per the RFC.
	if len(d) < 3 {
		return nil
	}
	i := 2
	for i < len(d) && d[i] != 0 {
		i += int(d[i]) + 1
	}
	i++
	var out []net.IP
	for i+4 <= len(d) {
		key := binary.BigEndian.Uint16(d[i : i+2])
		n := int(binary.BigEndian.Uint16(d[i+2 : i+4]))
		i += 4
		if i+n > len(d) {
			return out
		}
		size := map[uint16]int{4: 4, 6: 16}[key] // ipv4hint, ipv6hint
		if size > 0 && n%size == 0 {
			for j := i; j < i+n; j += size {
				out = append(out, net.IP(append([]byte(nil), d[j:j+size]...)))
			}
		}
		i += n
	}
	return out
}

// skipName returns the offset just past a possibly compressed name at i, or
// -1 if it runs off the end.
func skipName(r []byte, i int) int {
	for i < len(r) {
		l := int(r[i])
		switch {
		case l == 0:
			return i + 1
		case l&0xC0 == 0xC0:
			if i+2 > len(r) {
				return -1
			}
			return i + 2
		case l&0xC0 != 0:
			return -1
		}
		i += l + 1
	}
	return -1
}

// hostLabel reports whether a label is made of hostname characters: letters,
// digits, hyphens, and the underscore DNS service names use (_dns-sd).
func hostLabel(b []byte) bool {
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// questionType names the record type asked for, for the trace.
func questionType(q []byte) string {
	end := questionEnd(q)
	if end > len(q) || end < 16 {
		return "?"
	}
	t := binary.BigEndian.Uint16(q[end-4 : end-2])
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 65:
		return "HTTPS"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 16:
		return "TXT"
	case 33:
		return "SRV"
	}
	return fmt.Sprintf("TYPE%d", t)
}

// questionEnd is the offset just past the question section.
func questionEnd(q []byte) int {
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	return i + 5
}

// reply builds an answerless response to q with the given rcode.
func reply(q []byte, rcode byte) []byte {
	end := questionEnd(q)
	if end > len(q) {
		end = len(q)
	}
	r := append([]byte(nil), q[:end]...)
	r[2] = 0x80 | (q[2] & 0x79) // QR, opcode and RD kept
	r[3] = 0x80 | rcode         // RA
	binary.BigEndian.PutUint16(r[6:8], 0)
	binary.BigEndian.PutUint16(r[8:10], 0)
	binary.BigEndian.PutUint16(r[10:12], 0)
	return r
}

func refusal(q []byte) []byte  { return reply(q, 5) }
func servfail(q []byte) []byte { return reply(q, 2) }
