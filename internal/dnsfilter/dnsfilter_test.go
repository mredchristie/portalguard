package dnsfilter

import (
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// query builds the packet a stub resolver sends for one A lookup.
func query(id uint16, name string) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

// fakeUpstream answers every query with one A record and remembers the names
// it was asked, standing in for the network's resolver.
type fakeUpstream struct {
	conn  *net.UDPConn
	asked chan string
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{conn: c, asked: make(chan string, 16)}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			name, _ := questionName(buf[:n])
			f.asked <- name
			r := reply(buf[:n], 0)
			binary.BigEndian.PutUint16(r[6:8], 1)
			r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 198, 51, 100, 7)
			_, _ = c.WriteToUDP(r, from)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return f
}

func startFilter(t *testing.T, up *fakeUpstream, p *Policy) *Server {
	t.Helper()
	s := &Server{
		Upstreams:          []net.IP{net.IPv4(127, 0, 0, 1)},
		Policy:             p,
		ListenAddr:         "127.0.0.1:0",
		UpstreamSourcePort: -1,
		upstreamDst:        up.conn.LocalAddr().(*net.UDPAddr).Port,
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s
}

// ask sends one query to the filter and returns the reply.
func ask(t *testing.T, s *Server, id uint16, name string) []byte {
	t.Helper()
	c, err := net.Dial("udp4", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(query(id, name)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func rcode(r []byte) byte { return r[3] & 0x0F }

// TestAllowedNamesGoUpstream: the portal's name is forwarded, and the answer
// comes back with the client's own query ID.
func TestAllowedNamesGoUpstream(t *testing.T) {
	up := newFakeUpstream(t)
	s := startFilter(t, up, NewPolicy("", "www.guestwifi.test"))

	r := ask(t, s, 0xBEEF, "www.guestwifi.test")
	if rcode(r) != 0 || binary.BigEndian.Uint16(r[6:8]) != 1 {
		t.Fatalf("rcode %d, %d answers; want an answer", rcode(r), binary.BigEndian.Uint16(r[6:8]))
	}
	if binary.BigEndian.Uint16(r[0:2]) != 0xBEEF {
		t.Errorf("reply ID %#x, want the client's 0xbeef back", binary.BigEndian.Uint16(r[0:2]))
	}
	if got := <-up.asked; got != "www.guestwifi.test" {
		t.Errorf("upstream was asked %q", got)
	}
}

// TestEverythingElseIsRefusedAndNeverLeaves is the point of the package: a
// background daemon's lookup gets REFUSED, and the network never sees it.
func TestEverythingElseIsRefusedAndNeverLeaves(t *testing.T) {
	up := newFakeUpstream(t)
	s := startFilter(t, up, NewPolicy("", "www.guestwifi.test"))

	for _, name := range []string{"imap.mail.me.com", "b._dns-sd._udp.Home", "guestwifi.test", "evil.www.guestwifi.test"} {
		if r := ask(t, s, 7, name); rcode(r) != 5 {
			t.Errorf("%s: rcode %d, want REFUSED", name, rcode(r))
		}
	}
	select {
	case got := <-up.asked:
		t.Errorf("a refused name reached the network's resolver: %s", got)
	case <-time.After(200 * time.Millisecond):
	}
	refused := strings.Join(s.Refused(), " ")
	if !strings.Contains(refused, "imap.mail.me.com") || !strings.Contains(refused, "b._dns-sd._udp.home") {
		t.Errorf("refusals not recorded: %s", refused)
	}
}

// TestAllowFileReachesARunningFilter is how `allow` from a second process
// gets a name through a filter it does not own.
func TestAllowFileReachesARunningFilter(t *testing.T) {
	up := newFakeUpstream(t)
	file := filepath.Join(t.TempDir(), "dnsallow")
	s := startFilter(t, up, NewPolicy(file, "www.guestwifi.test"))

	if r := ask(t, s, 1, "cdn.guestwifi.test"); rcode(r) != 5 {
		t.Fatalf("cdn before allow: rcode %d, want REFUSED", rcode(r))
	}
	// A different mtime, even on a fast filesystem.
	time.Sleep(10 * time.Millisecond)
	if err := AppendAllowFile(file, "CDN.guestwifi.test."); err != nil {
		t.Fatal(err)
	}
	if r := ask(t, s, 2, "cdn.guestwifi.test"); rcode(r) != 0 {
		t.Fatalf("cdn after allow: rcode %d, want an answer", rcode(r))
	}
}

// TestQuestionNameRejectsGarbage: nothing to decide on, nothing sent.
func TestQuestionNameRejectsGarbage(t *testing.T) {
	for _, q := range [][]byte{nil, make([]byte, 11), append(query(1, "a.b")[:13], 0xC0)} {
		if _, ok := questionName(q); ok {
			t.Errorf("parsed a name out of %x", q)
		}
	}
}

func TestPolicyIgnoresAddressesAndBlanks(t *testing.T) {
	p := NewPolicy("", "", "203.0.113.5", "Portal.Example.")
	if p.Allowed("203.0.113.5") || p.Allowed("") {
		t.Error("an address or a blank became an allowed name")
	}
	if !p.Allowed("portal.example") {
		t.Error("names are not normalised")
	}
}

// fakeAuto wants the names in wants, and records what it was asked to open.
type fakeAuto struct {
	wants  map[string]bool
	fail   error
	opened chan []net.IP
}

func (f *fakeAuto) Wants(name string) bool { return f.wants[name] }

func (f *fakeAuto) Open(name string, addrs []net.IP) error {
	if f.fail != nil {
		return f.fail
	}
	f.opened <- addrs
	return nil
}

func startAutoFilter(t *testing.T, up *fakeUpstream, auto *fakeAuto) *Server {
	t.Helper()
	s := &Server{
		Upstreams:          []net.IP{net.IPv4(127, 0, 0, 1)},
		Policy:             NewPolicy("", "www.guestwifi.test"),
		Auto:               auto,
		ListenAddr:         "127.0.0.1:0",
		UpstreamSourcePort: -1,
		upstreamDst:        up.conn.LocalAddr().(*net.UDPAddr).Port,
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s
}

// TestAutoAllowOpensBeforeReplying: a name Auto wants is forwarded, and its
// addresses are opened before the client hears the answer.
func TestAutoAllowOpensBeforeReplying(t *testing.T) {
	up := newFakeUpstream(t)
	auto := &fakeAuto{wants: map[string]bool{"cdn.guestwifi.test": true}, opened: make(chan []net.IP, 1)}
	s := startAutoFilter(t, up, auto)

	r := ask(t, s, 0x4242, "cdn.guestwifi.test")
	if rcode(r) != 0 {
		t.Fatalf("rcode %d, want an answer", rcode(r))
	}
	select {
	case addrs := <-auto.opened:
		if len(addrs) != 1 || !addrs[0].Equal(net.IPv4(198, 51, 100, 7)) {
			t.Fatalf("opened %v, want 198.51.100.7", addrs)
		}
	default:
		t.Fatal("the reply came back before the address was opened")
	}
	if got := s.AutoAllowed(); len(got) != 1 || got[0] != "cdn.guestwifi.test" {
		t.Fatalf("AutoAllowed = %v", got)
	}
}

// TestAutoAllowFailureIsARefusal: if the firewall cannot be opened, the
// client is refused, exactly as without auto-allow, and the name is on the
// refused list for the suggestion.
func TestAutoAllowFailureIsARefusal(t *testing.T) {
	up := newFakeUpstream(t)
	auto := &fakeAuto{wants: map[string]bool{"cdn.guestwifi.test": true}, fail: errors.New("pf said no")}
	s := startAutoFilter(t, up, auto)

	if r := ask(t, s, 1, "cdn.guestwifi.test"); rcode(r) != 5 {
		t.Fatalf("rcode %d, want REFUSED", rcode(r))
	}
	if got := s.Refused(); len(got) != 1 || got[0] != "cdn.guestwifi.test" {
		t.Fatalf("Refused = %v", got)
	}
	if len(s.AutoAllowed()) != 0 {
		t.Fatal("a failed open counted as auto-allowed")
	}
}

// TestAutoAllowLeavesOtherNamesRefused: names Auto does not want never leave.
func TestAutoAllowLeavesOtherNamesRefused(t *testing.T) {
	up := newFakeUpstream(t)
	auto := &fakeAuto{wants: map[string]bool{"cdn.guestwifi.test": true}, opened: make(chan []net.IP, 1)}
	s := startAutoFilter(t, up, auto)

	if r := ask(t, s, 1, "imap.mail.me.com"); rcode(r) != 5 {
		t.Fatalf("rcode %d, want REFUSED", rcode(r))
	}
	select {
	case n := <-up.asked:
		t.Fatalf("%s reached the upstream", n)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestAnswerAddrsFollowsCNAMEs: a CNAME to a CDN ends in the CDN's
// addresses, and those are what the client connects to.
func TestAnswerAddrsFollowsCNAMEs(t *testing.T) {
	r := reply(query(1, "cdn.btwifi.com"), 0)
	binary.BigEndian.PutUint16(r[6:8], 3)
	// cdn.btwifi.com CNAME d1.cloudfront.net
	target := []byte{2, 'd', '1', 10, 'c', 'l', 'o', 'u', 'd', 'f', 'r', 'o', 'n', 't', 3, 'n', 'e', 't', 0}
	r = append(r, 0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, byte(len(target)))
	cname := len(r)
	r = append(r, target...)
	// d1.cloudfront.net A 203.0.113.9, and AAAA 2001:db8::9
	r = append(r, 0xC0|byte(cname>>8), byte(cname), 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9)
	v6 := net.ParseIP("2001:db8::9")
	r = append(r, 0xC0|byte(cname>>8), byte(cname), 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
	r = append(r, v6...)

	got := answerAddrs(r)
	if len(got) != 2 || !got[0].Equal(net.IPv4(203, 0, 113, 9)) || !got[1].Equal(v6) {
		t.Fatalf("answerAddrs = %v", got)
	}
	if answerAddrs(r[:len(r)-3]) == nil {
		t.Fatal("a truncated reply should still yield the records before the cut")
	}
	if answerAddrs(refusal(query(1, "x.test"))) != nil {
		t.Fatal("a refusal has no addresses")
	}
}

// TestTraceSeesEveryQuery: the trace hears each query and its verdict, not
// only the first refusal of each name as Logf does.
func TestTraceSeesEveryQuery(t *testing.T) {
	up := newFakeUpstream(t)
	type ev struct{ name, qtype, verdict string }
	got := make(chan ev, 8)
	auto := &fakeAuto{wants: map[string]bool{"cdn.guestwifi.test": true}, opened: make(chan []net.IP, 1)}
	s := &Server{
		Upstreams:          []net.IP{net.IPv4(127, 0, 0, 1)},
		Policy:             NewPolicy("", "www.guestwifi.test"),
		Auto:               auto,
		Trace:              func(n, q, v string) { got <- ev{n, q, v} },
		ListenAddr:         "127.0.0.1:0",
		UpstreamSourcePort: -1,
		upstreamDst:        up.conn.LocalAddr().(*net.UDPAddr).Port,
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)

	want := []ev{
		{"www.guestwifi.test", "A", "forwarded"},
		{"cdn.guestwifi.test", "A", "auto"},
		{"imap.mail.me.com", "A", "refused"},
		{"imap.mail.me.com", "A", "refused"},
	}
	for i, w := range want {
		ask(t, s, uint16(i+1), w.name)
		if e := <-got; e != w {
			t.Errorf("trace %d = %+v, want %+v", i, e, w)
		}
	}
}
