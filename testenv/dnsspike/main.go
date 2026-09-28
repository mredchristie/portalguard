// Command dnsspike answers every DNS A query with one marker address and logs
// the name, on UDP and TCP. It exists to prove that pf's rdr and route-to can
// divert this Mac's DNS to a local resolver: if a lookup comes back with the
// marker, the query was redirected. See testenv/dns-redirect-spike.sh.
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"strings"
)

func main() {
	addrs := flag.String("addr", "127.0.0.1:5300,[::1]:5300", "listen addresses, comma-separated, UDP and TCP")
	marker := flag.String("marker", "203.0.113.99", "the address every A query gets")
	flag.Parse()
	ip := net.ParseIP(*marker).To4()

	for _, addr := range strings.Split(*addrs, ",") {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			log.Fatal(err)
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
		go serveTCP(ln, ip)
		go serveUDP(pc, ip)
	}
	select {}
}

func serveTCP(ln net.Listener, ip net.IP) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			var n uint16
			if binary.Read(c, binary.BigEndian, &n) != nil {
				return
			}
			q := make([]byte, n)
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			if r := answer(q, ip, "tcp"); r != nil {
				_ = binary.Write(c, binary.BigEndian, uint16(len(r)))
				_, _ = c.Write(r)
			}
		}(c)
	}
}

func serveUDP(pc net.PacketConn, ip net.IP) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		if r := answer(buf[:n], ip, "udp"); r != nil {
			_, _ = pc.WriteTo(r, from)
		}
	}
}

func answer(q []byte, ip net.IP, via string) []byte {
	if len(q) < 12 {
		return nil
	}
	var labels []string
	i := 12
	for i < len(q) {
		l := int(q[i])
		i++
		if l == 0 || i+l > len(q) {
			break
		}
		labels = append(labels, string(q[i:i+l]))
		i += l
	}
	if i+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[i : i+2])
	log.Printf("%s query for %s", via, strings.Join(labels, "."))
	r := append([]byte{}, q[:i+4]...)
	r[2], r[3] = 0x84|(q[2]&1), 0x80
	r[6], r[7], r[8], r[9], r[10], r[11] = 0, 0, 0, 0, 0, 0
	if qtype == 1 {
		r[7] = 1
		r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4)
		r = append(r, ip...)
	}
	return r
}
