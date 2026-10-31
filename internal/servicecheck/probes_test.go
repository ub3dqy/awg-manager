package servicecheck

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Minimal fixture encoder for uncompressed A/AAAA questions. Production uses
// the maintained dnsmessage codec, never this fixture parser.
func dnsFixture(query []byte) []byte {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil
	}
	i := 12
	labels := []string{}
	for {
		if i >= len(query) {
			return nil
		}
		n := int(query[i])
		i++
		if n == 0 {
			break
		}
		if n > 63 || i+n > len(query) {
			return nil
		}
		labels = append(labels, string(query[i:i+n]))
		i += n
	}
	if i+4 > len(query) {
		return nil
	}
	typ := binary.BigEndian.Uint16(query[i : i+2])
	end := i + 4
	answer := append([]byte(nil), query[:end]...)
	binary.BigEndian.PutUint16(answer[2:4], 0x8180)
	for n := 6; n < 12; n++ {
		answer[n] = 0
	}
	if strings.EqualFold(strings.Join(labels, "."), "missing.test") {
		answer[3] = 0x83
		return answer
	}
	var addr []byte
	if typ == 1 {
		addr = []byte{203, 0, 113, 7}
	} else if typ == 28 {
		a := netip.MustParseAddr("2001:db8::7").As16()
		addr = a[:]
	}
	if addr == nil {
		return answer
	}
	binary.BigEndian.PutUint16(answer[6:8], 1)
	answer = append(answer, 0xc0, 0x0c, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 1, 0, byte(len(addr)))
	return append(answer, addr...)
}

func TestPolicyResolverUsesSelectedListenerAndDoesNotHideNXDOMAIN(t *testing.T) {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, addr, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			if reply := dnsFixture(b[:n]); reply != nil {
				c.WriteTo(reply, addr)
			}
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ports := DNSPorts{UDP: c.LocalAddr().(*net.UDPAddr).Port}
	ips, err := ResolvePolicyDNS(ctx, ports, "service.test")
	if err != nil || len(ips) != 2 {
		t.Fatalf("addresses=%v err=%v", ips, err)
	}
	// This name is normally in /etc/hosts. A policy check must nevertheless
	// ask the selected listener instead of accepting the local hosts entry.
	ips, err = ResolvePolicyDNS(ctx, ports, "localhost")
	if err != nil || len(ips) != 2 || ips[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("hosts entry bypassed selected DNS listener: %v %v", ips, err)
	}
	if ips, err := ResolvePolicyDNS(ctx, ports, "missing.test"); err == nil || len(ips) != 0 {
		t.Fatalf("NXDOMAIN was hidden: %v %v", ips, err)
	}
}

func servePolicyUDP(t *testing.T, reply func([]byte) []byte) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, addr, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			if packet := reply(b[:n]); packet != nil {
				c.WriteTo(packet, addr)
			}
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	return c.LocalAddr().(*net.UDPAddr).Port
}

func TestPolicyDNSRejectsMismatchedRepliesAndCNAMECycles(t *testing.T) {
	for _, scenario := range []string{"wrong-id", "wrong-question", "not-response", "cname-loop"} {
		t.Run(scenario, func(t *testing.T) {
			port := servePolicyUDP(t, func(packet []byte) []byte {
				var query dnsmessage.Message
				if query.Unpack(packet) != nil {
					return nil
				}
				query.Response = true
				switch scenario {
				case "wrong-id":
					query.ID++
				case "wrong-question":
					query.Questions[0].Name = dnsmessage.MustNewName("another.test.")
				case "not-response":
					query.Response = false
				case "cname-loop":
					query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeCNAME}, Body: &dnsmessage.CNAMEResource{CNAME: query.Questions[0].Name}}}
				}
				reply, _ := query.Pack()
				return reply
			})
			if rows, err := ResolvePolicyDNS(context.Background(), DNSPorts{UDP: port}, "service.test"); err == nil || len(rows) != 0 {
				t.Fatalf("accepted %s: %v %v", scenario, rows, err)
			}
		})
	}
}

func TestPolicyDNSFollowsCNAMEAndIgnoresUnrelatedAnswers(t *testing.T) {
	port := servePolicyUDP(t, func(packet []byte) []byte {
		var query dnsmessage.Message
		if query.Unpack(packet) != nil {
			return nil
		}
		query.Response = true
		q := query.Questions[0]
		alias := dnsmessage.MustNewName("alias.test.")
		if q.Name.String() == "service.test." {
			query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeCNAME}, Body: &dnsmessage.CNAMEResource{CNAME: alias}}}
		} else if q.Name.String() == alias.String() && q.Type == dnsmessage.TypeA {
			query.Answers = []dnsmessage.Resource{
				{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("unrelated.test."), Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 99}}},
				{Header: dnsmessage.ResourceHeader{Name: alias, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}}},
			}
		}
		reply, _ := query.Pack()
		return reply
	})
	rows, err := ResolvePolicyDNS(context.Background(), DNSPorts{UDP: port}, "service.test")
	if err != nil || len(rows) != 1 || rows[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("CNAME result: %v %v", rows, err)
	}
}

func TestPolicyDNSRetriesTruncatedUDPOnlyAtSelectedTCPPort(t *testing.T) {
	port := servePolicyUDP(t, func(packet []byte) []byte {
		var response dnsmessage.Message
		if response.Unpack(packet) != nil {
			return nil
		}
		response.Response, response.Truncated = true, true
		reply, _ := response.Pack()
		return reply
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			var size [2]byte
			if _, err := io.ReadFull(c, size[:]); err == nil {
				packet := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err := io.ReadFull(c, packet); err == nil {
					reply := dnsFixture(packet)
					binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
					c.Write(append(size[:], reply...))
				}
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { l.Close(); <-done })
	rows, err := ResolvePolicyDNS(context.Background(), DNSPorts{UDP: port, TCP: l.Addr().(*net.TCPAddr).Port}, "service.test")
	if err != nil || len(rows) != 2 {
		t.Fatalf("UDP to selected TCP retry: %v %v", rows, err)
	}
}

func TestPolicyResolverSupportsTCPOnlyProfile(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				packet := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err := io.ReadFull(c, packet); err != nil {
					return
				}
				reply := dnsFixture(packet)
				if reply == nil {
					return
				}
				binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
				c.Write(append(size[:], reply...))
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); <-done; workers.Wait() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := ResolvePolicyDNS(ctx, DNSPorts{TCP: l.Addr().(*net.TCPAddr).Port}, "service.test")
	if err != nil || len(ips) != 2 {
		t.Fatalf("TCP-only DNS: %v %v", ips, err)
	}
}
