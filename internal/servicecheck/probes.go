package servicecheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ResolvePolicyDNS talks ONLY to the selected ndnproxy listener. There is no
// system resolver/public resolver fallback that could hide a broken policy.
func ResolvePolicyDNS(ctx context.Context, ports DNSPorts, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// net.Resolver can satisfy a request from /etc/hosts or apply search
	// suffixes even with a custom Dial. Send exact A/AAAA questions ourselves
	// so a policy failure cannot be hidden by a different local resolver path.
	result := []netip.Addr{}
	seen := make(map[netip.Addr]bool)
	var firstErr error
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		rows, err := resolvePolicyType(ctx, ports, host, typ)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, ip := range rows {
			if !seen[ip] {
				result = append(result, ip)
				seen[ip] = true
			}
		}
	}
	if len(result) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return result, nil
}

func resolvePolicyType(ctx context.Context, ports DNSPorts, host string, typ dnsmessage.Type) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, ".")) + "."
	visited := make(map[string]bool)
	for range 8 {
		if visited[host] {
			return nil, fmt.Errorf("policy DNS CNAME loop")
		}
		visited[host] = true
		name, err := dnsmessage.NewName(host)
		if err != nil {
			return nil, err
		}
		var id [2]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, err
		}
		question := dnsmessage.Question{Name: name, Type: typ, Class: dnsmessage.ClassINET}
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
		packet, err := query.Pack()
		if err != nil {
			return nil, err
		}
		port, network := ports.UDP, "udp"
		if port == 0 {
			port, network = ports.TCP, "tcp"
		}
		reply, err := exchangePolicyDNS(ctx, network, port, packet)
		if err != nil {
			return nil, err
		}
		var response dnsmessage.Message
		err = response.Unpack(reply)
		if response.ID != query.ID || !response.Response || response.OpCode != 0 {
			return nil, fmt.Errorf("invalid policy DNS response")
		}
		if response.Truncated && network == "udp" {
			reply, err = exchangePolicyDNS(ctx, "tcp", ports.TCP, packet)
			if err != nil {
				return nil, err
			}
			response = dnsmessage.Message{}
			err = response.Unpack(reply)
		}
		if err != nil || response.ID != query.ID || !response.Response || response.OpCode != 0 || response.Truncated || len(response.Questions) != 1 || response.Questions[0] != question {
			return nil, fmt.Errorf("invalid policy DNS response")
		}
		if response.RCode != dnsmessage.RCodeSuccess {
			return nil, fmt.Errorf("policy DNS response code %d", response.RCode)
		}
		// Only accept records owned by the queried name or its CNAME chain.
		current := host
		for range 8 {
			addresses := []netip.Addr{}
			next := ""
			for _, record := range response.Answers {
				if record.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(record.Header.Name.String(), current) {
					continue
				}
				switch body := record.Body.(type) {
				case *dnsmessage.AResource:
					if typ == dnsmessage.TypeA {
						addresses = append(addresses, netip.AddrFrom4(body.A))
					}
				case *dnsmessage.AAAAResource:
					if typ == dnsmessage.TypeAAAA {
						addresses = append(addresses, netip.AddrFrom16(body.AAAA).Unmap())
					}
				case *dnsmessage.CNAMEResource:
					next = strings.ToLower(body.CNAME.String())
				}
			}
			if len(addresses) > 0 {
				return addresses, nil
			}
			if next == "" {
				break
			}
			if next == current || visited[next] {
				return nil, fmt.Errorf("policy DNS CNAME loop")
			}
			current = next
		}
		if current == host {
			return []netip.Addr{}, nil
		}
		host = current
	}
	return nil, fmt.Errorf("policy DNS CNAME chain too long")
}

func exchangePolicyDNS(ctx context.Context, network string, port int, packet []byte) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, ErrInput
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(2 * time.Second)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if network == "tcp" {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(packet)))
		if _, err := io.Copy(c, bytes.NewReader(append(size[:], packet...))); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return nil, err
		}
		reply := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		_, err := io.ReadFull(c, reply)
		return reply, err
	}
	if _, err := c.Write(packet); err != nil {
		return nil, err
	}
	reply := make([]byte, 4096)
	n, err := c.Read(reply)
	return reply[:n], err
}
