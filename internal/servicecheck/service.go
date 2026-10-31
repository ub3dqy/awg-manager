package servicecheck

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hoaxisr/awg-manager/internal/diagnostics"
	"github.com/hoaxisr/awg-manager/internal/ndms"
)

type Service struct {
	readers Readers
	probes  Probes
	running sync.Mutex
}

func New(readers Readers, probes Probes) *Service {
	if probes.Resolve == nil {
		probes.Resolve = ResolvePolicyDNS
	}
	if probes.TCP == nil {
		probes.TCP = ProbeTCP
	}
	return &Service{readers: readers, probes: probes}
}

type snapshot struct {
	devices                             []ndms.Device
	policies                            []ndms.Policy
	interfaces                          []ndms.Interface
	profiles                            []diagnostics.DNSProxy
	policyErr, interfaceErr, profileErr error
}

func (s *Service) snapshot(ctx context.Context) (snapshot, error) {
	var x snapshot
	if s.readers.Devices == nil || s.readers.Policies == nil || s.readers.Interfaces == nil || s.readers.DNSProfiles == nil {
		return x, ErrUnavailable
	}
	var err error
	x.devices, err = s.readers.Devices(ctx)
	if err != nil {
		return x, ErrUnavailable
	}
	x.policies, x.policyErr = s.readers.Policies(ctx)
	x.interfaces, x.interfaceErr = s.readers.Interfaces(ctx)
	x.profiles, x.profileErr = s.readers.DNSProfiles(ctx)
	return x, nil
}

func deviceView(d ndms.Device) Device {
	p := d.Access
	if p == "" {
		p = d.Policy
	}
	name := d.Name
	if name == "" {
		name = d.Hostname
	}
	return Device{IP: d.IP, Name: name, Policy: p, Active: d.Active}
}

func (s *Service) Options(ctx context.Context) (Options, error) {
	o := Options{Devices: []Device{}, Profiles: []Profile{}, Interfaces: []Interface{}}
	x, err := s.snapshot(ctx)
	if err != nil {
		return o, err
	}
	for _, d := range x.devices {
		if ip, err := netip.ParseAddr(d.IP); err == nil && usableIP(ip) {
			o.Devices = append(o.Devices, deviceView(d))
		}
	}
	labels := make(map[string]string)
	for _, p := range x.policies {
		labels[p.Name] = p.Description
	}
	for _, p := range x.profiles {
		o.Profiles = append(o.Profiles, Profile{Name: p.Name, Label: labels[p.Name], UpstreamCount: len(p.Upstreams)})
	}
	for _, i := range x.interfaces {
		if validIface.MatchString(i.SystemName) {
			o.Interfaces = append(o.Interfaces, interfaceView(i))
		}
	}
	return o, nil
}

func interfaceView(i ndms.Interface) Interface {
	label := i.Description
	if label == "" {
		label = i.ID
	}
	return Interface{ID: i.ID, Label: label, Up: i.State == "up" && i.Link != "down"}
}

var validIface = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
var validLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

func normalize(in Request) (Request, error) {
	in.ClientIP = strings.TrimSpace(in.ClientIP)
	client, err := netip.ParseAddr(in.ClientIP)
	if err != nil || !usableIP(client) {
		return in, ErrInput
	}
	in.ClientIP = client.Unmap().String()
	in.Target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Target)), ".")
	if ip, err := netip.ParseAddr(in.Target); err == nil {
		if !usableIP(ip) {
			return in, ErrInput
		}
		in.Target = ip.Unmap().String()
	} else {
		ascii := in.Target
		if len(ascii) == 0 || len(ascii) > 253 {
			return in, ErrInput
		}
		for _, label := range strings.Split(ascii, ".") {
			if len(label) > 63 || !validLabel.MatchString(label) {
				return in, ErrInput
			}
		}
		in.Target = ascii
	}
	if in.Port < 1 || in.Port > 65535 || len(in.DNSProfile) > 64 || len(in.ProbeInterface) > 64 {
		return in, ErrInput
	}
	return in, nil
}

func usableIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func (s *Service) Run(ctx context.Context, in Request) (Report, error) {
	in, err := normalize(in)
	if err != nil {
		return Report{}, err
	}
	if !s.running.TryLock() {
		return Report{}, ErrBusy
	}
	defer s.running.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	x, err := s.snapshot(ctx)
	if err != nil {
		return Report{}, err
	}
	r := Report{Version: 1, StartedAt: time.Now().UTC().Format(time.RFC3339), Target: in.Target, Port: in.Port, Warnings: []string{},
		DNS: DNSResult{Addresses: []string{}, Profile: in.DNSProfile}, Rules: RulesResult{Matches: []RuleMatch{}},
		Flows: FlowsResult{Rows: []Flow{}}, TCP: TCPResult{Attempts: []TCPAttempt{}, Interface: in.ProbeInterface}}
	found := 0
	for _, d := range x.devices {
		ip, e := netip.ParseAddr(d.IP)
		if e == nil && ip.Unmap().String() == in.ClientIP {
			r.Client = deviceView(d)
			found++
		}
	}
	if found != 1 {
		return Report{}, ErrInput
	}
	if !r.Client.Active {
		r.Warnings = append(r.Warnings, "device_inactive")
	}
	r.Policy = Check{"unknown", "policy_unknown"}
	for _, p := range x.policies {
		if p.Name == r.Client.Policy {
			r.Policy = Check{"ok", "policy_known"}
		}
	}
	if r.Client.Policy == "deny" {
		r.Policy = Check{"fail", "policy_denied"}
	}
	if x.policyErr != nil {
		r.Policy = Check{"unknown", "policy_unavailable"}
	}
	if r.Policy.Code != "policy_known" {
		r.Warnings = append(r.Warnings, "policy_unconfirmed")
	}
	if r.Policy.Code == "policy_known" && r.Client.Policy != in.DNSProfile {
		r.Warnings = append(r.Warnings, "profile_override")
	}
	addresses := []netip.Addr{}
	if ip, e := netip.ParseAddr(in.Target); e == nil {
		addresses = append(addresses, ip)
		r.DNS.Check = Check{"skipped", "dns_literal"}
		r.DNS.Addresses = append(r.DNS.Addresses, ip.String())
	} else {
		var profile *diagnostics.DNSProxy
		count := 0
		for i := range x.profiles {
			if x.profiles[i].Name == in.DNSProfile {
				profile = &x.profiles[i]
				count++
			}
		}
		r.DNS.Check = Check{"unknown", "dns_profile_unavailable"}
		if x.profileErr == nil && count == 1 && ((profile.UDPPort > 0 && profile.UDPPort <= 65535) || (profile.TCPPort > 0 && profile.TCPPort <= 65535)) {
			r.DNS.Port, r.DNS.UpstreamCount = profile.UDPPort, len(profile.Upstreams)
			if r.DNS.Port == 0 {
				r.DNS.Port = profile.TCPPort
			}
			addresses, err = s.probes.Resolve(ctx, DNSPorts{UDP: profile.UDPPort, TCP: profile.TCPPort}, in.Target)
			r.DNS.Check = Check{"ok", "dns_answer"}
			if err != nil {
				r.DNS.Check = Check{"fail", "dns_failed"}
				addresses = nil
			}
			if len(addresses) > 32 {
				addresses = addresses[:32]
				r.Warnings = append(r.Warnings, "dns_addresses_limited")
			}
			for _, ip := range addresses {
				if ip.IsValid() {
					r.DNS.Addresses = append(r.DNS.Addresses, ip.Unmap().String())
				}
			}
			if err == nil && len(r.DNS.Addresses) == 0 {
				r.DNS.Check = Check{"warning", "dns_empty"}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	r.Rules = s.rules(ctx, in.Target, addresses)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	r.Flows = s.flows(ctx, in, addresses)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	r.TCP.Check = Check{"skipped", "tcp_disabled"}
	if in.ProbeInterface != "" {
		var selected *ndms.Interface
		for i := range x.interfaces {
			if x.interfaces[i].ID == in.ProbeInterface {
				selected = &x.interfaces[i]
				break
			}
		}
		if selected == nil || x.interfaceErr != nil {
			r.TCP.Check = Check{"unknown", "interface_unknown"}
		} else if !interfaceView(*selected).Up {
			r.TCP.Check = Check{"warning", "interface_down"}
		} else if !validIface.MatchString(selected.SystemName) {
			r.TCP.Check = Check{"unknown", "interface_unknown"}
		} else {
			r.TCP = s.tcp(ctx, selected.SystemName, in.ProbeInterface, addresses, in.Port)
		}
	}
	r.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	return r, nil
}

func (s *Service) tcp(ctx context.Context, kernel, id string, addresses []netip.Addr, port int) TCPResult {
	r := TCPResult{Check: Check{"unknown", "tcp_no_address"}, Interface: id, Attempts: []TCPAttempt{}}
	// Bounded work on low-memory routers; one address per family is enough for
	// a sample. Untried addresses are not labelled failed.
	seen := map[bool]bool{}
	for _, ip := range addresses {
		ip = ip.Unmap()
		if !usableIP(ip) || seen[ip.Is6()] {
			continue
		}
		seen[ip.Is6()] = true
		elapsed, err := s.probes.TCP(ctx, kernel, ip, port)
		if errors.Is(err, ErrUnsupported) {
			r.Check = Check{"unknown", "tcp_unsupported"}
			return r
		}
		r.Attempts = append(r.Attempts, TCPAttempt{Address: ip.String(), Connected: err == nil, LatencyMS: elapsed.Milliseconds()})
	}
	if len(r.Attempts) > 0 {
		r.Check = Check{"warning", "tcp_failed"}
		for _, a := range r.Attempts {
			if a.Connected {
				r.Check = Check{"ok", "tcp_connected"}
				break
			}
		}
	}
	return r
}

func (s *Service) flows(ctx context.Context, in Request, ips []netip.Addr) FlowsResult {
	r := FlowsResult{Check: Check{"unknown", "flows_unavailable"}, Rows: []Flow{}}
	if s.readers.Connections == nil {
		return r
	}
	data, err := s.readers.Connections(ctx, in.ClientIP)
	if err != nil || data == nil {
		return r
	}
	r.FetchedAt = data.FetchedAt
	r.Truncated = data.Pagination.Total > data.Pagination.Returned
	r.Check = Check{"unknown", "flows_absent"}
	for _, c := range data.Connections {
		src, err := netip.ParseAddr(c.Src)
		if err != nil || src.Unmap().String() != in.ClientIP {
			continue
		}
		matched := false
		if dst, err := netip.ParseAddr(c.Dst); err == nil {
			for _, ip := range ips {
				if dst.Unmap() == ip.Unmap() {
					matched = true
				}
			}
		}
		for _, hit := range c.Rules {
			if strings.EqualFold(strings.TrimSuffix(hit.FQDN, "."), in.Target) {
				matched = true
			}
		}
		if !matched {
			continue
		}
		r.Rows = append(r.Rows, Flow{Destination: c.Dst, Protocol: c.Protocol, Port: c.DstPort, Interface: c.Interface, RouteClass: c.RouteClass, BytesIn: c.BytesIn, BytesOut: c.BytesOut})
		if len(r.Rows) == 100 {
			r.Truncated = true
			break
		}
	}
	if len(r.Rows) > 0 {
		r.Check = Check{"warning", "flows_no_reply"}
		for _, row := range r.Rows {
			if row.BytesIn > 0 && row.BytesOut > 0 {
				r.Check = Check{"ok", "flows_exchange"}
				break
			}
		}
	}
	return r
}
