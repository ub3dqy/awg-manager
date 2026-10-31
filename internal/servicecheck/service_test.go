package servicecheck

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/hoaxisr/awg-manager/internal/connections"
	"github.com/hoaxisr/awg-manager/internal/diagnostics"
	"github.com/hoaxisr/awg-manager/internal/dnsroute"
	"github.com/hoaxisr/awg-manager/internal/ndms"
)

func fixture() (Readers, Probes, Request) {
	r := Readers{
		Devices: func(context.Context) ([]ndms.Device, error) {
			return []ndms.Device{{IP: "192.168.1.20", Name: "phone", Access: "Policy0", Active: true}}, nil
		},
		Policies: func(context.Context) ([]ndms.Policy, error) {
			return []ndms.Policy{{Name: "Policy0", Description: "VPN"}}, nil
		},
		Interfaces: func(context.Context) ([]ndms.Interface, error) {
			return []ndms.Interface{{ID: "Wireguard0", SystemName: "nwg0", State: "up", Link: "up"}}, nil
		},
		DNSProfiles: func(context.Context) ([]diagnostics.DNSProxy, error) {
			return []diagnostics.DNSProxy{{Name: "System", UDPPort: 53}, {Name: "Policy0", UDPPort: 41100, Upstreams: []diagnostics.DNSUpstream{{Address: "8.8.8.8"}}}}, nil
		},
		Rules: func(context.Context) ([]dnsroute.DomainList, error) {
			return []dnsroute.DomainList{{Name: "example", Domains: []string{"service.test"}, Enabled: true, Routes: []dnsroute.RouteTarget{{Interface: "Wireguard0"}}}}, nil
		},
		Connections: func(context.Context, string) (*connections.ListResponse, error) {
			return &connections.ListResponse{Connections: []connections.Connection{{Src: "192.168.1.20", Dst: "203.0.113.7", DstPort: 443, Protocol: "tcp", Interface: "nwg0", RouteClass: "tunnel", BytesIn: 20, BytesOut: 30}}, Pagination: connections.PaginationInfo{Total: 1, Returned: 1}}, nil
		},
	}
	p := Probes{
		Resolve: func(context.Context, DNSPorts, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
		},
		TCP: func(context.Context, string, netip.Addr, int) (time.Duration, error) {
			return 20 * time.Millisecond, nil
		},
	}
	return r, p, Request{ClientIP: "192.168.1.20", Target: "service.test", DNSProfile: "Policy0", Port: 443}
}

func TestSelectedPolicyDNSAndSeparateEvidence(t *testing.T) {
	r, p, in := fixture()
	p.Resolve = func(_ context.Context, port DNSPorts, host string) ([]netip.Addr, error) {
		if port.UDP != 41100 || host != "service.test" {
			t.Fatalf("wrong policy path: %+v %s", port, host)
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	}
	p.TCP = func(context.Context, string, netip.Addr, int) (time.Duration, error) {
		t.Fatal("TCP probe was not requested")
		return 0, nil
	}
	out, err := New(r, p).Run(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out.DNS.Code != "dns_answer" || out.Flows.Code != "flows_exchange" || out.Rules.Code != "rules_candidates" || out.TCP.Code != "tcp_disabled" {
		t.Fatalf("unexpected report: %+v", out)
	}
	if out.Flows.Rows[0].Interface != "nwg0" {
		t.Fatal("observed interface lost")
	}
}

func TestDNSFailureNeverFallsBackOrAttemptsTCP(t *testing.T) {
	r, p, in := fixture()
	in.ProbeInterface = "Wireguard0"
	calls := 0
	p.Resolve = func(_ context.Context, port DNSPorts, _ string) ([]netip.Addr, error) {
		calls++
		if port.UDP != 41100 {
			t.Fatal("fallback resolver")
		}
		return nil, errors.New("timeout")
	}
	p.TCP = func(context.Context, string, netip.Addr, int) (time.Duration, error) {
		t.Fatal("TCP without resolved addresses")
		return 0, nil
	}
	out, err := New(r, p).Run(context.Background(), in)
	if err != nil || calls != 1 || out.DNS.Status != "fail" || out.TCP.Code != "tcp_no_address" {
		t.Fatalf("err=%v calls=%d report=%+v", err, calls, out)
	}
}

func TestMissingOrAmbiguousProfileDoesNotUseSystem(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "duplicate"}[duplicate], func(t *testing.T) {
			r, p, in := fixture()
			if duplicate {
				original := r.DNSProfiles
				r.DNSProfiles = func(ctx context.Context) ([]diagnostics.DNSProxy, error) {
					rows, _ := original(ctx)
					return append(rows, rows[1]), nil
				}
			} else {
				in.DNSProfile = "missing"
			}
			p.Resolve = func(context.Context, DNSPorts, string) ([]netip.Addr, error) {
				t.Fatal("ambiguous profile was probed")
				return nil, nil
			}
			out, err := New(r, p).Run(context.Background(), in)
			if err != nil || out.DNS.Code != "dns_profile_unavailable" {
				t.Fatalf("%+v %v", out, err)
			}
		})
	}
}

func TestLiteralAndBoundProbeUseOnlyRequestedInterface(t *testing.T) {
	r, p, in := fixture()
	in.Target = "203.0.113.7"
	in.ProbeInterface = "Wireguard0"
	p.Resolve = func(context.Context, DNSPorts, string) ([]netip.Addr, error) {
		t.Fatal("literal resolved")
		return nil, nil
	}
	p.TCP = func(_ context.Context, iface string, ip netip.Addr, port int) (time.Duration, error) {
		if iface != "nwg0" || ip.String() != in.Target || port != 443 {
			t.Fatal("wrong probe route")
		}
		return time.Millisecond, nil
	}
	out, err := New(r, p).Run(context.Background(), in)
	if err != nil || out.DNS.Code != "dns_literal" || out.TCP.Code != "tcp_connected" {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestUnavailableInterfaceNeverUsesDefault(t *testing.T) {
	for _, state := range []string{"missing", "down", "unknown-kernel"} {
		t.Run(state, func(t *testing.T) {
			r, p, in := fixture()
			in.Target = "203.0.113.7"
			in.ProbeInterface = "Wireguard0"
			r.Interfaces = func(context.Context) ([]ndms.Interface, error) {
				if state == "missing" {
					return nil, nil
				}
				i := ndms.Interface{ID: "Wireguard0", SystemName: "nwg0", State: "up"}
				if state == "down" {
					i.State = "down"
				}
				if state == "unknown-kernel" {
					i.SystemName = ""
				}
				return []ndms.Interface{i}, nil
			}
			p.TCP = func(context.Context, string, netip.Addr, int) (time.Duration, error) {
				t.Fatal("default path substituted")
				return 0, nil
			}
			out, err := New(r, p).Run(context.Background(), in)
			if err != nil || out.TCP.Status == "ok" {
				t.Fatalf("%+v %v", out, err)
			}
		})
	}
}

func TestUnknownClientAndAmbiguousIPRejectedBeforeProbes(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "duplicate"}[duplicate], func(t *testing.T) {
			r, p, in := fixture()
			if duplicate {
				original := r.Devices
				r.Devices = func(ctx context.Context) ([]ndms.Device, error) {
					rows, _ := original(ctx)
					return append(rows, rows[0]), nil
				}
			} else {
				in.ClientIP = "192.168.1.30"
			}
			p.Resolve = func(context.Context, DNSPorts, string) ([]netip.Addr, error) {
				t.Fatal("unknown client probed")
				return nil, nil
			}
			_, err := New(r, p).Run(context.Background(), in)
			if !errors.Is(err, ErrInput) {
				t.Fatal(err)
			}
		})
	}
}

func TestNoFlowsIsUnknownAndTruncationIsExplicit(t *testing.T) {
	r, p, in := fixture()
	r.Connections = func(context.Context, string) (*connections.ListResponse, error) {
		return &connections.ListResponse{Connections: []connections.Connection{{Src: "192.168.1.200", Dst: "203.0.113.7", BytesIn: 20, BytesOut: 20}}, Pagination: connections.PaginationInfo{Total: 700, Returned: 500}}, nil
	}
	out, err := New(r, p).Run(context.Background(), in)
	if err != nil || out.Flows.Code != "flows_absent" || out.Flows.Status != "unknown" || !out.Flows.Truncated {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestRulesPreserveExclusionsAndUncertainty(t *testing.T) {
	r, p, in := fixture()
	r.Rules = func(context.Context) ([]dnsroute.DomainList, error) {
		return []dnsroute.DomainList{{Name: "excluded", Domains: []string{"test"}, Excludes: []string{"service.test"}, Enabled: false}, {Name: "unrelated", Domains: []string{"notservice.test"}}, {Name: "geo", Domains: []string{"geosite:example"}}}, nil
	}
	out, err := New(r, p).Run(context.Background(), in)
	if err != nil || len(out.Rules.Matches) != 1 || !out.Rules.Matches[0].Excluded || out.Rules.Matches[0].Enabled || out.Rules.Unevaluated != 1 {
		t.Fatalf("%+v %v", out.Rules, err)
	}
}

func TestNormalizationRejectsURLsAndLocalServiceTargets(t *testing.T) {
	_, _, in := fixture()
	for _, target := range []string{"https://secret@example.org/path", "example.org:443", "127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "fe80::1%lo", "-bad.test", "a..test"} {
		in.Target = target
		if _, err := normalize(in); err == nil {
			t.Fatalf("accepted %q", target)
		}
	}
	in.Target = "XN--E1AFMKFD.XN--P1AI."
	out, err := normalize(in)
	if err != nil || out.Target != "xn--e1afmkfd.xn--p1ai" {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestOnlyOneCheckAndCancellation(t *testing.T) {
	r, p, in := fixture()
	r.Rules = func(context.Context) ([]dnsroute.DomainList, error) {
		t.Fatal("routing read started after cancellation")
		return nil, nil
	}
	r.Connections = func(context.Context, string) (*connections.ListResponse, error) {
		t.Fatal("shared connection snapshot started after cancellation")
		return nil, nil
	}
	started := make(chan struct{})
	p.Resolve = func(ctx context.Context, _ DNSPorts, _ string) ([]netip.Addr, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	svc := New(r, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := svc.Run(ctx, in); done <- err }()
	<-started
	if _, err := svc.Run(context.Background(), in); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent check: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
