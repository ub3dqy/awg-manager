package server

import (
	"context"
	"fmt"

	"github.com/hoaxisr/awg-manager/internal/api"
	"github.com/hoaxisr/awg-manager/internal/connections"
	"github.com/hoaxisr/awg-manager/internal/diagnostics"
	"github.com/hoaxisr/awg-manager/internal/dnsroute"
	"github.com/hoaxisr/awg-manager/internal/ndms"
	"github.com/hoaxisr/awg-manager/internal/servicecheck"
)

func (s *Server) newServiceCheckHandler(h *routeHandlers) *api.ServiceCheckHandler {
	q := s.ndmsQueries
	if q == nil || q.Hotspot == nil || q.Policies == nil || q.Interfaces == nil || q.DNSProxyStatus == nil {
		return nil
	}
	readers := servicecheck.Readers{
		Devices: func(ctx context.Context) ([]ndms.Device, error) {
			q.Hotspot.InvalidateAll()
			return q.Hotspot.List(ctx)
		},
		Policies: func(ctx context.Context) ([]ndms.Policy, error) {
			q.Policies.InvalidateAll()
			return q.Policies.List(ctx)
		},
		Interfaces: func(ctx context.Context) ([]ndms.Interface, error) {
			q.Interfaces.InvalidateAll()
			rows, err := q.Interfaces.List(ctx)
			if err != nil {
				return nil, err
			}
			// Never edit query-store cache elements when filling kernel names.
			rows = append([]ndms.Interface(nil), rows...)
			for i := range rows {
				if rows[i].SystemName == "" {
					rows[i].SystemName = q.Interfaces.ResolveSystemName(ctx, rows[i].ID)
				}
			}
			return rows, nil
		},
		DNSProfiles: func(ctx context.Context) ([]diagnostics.DNSProxy, error) {
			q.DNSProxyStatus.InvalidateAll()
			raw, err := q.DNSProxyStatus.List(ctx)
			if err != nil {
				return nil, err
			}
			return diagnostics.ParseDNSProxy(raw)
		},
		Rules: func(ctx context.Context) ([]dnsroute.DomainList, error) {
			if s.dnsRouteService == nil {
				return nil, fmt.Errorf("routing list source unavailable")
			}
			return s.dnsRouteService.List(ctx)
		},
		Connections: func(ctx context.Context, source string) (*connections.ListResponse, error) {
			if h.connectionsService == nil {
				return nil, fmt.Errorf("connection source unavailable")
			}
			return h.connectionsService.List(ctx, connections.ListParams{Search: source, Limit: 500})
		},
	}
	return api.NewServiceCheckHandler(servicecheck.New(readers, servicecheck.Probes{}))
}
