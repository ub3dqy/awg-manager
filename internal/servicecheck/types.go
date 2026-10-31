// Package servicecheck diagnoses a selected LAN device and destination without
// changing router configuration. Network probes run on the router, not the client.
package servicecheck

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/hoaxisr/awg-manager/internal/connections"
	"github.com/hoaxisr/awg-manager/internal/diagnostics"
	"github.com/hoaxisr/awg-manager/internal/dnsroute"
	"github.com/hoaxisr/awg-manager/internal/ndms"
)

var (
	ErrInput       = errors.New("invalid service diagnostic request")
	ErrBusy        = errors.New("service diagnostics already running")
	ErrUnavailable = errors.New("service diagnostic sources unavailable")
	ErrUnsupported = errors.New("interface-bound probe unavailable")
)

// Readers intentionally has no configuration writers, restart or cleanup hooks.
type Readers struct {
	Devices     func(context.Context) ([]ndms.Device, error)
	Policies    func(context.Context) ([]ndms.Policy, error)
	Interfaces  func(context.Context) ([]ndms.Interface, error)
	DNSProfiles func(context.Context) ([]diagnostics.DNSProxy, error)
	Rules       func(context.Context) ([]dnsroute.DomainList, error)
	Connections func(context.Context, string) (*connections.ListResponse, error)
}

type Probes struct {
	Resolve func(context.Context, DNSPorts, string) ([]netip.Addr, error)
	TCP     func(context.Context, string, netip.Addr, int) (time.Duration, error)
}

type DNSPorts struct{ UDP, TCP int }

type Device struct {
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Policy string `json:"policy"`
	Active bool   `json:"active"`
}

type Profile struct {
	Name          string `json:"name"`
	Label         string `json:"label"`
	UpstreamCount int    `json:"upstreamCount"`
}

type Interface struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Up    bool   `json:"up"`
}

type Options struct {
	Devices    []Device    `json:"devices"`
	Profiles   []Profile   `json:"profiles"`
	Interfaces []Interface `json:"interfaces"`
}

type Request struct {
	ClientIP   string `json:"clientIP"`
	Target     string `json:"target"`
	DNSProfile string `json:"dnsProfile"`
	// Optional NDMS interface ID, validated against the current snapshot. An
	// empty value disables TCP probes; it never means the default/WAN path.
	ProbeInterface string `json:"probeInterface,omitempty"`
	Port           int    `json:"port"`
}

type Check struct {
	Status string `json:"status"` // ok, warning, fail, unknown, skipped
	Code   string `json:"code"`
}

type DNSResult struct {
	Check
	Profile       string   `json:"profile"`
	Port          int      `json:"port"`
	Addresses     []string `json:"addresses"`
	UpstreamCount int      `json:"upstreamCount"`
}

type RuleMatch struct {
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Excluded bool     `json:"excluded"`
	Targets  []string `json:"targets"`
}

type RulesResult struct {
	Check
	Matches     []RuleMatch `json:"matches"`
	Unevaluated int         `json:"unevaluated"`
}

// Flow deliberately omits MACs, raw configuration, log text and payloads.
type Flow struct {
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Interface   string `json:"interface"`
	RouteClass  string `json:"routeClass"`
	BytesIn     int64  `json:"bytesIn"`
	BytesOut    int64  `json:"bytesOut"`
}

type FlowsResult struct {
	Check
	Rows      []Flow `json:"rows"`
	Truncated bool   `json:"truncated"`
	FetchedAt string `json:"fetchedAt"`
}

type TCPAttempt struct {
	Address   string `json:"address"`
	Connected bool   `json:"connected"`
	LatencyMS int64  `json:"latencyMS"`
}

type TCPResult struct {
	Check
	Interface string       `json:"interface"`
	Attempts  []TCPAttempt `json:"attempts"`
}

type Report struct {
	Version    int         `json:"version"`
	StartedAt  string      `json:"startedAt"`
	FinishedAt string      `json:"finishedAt"`
	Client     Device      `json:"client"`
	Target     string      `json:"target"`
	Port       int         `json:"port"`
	Policy     Check       `json:"policy"`
	DNS        DNSResult   `json:"dns"`
	Rules      RulesResult `json:"rules"`
	Flows      FlowsResult `json:"flows"`
	TCP        TCPResult   `json:"tcp"`
	Warnings   []string    `json:"warnings"`
}
