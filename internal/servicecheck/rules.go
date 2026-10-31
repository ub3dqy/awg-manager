package servicecheck

import (
	"context"
	"net/netip"
	"strings"
)

// These are matching list candidates, NOT a simulation of NDMS/sing-box priority.
func (s *Service) rules(ctx context.Context, host string, ips []netip.Addr) RulesResult {
	r := RulesResult{Check: Check{"unknown", "rules_unavailable"}, Matches: []RuleMatch{}}
	if s.readers.Rules == nil {
		return r
	}
	lists, err := s.readers.Rules(ctx)
	if err != nil {
		return r
	}
	r.Check = Check{"unknown", "rules_no_match"}
	for _, list := range lists {
		entries := append(append([]string{}, list.Domains...), list.Subnets...)
		hit, unknown := matches(entries, host, ips)
		if unknown {
			r.Unevaluated++
		}
		if !hit {
			continue
		}
		excluded, uncertainExclude := matches(append(append([]string{}, list.Excludes...), list.ExcludeSubnets...), host, ips)
		if uncertainExclude {
			r.Unevaluated++
		}
		row := RuleMatch{Name: list.Name, Enabled: list.Enabled, Excluded: excluded, Targets: []string{}}
		for _, route := range list.Routes {
			target := route.Interface
			if target == "" {
				target = route.TunnelID
			}
			if target != "" {
				row.Targets = append(row.Targets, target)
			}
		}
		if list.HRPolicyName != "" {
			row.Targets = append(row.Targets, list.HRPolicyName)
		}
		r.Matches = append(r.Matches, row)
	}
	if len(r.Matches) > 0 {
		r.Check = Check{"ok", "rules_candidates"}
	}
	return r
}

func matches(entries []string, host string, ips []netip.Addr) (bool, bool) {
	hit, unknown := false, false
	for _, entry := range entries {
		entry = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry)), ".")
		if strings.HasPrefix(entry, "geoip:") || strings.HasPrefix(entry, "geosite:") {
			unknown = true
			continue
		}
		if subnet, err := netip.ParsePrefix(entry); err == nil {
			for _, ip := range ips {
				if subnet.Contains(ip) {
					hit = true
				}
			}
			continue
		}
		if ip, err := netip.ParseAddr(entry); err == nil {
			for _, addr := range ips {
				if ip.Unmap() == addr.Unmap() {
					hit = true
				}
			}
			continue
		}
		if strings.HasPrefix(entry, "*.") {
			entry = strings.TrimPrefix(entry, "*.")
		}
		if strings.ContainsAny(entry, "*?[") {
			unknown = true
			continue
		}
		if entry != "" && (host == entry || strings.HasSuffix(host, "."+entry)) {
			hit = true
		}
	}
	return hit, unknown
}
