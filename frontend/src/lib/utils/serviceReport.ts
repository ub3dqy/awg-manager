import type { ServiceReport } from '$lib/types/serviceCheck';
import { toAsciiHostname } from './singboxInlineRules';

export function normalizeServiceTarget(value: string): string | null {
	value = value.trim().replace(/\.$/, '');
	if (!value || value.length > 253 || /[/?#@\\]/.test(value)) return null;
	// IPv6 is validated precisely again by the backend; no URL/userinfo/zone.
	if (/^[0-9a-f:]+$/i.test(value) && value.includes(':')) return value.toLowerCase();
	return toAsciiHostname(value);
}

/** Export only this bounded report; never collect logs, configs or credentials.
 * Replace user-defined strings consistently so relationships remain visible. */
export function redactServiceReport(report: ServiceReport): ServiceReport {
	// Reports contain JSON values only. JSON cloning also accepts Svelte's
	// reactive proxies, which structuredClone rejects at the save button.
	const copy: ServiceReport = JSON.parse(JSON.stringify(report));
	const tokens = new Map<string, string>();
	const counts = new Map<string, number>();
	function token(value: string, kind: string): string {
		if (!value) return '';
		const previous = tokens.get(value);
		if (previous) return previous;
		const n = (counts.get(kind) ?? 0) + 1;
		counts.set(kind, n);
		const result = `${kind}-${n}`;
		tokens.set(value, result);
		return result;
	}
	copy.client.ip = token(copy.client.ip, 'client');
	copy.client.name = token(copy.client.name, 'device');
	copy.client.policy = token(copy.client.policy, 'policy');
	copy.target = token(copy.target, 'destination');
	copy.dns.profile = token(copy.dns.profile, 'profile');
	copy.dns.addresses = copy.dns.addresses.map(value => token(value, 'address'));
	copy.tcp.interface = token(copy.tcp.interface, 'interface');
	for (const row of copy.tcp.attempts) row.address = token(row.address, 'address');
	for (const row of copy.rules.matches) {
		row.name = token(row.name, 'rule');
		row.targets = row.targets.map(value => token(value, 'route'));
	}
	for (const row of copy.flows.rows) {
		row.destination = token(row.destination, 'address');
		row.interface = token(row.interface, 'interface');
	}
	return copy;
}
