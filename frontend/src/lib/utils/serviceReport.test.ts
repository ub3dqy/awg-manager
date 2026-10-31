import { describe, it, expect } from 'vitest';
import { redactServiceReport, normalizeServiceTarget } from './serviceReport';
import type { ServiceReport } from '$lib/types/serviceCheck';
import { makeServiceCheckReport } from '../../../scripts/mock-service-check.mjs';

describe('service report privacy', () => {
	it('converts IDNs and rejects URLs or credentials before sending a request', () => {
		expect(normalizeServiceTarget('ПРИМЕР.РФ.')).toBe('xn--e1afmkfd.xn--p1ai');
		for (const value of ['https://example.org/path','secret@example.org','example.org/?token=secret']) expect(normalizeServiceTarget(value)).toBeNull();
		expect(normalizeServiceTarget('2001:db8::7')).toBe('2001:db8::7');
	});
	it('removes addresses and user-defined names without mutating the screen result', () => {
		const input = makeServiceCheckReport({ clientIP:'192.0.2.20', target:'private.example', dnsProfile:'Policy0', probeInterface:'Wireguard0', port:9000 }) as ServiceReport;
		const before = JSON.stringify(input);
		const output = redactServiceReport(input);
		const json = JSON.stringify(output);
		for (const value of ['192.0.2.20','private.example','Policy0','Wireguard0','203.0.113.7','Demo Phone','Demo service','nwg0']) expect(json).not.toContain(value);
		expect(JSON.stringify(input)).toBe(before);
		expect(output.dns.profile).toBe(output.client.policy);
		expect(output.dns.addresses[0]).toBe(output.tcp.attempts[0].address);
		expect(output.flows.rows[0].bytesIn).toBe(2048);
		expect(output.flows.code).toBe('flows_exchange');
	});
});
