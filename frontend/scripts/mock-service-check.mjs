// Development fixtures only. No router, DNS server or external service is used.
export const serviceCheckOptions = {
	devices: [
		{ ip:'192.0.2.20', name:'Demo Phone', policy:'Policy0', active:true },
		{ ip:'192.0.2.21', name:'Demo Camera', policy:'Policy0', active:true },
	],
	profiles: [{ name:'System', label:'', upstreamCount:2 }, { name:'Policy0', label:'Demo VPN', upstreamCount:2 }],
	interfaces: [{ id:'Wireguard0', label:'Demo VPN', up:true }],
};

/** @param {import('../src/lib/types/serviceCheck').ServiceCheckRequest} input */
export function makeServiceCheckReport(input) {
	const dnsFailed = input.target === 'broken.test';
	const client = serviceCheckOptions.devices.find(d => d.ip === input.clientIP) ?? serviceCheckOptions.devices[0];
	const checked = new Date().toISOString();
	let tcpCode = 'tcp_disabled';
	if (input.probeInterface) tcpCode = dnsFailed ? 'tcp_no_address' : 'tcp_connected';
	return {
		version:1, startedAt:checked, finishedAt:checked, client, target:input.target, port:input.port,
		warnings:['demo_fixture'], policy:{ status:'ok', code:'policy_known' },
		dns:{ status:dnsFailed ? 'fail' : 'ok', code:dnsFailed ? 'dns_failed' : 'dns_answer', profile:input.dnsProfile, port:41100, upstreamCount:2, addresses:dnsFailed ? [] : ['203.0.113.7'] },
		rules:{ status:'ok', code:'rules_candidates', matches:[{ name:'Demo service', enabled:true, excluded:false, targets:['Wireguard0'] }], unevaluated:0 },
		flows:{ status:dnsFailed ? 'unknown' : 'ok', code:dnsFailed ? 'flows_absent' : 'flows_exchange', fetchedAt:checked, truncated:false, rows:dnsFailed ? [] : [{ destination:'203.0.113.7', protocol:'tcp', port:443, interface:'nwg0', routeClass:'tunnel', bytesIn:2048, bytesOut:512 }] },
		tcp:{ status:input.probeInterface && !dnsFailed ? 'ok' : 'skipped', code:tcpCode, interface:input.probeInterface, attempts:input.probeInterface && !dnsFailed ? [{ address:'203.0.113.7', connected:true, latencyMS:32 }] : [] },
	};
}
