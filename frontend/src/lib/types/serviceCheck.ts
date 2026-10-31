export interface ServiceCheck { status: 'ok' | 'warning' | 'fail' | 'unknown' | 'skipped'; code: string }
export interface ServiceDevice { ip: string; name: string; policy: string; active: boolean }
export interface ServiceCheckOptions {
	devices: ServiceDevice[];
	profiles: { name: string; label: string; upstreamCount: number }[];
	interfaces: { id: string; label: string; up: boolean }[];
}
export interface ServiceCheckRequest { clientIP: string; target: string; dnsProfile: string; probeInterface: string; port: number }
export interface ServiceReport {
	version: number; startedAt: string; finishedAt: string;
	client: ServiceDevice; target: string; port: number; policy: ServiceCheck; warnings: string[];
	dns: ServiceCheck & { profile: string; port: number; addresses: string[]; upstreamCount: number };
	rules: ServiceCheck & { matches: { name: string; enabled: boolean; excluded: boolean; targets: string[] }[]; unevaluated: number };
	flows: ServiceCheck & { fetchedAt: string; truncated: boolean; rows: { destination: string; protocol: string; port: number; interface: string; routeClass: string; bytesIn: number; bytesOut: number }[] };
	tcp: ServiceCheck & { interface: string; attempts: { address: string; connected: boolean; latencyMS: number }[] };
}
