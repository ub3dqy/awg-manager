<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { m, formatLocale } from '$lib/i18n';
	import { api } from '$lib/api/client';
	import { Button, Card, Dropdown, Input } from '$lib/components/ui';
	import type { ServiceCheckOptions, ServiceReport } from '$lib/types/serviceCheck';
	import { redactServiceReport, normalizeServiceTarget } from '$lib/utils/serviceReport';
	import { downloadBlob } from '$lib/utils/download';

	let options = $state<ServiceCheckOptions | null>(null);
	let clientIP = $state('');
	let target = $state('');
	let profile = $state('');
	let probeInterface = $state('');
	let port = $state('443');
	let loading = $state(false);
	let running = $state(false);
	let failed = $state(false);
	let failureStatus = $state(0);
	let report = $state<ServiceReport | null>(null);
	let controller: AbortController | null = null;
	let requestSeq = 0;

	const deviceOptions = $derived((options?.devices ?? []).map(d => ({ value:d.ip, label:`${d.name || d.ip} · ${d.ip}${d.active ? '' : ` · ${m.sc_offline()}`}` })));
	const profileOptions = $derived((options?.profiles ?? []).map(p => ({ value:p.name, label:p.label || (p.name === 'System' ? m.sc_system() : p.name) })));
	const interfaceOptions = $derived([
		{ value:'', label:m.sc_no_tcp() },
		...(options?.interfaces ?? []).map(i => ({ value:i.id, label:`${i.label} · ${i.id}${i.up ? '' : ` · ${m.sc_offline()}`}` })),
	]);
	const validPort = $derived(/^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535);
	const normalizedTarget = $derived(normalizeServiceTarget(target));
	const canRun = $derived(!!clientIP && !!normalizedTarget && (!probeInterface || validPort) && !running && !loading);

	function selectClient(ip: string) {
		clientIP = ip;
		report = null;
		const device = options?.devices.find(d => d.ip === ip);
		profile = options?.profiles.find(p => p.name === device?.policy)?.name ?? options?.profiles.find(p => p.name === 'System')?.name ?? '';
	}

	async function loadOptions() {
		const seq = ++requestSeq;
		controller?.abort();
		controller = new AbortController();
		loading = true;
		failed = false;
		failureStatus = 0;
		try {
			const result = await api.getServiceCheckOptions(controller.signal);
			if (seq !== requestSeq) return;
			options = result;
			if (!result.devices.some(d => d.ip === clientIP)) clientIP = '';
			if (!result.profiles.some(p => p.name === profile)) profile = '';
			if (!result.interfaces.some(i => i.id === probeInterface)) probeInterface = '';
		} catch { if (seq === requestSeq) failed = true; }
		finally { if (seq === requestSeq) loading = false; }
	}

	async function run() {
		if (!canRun) return;
		const seq = ++requestSeq;
		controller?.abort();
		controller = new AbortController();
		running = true;
		failed = false;
		failureStatus = 0;
		report = null;
		try {
			const result = await api.runServiceCheck({ clientIP, target:normalizedTarget!, dnsProfile:profile, probeInterface, port:probeInterface ? Number(port) : 443 }, controller.signal);
			if (seq === requestSeq) report = result;
		} catch (error) {
			if (seq === requestSeq) { failed = true; failureStatus = (error as { status?:number })?.status ?? 0; }
		}
		finally { if (seq === requestSeq) running = false; }
	}

	function cancel() {
		requestSeq++;
		controller?.abort();
		running = false;
		loading = false;
	}

	function message(code: string): string {
		const messages: Record<string, () => string> = {
			policy_unknown:m.sc_policy_unknown, policy_known:m.sc_policy_known, policy_denied:m.sc_policy_denied, policy_unavailable:m.sc_policy_unavailable,
			dns_literal:m.sc_dns_literal, dns_profile_unavailable:m.sc_dns_profile_unavailable, dns_answer:m.sc_dns_answer, dns_failed:m.sc_dns_failed, dns_empty:m.sc_dns_empty,
			rules_unavailable:m.sc_rules_unavailable, rules_no_match:m.sc_rules_no_match, rules_candidates:m.sc_rules_candidates,
			flows_unavailable:m.sc_flows_unavailable, flows_absent:m.sc_flows_absent, flows_no_reply:m.sc_flows_no_reply, flows_exchange:m.sc_flows_exchange,
			tcp_disabled:m.sc_tcp_disabled, interface_unknown:m.sc_interface_unknown, interface_down:m.sc_interface_down, tcp_no_address:m.sc_tcp_no_address,
			tcp_unsupported:m.sc_tcp_unsupported, tcp_failed:m.sc_tcp_failed, tcp_connected:m.sc_tcp_connected,
			device_inactive:m.sc_device_inactive, policy_unconfirmed:m.sc_policy_unconfirmed, profile_override:m.sc_profile_override,
			demo_fixture:m.sc_demo_fixture,
			dns_addresses_limited:m.sc_dns_addresses_limited,
		};
		return (messages[code] ?? m.sc_unknown)();
	}

	function summary(result: ServiceReport): string {
		if (result.policy.code === 'policy_denied') return m.sc_summary_denied();
		if (result.dns.status === 'fail') return m.sc_summary_dns();
		if (result.tcp.code === 'interface_down') return m.sc_summary_interface();
		if (result.flows.code === 'flows_exchange') return m.sc_summary_exchange();
		return m.sc_summary_unknown();
	}

	function saveReport() {
		if (!report) return;
		downloadBlob(new Blob([JSON.stringify(redactServiceReport(report), null, 2)], { type:'application/json' }), 'awg-service-diagnostic.json');
	}

	onMount(loadOptions);
	onDestroy(() => { requestSeq++; controller?.abort(); });
</script>

<div class="service-check">
	<header><h2>{m.sc_title()}</h2><p>{m.sc_intro()}</p></header>
	<Card>
		<form onsubmit={(event) => { event.preventDefault(); void run(); }}>
			<div class="fields">
				<Dropdown label={m.sc_device()} value={clientIP} options={deviceOptions} onchange={selectClient} disabled={running || loading} fullWidth />
				<Input label={m.sc_destination()} value={target} oninput={(value) => { target=value; report=null; }} placeholder={m.sc_destination_hint()} error={target.trim() && !normalizedTarget ? m.sc_invalid_destination() : undefined} disabled={running} fullWidth />
				<Dropdown label={m.sc_dns_profile()} bind:value={profile} options={profileOptions} disabled={running || loading} fullWidth />
				<Dropdown label={m.sc_probe_path()} bind:value={probeInterface} options={interfaceOptions} disabled={running || loading} fullWidth />
				{#if probeInterface}<Input label={m.sc_port()} type="number" bind:value={port} error={!validPort ? m.sc_invalid_port() : undefined} disabled={running} fullWidth />{/if}
			</div>
			<p class="hint">{m.sc_scope()}</p>
			<div class="actions">
				<Button type="submit" variant="primary" disabled={!canRun} loading={running}>{m.sc_run()}</Button>
				{#if running}<Button onclick={cancel}>{m.common_cancel()}</Button>{:else}<Button onclick={loadOptions} disabled={loading}>{m.sc_refresh()}</Button>{/if}
			</div>
		</form>
	</Card>
	{#if failed}<p class="notice" role="alert">{failureStatus === 409 ? m.sc_busy() : failureStatus === 400 ? m.sc_invalid_request() : m.sc_request_failed()}</p>{/if}
	{#if options && !loading && options.devices.length === 0}<p class="notice">{m.sc_no_devices()}</p>{/if}
	{#if report}
		<section aria-label={m.sc_report()} aria-live="polite">
			<div class="report-head"><div><h3>{m.sc_report()}</h3><p>{report.client.name || report.client.ip} · {report.target} · {new Date(report.finishedAt).toLocaleString(formatLocale())}</p></div><Button onclick={saveReport}>{m.sc_save()}</Button></div>
			<p class="summary">{summary(report)}</p>
			{#each report.warnings as warning}<p class="notice">{message(warning)}</p>{/each}
			<div class="steps">
				<Card><h4>{m.sc_policy()}</h4><p class="result" data-status={report.policy.status}>{message(report.policy.code)}</p><code>{report.client.policy || m.sc_unknown()}</code></Card>
				<Card><h4>{m.sc_dns()}</h4><p class="result" data-status={report.dns.status}>{message(report.dns.code)}</p><p>{m.sc_dns_details({ profile:report.dns.profile || m.sc_unknown(), count:report.dns.upstreamCount })}</p><div class="addresses">{#each report.dns.addresses as address}<code>{address}</code>{/each}</div><p class="hint">{m.sc_dns_limit()}</p></Card>
				<Card><h4>{m.sc_rules()}</h4><p class="result" data-status={report.rules.status}>{message(report.rules.code)}</p>{#each report.rules.matches as rule}<p><strong>{rule.name}</strong> · {rule.enabled ? m.sc_enabled() : m.sc_disabled()}{rule.excluded ? ` · ${m.sc_excluded()}` : ''}<br /><code>{rule.targets.join(', ')}</code></p>{/each}{#if report.rules.unevaluated}<p class="notice">{m.sc_rules_unevaluated({ count:report.rules.unevaluated })}</p>{/if}<p class="hint">{m.sc_rules_limit()}</p></Card>
				<Card><h4>{m.sc_flows()}</h4><p class="result" data-status={report.flows.status}>{message(report.flows.code)}</p>{#if report.flows.rows.length}<div class="sc-table-wrap"><table><thead><tr><th>{m.sc_destination()}</th><th>{m.sc_path()}</th><th>{m.sc_bytes()}</th></tr></thead><tbody>{#each report.flows.rows as row}<tr><td><code>{row.destination}:{row.port}</code><br />{row.protocol}</td><td>{row.interface || m.sc_unknown()}<br />{row.routeClass}</td><td>{row.bytesOut} / {row.bytesIn}</td></tr>{/each}</tbody></table></div>{/if}{#if report.flows.truncated}<p class="notice">{m.sc_flows_truncated()}</p>{/if}<p class="hint">{m.sc_flows_limit()}</p></Card>
				<Card><h4>{m.sc_tcp()}</h4><p class="result" data-status={report.tcp.status}>{message(report.tcp.code)}</p>{#if report.tcp.interface}<code>{report.tcp.interface} · TCP {report.port}</code>{/if}{#each report.tcp.attempts as attempt}<p><code>{attempt.address}</code> · {attempt.connected ? m.sc_tcp_timing({ ms:attempt.latencyMS }) : m.sc_no_connection()}</p>{/each}<p class="hint">{m.sc_tcp_limit()}</p></Card>
			</div>
			<p class="hint">{m.sc_export_hint()}</p>
		</section>
	{/if}
</div>

<style>
	.service-check { max-width: 1120px; display: grid; gap: 1rem; }
	h2,h3,h4,p { margin: 0 0 .65rem; }
	h2 { font-size: 1.2rem; } h3 { font-size: 1.1rem; } h4 { font-size: 1rem; }
	header p,.hint { color: var(--text-muted); font-size: .8125rem; line-height: 1.6; }
	.fields { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 1rem; margin-bottom: 1rem; }
	.actions,.report-head { display: flex; align-items: center; gap: .65rem; flex-wrap: wrap; }
	.report-head { justify-content: space-between; margin-bottom: 1rem; }
	.steps { display: grid; gap: .8rem; }
	.result { font-weight: 600; } .result[data-status='ok'] { color: var(--success); }
	.result[data-status='fail'] { color: var(--danger, #dc2626); }
	.result[data-status='warning'],.notice { color: var(--warning); }
	.notice { font-size: .8125rem; line-height: 1.6; }
	.summary { font-weight: 600; line-height: 1.6; }
	.addresses { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: .75rem; }
	code { overflow-wrap: anywhere; font-size: .8rem; }
	.sc-table-wrap { overflow-x: auto; margin-bottom: .75rem; }
	table { width: 100%; border-collapse: collapse; font-size: .8125rem; } th,td { text-align: left; padding: .5rem; border-bottom: 1px solid var(--color-border); vertical-align: top; }
	@media(max-width:640px) { .fields { grid-template-columns: 1fr; } }
</style>
