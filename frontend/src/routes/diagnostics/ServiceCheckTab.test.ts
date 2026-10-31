import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/svelte';
import { flushSync } from 'svelte';
import { api } from '$lib/api/client';
import { locale } from '$lib/i18n';
import { downloadBlob } from '$lib/utils/download';
import type { ServiceReport } from '$lib/types/serviceCheck';
import { makeServiceCheckReport, serviceCheckOptions } from '../../../scripts/mock-service-check.mjs';
import ServiceCheckTab from './ServiceCheckTab.svelte';

vi.mock('$lib/api/client', () => ({ api:{ getServiceCheckOptions:vi.fn(), runServiceCheck:vi.fn() } }));
vi.mock('$lib/utils/download', () => ({ downloadBlob:vi.fn() }));

beforeEach(() => {
	vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
	vi.mocked(api.getServiceCheckOptions).mockResolvedValue(structuredClone(serviceCheckOptions));
	locale.set('ru');
});
afterEach(() => { cleanup(); vi.resetAllMocks(); vi.unstubAllGlobals(); locale.set('ru'); });

async function chooseDevice() {
	await screen.findByText('VPN подключён, а приложение не работает?');
	await waitFor(() => expect(api.getServiceCheckOptions).toHaveBeenCalledOnce());
	await fireEvent.click(screen.getByLabelText('Устройство'));
	await fireEvent.click(await screen.findByRole('option', { name:/Demo Phone/ }));
	await fireEvent.input(screen.getByLabelText('Домен или IP'), { target:{ value:'broken.test' } });
}

describe('service diagnostics', () => {
	it('uses the selected device policy, leaves TCP opt-in and distinguishes DNS failure from missing flows', async () => {
		vi.mocked(api.runServiceCheck).mockImplementation(async (input) => makeServiceCheckReport(input) as ServiceReport);
		render(ServiceCheckTab);
		await chooseDevice();
		await fireEvent.click(screen.getByRole('button', { name:'Проверить' }));
		await screen.findByText(/Запрос через выбранный DNS-профиль/);
		expect(api.runServiceCheck).toHaveBeenCalledWith({ clientIP:'192.0.2.20', target:'broken.test', dnsProfile:'Policy0', probeInterface:'', port:443 }, expect.any(AbortSignal));
		expect(screen.getByText(/Это не доказывает сбой/)).toBeTruthy();
		expect(screen.getByText(/Демонстрационные данные/)).toBeTruthy();
		await fireEvent.click(screen.getByRole('button', { name:'Сохранить обезличенный отчёт' }));
		expect(downloadBlob).toHaveBeenCalledWith(expect.any(Blob), 'awg-service-diagnostic.json');
		locale.set('en'); flushSync();
		expect(screen.getByText(/The query through this DNS profile failed/)).toBeTruthy();
	});

	it('does not display a late response after cancellation', async () => {
		let complete!: (value:ServiceReport) => void;
		vi.mocked(api.runServiceCheck).mockImplementation(() => new Promise(resolve => { complete=resolve; }));
		render(ServiceCheckTab); await chooseDevice();
		await fireEvent.click(screen.getByRole('button', { name:'Проверить' }));
		await fireEvent.click(screen.getByRole('button', { name:'Отмена' }));
		complete(makeServiceCheckReport({ clientIP:'192.0.2.20', target:'broken.test', dnsProfile:'Policy0', probeInterface:'', port:443 }) as ServiceReport);
		await Promise.resolve(); flushSync();
		expect(screen.queryByText('Результат проверки')).toBeNull();
	});
});
